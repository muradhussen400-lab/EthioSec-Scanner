"""
EthioSec Scanner — Professional Evidence-Driven Cookie Security Engine.

Audits HTTP response Set-Cookie headers for:
1. Transport Security (Secure flag enforcement based on origin scheme).
2. Script Inaccessibility (HttpOnly flag on sensitive session tokens).
3. Cross-Site Request Handling (SameSite=Strict/Lax/None validation).
4. Scope Exposure (Domain and Path scope boundaries).
5. Expiration & Lifecycle (Session vs persistent cookies, Max-Age bounds).
6. Modern Cookie Prefixes (__Host-, __Secure-, __Http-, __Host-Http-).

Strict Hygiene:
- Cookie values, session IDs, and tokens are strictly REDACTED in evidence, logs, and database records.
- Canonical finding statuses (CONFIRMED, POTENTIAL, NOT_DETECTED, NOT_TESTED, ERROR) are strictly preserved.
"""

import re
import logging
from typing import TYPE_CHECKING, Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass, field
from enum import Enum
from email.utils import parsedate_to_datetime

from scanner.test_case import TestCaseResult

if TYPE_CHECKING:
    from scanner.engine import SecurityScanner
    import httpx

logger = logging.getLogger("ethiosec.scanner.cookies")


class CookiePurpose(str, Enum):
    SESSION = "session"
    PREFERENCE = "preference"
    GENERAL = "general"


# Canonical session cookie names (case-insensitive exact match)
CANONICAL_SESSION_COOKIE_NAMES = {
    "session", "sessionid", "session_id", "phpsessid", "jsessionid",
    "asp.net_sessionid", "connect.sid", "sid", "token", "auth_token",
    "jwt", "access_token", "id_token", "logged_in", "remember_token",
    "authtoken", "user_session", "app_session", "laravel_session",
    "secure_session", "authenticity_token"
}

# Canonical non-sensitive preference / analytics names (case-insensitive exact match)
CANONICAL_PREFERENCE_NAMES = {
    "theme", "dark_mode", "mode", "lang", "language", "locale",
    "timezone", "tz", "cookie_consent", "gdpr", "consent", "accepted_cookies",
    "_ga", "_gid", "_gat", "analytics", "ui_pref", "font_size", "sidebar_state"
}

# Conservative boundary regex for session/auth hints
SESSION_TOKEN_PATTERN = re.compile(
    r"(?i)(^|[_\.-])(session|sess|auth|jwt|token|login|logged)([_\.-]|$)"
)

# Conservative boundary regex for preference hints
PREFERENCE_PATTERN = re.compile(
    r"(?i)(^|[_\.-])(theme|lang|locale|mode|cookie_consent|consent|analytics)([_\.-]|$)"
)


@dataclass
class ParsedCookie:
    raw_header: str
    name: str
    has_value: bool
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    expires: Optional[str] = None
    max_age: Optional[int] = None
    purpose: CookiePurpose = CookiePurpose.GENERAL
    is_session: bool = False
    prefixes: List[str] = field(default_factory=list)
    malformed_attributes: List[str] = field(default_factory=list)


def sanitize_set_cookie(header_str: str) -> str:
    """
    Redacts the raw cookie value while preserving the cookie name and all attributes intact.
    Example: 'session=secret123; Path=/; Secure' -> 'session=[REDACTED]; Path=/; Secure'
    """
    if not header_str:
        return ""
    tokens = [t.strip() for t in str(header_str).split(";") if t.strip()]
    if not tokens:
        return ""
    first = tokens[0]
    if "=" in first:
        k, _ = first.split("=", 1)
        sanitized_first = f"{k.strip()}=[REDACTED]"
    else:
        sanitized_first = f"{first.strip()}"
    if len(tokens) > 1:
        return f"{sanitized_first}; " + "; ".join(tokens[1:])
    return sanitized_first


def classify_cookie_purpose(name: str) -> CookiePurpose:
    """
    Conservatively classifies cookie purpose:
    - SESSION: Identifies likely authentication or authorization session state.
    - PREFERENCE: Identifies UI preferences, language, or consent settings.
    - GENERAL: Unknown or general purpose; evaluated with calibrated severity.
    """
    if not name:
        return CookiePurpose.GENERAL
    n_lower = name.strip().lower()
    if n_lower in CANONICAL_SESSION_COOKIE_NAMES:
        return CookiePurpose.SESSION
    if n_lower in CANONICAL_PREFERENCE_NAMES:
        return CookiePurpose.PREFERENCE
    if SESSION_TOKEN_PATTERN.search(n_lower):
        return CookiePurpose.SESSION
    if PREFERENCE_PATTERN.search(n_lower):
        return CookiePurpose.PREFERENCE
    return CookiePurpose.GENERAL


def parse_set_cookie(header_val: str) -> Optional[ParsedCookie]:
    """
    Parses a single Set-Cookie header string safely without splitting on commas,
    preserving comma-separated dates in Expires attributes.
    """
    if not header_val or not isinstance(header_val, str):
        return None

    raw_header = header_val.strip()
    if not raw_header:
        return None

    parts = [p.strip() for p in raw_header.split(";") if p.strip()]
    if not parts:
        return None

    first = parts[0]
    if "=" in first:
        raw_name, raw_val = first.split("=", 1)
        has_val = bool(raw_val.strip())
    else:
        raw_name = first
        has_val = False

    name = raw_name.strip()
    if not name:
        return None

    cookie = ParsedCookie(
        raw_header=raw_header,
        name=name,
        has_value=has_val
    )

    # Classify purpose
    cookie.purpose = classify_cookie_purpose(cookie.name)
    cookie.is_session = (cookie.purpose == CookiePurpose.SESSION)

    # Detect prefix conventions (RFC 6265bis specifies case-sensitive prefix rules)
    for pfx in ("__Host-", "__Secure-", "__Http-", "__Host-Http-"):
        if cookie.name.startswith(pfx):
            cookie.prefixes.append(pfx)

    # Parse remaining attributes case-insensitively
    for token in parts[1:]:
        if "=" in token:
            attr_k, attr_v = token.split("=", 1)
            attr_k = attr_k.strip().lower()
            attr_v = attr_v.strip()
        else:
            attr_k = token.strip().lower()
            attr_v = ""

        if attr_k == "secure":
            cookie.secure = True
        elif attr_k == "httponly":
            cookie.httponly = True
        elif attr_k == "samesite":
            cookie.samesite = attr_v.lower() if attr_v else "none"
        elif attr_k == "domain":
            cookie.domain = attr_v
        elif attr_k == "path":
            cookie.path = attr_v
        elif attr_k == "expires":
            cookie.expires = attr_v
            if attr_v:
                try:
                    parsedate_to_datetime(attr_v)
                except Exception:
                    cookie.malformed_attributes.append(f"Invalid Expires date format '{attr_v}'")
        elif attr_k == "max-age":
            try:
                cookie.max_age = int(attr_v)
            except (ValueError, TypeError):
                cookie.malformed_attributes.append(f"Invalid Max-Age '{attr_v}'")

    return cookie


def _emit_cookie_finding(
    scanner: "SecurityScanner",
    test_case: TestCaseResult,
    title: str,
    description: str,
    sanitized_evidence: str,
    impact: str,
    url: str,
    c_name: str,
    http_method: str
):
    """
    Evaluates test_case, appends sanitized header evidence showing the exact directive
    with cookie values redacted, and dispatches the finding to the scanner engine.
    """
    test_case.evaluate()
    evidence_str = f"{test_case.evidence}\nObserved directive: {sanitized_evidence}"
    scanner._add_finding(
        f_type="cookies",
        severity=test_case.severity,
        status=test_case.status,
        verification_status=test_case.verification_status,
        confidence=test_case.confidence,
        title=title,
        description=description,
        evidence=evidence_str,
        impact=impact,
        remediation=test_case.remediation,
        owasp=test_case.owasp,
        cwe=test_case.cwe,
        url=url,
        parameter=f"Cookie: {c_name}",
        http_method=http_method
    )


async def check_cookies(scanner: "SecurityScanner", url: str, response: Any):
    """
    Professional, evidence-driven cookie security audit.
    Evaluates Set-Cookie headers from response against security standards:
    - Transport Security (Secure flag)
    - Client-Side Script Protection (HttpOnly)
    - Cross-Site Request Security (SameSite=Strict/Lax/None)
    - Modern Cookie Prefixes (__Host-, __Secure-)
    - Domain & Scope Exposure
    """
    # 1. Extract Set-Cookie headers safely
    raw_cookies: List[str] = []
    try:
        if hasattr(response, "headers") and response.headers is not None:
            if hasattr(response.headers, "get_list"):
                raw_cookies = response.headers.get_list("set-cookie")
            elif "set-cookie" in response.headers:
                val = response.headers["set-cookie"]
                raw_cookies = [val] if isinstance(val, str) else list(val)
    except Exception as extract_err:
        logger.warning(f"Error extracting Set-Cookie headers from response: {extract_err}")
        scanner._add_finding(
            f_type="cookies",
            severity="info",
            status="SCANNER_ERROR",
            verification_status="ERROR",
            title="Cookie Security Check Error",
            description="The scanner encountered an unexpected error while reading response headers.",
            evidence=f"Header extraction error: {type(extract_err).__name__}",
            url=url
        )
        return

    # 2. Resolve context: origin scheme and request method
    parsed_url = urlparse(url or "")
    is_https = parsed_url.scheme.lower() == "https"
    http_method = "GET"
    if hasattr(response, "request") and response.request is not None:
        http_method = getattr(response.request, "method", "GET") or "GET"

    # 3. Handle Truthful NOT_TESTED when no Set-Cookie headers are present
    if not raw_cookies:
        scanner._add_finding(
            f_type="cookies",
            severity="info",
            status="NOT_TESTED",
            verification_status="NOT_TESTED",
            confidence="HIGH",
            title="Cookie Security Assessment Not Tested (No Set-Cookie Headers Observed)",
            description=(
                "The server response did not issue any Set-Cookie headers. "
                "Cookie security flag evaluation was not applicable for this response."
            ),
            evidence=f"Response from {url} contained 0 Set-Cookie directives.",
            url=url,
            http_method=http_method
        )
        return

    parsed_cookies: List[ParsedCookie] = []
    findings_emitted = 0

    # 4. Parse and evaluate each cookie independently
    for raw in raw_cookies:
        try:
            cookie = parse_set_cookie(raw)
            if not cookie:
                continue
            parsed_cookies.append(cookie)

            sanitized_evidence = sanitize_set_cookie(raw)
            c_name = cookie.name

            # -----------------------------------------------------------------
            # CHECK A: Insecure Cookie Transmission (Missing 'Secure' Flag)
            # -----------------------------------------------------------------
            if is_https and not cookie.secure:
                test_case = TestCaseResult(
                    category="cookies",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter=f"Cookie: {c_name}",
                    baseline_response={"set-cookie": sanitized_evidence},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
                )

                if cookie.is_session:
                    test_case.severity = "medium"
                    test_case.status = "MEDIUM"
                    test_case.confidence = "MEDIUM"
                    test_case.add_observation(
                        "session_cookie_missing_secure",
                        f"Cookie '{c_name}' (heuristically classified as session-related) was set without the 'Secure' attribute on an HTTPS endpoint. "
                        "Observed configuration weakness: browsers may transmit this cookie over unencrypted HTTP if an insecure link or resource is accessed. Exploitability is potential and contingent on cleartext network interception or SSL stripping.",
                        is_suspicious=True
                    )
                    test_case.remediation = [
                        f"Add the 'Secure' attribute to the '{c_name}' cookie to ensure it is transmitted exclusively over TLS encrypted connections.",
                        "Enforce HTTP Strict Transport Security (HSTS) with includeSubDomains."
                    ]
                    title = f"Cookie Missing 'Secure' Attribute (Likely Session Cookie: '{c_name}')"
                    desc = f"The cookie '{c_name}' was set without the 'Secure' attribute. Attackers monitoring network traffic can potentially intercept credentials over unencrypted HTTP if insecure requests are made."
                else:
                    test_case.severity = "low"
                    test_case.status = "LOW"
                    test_case.confidence = "LOW"
                    test_case.add_observation(
                        "cookie_missing_secure",
                        f"Cookie '{c_name}' was set without the 'Secure' attribute on an HTTPS endpoint.",
                        is_suspicious=True
                    )
                    test_case.remediation = [
                        f"Set the 'Secure' attribute on the '{c_name}' cookie to prevent plaintext transmission over HTTP."
                    ]
                    title = f"Cookie Missing 'Secure' Attribute ('{c_name}')"
                    desc = f"The cookie '{c_name}' was set without the 'Secure' attribute. Browsers may transmit it in plaintext if unencrypted HTTP requests are made."

                _emit_cookie_finding(
                    scanner=scanner,
                    test_case=test_case,
                    title=title,
                    description=desc,
                    sanitized_evidence=sanitized_evidence,
                    impact="Permits transmission of cookies in unencrypted HTTP requests, vulnerable to potential network interception or SSL-stripping.",
                    url=url,
                    c_name=c_name,
                    http_method=http_method
                )
                findings_emitted += 1

            elif not is_https and not cookie.secure and cookie.is_session:
                test_case = TestCaseResult(
                    category="cookies",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter=f"Cookie: {c_name}",
                    baseline_response={"set-cookie": sanitized_evidence},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-319: Cleartext Transmission of Sensitive Information"
                )
                test_case.severity = "medium"
                test_case.status = "MEDIUM"
                test_case.confidence = "MEDIUM"
                test_case.add_observation(
                    "session_cookie_transmitted_over_http",
                    f"Cookie '{c_name}' (heuristically classified as session-related) was issued over an unencrypted HTTP connection ({url}) without the 'Secure' attribute. "
                    "Observed configuration: initial Set-Cookie transmission occurs in cleartext, exposing the token to potential network eavesdropping.",
                    is_suspicious=True
                )
                test_case.remediation = [
                    f"Migrate the application to HTTPS and configure the 'Secure' attribute on the '{c_name}' cookie.",
                    "Implement HTTP Strict Transport Security (HSTS) with includeSubDomains."
                ]
                _emit_cookie_finding(
                    scanner=scanner,
                    test_case=test_case,
                    title=f"Cookie Missing 'Secure' Attribute (Cleartext HTTP Transmission: '{c_name}')",
                    description=f"The cookie '{c_name}' was issued over plain HTTP without the 'Secure' attribute. Attackers monitoring network traffic can potentially intercept credentials in transit.",
                    sanitized_evidence=sanitized_evidence,
                    impact="Exposes sensitive session credentials to cleartext network eavesdropping.",
                    url=url,
                    c_name=c_name,
                    http_method=http_method
                )
                findings_emitted += 1

            elif not is_https and cookie.secure:
                test_case = TestCaseResult(
                    category="cookies",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter=f"Cookie: {c_name}",
                    baseline_response={"set-cookie": sanitized_evidence},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
                )
                test_case.severity = "low"
                test_case.status = "LOW"
                test_case.confidence = "MEDIUM"
                test_case.add_observation(
                    "secure_cookie_over_http",
                    f"Cookie '{c_name}' specifies the 'Secure' attribute over an unencrypted HTTP origin ({url}). "
                    "Modern browsers complying with RFC 6265bis will reject or ignore setting this cookie.",
                    is_suspicious=True
                )
                test_case.remediation = ["Serve the web application exclusively over HTTPS."]
                _emit_cookie_finding(
                    scanner=scanner,
                    test_case=test_case,
                    title=f"Cookie Setting 'Secure' Flag Over Unencrypted HTTP ('{c_name}')",
                    description=f"The cookie '{c_name}' sets 'Secure' from an unencrypted HTTP origin. Browsers complying with RFC 6265bis reject cookies with Secure over HTTP.",
                    sanitized_evidence=sanitized_evidence,
                    impact="The cookie may be discarded by client browsers, causing session or state retention failures.",
                    url=url,
                    c_name=c_name,
                    http_method=http_method
                )
                findings_emitted += 1

            # -----------------------------------------------------------------
            # CHECK B: Missing 'HttpOnly' Attribute (Script Inaccessibility)
            # -----------------------------------------------------------------
            if not cookie.httponly:
                if cookie.is_session:
                    test_case = TestCaseResult(
                        category="cookies",
                        target_endpoint=url,
                        http_method=http_method,
                        parameter=f"Cookie: {c_name}",
                        baseline_response={"set-cookie": sanitized_evidence},
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
                    )
                    test_case.severity = "medium"
                    test_case.status = "MEDIUM"
                    test_case.confidence = "MEDIUM"
                    test_case.add_observation(
                        "session_cookie_missing_httponly",
                        f"Cookie '{c_name}' (heuristically classified as session-related) was issued without the 'HttpOnly' attribute. "
                        "Observed configuration weakness: client-side JavaScript APIs (e.g. document.cookie) have direct read access. Exploitability is potential and contingent on a script injection vulnerability (XSS); missing HttpOnly alone does not prove session theft.",
                        is_suspicious=True
                    )
                    test_case.remediation = [
                        f"Set HttpOnly=true on the '{c_name}' cookie to block JavaScript access and mitigate session theft via XSS."
                    ]
                    _emit_cookie_finding(
                        scanner=scanner,
                        test_case=test_case,
                        title=f"Cookie Missing 'HttpOnly' Attribute (Likely Session Cookie: '{c_name}')",
                        description=f"The cookie '{c_name}' was set without the 'HttpOnly' flag. In the event of a Cross-Site Scripting (XSS) vulnerability, an attacker could potentially extract this token via JavaScript.",
                        sanitized_evidence=sanitized_evidence,
                        impact="Elevates the impact of any XSS vulnerability to potential account hijacking via session cookie theft.",
                        url=url,
                        c_name=c_name,
                        http_method=http_method
                    )
                    findings_emitted += 1

                elif cookie.purpose == CookiePurpose.GENERAL:
                    test_case = TestCaseResult(
                        category="cookies",
                        target_endpoint=url,
                        http_method=http_method,
                        parameter=f"Cookie: {c_name}",
                        baseline_response={"set-cookie": sanitized_evidence},
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
                    )
                    test_case.severity = "low"
                    test_case.add_observation(
                        "cookie_missing_httponly",
                        f"Cookie '{c_name}' lacks the 'HttpOnly' attribute. If this cookie contains sensitive state, it should be restricted from JavaScript access.",
                        is_suspicious=True
                    )
                    test_case.remediation = [f"Add 'HttpOnly' to '{c_name}' unless client-side JavaScript specifically requires read access."]
                    _emit_cookie_finding(
                        scanner=scanner,
                        test_case=test_case,
                        title=f"Cookie Missing 'HttpOnly' Attribute ('{c_name}')",
                        description=f"The cookie '{c_name}' does not specify the 'HttpOnly' attribute. Verify whether this cookie contains sensitive state that should be shielded from client-side scripts.",
                        sanitized_evidence=sanitized_evidence,
                        impact="Exposes cookie contents to client-side scripts if an injection vulnerability exists.",
                        url=url,
                        c_name=c_name,
                        http_method=http_method
                    )
                    findings_emitted += 1

            # -----------------------------------------------------------------
            # CHECK C: SameSite Validation & Cross-Site Request Security
            # -----------------------------------------------------------------
            if cookie.samesite is None:
                if cookie.purpose != CookiePurpose.PREFERENCE:
                    test_case = TestCaseResult(
                        category="cookies",
                        target_endpoint=url,
                        http_method=http_method,
                        parameter=f"Cookie: {c_name}",
                        baseline_response={"set-cookie": sanitized_evidence},
                        owasp="A01:2021-Broken Access Control",
                        cwe="CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
                    )
                    test_case.severity = "low"
                    test_case.add_observation(
                        "cookie_missing_samesite",
                        f"Cookie '{c_name}' does not specify an explicit 'SameSite' attribute. "
                        "Explicitly setting SameSite=Lax or SameSite=Strict ensures consistent cross-origin behavior across all user agents.",
                        is_suspicious=True
                    )
                    test_case.remediation = [
                        f"Configure SameSite=Lax or SameSite=Strict on the '{c_name}' cookie to protect against Cross-Site Request Forgery (CSRF).",
                        "Do not rely solely on SameSite as a substitute for server-side anti-CSRF token verification."
                    ]
                    _emit_cookie_finding(
                        scanner=scanner,
                        test_case=test_case,
                        title=f"Cookie Missing 'SameSite' Attribute ('{c_name}')",
                        description=(
                            f"The cookie '{c_name}' lacks an explicit SameSite attribute. While modern browsers default to Lax, "
                            "setting SameSite explicitly ensures deterministic protection against Cross-Site Request Forgery."
                        ),
                        sanitized_evidence=sanitized_evidence,
                        impact="Cross-origin requests may include this cookie depending on browser default policies.",
                        url=url,
                        c_name=c_name,
                        http_method=http_method
                    )
                    findings_emitted += 1

            elif cookie.samesite not in ("strict", "lax", "none"):
                test_case = TestCaseResult(
                    category="cookies",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter=f"Cookie: {c_name}",
                    baseline_response={"set-cookie": sanitized_evidence},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
                )
                test_case.severity = "low"
                test_case.add_observation(
                    "cookie_invalid_samesite",
                    f"Cookie '{c_name}' specifies an invalid SameSite attribute value: '{cookie.samesite}'. "
                    "Valid values are 'Strict', 'Lax', or 'None'.",
                    is_suspicious=True
                )
                test_case.remediation = ["Set SameSite to 'Strict', 'Lax', or 'None'."]
                _emit_cookie_finding(
                    scanner=scanner,
                    test_case=test_case,
                    title=f"Cookie With Malformed 'SameSite' Attribute ('{c_name}')",
                    description=f"The cookie '{c_name}' has an unrecognized SameSite value '{cookie.samesite}'. Browsers may disregard this attribute.",
                    sanitized_evidence=sanitized_evidence,
                    impact="Browser may fall back to default behavior or drop the cookie attribute.",
                    url=url,
                    c_name=c_name,
                    http_method=http_method
                )
                findings_emitted += 1

            elif cookie.samesite == "none" and not cookie.secure:
                test_case = TestCaseResult(
                    category="cookies",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter=f"Cookie: {c_name}",
                    baseline_response={"set-cookie": sanitized_evidence},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
                )
                test_case.severity = "high"
                test_case.add_observation(
                    "samesite_none_without_secure",
                    f"Cookie '{c_name}' specifies SameSite=None without the 'Secure' attribute. "
                    "Modern standards (RFC 6265bis, Chromium, Firefox, WebKit) mandate that SameSite=None cookies must also be Secure; otherwise browsers reject the cookie.",
                    is_strong_evidence=True
                )
                test_case.remediation = ["Add the 'Secure' attribute to any cookie configured with SameSite=None, and serve exclusively over HTTPS."]
                _emit_cookie_finding(
                    scanner=scanner,
                    test_case=test_case,
                    title=f"Insecure SameSite Configuration: 'SameSite=None' Without 'Secure' ('{c_name}')",
                    description=f"The cookie '{c_name}' specifies SameSite=None without the Secure attribute. Modern browsers reject this configuration and discard the cookie.",
                    sanitized_evidence=sanitized_evidence,
                    impact="The cookie is rejected by conforming web browsers, disrupting authentication and state handling.",
                    url=url,
                    c_name=c_name,
                    http_method=http_method
                )
                findings_emitted += 1

            # -----------------------------------------------------------------
            # CHECK D: Cookie Prefix Requirements (__Host-, __Secure-)
            # -----------------------------------------------------------------
            if "__Secure-" in cookie.prefixes:
                if not cookie.secure or not is_https:
                    test_case = TestCaseResult(
                        category="cookies",
                        target_endpoint=url,
                        http_method=http_method,
                        parameter=f"Cookie: {c_name}",
                        baseline_response={"set-cookie": sanitized_evidence},
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
                    )
                    test_case.severity = "medium"
                    test_case.add_observation(
                        "prefix_secure_violation",
                        f"Cookie '{c_name}' uses the '__Secure-' prefix but was set without the 'Secure' attribute (or over an insecure connection). "
                        "RFC 6265bis mandates that __Secure- cookies must include the 'Secure' flag and be set over HTTPS. Browsers will reject this cookie.",
                        is_strong_evidence=True
                    )
                    test_case.remediation = ["Add the 'Secure' attribute and serve the application over HTTPS."]
                    _emit_cookie_finding(
                        scanner=scanner,
                        test_case=test_case,
                        title=f"Cookie Prefix Violation: '__Secure-' Prefix Without 'Secure' Attribute ('{c_name}')",
                        description=f"The cookie '{c_name}' uses the '__Secure-' prefix but fails prefix constraints. Browsers adhering to cookie prefix standards will reject this cookie.",
                        sanitized_evidence=sanitized_evidence,
                        impact="Conforming browsers will reject and drop the cookie.",
                        url=url,
                        c_name=c_name,
                        http_method=http_method
                    )
                    findings_emitted += 1

            if "__Host-" in cookie.prefixes:
                host_violations: List[str] = []
                if not cookie.secure:
                    host_violations.append("missing 'Secure' attribute")
                if not is_https:
                    host_violations.append("served over plain HTTP")
                if cookie.domain:
                    host_violations.append(f"contains forbidden 'Domain={cookie.domain}' attribute (must be host-only)")
                if not cookie.path or cookie.path != "/":
                    host_violations.append(f"Path must be '/' (observed: '{cookie.path}')")

                if host_violations:
                    test_case = TestCaseResult(
                        category="cookies",
                        target_endpoint=url,
                        http_method=http_method,
                        parameter=f"Cookie: {c_name}",
                        baseline_response={"set-cookie": sanitized_evidence},
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
                    )
                    test_case.severity = "medium"
                    test_case.add_observation(
                        "prefix_host_violation",
                        f"Cookie '{c_name}' uses the '__Host-' prefix but violates prefix rules: {', '.join(host_violations)}. "
                        "RFC 6265bis mandates that __Host- cookies must be Secure, have Path=/, and omit the Domain attribute. Browsers will reject this cookie.",
                        is_strong_evidence=True
                    )
                    test_case.remediation = [
                        "Ensure the cookie includes 'Secure', sets 'Path=/', and does not specify a 'Domain' attribute.",
                        "Serve exclusively over HTTPS."
                    ]
                    _emit_cookie_finding(
                        scanner=scanner,
                        test_case=test_case,
                        title=f"Cookie Prefix Violation: Invalid '__Host-' Configuration ('{c_name}')",
                        description=f"The cookie '{c_name}' uses the '__Host-' prefix but violates RFC prefix specifications ({', '.join(host_violations)}). Browsers will reject this Set-Cookie directive.",
                        sanitized_evidence=sanitized_evidence,
                        impact="The browser will reject the cookie, preventing user sessions from establishing.",
                        url=url,
                        c_name=c_name,
                        http_method=http_method
                    )
                    findings_emitted += 1

            if ("__Http-" in cookie.prefixes or "__Host-Http-" in cookie.prefixes) and not cookie.httponly:
                test_case = TestCaseResult(
                    category="cookies",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter=f"Cookie: {c_name}",
                    baseline_response={"set-cookie": sanitized_evidence},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
                )
                test_case.severity = "medium"
                test_case.add_observation(
                    "prefix_httponly_violation",
                    f"Cookie '{c_name}' uses an HTTP-related prefix ({', '.join(cookie.prefixes)}) but is missing the 'HttpOnly' attribute.",
                    is_strong_evidence=True
                )
                test_case.remediation = ["Add the 'HttpOnly' attribute to the cookie."]
                _emit_cookie_finding(
                    scanner=scanner,
                    test_case=test_case,
                    title=f"Cookie Prefix Violation: Missing 'HttpOnly' Flag ('{c_name}')",
                    description=f"The cookie '{c_name}' uses an HTTP prefix convention but lacks the HttpOnly attribute.",
                    sanitized_evidence=sanitized_evidence,
                    impact="Permits client-side script access contrary to prefix intent.",
                    url=url,
                    c_name=c_name,
                    http_method=http_method
                )
                findings_emitted += 1

            # -----------------------------------------------------------------
            # CHECK E: Scope & Domain Boundary Inspection
            # -----------------------------------------------------------------
            if cookie.domain and cookie.is_session:
                d = cookie.domain.strip().lower()
                origin_host = (parsed_url.hostname or "").lower()
                clean_d = d.lstrip(".")

                is_broad = False
                if d.startswith("."):
                    is_broad = True
                elif origin_host and clean_d and origin_host != clean_d and origin_host.endswith("." + clean_d):
                    is_broad = True
                elif clean_d.count(".") < 1 or clean_d in ("com", "org", "net", "edu", "gov", "co.uk"):
                    is_broad = True

                if is_broad:
                    test_case = TestCaseResult(
                        category="cookies",
                        target_endpoint=url,
                        http_method=http_method,
                        parameter=f"Cookie: {c_name}",
                        baseline_response={"set-cookie": sanitized_evidence},
                        owasp="A01:2021-Broken Access Control",
                        cwe="CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
                    )
                    test_case.severity = "low"
                    test_case.add_observation(
                        "broad_domain_cookie",
                        f"Session cookie '{c_name}' explicitly sets Domain='{cookie.domain}'. "
                        f"This broadens cookie access to subdomains, exposing the session to vulnerabilities in auxiliary services or subdomain takeover.",
                        is_suspicious=True
                    )
                    test_case.remediation = ["Omit the Domain attribute to restrict the cookie to the exact origin host (host-only cookie)."]
                    _emit_cookie_finding(
                        scanner=scanner,
                        test_case=test_case,
                        title=f"Overly Broad Domain Scope for Session Cookie ('{c_name}')",
                        description=(
                            f"The session cookie '{c_name}' specifies an explicit domain '{cookie.domain}'. "
                            "This permits subdomains to access the session token."
                        ),
                        sanitized_evidence=sanitized_evidence,
                        impact="Cross-subdomain leakage: compromised or vulnerable subdomains can read or manipulate this session cookie.",
                        url=url,
                        c_name=c_name,
                        http_method=http_method
                    )
                    findings_emitted += 1

            # -----------------------------------------------------------------
            # CHECK F: Expiration & Lifecycle (Excessive Max-Age on Session Token)
            # -----------------------------------------------------------------
            if cookie.is_session and cookie.max_age is not None and cookie.max_age > 31536000:
                test_case = TestCaseResult(
                    category="cookies",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter=f"Cookie: {c_name}",
                    baseline_response={"set-cookie": sanitized_evidence},
                    owasp="A07:2021-Identification and Authentication Failures",
                    cwe="CWE-613: Insufficient Session Expiration"
                )
                test_case.severity = "low"
                test_case.add_observation(
                    "excessive_session_max_age",
                    f"Session cookie '{c_name}' sets an excessively long Max-Age ({cookie.max_age} seconds / {round(cookie.max_age / 86400)} days). "
                    "Long-lived persistent session cookies increase the window of opportunity for token theft.",
                    is_suspicious=True
                )
                test_case.remediation = ["Enforce shorter session timeouts (e.g. 1 to 14 days) and re-authenticate sensitive operations."]
                _emit_cookie_finding(
                    scanner=scanner,
                    test_case=test_case,
                    title=f"Excessive Cookie Max-Age on Session Cookie ('{c_name}')",
                    description=f"The session cookie '{c_name}' specifies a Max-Age exceeding 1 year ({round(cookie.max_age / 86400)} days).",
                    sanitized_evidence=sanitized_evidence,
                    impact="Increases the attack surface window for session hijacking via stolen tokens or abandoned devices.",
                    url=url,
                    c_name=c_name,
                    http_method=http_method
                )
                findings_emitted += 1

            # -----------------------------------------------------------------
            # CHECK G: Malformed Attribute Configuration
            # -----------------------------------------------------------------
            if cookie.malformed_attributes:
                malformed_desc = "; ".join(cookie.malformed_attributes)
                test_case = TestCaseResult(
                    category="cookies",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter=f"Cookie: {c_name}",
                    baseline_response={"set-cookie": sanitized_evidence},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
                )
                test_case.severity = "low"
                test_case.add_observation(
                    "cookie_malformed_attribute",
                    f"Cookie '{c_name}' contains malformed attribute syntax: {malformed_desc}.",
                    is_suspicious=True
                )
                test_case.remediation = ["Correct the attribute syntax in the Set-Cookie response header."]
                _emit_cookie_finding(
                    scanner=scanner,
                    test_case=test_case,
                    title=f"Cookie With Malformed Attribute Configuration ('{c_name}')",
                    description=f"The cookie '{c_name}' contains malformed attributes ({malformed_desc}). Browsers may reject or misinterpret these directives.",
                    sanitized_evidence=sanitized_evidence,
                    impact="Browser may ignore the attribute or fail to handle cookie lifecycle correctly.",
                    url=url,
                    c_name=c_name,
                    http_method=http_method
                )
                findings_emitted += 1

        except Exception as cookie_eval_err:
            logger.warning(f"Error evaluating cookie in {url}: {cookie_eval_err}")
            scanner._add_finding(
                f_type="cookies",
                severity="info",
                status="SCANNER_ERROR",
                verification_status="ERROR",
                title="Cookie Evaluation Warning",
                description="The scanner encountered an unexpected error while parsing a cookie directive.",
                evidence=f"Parser exception: {type(cookie_eval_err).__name__}",
                url=url
            )

    # 5. Clean Verification Outcome (NOT_DETECTED)
    if findings_emitted == 0 and parsed_cookies:
        cookie_names_str = ", ".join(c.name for c in parsed_cookies)
        scanner._add_finding(
            f_type="cookies",
            severity="info",
            status="NOT_DETECTED",
            verification_status="NOT_DETECTED",
            confidence="HIGH",
            title="Cookie Security Checks Passed",
            description=(
                f"Audited {len(parsed_cookies)} cookie(s) ({cookie_names_str}). "
                "All evaluated cookies implement recommended protective attributes "
                "(Secure, HttpOnly, valid SameSite flags, and correct prefix configurations)."
            ),
            evidence=f"Audited cookies: {cookie_names_str} on {url}. No insecure transmission, script access, or prefix violations observed.",
            url=url,
            http_method=http_method
        )
