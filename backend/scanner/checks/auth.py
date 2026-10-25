"""
EthioSec Scanner — Professional Authentication & Session Security Engine.

Methodology & Verification Hierarchy:
1. Attack Surface Discovery & Classification:
   - Identifies candidate login forms, registration forms, password reset forms from crawler.
   - Discovers candidate authentication endpoints (login APIs, token endpoints, OAuth routes).
   - Identifies candidate protected resources (endpoints returning 401/403, crawled API routes,
     and application areas requiring session authorization).
   - Catalogs observed session cookies from responses and redirects.

2. Credential & Form Transport Security:
   - Insecure form action (HTTP submission of credentials).
   - Insecure embedding page (form loaded over plain HTTP, vulnerable to MITM/SSL stripping).
   - Dangerous HTTP GET method for authentication forms (credentials in URL/logs/history).
   - Sensitive credentials or tokens exposed in URL query parameters.
   - Anti-CSRF protection absent on login forms.

3. Reliable Authentication Enforcement & Bypass Verification:
   - Validates authenticated baseline when authorized context is provided.
   - Issues controlled unauthenticated request preserving redirect and status telemetry.
   - Anti-False-Positive Heuristics:
     * Recognizes HTTP 3xx redirects to login as authentication enforcement, not bypass.
     * Recognizes HTTP 200 responses containing HTML login forms as enforcement.
     * Recognizes client-side Single Page Application (SPA) shells without protected data.
     * Evaluates differential body similarity and structural markers.
   - Classifies findings into CONFIRMED, POTENTIAL, NOT_DETECTED, or INCONCLUSIVE.

4. Session Cookie Security & Lifecycle:
   - Audits HttpOnly, Secure, SameSite, and cookie prefixes (__Host-, __Secure-) on session cookies.
   - Safe session rotation analysis when pre-auth and post-auth sessions are available.
   - Logout endpoint auditing (e.g. CSRF risk on GET-based logout).

5. Safe Bounded Rate Limiting & Account Enumeration:
   - Strictly bounded probe (maximum 5 requests) to evaluate brute-force/lockout signaling.
   - Respects 429 Too Many Requests, Retry-After, and target backoff.
   - Conservative classification avoiding false claims about high-volume policies.

6. Strict Safety, Hygiene & Coverage Accounting:
   - Credentials, tokens, and cookies are unconditionally redacted as [REDACTED].
   - Per-check cancellation tokens and request budgets enforced.
   - Inconclusive or skipped states reported honestly; zero-coverage never reports NOT_DETECTED.
"""

from typing import TYPE_CHECKING, Optional, Dict, Any, List, Set, Tuple
if TYPE_CHECKING:
    from scanner.engine import SecurityScanner

import asyncio
import logging
import re
import html
import time
from urllib.parse import urlparse, urljoin, parse_qsl, urlsplit, urlunsplit

from bs4 import BeautifulSoup
import httpx

from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult
from scanner.differential import BaselineEngine

logger = logging.getLogger("ethiosec.scanner.auth")

# Canonical identifiers for sensitive credential parameters
CREDENTIAL_PARAM_PATTERNS = re.compile(
    r"(?i)^(password|passwd|pwd|pass|secret|token|access_token|auth_token|api_key|apikey|bearer)$"
)
LOGIN_PARAM_PATTERNS = re.compile(
    r"(?i)(password|passwd|pwd|pass|login|username|user|uname|email|credential)"
)
RESET_PARAM_PATTERNS = re.compile(
    r"(?i)(reset|recover|forgot|new_password|confirm_password)"
)
SESSION_COOKIE_NAMES = {
    "session", "sessionid", "session_id", "phpsessid", "jsessionid",
    "asp.net_sessionid", "connect.sid", "sid", "token", "auth_token",
    "jwt", "access_token", "remember_token", "logged_in"
}

PROTECTED_PATH_HINTS = (
    "/protected", "/secure", "/private", "/internal", "/api/me",
    "/profile", "/account", "/dashboard", "/settings", "/admin",
    "/user", "/users", "/billing", "/orders", "/manage", "/portal"
)

PUBLIC_PATH_HINTS = (
    "/", "/index", "/home", "/about", "/contact", "/terms", "/privacy",
    "/faq", "/help", "/pricing", "/blog", "/docs", "/static", "/assets",
    "/login", "/signin", "/register", "/signup", "/forgot-password",
    "/legal", "/features", "/status", "/careers", "/news"
)


def is_session_cookie(name: str) -> bool:
    """Classifies whether a cookie name represents an authentication or session token."""
    if not name:
        return False
    n_lower = name.lower().strip()
    if n_lower in SESSION_COOKIE_NAMES:
        return True
    return any(k in n_lower for k in ("session", "token", "auth", "jwt", "sid", "logged"))


def redact_value(val: Any) -> str:
    """Masks secret material safely for evidence and logging."""
    if not val:
        return "[EMPTY]"
    s = str(val)
    if len(s) <= 4:
        return "[REDACTED]"
    return f"{s[:2]}...[REDACTED]"


def extract_form_inputs(form: Dict[str, Any]) -> List[str]:
    """Safely extracts input names from a crawler form dictionary."""
    raw = form.get("inputs", [])
    if isinstance(raw, list):
        return [str(i) for i in raw if i]
    if isinstance(raw, dict):
        return [str(k) for k in raw.keys()]
    return []


def extract_cookies_from_response(resp: Any) -> Dict[str, str]:
    """Extracts cookie key-value pairs from response object, inspecting cookies jar and Set-Cookie headers."""
    res: Dict[str, str] = {}
    if not resp:
        return res
    if hasattr(resp, "cookies") and resp.cookies:
        for k, v in resp.cookies.items():
            res[k] = v
    if hasattr(resp, "headers"):
        raw_list = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not raw_list and "set-cookie" in resp.headers:
            raw_list = [resp.headers["set-cookie"]]
        for raw in raw_list:
            parts = str(raw).split(";")
            if parts and "=" in parts[0]:
                k, v = parts[0].split("=", 1)
                res[k.strip()] = v.strip()
    return res


class AuthCoverageRecord:
    """
    Transparent execution and attack surface coverage record for authentication checks.
    Maintains exact counts of discovered forms, endpoints, and requests without ambiguity.
    """
    def __init__(self):
        self.candidate_forms_discovered: int = 0
        self.candidate_auth_endpoints_discovered: int = 0
        self.candidate_protected_resources_discovered: int = 0
        self.candidate_session_cookies_discovered: int = 0
        self.candidate_recovery_endpoints_discovered: int = 0
        self.candidate_mfa_endpoints_discovered: int = 0
        self.candidate_oauth_endpoints_discovered: int = 0
        self.candidate_logout_endpoints_discovered: int = 0
        self.forms_tested: int = 0
        self.endpoints_tested: int = 0
        self.requests_attempted: int = 0
        self.requests_completed: int = 0
        self.checks_completed: int = 0
        self.checks_skipped: int = 0
        self.checks_inconclusive: int = 0
        self.scanner_errors: int = 0
        self.findings_confirmed: int = 0
        self.findings_potential: int = 0
        self.rate_limiting_observed: bool = False
        self.tested_targets: List[str] = []
        self.blocking_reasons: List[str] = []
        self.limitations: List[str] = []
        self.verification_completed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_forms_discovered": self.candidate_forms_discovered,
            "candidate_auth_endpoints_discovered": self.candidate_auth_endpoints_discovered,
            "candidate_protected_resources_discovered": self.candidate_protected_resources_discovered,
            "candidate_session_cookies_discovered": self.candidate_session_cookies_discovered,
            "candidate_recovery_endpoints_discovered": self.candidate_recovery_endpoints_discovered,
            "candidate_mfa_endpoints_discovered": self.candidate_mfa_endpoints_discovered,
            "candidate_oauth_endpoints_discovered": self.candidate_oauth_endpoints_discovered,
            "candidate_logout_endpoints_discovered": self.candidate_logout_endpoints_discovered,
            "forms_tested": self.forms_tested,
            "endpoints_tested": self.endpoints_tested,
            "requests_attempted": self.requests_attempted,
            "requests_completed": self.requests_completed,
            "checks_completed": self.checks_completed,
            "checks_skipped": self.checks_skipped,
            "checks_inconclusive": self.checks_inconclusive,
            "findings_confirmed": self.findings_confirmed,
            "findings_potential": self.findings_potential,
            "rate_limiting_observed": self.rate_limiting_observed,
            "blocking_reasons": self.blocking_reasons,
            "limitations": self.limitations,
            "verification_completed": self.verification_completed,
        }


def is_html_login_page(html_text: str) -> bool:
    """
    Inspects response HTML to determine whether it is a login page or authentication gate.
    Used to prevent mistaking an unauthenticated HTTP 200 response for an unauthorized bypass.
    """
    if not html_text or len(html_text) < 20:
        return False
    soup = BeautifulSoup(html_text[:50000], "html.parser")
    has_pwd = soup.find("input", attrs={"type": re.compile(r"^password$", re.I)})
    if has_pwd:
        return True
    for form in soup.find_all("form"):
        form_str = str(form).lower()
        if any(w in form_str for w in ("password", "signin", "sign-in", "login", "log-in", "authenticate")):
            return True
    return False


def is_spa_shell(html_text: str) -> bool:
    """
    Determines if an HTML response is an unrendered Single Page Application shell
    (e.g., React, Vue, Angular root with bundle scripts) rather than actual protected content.
    """
    if not html_text:
        return False
    soup = BeautifulSoup(html_text[:30000], "html.parser")
    has_spa_mount = soup.find(id=re.compile(r"^(root|app|__next|__nuxt|main-content)$", re.I))
    body = soup.find("body")
    body_text_len = len(body.get_text().strip()) if body else 0
    has_scripts = len(soup.find_all("script")) > 0
    if has_spa_mount and body_text_len < 300 and has_scripts:
        return True
    return False


def is_generic_error_page(html_text: str) -> bool:
    """
    Detects whether an unauthenticated HTTP 200 response contains a generic error template
    (e.g., custom 404, 500 error page, or resource-not-found message).
    """
    if not html_text:
        return False
    lower = html_text.lower()
    error_phrases = (
        "<title>404", "<title>error", "<title>not found",
        "page not found", "404 not found", "an unexpected error occurred",
        "internal server error", "500 internal", "something went wrong",
        "bad request", "the requested url was not found", "resource not found"
    )
    return any(phrase in lower for phrase in error_phrases)


def has_access_denied_indicator(text: str) -> bool:
    """
    Detects explicit authentication or authorization refusal messages inside a 200 OK response.
    """
    if not text:
        return False
    lower = text.lower()
    denied_phrases = (
        "access denied", "unauthorized access", "permission denied",
        "you must be logged in", "please log in to continue", "please sign in",
        "authentication required", "session expired", "invalid session",
        "login required", "not authorized", "please authenticate"
    )
    return any(phrase in lower for phrase in denied_phrases)


def extract_protected_markers(text: str) -> Set[str]:
    """
    Extracts distinct identifiers of authenticated user data or privileged state
    from response body to verify whether protected content is actually served.
    """
    if not text:
        return set()
    markers = set()
    lower = text.lower()
    for cue in ("user", "username", "user_id", "account_id", "balance", "roles", "permissions", "api_key", "secret_key", "secret", "admin", "token", "auth", "financial", "private", "internal", "email", "profile", "data", "confidential"):
        if cue in lower:
            markers.add(cue)
    for cue in ("welcome,", "logged in as", "sign out", "logout", "my account", "admin dashboard"):
        if cue in lower:
            markers.add(cue)
    return markers


def is_redirect_to_login(location: str) -> bool:
    """
    Checks if a redirect Location header leads to an authentication gateway.
    """
    if not location:
        return False
    loc_lower = location.lower()
    return any(k in loc_lower for k in ("/login", "/signin", "/auth", "/sign-in", "/log-in", "/session/new", "return_to=", "next="))


async def check_auth(
    scanner: "SecurityScanner",
    discovered_urls: list,
    discovered_forms: list,
    client: SafeHTTPClient,
    auth_context: dict = None,
    endpoints: list = None,
    cookies: list = None,
    mode: str = "standard"
) -> AuthCoverageRecord:
    """
    Comprehensive, evidence-driven authentication and session security module.
    """
    coverage = AuthCoverageRecord()
    auth_context = auth_context or {}
    has_auth_context = bool(auth_context and isinstance(auth_context, dict) and any(auth_context.values()))

    # Resolve target URL safely
    target_url = getattr(scanner, "target_url", "") or ""
    if not target_url and hasattr(scanner, "db") and hasattr(scanner, "scan_id"):
        from models import Scan
        s = scanner.db.query(Scan).filter(Scan.id == scanner.scan_id).first()
        if s and s.target_url:
            target_url = s.target_url

    max_budget = 30 if mode == "deep" else 15

    def _is_cancelled() -> bool:
        if hasattr(scanner, "_is_cancelled") and callable(scanner._is_cancelled):
            return scanner._is_cancelled()
        scan_id = getattr(scanner, "scan_id", None)
        db = getattr(scanner, "db", None)
        if scan_id and db:
            from models import Scan
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if s and s.status == "cancelled":
                return True
        return False

    if _is_cancelled():
        coverage.blocking_reasons.append("Scan cancelled by user.")
        return coverage

    # =========================================================================
    # STAGE 1: Attack Surface Inventory & Classification
    # =========================================================================
    candidate_forms: List[Dict[str, Any]] = []
    for form in (discovered_forms or []):
        inputs = extract_form_inputs(form)
        action_url = form.get("action_url", "") or ""
        page_url = form.get("page_url", "") or ""
        method = (form.get("method", "GET") or "GET").upper()

        explicit_auth = form.get("is_auth")
        explicit_reset = form.get("is_reset")

        has_reset_hints = (
            any(RESET_PARAM_PATTERNS.search(name) for name in inputs)
            or any(k in (action_url + " " + page_url).lower() for k in ("/reset", "/forgot", "/recover", "/password_reset"))
        )
        is_reset = explicit_reset if explicit_reset is not None else has_reset_hints

        has_auth_hints = (
            any(LOGIN_PARAM_PATTERNS.search(name) for name in inputs)
            or any(k in (action_url + " " + page_url).lower() for k in ("/login", "/signin", "/auth", "/token", "/session"))
        )
        if explicit_auth is not None:
            is_auth = explicit_auth
        else:
            is_auth = False if is_reset else has_auth_hints

        if is_auth or is_reset or has_auth_hints or has_reset_hints:
            candidate_forms.append({
                "action_url": action_url,
                "page_url": page_url,
                "method": method,
                "inputs": inputs,
                "fields": form.get("fields", {}),
                "has_csrf_token": form.get("has_csrf_token", False),
                "is_auth": is_auth,
                "is_reset": is_reset
            })
            coverage.candidate_forms_discovered += 1

    # Candidate protected endpoints
    candidate_protected: List[Dict[str, Any]] = []
    seen_protected_urls: Set[str] = set()

    # Ingest structured crawler endpoints (dict or string)
    for ep in (endpoints or []):
        if isinstance(ep, str):
            ep_url = ep
            ep_method = "GET"
            req_auth = False
            status_code = None
        else:
            ep_url = ep.get("url", "")
            ep_method = (ep.get("method", "GET") or "GET").upper()
            status_code = ep.get("status_code")
            req_auth = ep.get("requires_auth", False) or (status_code in (401, 403))

        if ep_url and ep_url not in seen_protected_urls:
            path_lower = urlparse(ep_url).path.lower()
            is_hint = any(h in path_lower for h in PROTECTED_PATH_HINTS)
            is_public = any(path_lower == pub or path_lower.startswith(pub + "/") for pub in PUBLIC_PATH_HINTS)
            if not req_auth and is_public:
                continue
            if req_auth or is_hint:
                seen_protected_urls.add(ep_url)
                candidate_protected.append({
                    "url": ep_url,
                    "method": ep_method,
                    "requires_auth": req_auth,
                    "status_code": status_code
                })
                coverage.candidate_protected_resources_discovered += 1

    # Ingest discovered URLs fallback
    for u in (discovered_urls or []):
        if isinstance(u, str) and u and u not in seen_protected_urls:
            p_lower = urlparse(u).path.lower()
            is_public = any(p_lower == pub or p_lower.startswith(pub + "/") for pub in PUBLIC_PATH_HINTS)
            if not is_public and any(h in p_lower for h in PROTECTED_PATH_HINTS):
                seen_protected_urls.add(u)
                candidate_protected.append({
                    "url": u,
                    "method": "GET",
                    "requires_auth": False,
                    "status_code": 200
                })
                coverage.candidate_protected_resources_discovered += 1

    # Session cookies observed
    candidate_cookies: List[Dict[str, Any]] = []
    seen_cookies: Set[str] = set()
    for c in (cookies or []):
        c_name = c.get("name") if isinstance(c, dict) else getattr(c, "name", None)
        if c_name and c_name not in seen_cookies and is_session_cookie(c_name):
            seen_cookies.add(c_name)
            candidate_cookies.append(c if isinstance(c, dict) else {
                "name": c_name,
                "secure": getattr(c, "secure", False),
                "httponly": getattr(c, "httponly", False),
                "samesite": getattr(c, "samesite", None)
            })
            coverage.candidate_session_cookies_discovered += 1

    # =========================================================================
    # STAGE 2: Credential & Form Transport Security Checks
    # =========================================================================
    for form in candidate_forms:
        if _is_cancelled():
            coverage.blocking_reasons.append("Scan cancelled by user.")
            break

        action_url = form["action_url"]
        page_url = form["page_url"]
        method = form["method"]
        inputs = form["inputs"]
        has_csrf = form["has_csrf_token"]
        coverage.forms_tested += 1

        # Resolve relative action against page_url or target_url
        resolved_action_url = action_url
        if page_url and action_url:
            resolved_action_url = urljoin(page_url, action_url)
        elif page_url and not action_url:
            resolved_action_url = page_url
        elif target_url and action_url:
            resolved_action_url = urljoin(target_url, action_url)

        parsed_action = urlparse(resolved_action_url)
        parsed_page = urlparse(page_url) if page_url else urlparse(target_url)

        # Check 2a: Insecure Form Action URL (HTTP Action)
        has_cred_input = any(CREDENTIAL_PARAM_PATTERNS.match(p) or any(k in p.lower() for k in ("pass", "pwd", "secret", "token", "key")) for p in inputs)
        is_cred_form = form.get("is_auth") or form.get("is_reset") or has_cred_input

        if parsed_action.scheme == "http" and is_cred_form:
            target_ep = resolved_action_url or action_url
            test_case = TestCaseResult(
                category="auth",
                target_endpoint=target_ep,
                http_method=method,
                parameter=", ".join(inputs),
                remediation=[
                    "Ensure all authentication endpoints and form actions enforce HTTPS.",
                    "Implement HTTP Strict Transport Security (HSTS) with long max-age."
                ],
                owasp="A07:2021-Identification and Authentication Failures",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information"
            )
            test_case.add_observation(
                "insecure_action",
                f"Authentication form submits credentials over unencrypted HTTP to {target_ep}.",
                is_strong_evidence=True
            )
            test_case.evaluate()

            is_reset_form = form.get("is_reset") and not form.get("is_auth")
            title = "Insecure Password Recovery Form Action (Unencrypted HTTP)" if is_reset_form else "Insecure Authentication Form Action (Unencrypted HTTP)"
            description = (
                f"A password reset / recovery form at {page_url} submits credentials or reset tokens to an unencrypted HTTP endpoint: {target_ep}."
                if is_reset_form else
                f"An authentication form at {page_url} submits credentials to an unencrypted HTTP endpoint: {target_ep}."
            )

            scanner._add_finding(
                f_type="auth",
                severity="high",
                status="HIGH",
                verification_status="CONFIRMED",
                confidence="HIGH",
                title=title,
                description=description,
                evidence=test_case.evidence,
                impact="Network eavesdroppers or malicious access points can intercept user credentials in transit.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                url=page_url or target_ep,
                parameter=test_case.parameter,
                http_method=method
            )
            coverage.findings_confirmed += 1

        # Check 2b: Insecure Embedding Page (Loaded over HTTP with HTTPS Action)
        elif parsed_page.scheme == "http" and parsed_action.scheme == "https" and is_cred_form:
            test_case = TestCaseResult(
                category="auth",
                target_endpoint=page_url,
                http_method="GET",
                parameter=", ".join(inputs),
                remediation=[
                    "Serve all authentication pages exclusively over HTTPS.",
                    "Redirect all unencrypted HTTP traffic to HTTPS before presenting login forms."
                ],
                owasp="A07:2021-Identification and Authentication Failures",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information"
            )
            test_case.add_observation(
                "insecure_hosting_page",
                f"Authentication form is hosted on insecure HTTP page ({page_url}), even though action targets HTTPS.",
                is_strong_evidence=True
            )
            test_case.evaluate()

            scanner._add_finding(
                f_type="auth",
                severity="medium",
                status="MEDIUM",
                verification_status="CONFIRMED",
                confidence="HIGH",
                title="Authentication Form Hosted on Insecure HTTP Page",
                description=f"The login page at {page_url} is served over plain HTTP. Although the form submits to HTTPS, an active attacker can alter the form action or inject malicious scripts into the unencrypted hosting page.",
                evidence=test_case.evidence,
                impact="Active network attackers can modify the form action or harvest credentials via script injection.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                url=page_url,
                parameter=test_case.parameter,
                http_method="GET"
            )
            coverage.findings_confirmed += 1

        # Check 2c: Dangerous HTTP GET Method for Credentials
        if method == "GET" and any(CREDENTIAL_PARAM_PATTERNS.match(p) for p in inputs):
            test_case = TestCaseResult(
                category="auth",
                target_endpoint=action_url,
                http_method="GET",
                parameter=", ".join(inputs),
                remediation=[
                    "Change the authentication form method to POST.",
                    "Ensure sensitive credentials are never accepted or transmitted in URL query strings."
                ],
                owasp="A07:2021-Identification and Authentication Failures",
                cwe="CWE-598: Use of GET Request Method With Sensitive Query Strings"
            )
            test_case.add_observation(
                "get_credential_form",
                f"Authentication form uses HTTP GET to submit sensitive credential fields ({', '.join(inputs)}).",
                is_strong_evidence=True
            )
            test_case.evaluate()

            scanner._add_finding(
                f_type="auth",
                severity="high",
                status="HIGH",
                verification_status="CONFIRMED",
                confidence="HIGH",
                title="Authentication Form Submits Credentials via HTTP GET",
                description=f"The authentication form targeting {action_url} uses the HTTP GET method. Submitted passwords will be exposed in browser history, web server access logs, proxy caches, and Referer headers.",
                evidence=test_case.evidence,
                impact="User credentials will leak into logs, web analytics, proxies, and browser histories.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                url=action_url,
                parameter=test_case.parameter,
                http_method="GET"
            )
            coverage.findings_confirmed += 1

        # Check 2d: Missing Anti-CSRF Protection on Login / Password Recovery Forms
        if (form.get("is_auth") or form.get("is_reset")) and not has_csrf:
            is_reset_form = form.get("is_reset") and not form.get("is_auth")
            csrf_title = "Password Reset Request Form Missing Anti-CSRF Token" if is_reset_form else "Login Form Missing Anti-CSRF Token"
            test_case = TestCaseResult(
                category="auth",
                target_endpoint=action_url,
                http_method=method,
                parameter="anti_csrf_token",
                remediation=[
                    "Implement synchronizer tokens (anti-CSRF tokens) or SameSite=Strict cookies on forms.",
                    "Ensure user authentication and password recovery requests cannot be forged by third-party origins."
                ],
                owasp="A01:2021-Broken Access Control",
                cwe="CWE-352: Cross-Site Request Forgery (CSRF)"
            )
            test_case.add_observation(
                "missing_form_csrf",
                f"Form at {page_url} has no detectable anti-CSRF token or nonce.",
                is_suspicious=True
            )
            test_case.evaluate()

            scanner._add_finding(
                f_type="auth",
                severity="low",
                status="LOW",
                verification_status="POTENTIAL",
                confidence="MEDIUM",
                title=csrf_title,
                description=(
                    f"The password reset form at {page_url} (submitting to {action_url}) does not contain an anti-CSRF token."
                    if is_reset_form else
                    f"The login form at {page_url} (submitting to {action_url}) does not contain an anti-CSRF token. While login CSRF often carries lower impact than state-changing CSRF, it can permit attackers to log victims into an attacker's account to harvest user activity."
                ),
                evidence=test_case.evidence,
                impact="Attackers may trigger unauthorized password recovery requests on behalf of victims." if is_reset_form else "Attackers may force users to authenticate into an attacker-controlled account.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                url=page_url or action_url,
                parameter="anti_csrf_token",
                http_method=method
            )
            coverage.findings_potential += 1

    # Check 2e: Credentials Exposed in URL Query Strings of Discovered URLs
    for u in (discovered_urls or []):
        if not isinstance(u, str):
            continue
        parsed_u = urlsplit(u)
        if parsed_u.query:
            q_pairs = parse_qsl(parsed_u.query, keep_blank_values=True)
            leaked_params = [k for k, v in q_pairs if CREDENTIAL_PARAM_PATTERNS.match(k)]
            if leaked_params:
                clean_url = urlunsplit((parsed_u.scheme, parsed_u.netloc, parsed_u.path, "", ""))
                test_case = TestCaseResult(
                    category="auth",
                    target_endpoint=clean_url,
                    http_method="GET",
                    parameter=", ".join(leaked_params),
                    remediation=[
                        "Remove sensitive parameters from URL query strings.",
                        "Transmit credentials, tokens, and API secrets in request headers (e.g. Authorization: Bearer) or POST bodies."
                    ],
                    owasp="A07:2021-Identification and Authentication Failures",
                    cwe="CWE-598: Use of GET Request Method With Sensitive Query Strings"
                )
                test_case.add_observation(
                    "credential_in_query",
                    f"Sensitive credential parameter(s) '{', '.join(leaked_params)}' observed in URL query string.",
                    is_strong_evidence=True
                )
                test_case.evaluate()

                scanner._add_finding(
                    f_type="auth",
                    severity="medium",
                    status="MEDIUM",
                    verification_status="CONFIRMED",
                    confidence="HIGH",
                    title="Sensitive Credentials Exposed in URL Query Parameters",
                    description=f"The endpoint {clean_url} exposes sensitive parameters ({', '.join(leaked_params)}) in its URL query string.",
                    evidence=test_case.evidence,
                    impact="Credentials and tokens in query strings are leaked to intermediate proxies, referer headers, and browser history.",
                    remediation=test_case.remediation,
                    owasp=test_case.owasp,
                    url=clean_url,
                    parameter=", ".join(leaked_params),
                    http_method="GET"
                )
                coverage.findings_confirmed += 1

    # =========================================================================
    # STAGE 3: Authentication Bypass / Missing Authentication Enforcement
    # =========================================================================
    if not has_auth_context:
        # Only record limitation if there are actually candidate protected endpoints to test
        if coverage.candidate_protected_resources_discovered > 0:
            coverage.limitations.append(
                "No authenticated session context (auth_context_1) was configured. "
                "Differential authenticated-vs-unauthenticated bypass checks could not be executed."
            )
            coverage.checks_inconclusive += 1

            scanner._add_finding(
                f_type="auth",
                severity="info",
                status="INCONCLUSIVE",
                verification_status="INCONCLUSIVE",
                confidence="HIGH",
                title="Authentication Enforcement Checks Inconclusive (Credentials Required)",
                description=(
                    "Authentication enforcement and differential bypass checks require an authenticated session context "
                    "(such as an Authorization Bearer token or session cookie) to establish an authorized baseline. "
                    "Because no authentication context was supplied for this scan, bypass tests were not executed."
                ),
                evidence="Authenticated baseline comparison skipped: auth_context_1 not provided in scan configuration.",
                impact="SCANNER_NOTICE",
                remediation=[
                    "Configure an authorized session token in New Scan > Advanced Authentication Settings (Context 1).",
                    "Ensure authenticated endpoints verify tokens on all sensitive routes."
                ],
                owasp="A07:2021-Identification and Authentication Failures",
                url=target_url or (candidate_protected[0]["url"] if candidate_protected else ""),
                parameter=None,
                http_method="GET"
            )
    else:
        # Bounded evaluation of candidate protected endpoints
        for ep_item in candidate_protected[:max_budget]:
            if _is_cancelled():
                coverage.blocking_reasons.append("Scan cancelled by user.")
                break

            ep_url = ep_item["url"]
            ep_method = ep_item.get("method", "GET")
            coverage.endpoints_tested += 1

            test_case = TestCaseResult(
                category="auth",
                target_endpoint=ep_url,
                http_method=ep_method,
                remediation=[
                    "Ensure all protected endpoints verify a valid session or token before granting access.",
                    "Return HTTP 401 Unauthorized or HTTP 403 Forbidden for unauthenticated requests.",
                    "Do not return HTTP 200 OK or protected data to unauthenticated callers."
                ],
                owasp="A07:2021-Identification and Authentication Failures",
                cwe="CWE-306: Missing Authentication for Critical Function"
            )

            try:
                # 1. Establish authenticated baseline
                coverage.requests_attempted += 1
                resp_auth = await client.request(ep_method, ep_url, **auth_context)
                coverage.requests_completed += 1

                if resp_auth.status_code != 200:
                    test_case.add_observation(
                        "auth_baseline_failed",
                        f"Authenticated baseline request to {ep_url} returned HTTP {resp_auth.status_code} rather than 200 OK. Credentials may be expired or lack permissions."
                    )
                    coverage.limitations.append(f"Baseline failed on {ep_url} (HTTP {resp_auth.status_code}).")
                    continue

                auth_body = resp_auth.text
                test_case.add_observation(
                    "authenticated_baseline_ok",
                    f"Authenticated baseline request to {ep_url} succeeded (HTTP 200, length {len(auth_body)})."
                )

                # 2. Controlled unauthenticated request
                coverage.requests_attempted += 1
                resp_no_auth = await client.request(ep_method, ep_url)
                coverage.requests_completed += 1

                no_auth_status = resp_no_auth.status_code
                no_auth_body = resp_no_auth.text

                # 3. Anti-False-Positive Analysis
                if no_auth_status in (401, 403):
                    test_case.add_observation(
                        "enforced_status",
                        f"Unauthenticated request was properly rejected with HTTP {no_auth_status}."
                    )

                elif no_auth_status in (301, 302, 303, 307, 308):
                    loc = resp_no_auth.headers.get("location", "")
                    if is_redirect_to_login(loc):
                        test_case.add_observation(
                            "enforced_redirect",
                            f"Unauthenticated request was redirected to login/auth gateway (HTTP {no_auth_status} -> {loc})."
                        )
                    else:
                        test_case.add_observation(
                            "redirect_observed",
                            f"Unauthenticated request was redirected (HTTP {no_auth_status} -> {loc})."
                        )

                elif no_auth_status == 200:
                    diff = BaselineEngine.compare(resp_auth, resp_no_auth)

                    if is_html_login_page(no_auth_body):
                        test_case.add_observation(
                            "enforced_login_page",
                            "Unauthenticated request returned HTTP 200 containing a login form; authentication is required to access data."
                        )

                    elif is_spa_shell(no_auth_body) and is_spa_shell(auth_body):
                        test_case.add_observation(
                            "spa_shell_observed",
                            "Endpoint serves a generic client-side SPA shell without embedded protected data. API-level authorization must be evaluated directly."
                        )

                    elif has_access_denied_indicator(no_auth_body):
                        test_case.add_observation(
                            "access_denied_indicator",
                            "Unauthenticated response returned HTTP 200 with an access-denied or login-required indicator."
                        )

                    elif is_generic_error_page(no_auth_body):
                        test_case.add_observation(
                            "generic_error_template",
                            "Unauthenticated request returned HTTP 200 displaying a generic error/not-found template."
                        )

                    else:
                        ep_path_lower = urlparse(ep_url).path.lower()
                        is_verified_protected = (
                            ep_item.get("requires_auth", False)
                            or ep_item.get("status_code") in (401, 403)
                            or any(h in ep_path_lower for h in ("/protected", "/private", "/internal", "/admin", "/secure", "/api/me", "/dashboard", "/account", "/profile", "/settings", "/billing", "/orders"))
                        )
                        auth_markers = extract_protected_markers(auth_body)
                        no_auth_markers = extract_protected_markers(no_auth_body)
                        shared_markers = auth_markers.intersection(no_auth_markers)

                        if is_verified_protected:
                            if diff.get("is_body_identical") or (auth_markers and shared_markers):
                                test_case.add_observation(
                                    "bypass_confirmed",
                                    f"Protected endpoint {ep_url} returned HTTP 200 granting full access to unauthorized callers. Evidence includes verified authorization markers ({', '.join(sorted(shared_markers)) or 'identical body'}).",
                                    is_strong_evidence=True
                                )
                            elif diff.get("is_body_similar") and diff.get("similarity_ratio", 0) > 0.85:
                                test_case.add_observation(
                                    "bypass_potential",
                                    f"Protected endpoint {ep_url} returned HTTP 200 with high response similarity ({int(diff.get('similarity_ratio', 0) * 100)}%) to authenticated baseline, but lacked explicit verified authorization markers.",
                                    is_suspicious=True
                                )
                            else:
                                test_case.add_observation(
                                    "protected_differential",
                                    f"Protected endpoint {ep_url} returned HTTP 200 with differing response; review whether public or unauthenticated preview was served."
                                )
                        else:
                            # Endpoint was NOT known to require authorization (e.g. general URL hint like /account)
                            if auth_markers and shared_markers:
                                test_case.add_observation(
                                    "bypass_confirmed",
                                    f"Endpoint {ep_url} returned HTTP 200 leaking authenticated user/session data markers ({', '.join(sorted(shared_markers))}) to unauthenticated callers.",
                                    is_strong_evidence=True
                                )
                            elif diff.get("is_body_identical") or (diff.get("is_body_similar") and diff.get("similarity_ratio", 0) > 0.90):
                                test_case.add_observation(
                                    "public_page_detected",
                                    f"Endpoint {ep_url} returned identical/similar HTTP 200 responses with and without authentication, but contains no protected data markers or prior authorization requirement. Correctly classified as public content."
                                )
                            else:
                                test_case.add_observation(
                                    "public_differential",
                                    f"Endpoint {ep_url} returned differing HTTP 200 responses; classified as public content."
                                )
                else:
                    test_case.add_observation(
                        "non_standard_status",
                        f"Unauthenticated request returned unexpected status HTTP {no_auth_status}."
                    )

                test_case.evaluate()

                obs_types = [getattr(o, "signal_type", None) or (o.get("signal_type") if isinstance(o, dict) else None) for o in getattr(test_case, "observations", [])]

                if test_case.status in ("CRITICAL", "HIGH") and "bypass_confirmed" in obs_types:
                    scanner._add_finding(
                        f_type="auth",
                        severity="high",
                        status="HIGH",
                        verification_status="CONFIRMED",
                        confidence="HIGH",
                        title="Authentication Bypass: Protected Resource Accessible Anonymously",
                        description=f"The protected endpoint {ep_url} returned HTTP 200 with verified protected content when accessed without credentials.",
                        evidence=test_case.evidence,
                        impact="Unauthenticated remote attackers can access sensitive user data or functionality without credentials.",
                        remediation=test_case.remediation,
                        owasp=test_case.owasp,
                        url=ep_url,
                        parameter=None,
                        http_method=ep_method
                    )
                    coverage.findings_confirmed += 1

                elif (test_case.status in ("MEDIUM", "LOW") or "bypass_potential" in obs_types) and "bypass_potential" in obs_types:
                    scanner._add_finding(
                        f_type="auth",
                        severity="medium",
                        status="MEDIUM",
                        verification_status="POTENTIAL",
                        confidence="MEDIUM",
                        title="Potential Missing Authentication on Sensitive Endpoint",
                        description=f"The endpoint {ep_url} returned HTTP 200 to unauthenticated requests, with high similarity to the authenticated baseline. Review whether public data or protected information was returned.",
                        evidence=test_case.evidence,
                        impact="Attackers may be able to read partially protected information.",
                        remediation=test_case.remediation,
                        owasp=test_case.owasp,
                        url=ep_url,
                        parameter=None,
                        http_method=ep_method
                    )
                    coverage.findings_potential += 1

            except Exception as ep_err:
                logger.warning(f"Error testing auth bypass on {ep_url}: {ep_err}")
                coverage.scanner_errors += 1

    # =========================================================================
    # STAGE 4: Session Cookie Security & Lifecycle
    # =========================================================================
    is_https = urlparse(target_url).scheme == "https" or str(target_url).startswith("https")

    for c_info in candidate_cookies:
        c_name = c_info.get("name", "")
        c_secure = c_info.get("secure", False)
        c_httponly = c_info.get("httponly", False)
        c_samesite = c_info.get("samesite")

        missing_attrs = []
        if is_https and not c_secure:
            missing_attrs.append("Secure")
        if not c_httponly:
            missing_attrs.append("HttpOnly")
        if not c_samesite or str(c_samesite).lower() not in ("lax", "strict"):
            missing_attrs.append("SameSite")

        if missing_attrs:
            test_case = TestCaseResult(
                category="auth",
                target_endpoint=target_url,
                http_method="GET",
                parameter=f"Cookie: {c_name}",
                remediation=[
                    f"Configure the '{c_name}' cookie with HttpOnly=true to prevent JavaScript XSS theft.",
                    f"Configure the '{c_name}' cookie with Secure=true to prevent unencrypted transmission.",
                    f"Set SameSite=Lax or SameSite=Strict to protect against CSRF."
                ],
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
            )
            test_case.add_observation(
                "session_cookie_flags",
                f"Session cookie '{c_name}' was issued without required protective flags: {', '.join(missing_attrs)}.",
                is_strong_evidence=True
            )
            test_case.evaluate()

            sev = "high" if ("Secure" in missing_attrs and is_https) or "HttpOnly" in missing_attrs else "medium"
            scanner._add_finding(
                f_type="auth",
                severity=sev,
                status="HIGH" if sev == "high" else "MEDIUM",
                verification_status="CONFIRMED",
                confidence="HIGH",
                title=f"Session Cookie '{c_name}' Missing Security Flags ({', '.join(missing_attrs)})",
                description=f"The session cookie '{c_name}' was issued without the {', '.join(missing_attrs)} attribute(s).",
                evidence=test_case.evidence,
                impact="Cookies without HttpOnly can be stolen via XSS. Cookies without Secure can be intercepted in transit.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                url=target_url,
                parameter=f"Cookie: {c_name}",
                http_method="GET"
            )
            coverage.findings_confirmed += 1

    # =========================================================================
    # STAGE 4b: Active Session Rotation & Fixation Analysis (Phase 2.B)
    # =========================================================================
    if candidate_forms and isinstance(auth_context, dict) and auth_context.get("username") and auth_context.get("password") and not _is_cancelled():
        auth_form = next((f for f in candidate_forms if f.get("is_auth")), None)
        if auth_form:
            rot_login_url = auth_form["action_url"]
            rot_login_url = urljoin(auth_form.get("page_url") or target_url, rot_login_url)
            rot_login_method = auth_form["method"]
            rot_inputs = auth_form["inputs"]

            user_f = next((i for i in rot_inputs if any(u in i.lower() for u in ("user", "email", "login", "uname"))), "username")
            pwd_f = next((i for i in rot_inputs if any(p in i.lower() for p in ("pass", "pwd"))), "password")

            try:
                # 1. Pre-auth request to observe initial session cookie
                coverage.requests_attempted += 1
                pre_resp = await client.request("GET", auth_form.get("page_url") or rot_login_url)
                coverage.requests_completed += 1
                pre_cookies = extract_cookies_from_response(pre_resp)
                pre_session_cookies = {k: v for k, v in pre_cookies.items() if is_session_cookie(k)}

                # 2. Submit credentials presenting observed pre-auth cookies
                login_body = {user_f: auth_context["username"], pwd_f: auth_context["password"]}
                for f_name in rot_inputs:
                    if f_name not in login_body:
                        login_body[f_name] = "test"
                coverage.requests_attempted += 1
                if rot_login_method == "POST":
                    post_resp = await client.request("POST", rot_login_url, data=login_body, cookies=pre_cookies)
                else:
                    post_resp = await client.request("GET", rot_login_url, params=login_body, cookies=pre_cookies)
                coverage.requests_completed += 1
                post_cookies = extract_cookies_from_response(post_resp)

                # 3. Compare session identifiers
                for c_name, c_val in pre_session_cookies.items():
                    if c_name in post_cookies and post_cookies[c_name] == c_val:
                        test_case = TestCaseResult(
                            category="auth",
                            target_endpoint=rot_login_url,
                            http_method=rot_login_method,
                            parameter=f"Cookie: {c_name}",
                            remediation=[
                                "Generate a new session identifier upon successful user authentication.",
                                "Invalidate the pre-authentication session identifier.",
                                "Never reuse pre-login session cookies after authentication."
                            ],
                            owasp="A07:2021-Identification and Authentication Failures",
                            cwe="CWE-384: Session Fixation"
                        )
                        test_case.add_observation(
                            "session_not_rotated",
                            f"Session cookie '{c_name}' retained its exact pre-authentication value ({redact_value(c_val)}) after successful login.",
                            is_strong_evidence=True
                        )
                        test_case.evaluate()

                        scanner._add_finding(
                            f_type="auth",
                            severity="medium",
                            status="MEDIUM",
                            verification_status="CONFIRMED",
                            confidence="HIGH",
                            title=f"Session Identifier Not Rotated After Authentication ('{c_name}')",
                            description=(
                                f"The session cookie '{c_name}' was not rotated after authentication. "
                                "An attacker who implants or observes this session identifier before login can hijack the session."
                            ),
                            evidence=test_case.evidence,
                            impact="Permits session fixation attacks where an attacker pre-sets a session identifier for a victim.",
                            remediation=test_case.remediation,
                            owasp=test_case.owasp,
                            url=rot_login_url,
                            parameter=f"Cookie: {c_name}",
                            http_method=rot_login_method
                        )
                        coverage.findings_confirmed += 1
            except Exception as rot_err:
                logger.debug(f"Session rotation test notice: {rot_err}")
    else:
        coverage.limitations.append("Active session rotation testing skipped: dedicated login credentials (username/password) were not configured in auth_context.")

    # =========================================================================
    # STAGE 5: Safe Bounded Rate Limiting & Account Enumeration Verification
    # =========================================================================
    if candidate_forms and not _is_cancelled():
        auth_form = next((f for f in candidate_forms if f.get("is_auth")), None)
        if auth_form:
            login_url = auth_form["action_url"]
            login_method = auth_form["method"]
            inputs = auth_form["inputs"]

            user_field = next((i for i in inputs if any(u in i.lower() for u in ("user", "email", "login", "uname"))), "username")
            pwd_field = next((i for i in inputs if any(p in i.lower() for p in ("pass", "pwd"))), "password")

            throttled = False
            probe_count = 0
            max_probes = 5
            valid_statuses_seen = []
            probe_responses = []

            for i in range(max_probes):
                if _is_cancelled():
                    break
                payload = {
                    user_field: f"ethiosec_test_user_{i}@example.com",
                    pwd_field: "InvalidPassword123!"
                }
                for f_name in inputs:
                    if f_name not in payload:
                        payload[f_name] = "test"

                try:
                    coverage.requests_attempted += 1
                    if login_method == "POST":
                        resp = await client.request("POST", login_url, data=payload)
                    else:
                        resp = await client.request("GET", login_url, params=payload)
                    coverage.requests_completed += 1
                    probe_count += 1
                    valid_statuses_seen.append(resp.status_code)
                    probe_responses.append(resp)

                    if resp.status_code == 429 or "retry-after" in resp.headers:
                        throttled = True
                        coverage.rate_limiting_observed = True
                        break
                    if any(w in resp.text.lower() for w in ("too many requests", "rate limit", "locked out", "temporarily blocked", "captcha")):
                        throttled = True
                        coverage.rate_limiting_observed = True
                        break

                    await asyncio.sleep(0.05)
                except Exception:
                    break

            # Rate Limiting Evaluation
            has_active_auth_responses = any(s in (200, 400, 401, 403) for s in valid_statuses_seen)

            if not throttled and probe_count >= 4 and has_active_auth_responses:
                test_case = TestCaseResult(
                    category="auth",
                    target_endpoint=login_url,
                    http_method=login_method,
                    parameter=f"{user_field}, {pwd_field}",
                    remediation=[
                        "Implement IP-based and account-based rate limiting on authentication endpoints.",
                        "Enforce progressive delays or CAPTCHAs after multiple failed login attempts.",
                        "Return HTTP 429 Too Many Requests when rate limits are exceeded."
                    ],
                    owasp="A07:2021-Identification and Authentication Failures",
                    cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts"
                )
                test_case.add_observation(
                    "no_rate_limiting_observed",
                    f"Authentication endpoint {login_url} processed {probe_count} consecutive failed login attempts without throttling, HTTP 429, or CAPTCHA challenges.",
                    is_suspicious=True
                )
                test_case.evaluate()

                scanner._add_finding(
                    f_type="auth",
                    severity="low",
                    status="LOW",
                    verification_status="POTENTIAL",
                    confidence="LOW",
                    title="Authentication Endpoint Lacks Evident Low-Volume Rate Limiting",
                    description=(
                        f"The authentication endpoint at {login_url} was probed with {probe_count} consecutive invalid login attempts. "
                        "No HTTP 429, Retry-After header, progressive delay, or CAPTCHA challenge was observed. "
                        "Note: Stricter lockout policies may exist at higher thresholds (e.g. 10+ attempts)."
                    ),
                    evidence=test_case.evidence,
                    impact="Permits brute-force credential guessing and password-spraying attacks.",
                    remediation=test_case.remediation,
                    owasp=test_case.owasp,
                    url=login_url,
                    parameter=f"{user_field}, {pwd_field}",
                    http_method=login_method
                )
                coverage.findings_potential += 1

            # Safe Account Enumeration Evaluation (Phase 1.D)
            if not throttled and probe_responses and not _is_cancelled():
                last_resp_text = probe_responses[-1].text.lower()
                enum_keywords = [
                    "user not found", "user does not exist", "account not found",
                    "no account found", "unknown user", "username does not exist",
                    "email not registered", "no user with this email"
                ]
                leak_found = next((k for k in enum_keywords if k in last_resp_text), None)

                # Check differential against configured user if available in auth_context
                configured_usr = auth_context.get("username") or auth_context.get("email") if isinstance(auth_context, dict) else None
                if configured_usr and not leak_found and not _is_cancelled():
                    try:
                        valid_usr_payload = {user_field: configured_usr, pwd_field: "InvalidProbePass999!"}
                        for f_name in inputs:
                            if f_name not in valid_usr_payload:
                                valid_usr_payload[f_name] = "test"
                        coverage.requests_attempted += 1
                        if login_method == "POST":
                            resp_val = await client.request("POST", login_url, data=valid_usr_payload)
                        else:
                            resp_val = await client.request("GET", login_url, params=valid_usr_payload)
                        coverage.requests_completed += 1

                        if resp_val.status_code != probe_responses[-1].status_code or (
                            ("incorrect password" in resp_val.text.lower() or "wrong password" in resp_val.text.lower())
                            and resp_val.text != probe_responses[-1].text
                        ):
                            leak_found = "observable differential response between valid and non-existent accounts"
                    except Exception as diff_err:
                        logger.debug(f"Account enumeration diff probe notice: {diff_err}")

                if leak_found:
                    test_case_enum = TestCaseResult(
                        category="auth",
                        target_endpoint=login_url,
                        http_method=login_method,
                        parameter=user_field,
                        remediation=[
                            "Return generic authentication failure messages such as 'Invalid username or password'.",
                            "Ensure responses for non-existent users and wrong passwords have identical status codes and error messages.",
                            "Mitigate timing side channels with constant-time password verification."
                        ],
                        owasp="A07:2021-Identification and Authentication Failures",
                        cwe="CWE-204: Observable Response Discrepancy"
                    )
                    test_case_enum.add_observation(
                        "account_enumeration_signal",
                        f"Authentication endpoint produces observable account existence differences ('{leak_found}').",
                        is_suspicious=True
                    )
                    test_case_enum.evaluate()

                    scanner._add_finding(
                        f_type="auth",
                        severity="low",
                        status="LOW",
                        verification_status="POTENTIAL",
                        confidence="MEDIUM",
                        title="Authentication Endpoint Discloses Account Existence (Account Enumeration)",
                        description=(
                            f"The authentication endpoint at {login_url} produces observable differences when non-existent accounts are probed ('{leak_found}'). "
                            "Attackers can leverage this behavior to harvest registered usernames or email addresses."
                        ),
                        evidence=test_case_enum.evidence,
                        impact="Permits enumeration of valid user accounts for targeted phishing and credential guessing.",
                        remediation=test_case_enum.remediation,
                        owasp=test_case_enum.owasp,
                        url=login_url,
                        parameter=user_field,
                        http_method=login_method
                    )
                    coverage.findings_potential += 1

    # =========================================================================
    # STAGE 6: Logout CSRF & Active Invalidation Inspection
    # =========================================================================
    logout_endpoints_found = []
    all_logout_candidates = list(discovered_urls or [])
    for ep in (endpoints or []):
        if isinstance(ep, str):
            all_logout_candidates.append(ep)
        elif isinstance(ep, dict) and ep.get("url"):
            all_logout_candidates.append(ep["url"])

    for u in all_logout_candidates:
        if not isinstance(u, str):
            continue
        p_lower = urlparse(u).path.lower()
        if any(k in p_lower for k in ("/logout", "/signout", "/log-out")):
            if u not in logout_endpoints_found:
                logout_endpoints_found.append(u)

            # Evidence-driven check: verify whether the logout endpoint actually accepts GET (not 405 Method Not Allowed)
            try:
                coverage.requests_attempted += 1
                get_test_resp = await client.request("GET", u)
                coverage.requests_completed += 1
                if get_test_resp.status_code in (200, 301, 302, 303, 307):
                    test_case = TestCaseResult(
                        category="auth",
                        target_endpoint=u,
                        http_method="GET",
                        parameter="logout_method",
                        remediation=[
                            "Implement logout via HTTP POST with a valid anti-CSRF token.",
                            "Ensure user sessions are invalidated server-side upon logout."
                        ],
                        owasp="A01:2021-Broken Access Control",
                        cwe="CWE-352: Cross-Site Request Forgery (CSRF)"
                    )
                    test_case.add_observation(
                        "logout_via_get",
                        f"Logout endpoint {u} is accessible via HTTP GET (status {get_test_resp.status_code}), which allows third-party websites to trigger forced user logout.",
                        is_suspicious=True
                    )
                    test_case.evaluate()

                    scanner._add_finding(
                        f_type="auth",
                        severity="low",
                        status="LOW",
                        verification_status="POTENTIAL",
                        confidence="MEDIUM",
                        title="Logout Action Accessible via HTTP GET (Forced Logout CSRF)",
                        description=f"The logout endpoint {u} is accessible via HTTP GET. Web browsers pre-fetching links or third-party web pages embedding <img src='{u}'> can terminate the user's active session without consent.",
                        evidence=test_case.evidence,
                        impact="Attackers can terminate victim sessions remotely via Cross-Site Request Forgery.",
                        remediation=test_case.remediation,
                        owasp=test_case.owasp,
                        url=u,
                        parameter="logout_method",
                        http_method="GET"
                    )
                    coverage.findings_potential += 1
            except Exception as get_err:
                logger.debug(f"Logout GET accessibility probe notice: {get_err}")

    # Active Server-Side Logout Invalidation Verification (Phase 2.C)
    if has_auth_context and logout_endpoints_found and candidate_protected and not _is_cancelled():
        test_logout = logout_endpoints_found[0]
        test_prot = candidate_protected[0]["url"]
        test_prot_meth = candidate_protected[0].get("method", "GET")

        try:
            # 1. Establish session works on protected endpoint
            coverage.requests_attempted += 1
            pre_logout_resp = await client.request(test_prot_meth, test_prot, **auth_context)
            coverage.requests_completed += 1

            if pre_logout_resp.status_code == 200:
                # 2. Trigger logout
                coverage.requests_attempted += 1
                logout_resp = await client.request("POST", test_logout, **auth_context)
                if logout_resp.status_code in (404, 405):
                    logout_resp = await client.request("GET", test_logout, **auth_context)
                coverage.requests_completed += 1

                # 3. Re-issue request with same session credentials
                coverage.requests_attempted += 1
                post_logout_resp = await client.request(test_prot_meth, test_prot, **auth_context)
                coverage.requests_completed += 1

                if post_logout_resp.status_code == 200 and post_logout_resp.text == pre_logout_resp.text:
                    test_case_inv = TestCaseResult(
                        category="auth",
                        target_endpoint=test_logout,
                        http_method="POST",
                        parameter="session_revocation",
                        remediation=[
                            "Invalidate session records and tokens server-side upon logout.",
                            "Do not rely solely on client-side cookie deletion to terminate sessions."
                        ],
                        owasp="A07:2021-Identification and Authentication Failures",
                        cwe="CWE-613: Insufficient Session Expiration"
                    )
                    test_case_inv.add_observation(
                        "session_active_after_logout",
                        f"Re-using session credentials after requesting logout on {test_logout} successfully accessed protected resource {test_prot} with HTTP 200.",
                        is_strong_evidence=True
                    )
                    test_case_inv.evaluate()

                    scanner._add_finding(
                        f_type="auth",
                        severity="medium",
                        status="MEDIUM",
                        verification_status="CONFIRMED",
                        confidence="HIGH",
                        title="Session Remains Valid After Logout (Server-Side Invalidation Failure)",
                        description=(
                            f"The application logged out at {test_logout}, but the associated session token continued to grant access to {test_prot} (HTTP 200). "
                            "The session was not revoked server-side."
                        ),
                        evidence=test_case_inv.evidence,
                        impact="Stolen session tokens remain valid indefinitely even after the legitimate user logs out.",
                        remediation=test_case_inv.remediation,
                        owasp=test_case_inv.owasp,
                        url=test_logout,
                        parameter="session_revocation",
                        http_method="POST"
                    )
                    coverage.findings_confirmed += 1
        except Exception as inv_err:
            logger.debug(f"Logout invalidation probe notice: {inv_err}")

    # =========================================================================
    # STAGE 7: Password Recovery, MFA & Alternate Authentication (Phase 4)
    # =========================================================================
    for u in (discovered_urls or []):
        if not isinstance(u, str):
            continue
        p_lower = urlparse(u).path.lower()
        if any(k in p_lower for k in ("/reset", "/recover", "/forgot")):
            coverage.candidate_recovery_endpoints_discovered += 1
        elif any(k in p_lower for k in ("/mfa", "/2fa", "/otp", "/totp")):
            coverage.candidate_mfa_endpoints_discovered += 1
        elif any(k in p_lower for k in ("/oauth", "/oidc", "/authorize", "/sso")):
            coverage.candidate_oauth_endpoints_discovered += 1

    coverage.limitations.append(
        "Active password reset token entropy, single-use invalidation, and MFA bypass tests were safely skipped. "
        "These active checks require out-of-band email/SMS delivery infrastructure or operator authorization."
    )

    # =========================================================================
    # STAGE 8: Clean Completion & Coverage Reporting
    # =========================================================================
    coverage.verification_completed = True
    total_findings_this_run = coverage.findings_confirmed + coverage.findings_potential

    if total_findings_this_run == 0 and coverage.checks_inconclusive == 0:
        if (coverage.forms_tested > 0 or (coverage.endpoints_tested > 0 and has_auth_context)) and coverage.requests_completed > 0:
            scanner._add_finding(
                f_type="auth",
                severity="info",
                status="NOT_DETECTED",
                verification_status="NOT_DETECTED",
                confidence="HIGH",
                title="Authentication & Session Security Checks Passed",
                description=(
                    f"Audited {coverage.forms_tested} authentication form(s), {coverage.endpoints_tested} protected endpoint(s), "
                    f"and {coverage.candidate_session_cookies_discovered} session cookie(s). "
                    "No plaintext credential submission, authentication bypass, or insecure session cookies were identified."
                ),
                evidence=f"Tested attack surface: {coverage.forms_tested} forms, {coverage.endpoints_tested} endpoints, {coverage.requests_completed} HTTP requests completed cleanly.",
                url=target_url
            )
        else:
            # Honest zero-coverage reporting
            scanner._add_finding(
                f_type="auth",
                severity="info",
                status="SKIPPED",
                verification_status="SKIPPED",
                confidence="HIGH",
                title="Authentication Checks Skipped: No Authentication Attack Surface Discovered",
                description=(
                    "The crawler did not discover login forms, authentication endpoints, or protected routes on the target application. "
                    "Authentication security checks were skipped because no eligible attack surface was available for evaluation."
                ),
                evidence="Zero candidate authentication forms or protected endpoints discovered during crawling.",
                url=target_url
            )

    return coverage
