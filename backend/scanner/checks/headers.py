"""
EthioSec Scanner — Professional Evidence-Driven HTTP Security Headers Engine.

Audits HTTP response headers for defensive security posture:
1. Content-Security-Policy (CSP) enforcement, directive hardening (default-src, script-src, object-src, base-uri, frame-ancestors), unsafe-inline/eval/wildcard detection, and Report-Only distinction.
2. HTTP Strict Transport Security (HSTS) enforcement on HTTPS, max-age validation, includeSubDomains, and preload.
3. MIME Sniffing Protection (X-Content-Type-Options: nosniff).
4. Framing & Clickjacking Defense (CSP frame-ancestors and X-Frame-Options: DENY/SAMEORIGIN interaction).
5. Referrer Policy (Referrer-Policy validation, unsafe-url / overly permissive leakage detection).
6. Permissions Policy (Permissions-Policy / Feature-Policy feature restriction).

Strict Principles:
- Observed configuration weakness is separated from confirmed exploitability (status=POTENTIAL).
- Truthful coverage: NOT_TESTED when uninspected; NOT_DETECTED when audited headers pass.
- Headers parsed case-insensitively with exact directive tokenization.
- Secret redaction and sanitized evidence formatting.
"""

import re
import logging
from typing import TYPE_CHECKING, Optional, List, Dict, Any, Set
from urllib.parse import urlparse

from scanner.test_case import TestCaseResult

if TYPE_CHECKING:
    from scanner.engine import SecurityScanner
    import httpx

logger = logging.getLogger("ethiosec.scanner.headers")

VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url"
}


def _parse_csp_directives(csp_value: str) -> Dict[str, List[str]]:
    """
    Parses a CSP header string into directive names and source lists.
    Directives are separated by semicolons. Directive names are case-insensitive.
    Under W3C CSP Level 3 §4.2.1, duplicate directives within a policy are ignored;
    the first occurrence takes precedence.
    """
    directives: Dict[str, List[str]] = {}
    if not csp_value:
        return directives

    tokens = [t.strip() for t in csp_value.split(";") if t.strip()]
    for token in tokens:
        parts = token.split()
        if not parts:
            continue
        d_name = parts[0].lower()
        d_sources = [s.strip() for s in parts[1:] if s.strip()]
        if d_name not in directives:
            directives[d_name] = d_sources

    return directives


def _emit_header_finding(
    scanner: "SecurityScanner",
    test_case: TestCaseResult,
    title: str,
    description: str,
    sanitized_evidence: str,
    impact: str,
    url: str,
    parameter: str,
    http_method: str
):
    """
    Evaluates test_case, appends sanitized header evidence, and dispatches to scanner engine.
    """
    test_case.evaluate()
    evidence_str = f"{test_case.evidence}\nObserved header: {sanitized_evidence}"
    scanner._add_finding(
        f_type="headers",
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
        parameter=parameter,
        http_method=http_method
    )


async def check_security_headers(scanner: "SecurityScanner", url: str, response: Any):
    """
    Professional, evidence-driven security headers audit.
    Evaluates HTTP response headers against current industry defense standards:
    - Content-Security-Policy (CSP)
    - Strict-Transport-Security (HSTS)
    - X-Content-Type-Options
    - Framing & Clickjacking Defense (CSP frame-ancestors & X-Frame-Options)
    - Referrer-Policy
    - Permissions-Policy / Feature-Policy
    """
    # 1. Resolve context: origin scheme and request method
    parsed_url = urlparse(url or "")
    is_https = parsed_url.scheme.lower() == "https"
    http_method = "GET"
    if hasattr(response, "request") and response.request is not None:
        http_method = getattr(response.request, "method", "GET") or "GET"

    # 2. Extract headers safely and case-insensitively
    headers: Dict[str, str] = {}
    try:
        if hasattr(response, "headers") and response.headers is not None:
            for k, v in response.headers.items():
                headers[k.lower()] = v
        else:
            headers = {}
    except Exception as extract_err:
        logger.warning(f"Error extracting headers from response: {extract_err}")
        scanner._add_finding(
            f_type="headers",
            severity="info",
            status="SCANNER_ERROR",
            verification_status="ERROR",
            title="Security Headers Check Error",
            description="The scanner encountered an unexpected error reading response headers.",
            evidence=f"Header extraction exception: {type(extract_err).__name__}",
            url=url,
            http_method=http_method
        )
        return

    # 3. Handle truthful NOT_TESTED when response headers are completely unavailable
    if not headers:
        scanner._add_finding(
            f_type="headers",
            severity="info",
            status="NOT_TESTED",
            verification_status="NOT_TESTED",
            confidence="HIGH",
            title="Security Headers Assessment Not Tested (No Response Headers Available)",
            description=(
                "The server response did not provide any inspectable HTTP headers. "
                "Security header verification could not be performed for this endpoint."
            ),
            evidence=f"Response from {url} contained 0 inspectable headers.",
            url=url,
            http_method=http_method
        )
        return

    # Determine response content-type context
    content_type = headers.get("content-type", "").lower()
    is_html = ("text/html" in content_type) or (not content_type and not url.endswith((".json", ".xml", ".txt", ".js", ".css", ".png", ".jpg")))

    findings_emitted = 0

    # =========================================================================
    # CHECK 1: Content-Security-Policy (CSP)
    # =========================================================================
    csp_enforced = headers.get("content-security-policy")
    csp_report_only = headers.get("content-security-policy-report-only")

    if not csp_enforced:
        if csp_report_only:
            # Report-only mode active, but no enforcing policy
            test_case_csp = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Content-Security-Policy",
                baseline_response={"content-security-policy-report-only": csp_report_only},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
            )
            test_case_csp.severity = "low"
            test_case_csp.status = "LOW"
            test_case_csp.verification_status = "POTENTIAL"
            test_case_csp.confidence = "HIGH"
            test_case_csp.add_observation(
                "csp_report_only",
                "The server returned Content-Security-Policy-Report-Only, but no enforcing Content-Security-Policy header. "
                "Violations are reported to the configured endpoint but are NOT blocked by the browser.",
                is_suspicious=True
            )
            test_case_csp.remediation = [
                "Transition the validated Content-Security-Policy-Report-Only rules into an enforcing Content-Security-Policy header."
            ]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_csp,
                title="Content-Security-Policy Not Set (Report-Only Mode Active)",
                description=(
                    "The server operates CSP in report-only mode without enforcing protection. "
                    "Browsers do not block malicious script execution or unauthorized resource loading in report-only mode."
                ),
                sanitized_evidence=f"Content-Security-Policy-Report-Only: {csp_report_only}",
                impact="Does not block Cross-Site Scripting (XSS) or unauthorized resource injection.",
                url=url,
                parameter="Header: Content-Security-Policy",
                http_method=http_method
            )
            findings_emitted += 1
        else:
            # Entirely missing CSP
            test_case_csp = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Content-Security-Policy",
                baseline_response={"headers": "Content-Security-Policy absent"},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
            )
            if is_html:
                test_case_csp.severity = "medium"
                test_case_csp.status = "MEDIUM"
                test_case_csp.confidence = "MEDIUM"
                test_case_csp.add_observation(
                    "missing_header_csp",
                    "No Content-Security-Policy header was returned on an HTML response. "
                    "Observed configuration weakness: client-side scripts run without origin restrictions.",
                    is_suspicious=True
                )
                title = "Content-Security-Policy Not Set"
                desc = "No Content-Security-Policy header was returned on an HTML response. Without CSP, client-side script injection runs with full page privileges."
            else:
                test_case_csp.severity = "low"
                test_case_csp.status = "LOW"
                test_case_csp.confidence = "LOW"
                test_case_csp.add_observation(
                    "missing_header_csp_non_html",
                    "No Content-Security-Policy header was returned on a non-HTML endpoint.",
                    is_suspicious=True
                )
                title = "Content-Security-Policy Not Set (Non-HTML Endpoint)"
                desc = "No Content-Security-Policy header was returned. While primary impact affects HTML pages, maintaining consistent defense-in-depth headers across all endpoints is recommended."

            test_case_csp.remediation = [
                "Implement a strict Content-Security-Policy starting with: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';"
            ]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_csp,
                title=title,
                description=desc,
                sanitized_evidence="Content-Security-Policy: [ABSENT]",
                impact="Allows arbitrary script execution and third-party resource loading if an injection vulnerability exists.",
                url=url,
                parameter="Header: Content-Security-Policy",
                http_method=http_method
            )
            findings_emitted += 1
    else:
        # Enforced CSP is present: Validate directives
        csp_directives = _parse_csp_directives(csp_enforced)

        # 1a. Check for 'unsafe-inline' without nonce or hash
        script_sources = csp_directives.get("script-src", csp_directives.get("default-src", []))
        has_nonce_or_hash = any(
            s.lower().startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
            for s in script_sources
        )
        has_unsafe_inline = any(s.lower() == "'unsafe-inline'" for s in script_sources)

        if has_unsafe_inline and not has_nonce_or_hash:
            test_case_ui = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Content-Security-Policy",
                baseline_response={"content-security-policy": csp_enforced},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-79: Improper Neutralization of Input During Web Page Generation"
            )
            test_case_ui.severity = "medium"
            test_case_ui.status = "MEDIUM"
            test_case_ui.verification_status = "POTENTIAL"
            test_case_ui.confidence = "MEDIUM"
            test_case_ui.add_observation(
                "csp_unsafe_inline",
                "The Content-Security-Policy enables 'unsafe-inline' scripts without cryptographic nonces or hashes. "
                "Observed configuration weakness: inline script execution is permitted, significantly weakening XSS mitigation.",
                is_suspicious=True
            )
            test_case_ui.remediation = [
                "Remove 'unsafe-inline' and refactor inline scripts into external files or use cryptographic nonces ('nonce-...') / hashes ('sha256-...')."
            ]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_ui,
                title="Weak Content-Security-Policy: 'unsafe-inline' Allowed",
                description="The Content-Security-Policy permits 'unsafe-inline' scripts without nonces or hashes. This substantially impairs CSP's ability to prevent Cross-Site Scripting (XSS).",
                sanitized_evidence=f"Content-Security-Policy: {csp_enforced}",
                impact="Reduces protection against stored and reflected XSS attacks.",
                url=url,
                parameter="Header: Content-Security-Policy",
                http_method=http_method
            )
            findings_emitted += 1

        # 1b. Check for 'unsafe-eval'
        if any(s.lower() == "'unsafe-eval'" for s in script_sources):
            test_case_ue = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Content-Security-Policy",
                baseline_response={"content-security-policy": csp_enforced},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
            )
            test_case_ue.severity = "low"
            test_case_ue.status = "LOW"
            test_case_ue.verification_status = "POTENTIAL"
            test_case_ue.confidence = "MEDIUM"
            test_case_ue.add_observation(
                "csp_unsafe_eval",
                "The Content-Security-Policy permits 'unsafe-eval' script execution, allowing dynamic string evaluation (e.g. eval(), Function()).",
                is_suspicious=True
            )
            test_case_ue.remediation = [
                "Refactor client-side code to avoid eval(), new Function(), and string-based setTimeout/setInterval."
            ]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_ue,
                title="Weak Content-Security-Policy: 'unsafe-eval' Allowed",
                description="The Content-Security-Policy enables 'unsafe-eval', allowing dynamic string code evaluation.",
                sanitized_evidence=f"Content-Security-Policy: {csp_enforced}",
                impact="Permits DOM-based evaluation vulnerabilities if unsanitized input reaches eval().",
                url=url,
                parameter="Header: Content-Security-Policy",
                http_method=http_method
            )
            findings_emitted += 1

        # 1c. Check for wildcard script sources
        if any(s in ("*", "http:", "https:") for s in script_sources):
            test_case_wc = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Content-Security-Policy",
                baseline_response={"content-security-policy": csp_enforced},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-79: Improper Neutralization of Input During Web Page Generation"
            )
            test_case_wc.severity = "low"
            test_case_wc.status = "LOW"
            test_case_wc.verification_status = "POTENTIAL"
            test_case_wc.confidence = "MEDIUM"
            test_case_wc.add_observation(
                "csp_wildcard_source",
                "The Content-Security-Policy permits wildcard or broad scheme sources in script execution.",
                is_suspicious=True
            )
            test_case_wc.remediation = ["Replace wildcard sources with specific trusted origin domains."]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_wc,
                title="Weak Content-Security-Policy: Wildcard Script Source",
                description="The Content-Security-Policy allows scripts from wildcard sources ('*' or unrestricted scheme).",
                sanitized_evidence=f"Content-Security-Policy: {csp_enforced}",
                impact="Allows scripts to be loaded from untrusted third-party hosts or CDNs.",
                url=url,
                parameter="Header: Content-Security-Policy",
                http_method=http_method
            )
            findings_emitted += 1

        # 1d. Check for missing object-src
        object_sources = csp_directives.get("object-src")
        default_sources = csp_directives.get("default-src", [])
        if object_sources is None and "'none'" not in default_sources:
            test_case_obj = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Content-Security-Policy",
                baseline_response={"content-security-policy": csp_enforced},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
            )
            test_case_obj.severity = "low"
            test_case_obj.status = "LOW"
            test_case_obj.verification_status = "POTENTIAL"
            test_case_obj.confidence = "MEDIUM"
            test_case_obj.add_observation(
                "csp_missing_object_src",
                "The Content-Security-Policy does not restrict object-src to 'none'.",
                is_suspicious=True
            )
            test_case_obj.remediation = ["Add 'object-src 'none'' to Content-Security-Policy to disable legacy plugin execution."]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_obj,
                title="Weak Content-Security-Policy: Missing 'object-src' Restriction",
                description="The Content-Security-Policy omits object-src, allowing legacy plugin execution (Flash, Java applets) if plugins are present.",
                sanitized_evidence=f"Content-Security-Policy: {csp_enforced}",
                impact="May allow plugin-based execution vulnerabilities.",
                url=url,
                parameter="Header: Content-Security-Policy",
                http_method=http_method
            )
            findings_emitted += 1

        # 1e. Check for missing base-uri
        if "base-uri" not in csp_directives:
            test_case_base = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Content-Security-Policy",
                baseline_response={"content-security-policy": csp_enforced},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
            )
            test_case_base.severity = "low"
            test_case_base.status = "LOW"
            test_case_base.verification_status = "POTENTIAL"
            test_case_base.confidence = "LOW"
            test_case_base.add_observation(
                "csp_missing_base_uri",
                "The Content-Security-Policy does not specify 'base-uri'. Without base-uri, injected <base> tags can alter relative resource resolution.",
                is_suspicious=True
            )
            test_case_base.remediation = ["Add 'base-uri 'self'' or 'base-uri 'none'' to Content-Security-Policy."]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_base,
                title="Weak Content-Security-Policy: Missing 'base-uri' Directive",
                description="The Content-Security-Policy omits base-uri. Attackers capable of injecting HTML tags can inject <base href='...'> to hijack relative URLs.",
                sanitized_evidence=f"Content-Security-Policy: {csp_enforced}",
                impact="Permits base-tag injection to redirect script and asset loading to external servers.",
                url=url,
                parameter="Header: Content-Security-Policy",
                http_method=http_method
            )
            findings_emitted += 1

    # =========================================================================
    # CHECK 2: Strict-Transport-Security (HSTS)
    # =========================================================================
    hsts_val = headers.get("strict-transport-security")

    if not is_https:
        # HTTP response: HSTS is strictly ignored by browsers per RFC 6797 §7.2
        if hsts_val:
            test_case_hsts = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Strict-Transport-Security",
                baseline_response={"strict-transport-security": hsts_val},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information"
            )
            test_case_hsts.severity = "low"
            test_case_hsts.status = "LOW"
            test_case_hsts.verification_status = "POTENTIAL"
            test_case_hsts.confidence = "HIGH"
            test_case_hsts.add_observation(
                "hsts_over_http",
                f"Strict-Transport-Security header was observed over plain HTTP ({url}). "
                "RFC 6797 mandates that browsers must ignore HSTS headers received over unencrypted connections.",
                is_suspicious=True
            )
            test_case_hsts.remediation = ["Serve the application exclusively over HTTPS and emit HSTS only on TLS connections."]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_hsts,
                title="HSTS Header Sent Over Insecure HTTP Origin",
                description="The server returns Strict-Transport-Security over an unencrypted HTTP response. Browsers adhering to RFC 6797 reject HSTS over plaintext.",
                sanitized_evidence=f"Strict-Transport-Security: {hsts_val}",
                impact="The HSTS policy is discarded by user agents, providing zero downgrade protection.",
                url=url,
                parameter="Header: Strict-Transport-Security",
                http_method=http_method
            )
            findings_emitted += 1
    else:
        # HTTPS response
        if not hsts_val:
            test_case_hsts = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Strict-Transport-Security",
                baseline_response={"headers": "Strict-Transport-Security absent"},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information"
            )
            test_case_hsts.severity = "medium"
            test_case_hsts.status = "MEDIUM"
            test_case_hsts.verification_status = "POTENTIAL"
            test_case_hsts.confidence = "HIGH"
            test_case_hsts.add_observation(
                "missing_hsts",
                "Strict-Transport-Security header is absent on an HTTPS endpoint. "
                "Observed configuration weakness: browsers will not automatically upgrade insecure HTTP requests or enforce TLS.",
                is_suspicious=True
            )
            test_case_hsts.remediation = [
                "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
            ]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_hsts,
                title="HSTS Not Set",
                description="The Strict-Transport-Security header is absent on this HTTPS response. Without HSTS, initial requests or insecure links can be intercepted via SSL-stripping.",
                sanitized_evidence="Strict-Transport-Security: [ABSENT]",
                impact="Vulnerable to SSL-stripping and man-in-the-middle network interception on initial requests.",
                url=url,
                parameter="Header: Strict-Transport-Security",
                http_method=http_method
            )
            findings_emitted += 1
        else:
            # Validate HSTS directives
            hsts_tokens = [t.strip() for t in hsts_val.split(";") if t.strip()]
            max_age_tokens = [t for t in hsts_tokens if t.lower().startswith("max-age")]

            if len(max_age_tokens) > 1:
                # Under RFC 6797 §6.1, a given directive MUST NOT appear more than once.
                # Duplicate max-age directives constitute a syntax error causing user agents to reject the header.
                test_case_hsts = TestCaseResult(
                    category="headers",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter="Header: Strict-Transport-Security",
                    baseline_response={"strict-transport-security": hsts_val},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-319: Cleartext Transmission of Sensitive Information"
                )
                test_case_hsts.severity = "low"
                test_case_hsts.status = "LOW"
                test_case_hsts.verification_status = "POTENTIAL"
                test_case_hsts.confidence = "HIGH"
                test_case_hsts.add_observation(
                    "hsts_duplicate_max_age",
                    "Strict-Transport-Security contains duplicate 'max-age' directives. "
                    "RFC 6797 §6.1 mandates that user agents reject HSTS headers with duplicate directives as syntax errors.",
                    is_suspicious=True
                )
                test_case_hsts.remediation = ["Specify exactly one valid 'max-age' directive."]
                _emit_header_finding(
                    scanner=scanner,
                    test_case=test_case_hsts,
                    title="Malformed HSTS Header: Duplicate 'max-age' Directives",
                    description="The HSTS header contains multiple 'max-age' directives. RFC 6797 requires user agents to discard the entire header field as a syntax error.",
                    sanitized_evidence=f"Strict-Transport-Security: {hsts_val}",
                    impact="HSTS policy is ignored by user agents due to RFC 6797 syntax violation.",
                    url=url,
                    parameter="Header: Strict-Transport-Security",
                    http_method=http_method
                )
                findings_emitted += 1
            elif not max_age_tokens or "=" not in max_age_tokens[0]:
                test_case_hsts = TestCaseResult(
                    category="headers",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter="Header: Strict-Transport-Security",
                    baseline_response={"strict-transport-security": hsts_val},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-319: Cleartext Transmission of Sensitive Information"
                )
                test_case_hsts.severity = "low"
                test_case_hsts.status = "LOW"
                test_case_hsts.verification_status = "POTENTIAL"
                test_case_hsts.confidence = "HIGH"
                test_case_hsts.add_observation(
                    "hsts_missing_max_age",
                    "Strict-Transport-Security header is present but missing a valid 'max-age' directive.",
                    is_suspicious=True
                )
                test_case_hsts.remediation = ["Configure a valid max-age directive (e.g. max-age=31536000)."]
                _emit_header_finding(
                    scanner=scanner,
                    test_case=test_case_hsts,
                    title="Malformed HSTS Header: Missing 'max-age' Directive",
                    description="The HSTS header lacks the mandatory 'max-age' directive. Conforming browsers ignore the header.",
                    sanitized_evidence=f"Strict-Transport-Security: {hsts_val}",
                    impact="HSTS policy is ignored by user agents.",
                    url=url,
                    parameter="Header: Strict-Transport-Security",
                    http_method=http_method
                )
                findings_emitted += 1
            else:
                raw_max_age = max_age_tokens[0].split("=", 1)[1].strip()
                try:
                    int_max_age = int(raw_max_age)
                    if int_max_age < 0:
                        # Negative integer is invalid under RFC 6797 §6.1.1 (1*DIGIT)
                        test_case_hsts = TestCaseResult(
                            category="headers",
                            target_endpoint=url,
                            http_method=http_method,
                            parameter="Header: Strict-Transport-Security",
                            baseline_response={"strict-transport-security": hsts_val},
                            owasp="A05:2021-Security Misconfiguration",
                            cwe="CWE-319: Cleartext Transmission of Sensitive Information"
                        )
                        test_case_hsts.severity = "low"
                        test_case_hsts.status = "LOW"
                        test_case_hsts.verification_status = "POTENTIAL"
                        test_case_hsts.confidence = "HIGH"
                        test_case_hsts.add_observation(
                            "hsts_negative_max_age",
                            f"Strict-Transport-Security specifies a negative max-age value ('{int_max_age}'). RFC 6797 §6.1.1 requires non-negative integers.",
                            is_suspicious=True
                        )
                        test_case_hsts.remediation = ["Ensure max-age is a positive integer (e.g. max-age=31536000)."]
                        _emit_header_finding(
                            scanner=scanner,
                            test_case=test_case_hsts,
                            title=f"Malformed HSTS Header: Negative 'max-age' Value ('{int_max_age}')",
                            description=f"The HSTS max-age attribute '{int_max_age}' is negative. Browsers reject negative max-age values as invalid.",
                            sanitized_evidence=f"Strict-Transport-Security: {hsts_val}",
                            impact="HSTS policy is ignored by user agents.",
                            url=url,
                            parameter="Header: Strict-Transport-Security",
                            http_method=http_method
                        )
                        findings_emitted += 1
                    elif int_max_age == 0:
                        test_case_hsts = TestCaseResult(
                            category="headers",
                            target_endpoint=url,
                            http_method=http_method,
                            parameter="Header: Strict-Transport-Security",
                            baseline_response={"strict-transport-security": hsts_val},
                            owasp="A05:2021-Security Misconfiguration",
                            cwe="CWE-319: Cleartext Transmission of Sensitive Information"
                        )
                        test_case_hsts.severity = "medium"
                        test_case_hsts.status = "MEDIUM"
                        test_case_hsts.verification_status = "POTENTIAL"
                        test_case_hsts.confidence = "HIGH"
                        test_case_hsts.add_observation(
                            "hsts_max_age_zero",
                            f"Strict-Transport-Security specifies max-age={int_max_age}, effectively disabling HSTS protection.",
                            is_suspicious=True
                        )
                        test_case_hsts.remediation = ["Set max-age to at least 31536000 (1 year)."]
                        _emit_header_finding(
                            scanner=scanner,
                            test_case=test_case_hsts,
                            title="HSTS Policy Disabled ('max-age=0')",
                            description="The HSTS header specifies max-age=0, which causes browsers to delete any cached HSTS pin for this host.",
                            sanitized_evidence=f"Strict-Transport-Security: {hsts_val}",
                            impact="Disables transport encryption pinning, permitting cleartext downgrade.",
                            url=url,
                            parameter="Header: Strict-Transport-Security",
                            http_method=http_method
                        )
                        findings_emitted += 1
                    elif int_max_age < 10368000:  # Less than 120 days
                        test_case_hsts = TestCaseResult(
                            category="headers",
                            target_endpoint=url,
                            http_method=http_method,
                            parameter="Header: Strict-Transport-Security",
                            baseline_response={"strict-transport-security": hsts_val},
                            owasp="A05:2021-Security Misconfiguration",
                            cwe="CWE-319: Cleartext Transmission of Sensitive Information"
                        )
                        test_case_hsts.severity = "low"
                        test_case_hsts.status = "LOW"
                        test_case_hsts.verification_status = "POTENTIAL"
                        test_case_hsts.confidence = "MEDIUM"
                        test_case_hsts.add_observation(
                            "hsts_short_max_age",
                            f"Strict-Transport-Security specifies a short max-age ({int_max_age} seconds / {round(int_max_age / 86400)} days). Recommended minimum is 10368000 (120 days) or 31536000 (1 year).",
                            is_suspicious=True
                        )
                        test_case_hsts.remediation = ["Increase max-age to 31536000 seconds (1 year)."]
                        _emit_header_finding(
                            scanner=scanner,
                            test_case=test_case_hsts,
                            title="HSTS Header With Short 'max-age' Duration",
                            description=f"The HSTS header specifies a short max-age duration ({round(int_max_age / 86400)} days).",
                            sanitized_evidence=f"Strict-Transport-Security: {hsts_val}",
                            impact="Requires users to revisit the site frequently to refresh HSTS pinning protection.",
                            url=url,
                            parameter="Header: Strict-Transport-Security",
                            http_method=http_method
                        )
                        findings_emitted += 1
                except (ValueError, TypeError):
                    test_case_hsts = TestCaseResult(
                        category="headers",
                        target_endpoint=url,
                        http_method=http_method,
                        parameter="Header: Strict-Transport-Security",
                        baseline_response={"strict-transport-security": hsts_val},
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-319: Cleartext Transmission of Sensitive Information"
                    )
                    test_case_hsts.severity = "low"
                    test_case_hsts.status = "LOW"
                    test_case_hsts.verification_status = "POTENTIAL"
                    test_case_hsts.confidence = "HIGH"
                    test_case_hsts.add_observation(
                        "hsts_invalid_max_age",
                        f"Strict-Transport-Security contains an invalid non-integer max-age value: '{raw_max_age}'.",
                        is_suspicious=True
                    )
                    test_case_hsts.remediation = ["Ensure max-age is a valid positive integer in seconds (e.g. max-age=31536000)."]
                    _emit_header_finding(
                        scanner=scanner,
                        test_case=test_case_hsts,
                        title=f"Malformed HSTS Header: Invalid 'max-age' Value ('{raw_max_age}')",
                        description=f"The HSTS max-age attribute '{raw_max_age}' is not a valid integer. Browsers will discard this header.",
                        sanitized_evidence=f"Strict-Transport-Security: {hsts_val}",
                        impact="HSTS policy is ignored by user agents.",
                        url=url,
                        parameter="Header: Strict-Transport-Security",
                        http_method=http_method
                    )
                    findings_emitted += 1

    # =========================================================================
    # CHECK 3: X-Content-Type-Options
    # =========================================================================
    cto_val = headers.get("x-content-type-options")
    if not cto_val:
        test_case_cto = TestCaseResult(
            category="headers",
            target_endpoint=url,
            http_method=http_method,
            parameter="Header: X-Content-Type-Options",
            baseline_response={"headers": "X-Content-Type-Options absent"},
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-79: Improper Neutralization of Input During Web Page Generation"
        )
        test_case_cto.severity = "low"
        test_case_cto.status = "LOW"
        test_case_cto.verification_status = "POTENTIAL"
        test_case_cto.confidence = "HIGH"
        test_case_cto.add_observation(
            "missing_cto",
            "The X-Content-Type-Options header is absent. Browsers may perform MIME sniffing, leading to script execution.",
            is_suspicious=True
        )
        test_case_cto.remediation = ["Add header: X-Content-Type-Options: nosniff."]
        _emit_header_finding(
            scanner=scanner,
            test_case=test_case_cto,
            title="Missing X-Content-Type-Options",
            description="The X-Content-Type-Options header is missing. Modern browsers may attempt MIME sniffing on ambiguously typed resources.",
            sanitized_evidence="X-Content-Type-Options: [ABSENT]",
            impact="Browsers may interpret non-executable resources (e.g. text/plain, images) as executable JavaScript.",
            url=url,
            parameter="Header: X-Content-Type-Options",
            http_method=http_method
        )
        findings_emitted += 1
    elif cto_val.strip().lower() != "nosniff":
        test_case_cto = TestCaseResult(
            category="headers",
            target_endpoint=url,
            http_method=http_method,
            parameter="Header: X-Content-Type-Options",
            baseline_response={"x-content-type-options": cto_val},
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-79: Improper Neutralization of Input During Web Page Generation"
        )
        test_case_cto.severity = "low"
        test_case_cto.status = "LOW"
        test_case_cto.verification_status = "POTENTIAL"
        test_case_cto.confidence = "HIGH"
        test_case_cto.add_observation(
            "invalid_cto",
            f"X-Content-Type-Options is set to '{cto_val}' instead of the standard 'nosniff' directive.",
            is_suspicious=True
        )
        test_case_cto.remediation = ["Set X-Content-Type-Options: nosniff."]
        _emit_header_finding(
            scanner=scanner,
            test_case=test_case_cto,
            title=f"Invalid X-Content-Type-Options Header Value ('{cto_val}')",
            description=f"The X-Content-Type-Options header value '{cto_val}' is invalid. The only recognized directive is 'nosniff'.",
            sanitized_evidence=f"X-Content-Type-Options: {cto_val}",
            impact="Browser does not enforce MIME sniffing restrictions.",
            url=url,
            parameter="Header: X-Content-Type-Options",
            http_method=http_method
        )
        findings_emitted += 1

    # =========================================================================
    # CHECK 4: Framing & Clickjacking Defense (CSP frame-ancestors & X-Frame-Options)
    # =========================================================================
    # Check if any ENFORCED CSP policy includes frame-ancestors (superseding X-Frame-Options)
    csp_enforced_list = []
    if hasattr(response, "headers") and hasattr(response.headers, "get_list"):
        csp_enforced_list = response.headers.get_list("content-security-policy")
    if not csp_enforced_list and csp_enforced:
        csp_enforced_list = [csp_enforced]

    has_csp_framing = any("frame-ancestors" in _parse_csp_directives(p) for p in csp_enforced_list)
    xfo_val = headers.get("x-frame-options")

    if has_csp_framing:
        # CSP frame-ancestors supersedes X-Frame-Options per W3C specification.
        # Framing defense is actively provided; do NOT report missing X-Frame-Options.
        pass
    else:
        # No CSP frame-ancestors; evaluate X-Frame-Options
        if not xfo_val:
            test_case_xfo = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: X-Frame-Options",
                baseline_response={"headers": "Neither X-Frame-Options nor CSP frame-ancestors observed"},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
            )
            test_case_xfo.severity = "medium" if is_html else "low"
            test_case_xfo.status = "MEDIUM" if is_html else "LOW"
            test_case_xfo.verification_status = "POTENTIAL"
            test_case_xfo.confidence = "HIGH"
            test_case_xfo.add_observation(
                "missing_framing_protection",
                "Neither X-Frame-Options nor Content-Security-Policy 'frame-ancestors' was observed on this response.",
                is_suspicious=True
            )
            test_case_xfo.remediation = [
                "Configure Content-Security-Policy: frame-ancestors 'self' or X-Frame-Options: SAMEORIGIN (or DENY)."
            ]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_xfo,
                title="Missing Framing Protection (X-Frame-Options / CSP frame-ancestors Absent)",
                description=(
                    "The application does not specify X-Frame-Options or CSP frame-ancestors. "
                    "Malicious websites can embed this page inside an <iframe>, leaving users vulnerable to Clickjacking."
                ),
                sanitized_evidence="X-Frame-Options: [ABSENT]; CSP frame-ancestors: [ABSENT]",
                impact="Allows malicious sites to frame this endpoint and execute Clickjacking / UI-redressing attacks.",
                url=url,
                parameter="Header: X-Frame-Options",
                http_method=http_method
            )
            findings_emitted += 1
        else:
            # X-Frame-Options is present: validate value
            xfo_clean = xfo_val.strip().lower()
            if xfo_clean.startswith("allow-from"):
                test_case_xfo = TestCaseResult(
                    category="headers",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter="Header: X-Frame-Options",
                    baseline_response={"x-frame-options": xfo_val},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
                )
                test_case_xfo.severity = "low"
                test_case_xfo.status = "LOW"
                test_case_xfo.verification_status = "POTENTIAL"
                test_case_xfo.confidence = "HIGH"
                test_case_xfo.add_observation(
                    "xfo_obsolete_allow_from",
                    "X-Frame-Options specifies 'ALLOW-FROM', which is obsolete and unsupported in modern browsers (Chrome, Firefox, Safari).",
                    is_suspicious=True
                )
                test_case_xfo.remediation = ["Migrate framing defense to Content-Security-Policy: frame-ancestors <trusted-origins>."]
                _emit_header_finding(
                    scanner=scanner,
                    test_case=test_case_xfo,
                    title="Obsolete X-Frame-Options Value ('ALLOW-FROM')",
                    description="The header specifies 'ALLOW-FROM', an obsolete directive dropped in modern browsers.",
                    sanitized_evidence=f"X-Frame-Options: {xfo_val}",
                    impact="Modern browsers ignore ALLOW-FROM, leaving framing unrestricted unless CSP frame-ancestors is present.",
                    url=url,
                    parameter="Header: X-Frame-Options",
                    http_method=http_method
                )
                findings_emitted += 1
            elif xfo_clean not in ("deny", "sameorigin"):
                test_case_xfo = TestCaseResult(
                    category="headers",
                    target_endpoint=url,
                    http_method=http_method,
                    parameter="Header: X-Frame-Options",
                    baseline_response={"x-frame-options": xfo_val},
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
                )
                test_case_xfo.severity = "low"
                test_case_xfo.status = "LOW"
                test_case_xfo.verification_status = "POTENTIAL"
                test_case_xfo.confidence = "HIGH"
                test_case_xfo.add_observation(
                    "xfo_invalid_value",
                    f"X-Frame-Options specifies an unrecognized value: '{xfo_val}'. Valid directives are DENY or SAMEORIGIN.",
                    is_suspicious=True
                )
                test_case_xfo.remediation = ["Set X-Frame-Options to DENY or SAMEORIGIN."]
                _emit_header_finding(
                    scanner=scanner,
                    test_case=test_case_xfo,
                    title=f"Invalid X-Frame-Options Header Value ('{xfo_val}')",
                    description=f"The X-Frame-Options value '{xfo_val}' is invalid. Browsers will discard unrecognized directives.",
                    sanitized_evidence=f"X-Frame-Options: {xfo_val}",
                    impact="Leaves the endpoint vulnerable to framing and UI redressing.",
                    url=url,
                    parameter="Header: X-Frame-Options",
                    http_method=http_method
                )
                findings_emitted += 1

    # =========================================================================
    # CHECK 5: Referrer-Policy
    # =========================================================================
    rp_val = headers.get("referrer-policy")
    if not rp_val:
        test_case_rp = TestCaseResult(
            category="headers",
            target_endpoint=url,
            http_method=http_method,
            parameter="Header: Referrer-Policy",
            baseline_response={"headers": "Referrer-Policy absent"},
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        )
        test_case_rp.severity = "low"
        test_case_rp.status = "LOW"
        test_case_rp.verification_status = "POTENTIAL"
        test_case_rp.confidence = "HIGH"
        test_case_rp.add_observation(
            "missing_referrer_policy",
            "The Referrer-Policy header is absent.",
            is_suspicious=True
        )
        test_case_rp.remediation = ["Add Referrer-Policy: strict-origin-when-cross-origin."]
        _emit_header_finding(
            scanner=scanner,
            test_case=test_case_rp,
            title="Referrer-Policy Not Set",
            description="No Referrer-Policy header was found. Browsers fall back to default policies that may leak path and query information.",
            sanitized_evidence="Referrer-Policy: [ABSENT]",
            impact="May leak sensitive URL query parameters to third-party domains.",
            url=url,
            parameter="Header: Referrer-Policy",
            http_method=http_method
        )
        findings_emitted += 1
    else:
        # Validate Referrer-Policy tokens
        rp_tokens = [t.strip().lower() for t in rp_val.split(",") if t.strip()]
        invalid_tokens = [t for t in rp_tokens if t not in VALID_REFERRER_POLICIES]

        if invalid_tokens:
            test_case_rp = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Referrer-Policy",
                baseline_response={"referrer-policy": rp_val},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
            )
            test_case_rp.severity = "low"
            test_case_rp.status = "LOW"
            test_case_rp.verification_status = "POTENTIAL"
            test_case_rp.confidence = "HIGH"
            test_case_rp.add_observation(
                "invalid_referrer_policy",
                f"Referrer-Policy contains unrecognized directives: {', '.join(invalid_tokens)}.",
                is_suspicious=True
            )
            test_case_rp.remediation = ["Configure a standard Referrer-Policy such as 'strict-origin-when-cross-origin' or 'no-referrer'."]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_rp,
                title=f"Invalid Referrer-Policy Directive ('{invalid_tokens[0]}')",
                description=f"The Referrer-Policy directive '{invalid_tokens[0]}' is unrecognized.",
                sanitized_evidence=f"Referrer-Policy: {rp_val}",
                impact="Browsers will disregard invalid tokens and fall back to default behavior.",
                url=url,
                parameter="Header: Referrer-Policy",
                http_method=http_method
            )
            findings_emitted += 1
        elif rp_tokens and rp_tokens[-1] == "unsafe-url":
            test_case_rp = TestCaseResult(
                category="headers",
                target_endpoint=url,
                http_method=http_method,
                parameter="Header: Referrer-Policy",
                baseline_response={"referrer-policy": rp_val},
                owasp="A05:2021-Security Misconfiguration",
                cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
            )
            test_case_rp.severity = "low"
            test_case_rp.status = "LOW"
            test_case_rp.verification_status = "POTENTIAL"
            test_case_rp.confidence = "MEDIUM"
            test_case_rp.add_observation(
                "insecure_referrer_policy",
                "Referrer-Policy specifies 'unsafe-url', which unconditionally transmits the entire URL (origin, path, and query parameters) on all cross-origin requests.",
                is_suspicious=True
            )
            test_case_rp.remediation = ["Change Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'."]
            _emit_header_finding(
                scanner=scanner,
                test_case=test_case_rp,
                title="Insecure Referrer-Policy ('unsafe-url')",
                description="The Referrer-Policy is set to 'unsafe-url', exposing the full URL and query parameters to any third-party resource loaded by the page.",
                sanitized_evidence=f"Referrer-Policy: {rp_val}",
                impact="Sensitive query strings, tokens, and navigation paths are leaked across origins.",
                url=url,
                parameter="Header: Referrer-Policy",
                http_method=http_method
            )
            findings_emitted += 1

    # =========================================================================
    # CHECK 6: Permissions-Policy / Feature-Policy
    # =========================================================================
    pp_val = headers.get("permissions-policy")
    fp_val = headers.get("feature-policy")

    if not pp_val and not fp_val:
        test_case_pp = TestCaseResult(
            category="headers",
            target_endpoint=url,
            http_method=http_method,
            parameter="Header: Permissions-Policy",
            baseline_response={"headers": "Permissions-Policy absent"},
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-693: Protection Mechanism Failure"
        )
        test_case_pp.severity = "low"
        test_case_pp.status = "LOW"
        test_case_pp.verification_status = "POTENTIAL"
        test_case_pp.confidence = "HIGH"
        test_case_pp.add_observation(
            "missing_permissions_policy",
            "No Permissions-Policy or Feature-Policy header was found.",
            is_suspicious=True
        )
        test_case_pp.remediation = ["Add Permissions-Policy to explicitly control browser features (e.g. geolocation=(), camera=(), microphone=())."]
        _emit_header_finding(
            scanner=scanner,
            test_case=test_case_pp,
            title="Permissions-Policy Not Set",
            description="No Permissions-Policy header was returned. The site does not restrict client-side hardware features (camera, microphone, geolocation).",
            sanitized_evidence="Permissions-Policy: [ABSENT]",
            impact="Permits embedded iframes or scripts to access browser device APIs if permissions are granted.",
            url=url,
            parameter="Header: Permissions-Policy",
            http_method=http_method
        )
        findings_emitted += 1
    elif pp_val and not pp_val.strip():
        test_case_pp = TestCaseResult(
            category="headers",
            target_endpoint=url,
            http_method=http_method,
            parameter="Header: Permissions-Policy",
            baseline_response={"permissions-policy": pp_val},
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-693: Protection Mechanism Failure"
        )
        test_case_pp.severity = "low"
        test_case_pp.status = "LOW"
        test_case_pp.verification_status = "POTENTIAL"
        test_case_pp.confidence = "HIGH"
        test_case_pp.add_observation(
            "empty_permissions_policy",
            "Permissions-Policy header is present but contains an empty directive string.",
            is_suspicious=True
        )
        test_case_pp.remediation = ["Configure meaningful feature restrictions (e.g. geolocation=(), camera=(), microphone=())."]
        _emit_header_finding(
            scanner=scanner,
            test_case=test_case_pp,
            title="Malformed Permissions-Policy Header (Empty Directive String)",
            description="The Permissions-Policy header is present but specifies no directives.",
            sanitized_evidence="Permissions-Policy: [EMPTY]",
            impact="Provides zero browser API restrictions.",
            url=url,
            parameter="Header: Permissions-Policy",
            http_method=http_method
        )
        findings_emitted += 1

    # =========================================================================
    # CHECK 7: Clean Verification Outcome (NOT_DETECTED)
    # =========================================================================
    if findings_emitted == 0:
        scanner._add_finding(
            f_type="headers",
            severity="info",
            status="NOT_DETECTED",
            verification_status="NOT_DETECTED",
            confidence="HIGH",
            title="Security Headers Evaluation Passed",
            description=(
                f"Audited HTTP response headers for {url}. "
                "Protective security headers (Content-Security-Policy, Strict-Transport-Security, "
                "X-Content-Type-Options, framing defense, Referrer-Policy, and Permissions-Policy) "
                "are configured with recommended defensive directives."
            ),
            evidence=f"Audited response headers on {url}. No missing or insecure security header directives observed.",
            url=url,
            http_method=http_method
        )
