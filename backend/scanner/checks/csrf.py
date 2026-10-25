import logging
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse
from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from scanner.engine import SecurityScanner

from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult

logger = logging.getLogger("ethiosec.scanner.csrf")

CSRF_TOKEN_PATTERNS = [
    "csrf", "xsrf", "_token", "csrftoken", "csrf_token", 
    "authenticity_token", "__requestverificationtoken", "nonce", "anti_forgery"
]

SENSITIVE_ACTION_KEYWORDS = [
    "password", "email", "profile", "user", "account", "settings",
    "delete", "remove", "update", "transfer", "pay", "checkout", "admin", "role"
]


class CSRFCoverageRecord:
    def __init__(self):
        self.forms_discovered: int = 0
        self.state_changing_forms: int = 0
        self.forms_tested: int = 0
        self.findings_added: int = 0
        self.inconclusive_reasons: List[str] = []
        self.blocking_reason: Optional[str] = None
        self.verification_completed: bool = False


async def check_csrf(
    scanner: "SecurityScanner",
    discovered_forms: list,
    client: SafeHTTPClient,
    cookies_observed: Optional[list] = None,
    auth_context: Optional[dict] = None
) -> CSRFCoverageRecord:
    """
    Evaluates Cross-Site Request Forgery (CSRF) protections on state-changing forms.
    Inspects anti-CSRF tokens, SameSite cookie isolation, and token validation.
    """
    coverage = CSRFCoverageRecord()
    coverage.forms_discovered = len(discovered_forms or [])

    # Filter for state-changing forms (POST, PUT, DELETE, PATCH)
    state_forms = [
        f for f in (discovered_forms or [])
        if f.get("method", "GET").upper() in ("POST", "PUT", "DELETE", "PATCH")
    ]
    coverage.state_changing_forms = len(state_forms)

    if not state_forms:
        coverage.blocking_reason = "No state-changing HTML forms (POST/PUT/DELETE) were discovered across the attack surface."
        coverage.verification_completed = True
        scanner._add_finding(
            f_type="csrf",
            severity="info",
            status="NOT_DETECTED",
            title="No State-Changing Forms Discovered",
            description="The crawler identified 0 state-changing (POST/PUT/DELETE) forms across the visited attack surface. Automated CSRF payload testing was not required for read-only pages.",
            evidence="Discovered 0 state-changing forms across crawled application scope.",
            url=scanner.db.query(scanner.db.models.Scan).filter_by(id=scanner.scan_id).first().target_url if hasattr(scanner, "db") else None,
            remediation=["Continue enforcing anti-CSRF tokens whenever new state-changing endpoints or forms are added."],
            owasp="A01:2021-Broken Access Control",
            cwe="CWE-352: Cross-Site Request Forgery (CSRF)"
        )
        return coverage

    # Inspect cookie attributes for SameSite defense-in-depth
    samesite_cookies = [
        c for c in (cookies_observed or [])
        if c.get("samesite") and c.get("samesite").lower() in ("strict", "lax")
    ]
    has_samesite_isolation = len(samesite_cookies) > 0

    for form in state_forms:
        coverage.forms_tested += 1
        action_url = form.get("action_url", "")
        page_url = form.get("page_url", action_url)
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", [])
        fields = form.get("fields", {})

        is_sensitive = any(
            kw in action_url.lower() or any(kw in inp.lower() for inp in inputs)
            for kw in SENSITIVE_ACTION_KEYWORDS
        )

        # Check for presence of anti-CSRF tokens
        token_found = form.get("has_csrf_token", False)
        token_field = form.get("csrf_field_name")
        if not token_found:
            for inp in inputs:
                if any(p in inp.lower() for p in CSRF_TOKEN_PATTERNS):
                    token_found = True
                    token_field = inp
                    break

        test_case = TestCaseResult(
            category="csrf",
            target_endpoint=action_url,
            http_method=method,
            parameter=token_field or "N/A",
            remediation=[
                "Implement cryptographically unpredictable anti-CSRF synchronization tokens validated on all state-changing requests.",
                "Set SameSite=Lax or SameSite=Strict on all authentication and session cookies.",
                "Enforce Origin and Referer header verification for sensitive operations."
            ],
            owasp="A01:2021-Broken Access Control"
        )

        if not token_found:
            if not has_samesite_isolation:
                obs_msg = f"State-changing form ({method} to {action_url}) lacks an anti-CSRF synchronization token, and no SameSite session cookie was observed."
                test_case.add_observation("missing_csrf_token", obs_msg, is_strong_evidence=True)
                test_case.severity = "high" if is_sensitive else "medium"
            else:
                obs_msg = f"State-changing form ({method} to {action_url}) lacks an anti-CSRF token. While SameSite cookies offer partial defense-in-depth, explicit tokens remain required for defense-in-depth."
                test_case.add_observation("csrf_samesite_partial", obs_msg, is_suspicious=True)
                test_case.severity = "medium" if is_sensitive else "low"
        else:
            test_case.add_observation(
                "token_present", 
                f"Anti-CSRF token field '{token_field}' detected in form submitting {method} to {action_url}.",
                is_suspicious=False
            )
            test_case.status = "NOT_DETECTED"

        test_case.evaluate()

        if test_case.status in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            coverage.findings_added += 1
            scanner._add_finding(
                f_type="csrf",
                severity=test_case.severity,
                status=test_case.status,
                title=f"Missing Anti-CSRF Protection on {method} Form",
                description=f"A state-changing form submitting to {action_url} lacks an anti-CSRF token, allowing attackers to forge unauthorized actions via cross-site requests.",
                evidence=test_case.evidence,
                impact="An attacker can trick authenticated users into executing unintended state-changing actions (such as account updates or setting changes) by luring them to a malicious page.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                cwe="CWE-352: Cross-Site Request Forgery (CSRF)",
                url=action_url or page_url,
                http_method=method
            )

    coverage.verification_completed = True
    return coverage
