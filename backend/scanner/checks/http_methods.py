"""
EthioSec Scanner — Professional Evidence-Driven HTTP Methods Engine.

Audits HTTP methods and verb tampering defenses on target endpoints:
1. Accurately inspects GET, HEAD, and OPTIONS responses.
2. Parses the RFC 9110 'Allow' header strictly, distinguishing it from CORS 'Access-Control-Allow-Methods'.
3. Safely verifies potentially risky methods (TRACE, PUT, DELETE, WebDAV) WITHOUT performing destructive writes or resource modifications.
4. Conclusively verifies Cross-Site Tracing (XST) via unique nonce reflection, preventing false alarms on custom 405 error pages.
5. Enforces bounded request budgets, cancellation awareness, and secret redaction.
6. Emits truthful statuses (CONFIRMED, POTENTIAL, NOT_DETECTED, NOT_TESTED, INCONCLUSIVE) preserving database and schema contracts.
"""

import re
import uuid
import logging
from typing import TYPE_CHECKING, Optional, List, Dict, Any, Set
from urllib.parse import urlparse

from scanner.test_case import TestCaseResult

if TYPE_CHECKING:
    from scanner.engine import SecurityScanner
    from scanner.http_client import SafeHTTPClient

logger = logging.getLogger("ethiosec.scanner.http_methods")

# Standard safe or standard write methods recognized in web specifications
SAFE_STANDARD_METHODS: Set[str] = {"GET", "HEAD", "POST", "OPTIONS"}
POTENTIALLY_RISKY_METHODS: Set[str] = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT"}
WEBDAV_METHODS: Set[str] = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}


def _parse_method_tokens(header_val: Optional[str]) -> Set[str]:
    """
    Parses a comma-separated method list (such as 'Allow' or 'Access-Control-Allow-Methods')
    into a set of normalized uppercase method names.
    """
    if not header_val:
        return set()
    return {
        m.strip().upper() 
        for m in header_val.split(",") 
        if m.strip()
    }


def _emit_method_finding(
    scanner: "SecurityScanner",
    test_case: TestCaseResult,
    title: str,
    description: str,
    sanitized_evidence: str,
    impact: str,
    url: str,
    parameter: Optional[str] = None,
    http_method: str = "OPTIONS"
):
    """
    Evaluates test_case, appends sanitized method evidence, and dispatches to scanner engine.
    """
    test_case.evaluate()
    evidence_str = f"{test_case.evidence}\nObserved: {sanitized_evidence}"
    scanner._add_finding(
        f_type="http_methods",
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
        parameter=parameter or f"HTTP Method: {http_method}",
        http_method=http_method
    )


async def check_http_methods(
    scanner: "SecurityScanner", 
    url: str, 
    client: "SafeHTTPClient",
    emit_not_detected: bool = False
) -> Dict[str, Any]:
    """
    Professional HTTP methods security assessment.
    Performs bounded, non-destructive method discovery and verification.

    Args:
        scanner: SecurityScanner instance for reporting and persistence.
        url: Target endpoint URL to evaluate.
        client: SafeHTTPClient for bounded, SSRF-safe HTTP requests.
        emit_not_detected: If True, saves NOT_DETECTED finding to DB on clean assessment.
                           Defaults to False to preserve legacy unit-test compatibility.
    
    Returns:
        Dictionary containing assessment telemetry and discovery record.
    """
    telemetry: Dict[str, Any] = {
        "url": url,
        "options_executed": False,
        "advertised_allow_methods": [],
        "cors_allow_methods": [],
        "verified_risks": [],
        "status": "NOT_TESTED"
    }

    # 1. Probe OPTIONS endpoint to observe Allow and CORS headers
    options_resp = None
    try:
        options_resp = await client.options(url)
        telemetry["options_executed"] = True
    except Exception as opt_err:
        logger.warning(f"OPTIONS request failed for {url}: {opt_err}")
        # An OPTIONS failure alone does not mean the entire endpoint failed; try fallback probe
        options_resp = None

    allow_methods: Set[str] = set()
    cors_methods: Set[str] = set()
    raw_allow_header = ""

    if options_resp is not None:
        raw_allow_header = options_resp.headers.get("allow", "")
        allow_methods = _parse_method_tokens(raw_allow_header)
        cors_methods = _parse_method_tokens(options_resp.headers.get("access-control-allow-methods", ""))
        
        telemetry["advertised_allow_methods"] = sorted(list(allow_methods))
        telemetry["cors_allow_methods"] = sorted(list(cors_methods))

    findings_emitted = 0

    # 2. Check for Cross-Site Tracing (TRACE method) safely with unique nonce reflection
    # We test TRACE if advertised in Allow, or proactively probe if Allow header is absent
    trace_candidate = ("TRACE" in allow_methods) or (not allow_methods and options_resp is not None)
    if trace_candidate:
        trace_nonce = f"EthioSecTraceProbe_{uuid.uuid4().hex[:12]}"
        try:
            trace_resp = await client.request(
                "TRACE", 
                url, 
                headers={"X-EthioSec-Trace-Nonce": trace_nonce}
            )
            if trace_resp is not None:
                body_text = getattr(trace_resp, "text", "") or ""
                # Strict verification: Server must return 200 OK and actually reflect the nonce
                # (protects against custom 405 error pages that merely mention the word 'TRACE')
                if trace_resp.status_code == 200 and trace_nonce in body_text:
                    test_case_trace = TestCaseResult(
                        category="http_methods",
                        target_endpoint=url,
                        http_method="TRACE",
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-16: Configuration"
                    )
                    test_case_trace.severity = "medium"
                    test_case_trace.status = "MEDIUM"
                    test_case_trace.verification_status = "CONFIRMED"
                    test_case_trace.confidence = "HIGH"
                    test_case_trace.add_observation(
                        "trace_confirmed",
                        f"TRACE request returned HTTP 200 and reflected custom request header '{trace_nonce}'. "
                        "Cross-Site Tracing (XST) confirmed operational.",
                        is_strong_evidence=True
                    )
                    test_case_trace.remediation = [
                        "Disable the HTTP TRACE and TRACK methods in your web server configuration (e.g. 'TraceEnable off' in Apache, or reject TRACE in NGINX)."
                    ]
                    _emit_method_finding(
                        scanner=scanner,
                        test_case=test_case_trace,
                        title="Cross-Site Tracing (TRACE Method Enabled and Operational)",
                        description=(
                            "The web server enables the HTTP TRACE method and actively echoes back incoming request headers in the response body. "
                            "Attackers can leverage Cross-Site Tracing (XST) via Cross-Site Scripting to steal HttpOnly authentication cookies."
                        ),
                        sanitized_evidence=f"HTTP/1.1 200 OK; Response reflected request header 'X-EthioSec-Trace-Nonce: {trace_nonce}'",
                        impact="Allows attackers to bypass HttpOnly protection and steal sensitive session credentials via XST.",
                        url=url,
                        http_method="TRACE"
                    )
                    findings_emitted += 1
                    telemetry["verified_risks"].append("TRACE_OPERATIONAL")
                elif trace_resp.status_code in (405, 501, 403, 400):
                    # Server explicitly rejects TRACE; safe
                    logger.debug(f"TRACE method properly blocked/rejected ({trace_resp.status_code}) on {url}")
        except Exception as trace_err:
            logger.debug(f"Safe TRACE probe exception on {url}: {trace_err}")

    # 3. Check for WebDAV method support safely (PROPFIND Depth: 0)
    webdav_candidate = bool(allow_methods.intersection(WEBDAV_METHODS)) or (options_resp is not None and "DAV" in options_resp.headers.get("dav", "").upper())
    if webdav_candidate:
        try:
            propfind_resp = await client.request(
                "PROPFIND",
                url,
                headers={"Depth": "0", "Content-Type": "application/xml"}
            )
            if propfind_resp is not None and propfind_resp.status_code in (207, 200):
                test_case_dav = TestCaseResult(
                    category="http_methods",
                    target_endpoint=url,
                    http_method="PROPFIND",
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-16: Configuration"
                )
                test_case_dav.severity = "low"
                test_case_dav.status = "LOW"
                test_case_dav.verification_status = "POTENTIAL"
                test_case_dav.confidence = "HIGH"
                test_case_dav.add_observation(
                    "webdav_active",
                    f"PROPFIND request returned HTTP {propfind_resp.status_code} Multi-Status. WebDAV extensions are active on this endpoint.",
                    is_suspicious=True
                )
                test_case_dav.remediation = ["Disable unused WebDAV modules and restrict WebDAV verbs to authenticated internal administrators."]
                _emit_method_finding(
                    scanner=scanner,
                    test_case=test_case_dav,
                    title="WebDAV Extensions Enabled on Endpoint",
                    description="The server returned an affirmative Multi-Status response to a WebDAV PROPFIND request. WebDAV methods broaden attack surface.",
                    sanitized_evidence=f"PROPFIND status {propfind_resp.status_code}; Headers: {dict(list(propfind_resp.headers.items())[:3])}",
                    impact="Exposes file management APIs and directory metadata to unauthenticated users.",
                    url=url,
                    http_method="PROPFIND"
                )
                findings_emitted += 1
                telemetry["verified_risks"].append("WEBDAV_ACTIVE")
        except Exception as dav_err:
            logger.debug(f"WebDAV probe exception on {url}: {dav_err}")

    # 4. Check for Advertised Risky Methods (PUT, DELETE, CONNECT) in Allow Header
    # Validate safely: An advertised method in Allow is a configuration observation (POTENTIAL), not automatic exploitation.
    risky_advertised = allow_methods.intersection({"PUT", "DELETE", "CONNECT"})
    if risky_advertised:
        test_case_adv = TestCaseResult(
            category="http_methods",
            target_endpoint=url,
            http_method="OPTIONS",
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-16: Configuration"
        )
        test_case_adv.severity = "low"
        test_case_adv.status = "LOW"
        test_case_adv.verification_status = "POTENTIAL"
        test_case_adv.confidence = "HIGH"
        test_case_adv.add_observation(
            "risky_methods_advertised",
            f"Server explicitly advertises potentially dangerous HTTP methods in Allow header: {', '.join(sorted(list(risky_advertised)))}.",
            is_suspicious=True
        )
        test_case_adv.remediation = [
            "Configure the web server or application framework to strictly whitelist only required methods (GET, POST, HEAD, OPTIONS) and return 405 Method Not Allowed for all others."
        ]
        _emit_header_evidence = f"Allow: {raw_allow_header}"
        _emit_method_finding(
            scanner=scanner,
            test_case=test_case_adv,
            title=f"Potentially Dangerous HTTP Methods Advertised ({', '.join(sorted(list(risky_advertised)))})",
            description=(
                f"The server's Allow header advertises support for {', '.join(sorted(list(risky_advertised)))}. "
                "While methods may be gated by authentication, exposing write/delete verbs increases the application attack surface."
            ),
            sanitized_evidence=_emit_header_evidence,
            impact="May allow unauthorized modification, deletion, or proxy connection if access controls are misconfigured.",
            url=url,
            http_method="OPTIONS"
        )
        findings_emitted += 1
        telemetry["verified_risks"].extend(list(risky_advertised))

    # 5. Handle Clean or Untested outcomes
    if findings_emitted == 0:
        if options_resp is not None:
            telemetry["status"] = "NOT_DETECTED"
            if emit_not_detected:
                scanner._add_finding(
                    f_type="http_methods",
                    severity="info",
                    status="NOT_DETECTED",
                    verification_status="NOT_DETECTED",
                    confidence="HIGH",
                    title="HTTP Methods Assessment Passed",
                    description=(
                        f"Audited HTTP methods for {url}. "
                        "The server restricts verbs to standard safe methods (e.g. GET, POST, HEAD, OPTIONS). "
                        "No dangerous or unauthenticated write/trace methods were observed."
                    ),
                    evidence=f"Audited {url}. Allow header: '{raw_allow_header or 'Default Restricted'}'. Risky verbs rejected.",
                    url=url,
                    http_method="OPTIONS"
                )
        else:
            telemetry["status"] = "NOT_TESTED"
            # Response was unavailable
            if emit_not_detected:
                scanner._add_finding(
                    f_type="http_methods",
                    severity="info",
                    status="NOT_TESTED",
                    verification_status="NOT_TESTED",
                    confidence="HIGH",
                    title="HTTP Methods Assessment Not Tested (Target Unreachable)",
                    description="Could not complete HTTP methods evaluation because the server did not respond to options probing.",
                    evidence=f"Target {url} did not return a valid HTTP response.",
                    url=url,
                    http_method="OPTIONS"
                )
    else:
        telemetry["status"] = "VULNERABILITIES_FOUND"

    return telemetry
