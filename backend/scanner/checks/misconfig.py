"""
EthioSec Scanner — Security Misconfiguration Audit Module.
Audits web server configurations, directory listings, debug diagnostics,
and default server test scripts.
"""

import logging
from urllib.parse import urljoin
from typing import TYPE_CHECKING, Optional
import httpx

from scanner.test_case import TestCaseResult

if TYPE_CHECKING:
    from scanner.engine import SecurityScanner
    from scanner.http_client import SafeHTTPClient

logger = logging.getLogger("ethiosec.scanner.misconfig")

DIRECTORY_LISTING_SIGNATURES = (
    "<title>index of",
    "index of /",
    "directory listing for",
    "[to parent directory]",
    "parent directory</a>",
    "last modified</a>"
)

SERVER_STATUS_SIGNATURES = (
    "apache server status",
    "server version: apache",
    "server uptime:",
    "phpinfo()",
    "configuration file (php.ini) path"
)


async def check_misconfig(
    scanner: "SecurityScanner",
    target_url: str,
    client: "SafeHTTPClient",
    root_response: Optional[httpx.Response] = None
):
    """
    Executes targeted, safe probes for common security misconfigurations:
    1. Directory indexing / listing on common asset directories.
    2. Exposed administrative diagnostics (e.g., /server-status, /phpinfo.php).
    3. Verbose debug error exposure on malformed URL paths.
    """
    findings_added = 0

    def _is_cancelled() -> bool:
        if hasattr(scanner, "_is_cancelled") and callable(scanner._is_cancelled):
            return scanner._is_cancelled()
        return False

    if _is_cancelled():
        return

    # Probe 1: Directory Listing on common resource directories
    test_dirs = ["/static/", "/uploads/", "/images/", "/assets/", "/backup/"]
    for dir_path in test_dirs:
        if _is_cancelled():
            break
        probe_url = urljoin(target_url, dir_path)
        try:
            resp = await client.get(probe_url)
            if resp.status_code == 200 and resp.text:
                lower = resp.text.lower()
                matched_sig = next((sig for sig in DIRECTORY_LISTING_SIGNATURES if sig in lower), None)
                if matched_sig and "<html" in lower:
                    test_case = TestCaseResult(
                        category="misconfig",
                        target_endpoint=probe_url,
                        http_method="GET",
                        remediation=[
                            "Disable directory browsing / indexing on the web server (e.g., 'Options -Indexes' in Apache, 'autoindex off' in Nginx).",
                            "Implement index.html or empty default files in public directories."
                        ],
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-548: Exposure of Information Through Directory Listing"
                    )
                    test_case.add_observation(
                        "directory_listing_detected",
                        f"Directory browsing is enabled on {probe_url}. Server response matched signature '{matched_sig}'.",
                        is_strong_evidence=True
                    )
                    test_case.evaluate()

                    scanner._add_finding(
                        f_type="misconfig",
                        severity="medium",
                        status="MEDIUM",
                        verification_status="CONFIRMED",
                        confidence="HIGH",
                        title=f"Directory Listing Enabled on {dir_path}",
                        description=f"The web server permits directory indexing on {probe_url}. Attackers can browse directories, list files, and identify unreferenced assets or backup copies.",
                        evidence=test_case.evidence,
                        impact="Attackers can view directory listings, discover hidden files, and download internal resources.",
                        remediation=test_case.remediation,
                        owasp=test_case.owasp,
                        cwe=test_case.cwe,
                        url=probe_url,
                        http_method="GET"
                    )
                    findings_added += 1
                    break
        except Exception as e:
            logger.debug(f"Misconfig directory probe notice on {probe_url}: {e}")

    # Probe 2: Exposed Server Diagnostic Endpoints
    diag_paths = ["/server-status", "/phpinfo.php"]
    for diag in diag_paths:
        if _is_cancelled():
            break
        probe_url = urljoin(target_url, diag)
        try:
            resp = await client.get(probe_url)
            if resp.status_code == 200 and resp.text:
                lower = resp.text.lower()
                matched_diag = next((sig for sig in SERVER_STATUS_SIGNATURES if sig in lower), None)
                if matched_diag:
                    test_case = TestCaseResult(
                        category="misconfig",
                        target_endpoint=probe_url,
                        http_method="GET",
                        remediation=[
                            "Restrict diagnostic and status pages to authorized internal IP addresses or disable them in production.",
                            "Remove phpinfo() scripts and test endpoints from web root."
                        ],
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
                    )
                    test_case.add_observation(
                        "diagnostic_page_exposed",
                        f"Diagnostic endpoint {probe_url} is publicly accessible (matched '{matched_diag}').",
                        is_strong_evidence=True
                    )
                    test_case.evaluate()

                    scanner._add_finding(
                        f_type="misconfig",
                        severity="high",
                        status="HIGH",
                        verification_status="CONFIRMED",
                        confidence="HIGH",
                        title=f"Exposed Server Diagnostic Page ({diag})",
                        description=f"The administrative status page {probe_url} is publicly accessible without authentication. It exposes server metrics, active connections, and runtime configurations.",
                        evidence=test_case.evidence,
                        impact="Attackers can gather detailed server metrics, request URLs, and runtime environment settings.",
                        remediation=test_case.remediation,
                        owasp=test_case.owasp,
                        cwe=test_case.cwe,
                        url=probe_url,
                        http_method="GET"
                    )
                    findings_added += 1
        except Exception as e:
            logger.debug(f"Misconfig diagnostic probe notice on {probe_url}: {e}")

    # Probe 3: Verbose Stack Trace / Debug Exposure on Malformed Path
    if not _is_cancelled():
        malformed_url = urljoin(target_url, "/nonexistent_probe_404_test_debug_%00")
        try:
            resp = await client.get(malformed_url)
            if resp.status_code >= 400 and resp.text:
                lower = resp.text.lower()
                debug_cues = (
                    "traceback (most recent call last):",
                    "werkzeug debugger",
                    "django version",
                    "exception value:",
                    "stack trace:",
                    "at org.apache.catalina"
                )
                matched_cue = next((c for c in debug_cues if c in lower), None)
                if matched_cue:
                    test_case = TestCaseResult(
                        category="misconfig",
                        target_endpoint=malformed_url,
                        http_method="GET",
                        remediation=[
                            "Disable debug mode (e.g. DEBUG=False in Django, app.debug=False in Flask) in production.",
                            "Implement custom generic error handling pages that suppress stack traces."
                        ],
                        owasp="A05:2021-Security Misconfiguration",
                        cwe="CWE-209: Generation of Error Message Containing Sensitive Information"
                    )
                    test_case.add_observation(
                        "debug_stack_trace_leak",
                        f"Server returned verbose debug trace on malformed path (matched '{matched_cue}').",
                        is_strong_evidence=True
                    )
                    test_case.evaluate()

                    scanner._add_finding(
                        f_type="misconfig",
                        severity="medium",
                        status="MEDIUM",
                        verification_status="CONFIRMED",
                        confidence="HIGH",
                        title="Verbose Debug Stack Trace Exposed in Error Responses",
                        description="The application displays detailed framework stack traces and debug output upon receiving unexpected or malformed requests.",
                        evidence=test_case.evidence,
                        impact="Exposes internal filenames, code structure, framework versions, and database schemas.",
                        remediation=test_case.remediation,
                        owasp=test_case.owasp,
                        cwe=test_case.cwe,
                        url=malformed_url,
                        http_method="GET"
                    )
                    findings_added += 1
        except Exception as e:
            logger.debug(f"Misconfig stack trace probe notice: {e}")

    # Clean outcome reporting
    if findings_added == 0:
        scanner._add_finding(
            f_type="misconfig",
            severity="info",
            status="NOT_DETECTED",
            verification_status="NOT_DETECTED",
            confidence="HIGH",
            title="Security Misconfiguration Checks Passed",
            description="Audited directory indexing, exposed server status interfaces, and verbose debug error handling. No directory listings, exposed diagnostic consoles, or stack traces were detected.",
            evidence=f"Probed common directory paths, status interfaces, and error handlers on {target_url} with safe non-destructive requests.",
            url=target_url
        )
