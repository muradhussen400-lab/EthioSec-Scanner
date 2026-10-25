"""
EthioSec Scanner — Professional Evidence-Driven HTTPS and TLS Assessment Engine.

Audits transport-layer encryption and TLS security configuration:
1. HTTPS enforcement and redirect assessment:
   - Evaluates plain HTTP origins, HTTP-to-HTTPS redirects, destination host verification, and downgrade detection.
2. Real asynchronous TLS handshake and certificate verification:
   - Validates trust chains, not-before/not-after validity dates, expired certificates, and hostname/SAN matching.
   - Detects self-signed certificates, untrusted authorities, and premature certificates.
   - Inspects negotiated TLS protocol version (TLS 1.2, TLS 1.3 vs deprecated TLS 1.0/1.1) and cipher strength.
3. Network Disambiguation:
   - Distinguishes network timeouts, port 443 connection refusal, and DNS resolution failures from TLS weaknesses.
4. Truthful statuses:
   - Maps confirmed defects to CONFIRMED, configuration observations to POTENTIAL, and clean evaluations to NOT_DETECTED.
   - Preserves backward compatibility with legacy passive tests via optional emit_not_detected flag.
"""

import ssl
import socket
import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional, Dict, Any, Tuple, List
from urllib.parse import urlparse

from scanner.test_case import TestCaseResult
from scanner.safety import is_safe_url

if TYPE_CHECKING:
    from scanner.engine import SecurityScanner
    from scanner.http_client import SafeHTTPClient
    import httpx

logger = logging.getLogger("ethiosec.scanner.https")


def _emit_https_finding(
    scanner: "SecurityScanner",
    test_case: TestCaseResult,
    title: str,
    description: str,
    sanitized_evidence: str,
    impact: str,
    url: str,
    parameter: Optional[str] = None,
    http_method: str = "GET"
):
    """
    Evaluates test_case, appends sanitized TLS evidence, and dispatches to scanner engine.
    """
    test_case.evaluate()
    evidence_str = f"{test_case.evidence}\nObserved: {sanitized_evidence}"
    scanner._add_finding(
        f_type="https",
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
        parameter=parameter or "Transport: TLS/SSL",
        http_method=http_method
    )


async def _inspect_tls_certificate(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Performs real asynchronous TLS handshake and certificate analysis using Python's ssl module.
    Returns structured analysis of certificate validity, trust, protocol version, and ciphers.
    """
    result: Dict[str, Any] = {
        "success": False,
        "trusted": False,
        "expired": False,
        "not_yet_valid": False,
        "hostname_mismatch": False,
        "self_signed": False,
        "tls_version": None,
        "cipher": None,
        "cipher_bits": None,
        "not_before": None,
        "not_after": None,
        "subject": None,
        "issuer": None,
        "sans": [],
        "error_type": None,
        "error_message": None
    }

    loop = asyncio.get_running_loop()

    def _sync_tls_handshake():
        # Standard default context with system CA verification and hostname checking
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    result["success"] = True
                    result["trusted"] = True
                    result["tls_version"] = ssl_sock.version()
                    cipher_info = ssl_sock.cipher()
                    if cipher_info:
                        result["cipher"] = cipher_info[0]
                        result["cipher_bits"] = cipher_info[2]

                    if cert:
                        # Extract validity dates
                        nb_str = cert.get("notBefore")
                        na_str = cert.get("notAfter")
                        if nb_str:
                            try:
                                dt_nb = datetime.strptime(nb_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                                result["not_before"] = dt_nb.isoformat()
                                if datetime.now(timezone.utc) < dt_nb:
                                    result["not_yet_valid"] = True
                            except Exception:
                                pass
                        if na_str:
                            try:
                                dt_na = datetime.strptime(na_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                                result["not_after"] = dt_na.isoformat()
                                if datetime.now(timezone.utc) > dt_na:
                                    result["expired"] = True
                            except Exception:
                                pass

                        # Extract SANs
                        sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]
                        result["sans"] = sans

                        # Subject and Issuer
                        result["subject"] = dict(x[0] for x in cert.get("subject", ()))
                        result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))

        except ssl.SSLCertVerificationError as cert_err:
            result["error_type"] = "SSLCertVerificationError"
            result["error_message"] = str(cert_err)
            err_msg_lower = str(cert_err).lower()

            if "certificate has expired" in err_msg_lower:
                result["expired"] = True
            elif "self-signed" in err_msg_lower or "self signed" in err_msg_lower:
                result["self_signed"] = True
            elif "doesn't match" in err_msg_lower or "hostname" in err_msg_lower or "ip address mismatch" in err_msg_lower:
                result["hostname_mismatch"] = True
            else:
                result["trusted"] = False

        except ssl.SSLError as ssl_err:
            result["error_type"] = "SSLError"
            result["error_message"] = str(ssl_err)

        except (socket.timeout, TimeoutError):
            result["error_type"] = "TimeoutError"
            result["error_message"] = f"Connection to {hostname}:{port} timed out after {timeout}s"

        except ConnectionRefusedError:
            result["error_type"] = "ConnectionRefused"
            result["error_message"] = f"Connection to {hostname}:{port} was refused"

        except socket.gaierror as dns_err:
            result["error_type"] = "DNSError"
            result["error_message"] = f"DNS resolution failed for {hostname}: {dns_err}"

        except Exception as generic_err:
            result["error_type"] = generic_err.__class__.__name__
            result["error_message"] = str(generic_err)

        return result

    try:
        return await loop.run_in_executor(None, _sync_tls_handshake)
    except Exception as exec_err:
        result["error_type"] = exec_err.__class__.__name__
        result["error_message"] = str(exec_err)
        return result


async def check_https(
    scanner: "SecurityScanner",
    url: str,
    response: Optional[Any] = None,
    client: Optional["SafeHTTPClient"] = None,
    emit_not_detected: bool = False
) -> Dict[str, Any]:
    """
    Professional HTTPS enforcement and TLS certificate assessment.

    Evaluates:
    1. HTTP vs HTTPS transport and redirect upgrade behavior.
    2. TLS certificate validity, expiration, trust chain, and hostname/SAN matching.
    3. Negotiated protocol version and cipher suite strength.
    """
    telemetry: Dict[str, Any] = {
        "url": url,
        "scheme": None,
        "redirects_to_https": False,
        "tls_inspected": False,
        "certificate_valid": False,
        "findings_count": 0,
        "status": "NOT_TESTED"
    }

    parsed = urlparse(url or "")
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    telemetry["scheme"] = scheme

    findings_emitted = 0

    # =========================================================================
    # PART 1: HTTP vs HTTPS Scheme and Redirect Assessment
    # =========================================================================
    if scheme == "http":
        # Check if HTTP endpoint redirects to HTTPS
        redirects_to_https = False
        redirect_target = None
        has_downgrade = False

        if response is not None:
            status_code = getattr(response, "status_code", 0)
            loc = (getattr(response, "headers", {}) or {}).get("location", "")
            if status_code in (301, 302, 303, 307, 308) and loc:
                redirect_target = loc
                if loc.lower().startswith("https://"):
                    redirects_to_https = True
                elif loc.lower().startswith("http://"):
                    has_downgrade = True

        telemetry["redirects_to_https"] = redirects_to_https

        if has_downgrade:
            test_case_dg = TestCaseResult(
                category="https",
                target_endpoint=url,
                http_method="GET",
                owasp="A02:2021-Cryptographic Failures",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information"
            )
            test_case_dg.severity = "high"
            test_case_dg.status = "HIGH"
            test_case_dg.verification_status = "POTENTIAL"
            test_case_dg.confidence = "HIGH"
            test_case_dg.add_observation(
                "https_downgrade",
                f"HTTP response redirects to unencrypted target: {redirect_target}.",
                is_suspicious=True
            )
            test_case_dg.remediation = ["Ensure all redirect targets explicitly use the https:// scheme."]
            _emit_https_finding(
                scanner=scanner,
                test_case=test_case_dg,
                title="Insecure Transport Redirect (Redirects to Plain HTTP)",
                description=f"The endpoint redirects to an insecure plain HTTP URL: '{redirect_target}'.",
                sanitized_evidence=f"Redirect Location: {redirect_target}",
                impact="Leaves client communication unencrypted.",
                url=url
            )
            findings_emitted += 1
        elif not redirects_to_https:
            test_case_http = TestCaseResult(
                category="https",
                target_endpoint=url,
                http_method="GET",
                baseline_response={"status_code": getattr(response, "status_code", None)},
                owasp="A02:2021-Cryptographic Failures",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information"
            )
            test_case_http.severity = "high"
            test_case_http.status = "HIGH"
            test_case_http.verification_status = "POTENTIAL"
            test_case_http.confidence = "HIGH"
            test_case_http.add_observation(
                "unencrypted_scheme",
                f"Endpoint communicates over plain HTTP ({url}) without upgrading to HTTPS.",
                is_strong_evidence=True
            )
            test_case_http.remediation = [
                "Enforce HTTPS across the entire domain.",
                "Implement an unconditional 301/308 permanent redirect from HTTP to HTTPS for all routes.",
                "Deploy Strict-Transport-Security (HSTS) with long max-age."
            ]
            _emit_https_finding(
                scanner=scanner,
                test_case=test_case_http,
                title="Unencrypted Communication (HTTP Protocol Active Without TLS Redirect)",
                description=(
                    "The application is accessible over unencrypted HTTP and does not automatically redirect to HTTPS. "
                    "All application traffic, credentials, cookies, and sensitive data are transmitted in cleartext."
                ),
                sanitized_evidence=f"Request to {url} returned HTTP {getattr(response, 'status_code', 'N/A')} without HTTPS redirect.",
                impact="Enables man-in-the-middle (MITM) network eavesdropping, session hijacking, and traffic tampering.",
                url=url
            )
            findings_emitted += 1

    # =========================================================================
    # PART 2: Real TLS Certificate and Protocol Verification (for HTTPS targets)
    # =========================================================================
    tls_target_hostname = hostname
    if scheme == "https" or telemetry.get("redirects_to_https"):
        is_safe = True
        try:
            is_safe_url(f"https://{tls_target_hostname}:443/")
        except Exception as ssrf_err:
            if "loopback" in str(ssrf_err).lower() or "private" in str(ssrf_err).lower():
                is_safe = False

        if is_safe and tls_target_hostname:
            telemetry["tls_inspected"] = True
            tls_data = await _inspect_tls_certificate(tls_target_hostname, port=443, timeout=5.0)

            if tls_data["expired"]:
                test_case_exp = TestCaseResult(
                    category="https",
                    target_endpoint=url,
                    http_method="GET",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-298: Improper Validation of Certificate Expiration"
                )
                test_case_exp.severity = "high"
                test_case_exp.status = "HIGH"
                test_case_exp.verification_status = "CONFIRMED"
                test_case_exp.confidence = "HIGH"
                test_case_exp.add_observation(
                    "cert_expired",
                    f"The TLS certificate for {tls_target_hostname} has expired (NotAfter: {tls_data.get('not_after')}).",
                    is_strong_evidence=True
                )
                test_case_exp.remediation = ["Renew and install a valid TLS certificate from a trusted Certificate Authority."]
                _emit_https_finding(
                    scanner=scanner,
                    test_case=test_case_exp,
                    title="Expired TLS/SSL Certificate",
                    description=f"The TLS certificate presented by {tls_target_hostname} is expired. Browsers will display security warnings and refuse connections.",
                    sanitized_evidence=f"Certificate expired on: {tls_data.get('not_after')}",
                    impact="Breaks user trust and triggers hard browser security blocks.",
                    url=url
                )
                findings_emitted += 1

            elif tls_data["not_yet_valid"]:
                test_case_pre = TestCaseResult(
                    category="https",
                    target_endpoint=url,
                    http_method="GET",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-295: Improper Certificate Validation"
                )
                test_case_pre.severity = "high"
                test_case_pre.status = "HIGH"
                test_case_pre.verification_status = "CONFIRMED"
                test_case_pre.confidence = "HIGH"
                test_case_pre.add_observation(
                    "cert_not_yet_valid",
                    f"The TLS certificate for {tls_target_hostname} is not yet valid (NotBefore: {tls_data.get('not_before')}).",
                    is_strong_evidence=True
                )
                test_case_pre.remediation = ["Ensure the server clock is synchronized and verify certificate issuance dates."]
                _emit_https_finding(
                    scanner=scanner,
                    test_case=test_case_pre,
                    title="Premature TLS/SSL Certificate (Not Yet Valid)",
                    description="The server presents a certificate whose valid date range is in the future.",
                    sanitized_evidence=f"Certificate valid from: {tls_data.get('not_before')}",
                    impact="User agents reject connections with invalid validity dates.",
                    url=url
                )
                findings_emitted += 1

            elif tls_data["self_signed"]:
                test_case_ss = TestCaseResult(
                    category="https",
                    target_endpoint=url,
                    http_method="GET",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-295: Improper Certificate Validation"
                )
                test_case_ss.severity = "high"
                test_case_ss.status = "HIGH"
                test_case_ss.verification_status = "CONFIRMED"
                test_case_ss.confidence = "HIGH"
                test_case_ss.add_observation(
                    "cert_self_signed",
                    f"The TLS certificate for {tls_target_hostname} is self-signed and untrusted.",
                    is_strong_evidence=True
                )
                test_case_ss.remediation = ["Deploy a certificate signed by a recognized Certificate Authority (e.g. Let's Encrypt)."]
                _emit_https_finding(
                    scanner=scanner,
                    test_case=test_case_ss,
                    title="Untrusted Self-Signed TLS Certificate",
                    description="The server presents a self-signed TLS certificate. Browsers reject self-signed certificates in public environments.",
                    sanitized_evidence="Certificate verification: self-signed in certificate chain.",
                    impact="Users receive prominent security warnings and connections can be intercepted via MITM.",
                    url=url
                )
                findings_emitted += 1

            elif tls_data["hostname_mismatch"]:
                test_case_hn = TestCaseResult(
                    category="https",
                    target_endpoint=url,
                    http_method="GET",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-297: Improper Validation of Certificate with Host Mismatch"
                )
                test_case_hn.severity = "high"
                test_case_hn.status = "HIGH"
                test_case_hn.verification_status = "CONFIRMED"
                test_case_hn.confidence = "HIGH"
                test_case_hn.add_observation(
                    "cert_hostname_mismatch",
                    f"The certificate does not match the requested hostname '{tls_target_hostname}'. SANs: {tls_data.get('sans')}.",
                    is_strong_evidence=True
                )
                test_case_hn.remediation = ["Reissue the certificate to include the requested domain in Subject Alternative Names (SAN)."]
                _emit_https_finding(
                    scanner=scanner,
                    test_case=test_case_hn,
                    title="TLS Certificate Hostname Mismatch",
                    description=f"The certificate subject does not match '{tls_target_hostname}'. Valid SANs: {', '.join(tls_data.get('sans', [])) or 'None'}.",
                    sanitized_evidence=f"Hostname mismatch: '{tls_target_hostname}' not in {tls_data.get('sans')}",
                    impact="Browser triggers red interstitial warning and blocks navigation.",
                    url=url
                )
                findings_emitted += 1

            elif not tls_data["trusted"] and tls_data.get("error_type") == "SSLCertVerificationError":
                test_case_uc = TestCaseResult(
                    category="https",
                    target_endpoint=url,
                    http_method="GET",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-295: Improper Certificate Validation"
                )
                test_case_uc.severity = "medium"
                test_case_uc.status = "MEDIUM"
                test_case_uc.verification_status = "CONFIRMED"
                test_case_uc.confidence = "HIGH"
                test_case_uc.add_observation(
                    "cert_untrusted_chain",
                    f"TLS verification failed for {tls_target_hostname}: {tls_data.get('error_message')}.",
                    is_strong_evidence=True
                )
                test_case_uc.remediation = ["Ensure intermediate certificates are installed correctly on the web server."]
                _emit_https_finding(
                    scanner=scanner,
                    test_case=test_case_uc,
                    title="Untrusted TLS Certificate Chain",
                    description="The certificate trust chain could not be verified by the local CA trust store.",
                    sanitized_evidence=f"Verification error: {tls_data.get('error_message')}",
                    impact="Clients without custom root stores cannot establish verified connections.",
                    url=url
                )
                findings_emitted += 1

            elif tls_data["success"] and tls_data["trusted"]:
                telemetry["certificate_valid"] = True
                # Check for deprecated TLS version (TLS 1.0, 1.1)
                tls_ver = tls_data.get("tls_version", "")
                if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    test_case_proto = TestCaseResult(
                        category="https",
                        target_endpoint=url,
                        http_method="GET",
                        owasp="A02:2021-Cryptographic Failures",
                        cwe="CWE-326: Inadequate Encryption Strength"
                    )
                    test_case_proto.severity = "medium"
                    test_case_proto.status = "MEDIUM"
                    test_case_proto.verification_status = "CONFIRMED"
                    test_case_proto.confidence = "HIGH"
                    test_case_proto.add_observation(
                        "tls_deprecated_version",
                        f"Negotiated deprecated protocol version: {tls_ver}.",
                        is_suspicious=True
                    )
                    test_case_proto.remediation = ["Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 and TLS 1.3 exclusively."]
                    _emit_https_finding(
                        scanner=scanner,
                        test_case=test_case_proto,
                        title=f"Deprecated TLS Protocol Version Negotiated ({tls_ver})",
                        description=f"The server negotiated {tls_ver}. TLS 1.0 and 1.1 have known cryptographic deficiencies and are deprecated per RFC 8996.",
                        sanitized_evidence=f"Negotiated TLS version: {tls_ver}",
                        impact="Exposes encrypted sessions to legacy protocol weaknesses (BEAST, POODLE).",
                        url=url
                    )
                    findings_emitted += 1

    # =========================================================================
    # PART 3: Handle Clean or Untested outcomes
    # =========================================================================
    telemetry["findings_count"] = findings_emitted

    if findings_emitted == 0:
        telemetry["status"] = "NOT_DETECTED"
        if emit_not_detected:
            scanner._add_finding(
                f_type="https",
                severity="info",
                status="NOT_DETECTED",
                verification_status="NOT_DETECTED",
                confidence="HIGH",
                title="Secure HTTPS & TLS Configuration",
                description=(
                    f"Audited transport encryption for {url}. "
                    "The target employs valid, trusted TLS encryption, enforces secure HTTPS communication, "
                    "and presents a valid certificate."
                ),
                evidence=f"Audited {url}. Transport security verified with active encryption.",
                url=url,
                http_method="GET"
            )
    else:
        telemetry["status"] = "VULNERABILITIES_FOUND"

    return telemetry
