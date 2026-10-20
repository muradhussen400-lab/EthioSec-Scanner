from scanner.engine import SecurityScanner
from urllib.parse import urlparse
from scanner.test_case import TestCaseResult
import httpx

async def check_https(scanner: SecurityScanner, url: str, response: httpx.Response):
    parsed = urlparse(url)
    
    test_case = TestCaseResult(
        category="https",
        target_endpoint=url,
        http_method="GET",
        remediation=["Configure a TLS certificate and redirect all HTTP traffic to HTTPS."],
        owasp="A02:2021-Cryptographic Failures"
    )
    
    try:
        if parsed.scheme == "http":
            test_case.add_observation("unencrypted_scheme", f"URL uses HTTP scheme: {url}", is_strong_evidence=True)
            # A real redirect check could happen here (i.e. does it redirect to HTTPS?)
            if response.status_code in [301, 302, 307, 308] and "https://" in response.headers.get("location", ""):
                test_case.add_observation("redirects_to_https", "HTTP endpoint redirects to HTTPS.", is_strong_evidence=False)
                # Not a vulnerability if it correctly redirects immediately
                test_case.status = "NOT_DETECTED"
            else:
                test_case.severity = "high"
                test_case.evaluate()
        elif parsed.scheme == "https":
            test_case.add_observation("encrypted_scheme", f"URL uses HTTPS scheme: {url}")
            test_case.status = "NOT_DETECTED"
    except Exception as e:
        test_case.status = "SCANNER_ERROR"
        test_case.evidence = f"Error during HTTPS check: {str(e)}"
        
    if test_case.status in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SCANNER_ERROR"]:
        scanner._add_finding(
            f_type="https",
            severity="high" if test_case.status != "SCANNER_ERROR" else "info",
            status=test_case.status,
            title="Unencrypted Communication (HTTP)" if test_case.status != "SCANNER_ERROR" else "HTTPS Check Failed",
            description="The application is communicating over plain HTTP.",
            evidence=test_case.evidence,
            impact="All data is transmitted in clear text and can be intercepted.",
            remediation=test_case.remediation,
            owasp=test_case.owasp,
            url=url
        )
