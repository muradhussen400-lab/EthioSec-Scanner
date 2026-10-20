from scanner.engine import SecurityScanner
from scanner.test_case import TestCaseResult
import httpx

async def check_security_headers(scanner: SecurityScanner, url: str, response: httpx.Response):
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    def evaluate_and_add(test_case, title, desc, impact, remediation, is_applicable=True):
        if not is_applicable:
            return
            
        try:
            if test_case.status != "SCANNER_ERROR":
                test_case.evaluate()
        except Exception as e:
            test_case.status = "SCANNER_ERROR"
            test_case.evidence = f"Error evaluating header: {str(e)}"
            
        if test_case.status in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SCANNER_ERROR"]:
            scanner._add_finding(
                f_type="headers", severity=test_case.severity if test_case.status != "SCANNER_ERROR" else "info", status=test_case.status,
                title=title if test_case.status != "SCANNER_ERROR" else f"{title} (Error)",
                description=desc,
                evidence=test_case.evidence,
                impact=impact,
                remediation=remediation,
                owasp=test_case.owasp, url=url
            )

    # Content-Security-Policy
    test_case_csp = TestCaseResult(category="headers", target_endpoint=url, http_method="GET", owasp="A05:2021-Security Misconfiguration")
    try:
        if "content-security-policy" not in headers:
            # HTML responses need CSP. JSON APIs do not strictly need CSP for themselves if content-type is correct.
            content_type = headers.get("content-type", "")
            if "text/html" in content_type:
                test_case_csp.add_observation("missing_header", "No Content-Security-Policy header on HTML response.", is_strong_evidence=True)
                test_case_csp.severity = "medium"
            else:
                test_case_csp.add_observation("missing_header", "No CSP header, but response is not HTML.", is_suspicious=True)
                test_case_csp.severity = "low"
    except Exception as e:
        test_case_csp.status = "SCANNER_ERROR"
        test_case_csp.evidence = str(e)
    evaluate_and_add(test_case_csp, "Content-Security-Policy Not Set", "No Content-Security-Policy header was returned.", "Without CSP, an injected <script> tag runs with full page privileges.", ["Move to default-src 'self'."])
        
    # Strict-Transport-Security (HSTS)
    test_case_hsts = TestCaseResult(category="headers", target_endpoint=url, http_method="GET", owasp="A05:2021-Security Misconfiguration")
    try:
        if "strict-transport-security" not in headers:
            test_case_hsts.add_observation("missing_header", "Strict-Transport-Security header is absent.", is_strong_evidence=True)
            test_case_hsts.severity = "medium"
    except Exception as e:
        test_case_hsts.status = "SCANNER_ERROR"
        test_case_hsts.evidence = str(e)
    # HSTS is only applicable to HTTPS
    is_https = url.startswith("https")
    evaluate_and_add(test_case_hsts, "HSTS Not Set", "Strict-Transport-Security header is absent.", "Browsers may downgrade to HTTP.", ["Add Strict-Transport-Security: max-age=31536000."], is_applicable=is_https)
        
    # X-Content-Type-Options
    test_case_cto = TestCaseResult(category="headers", target_endpoint=url, http_method="GET", owasp="A05:2021-Security Misconfiguration")
    try:
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            test_case_cto.add_observation("missing_header", "Missing X-Content-Type-Options: nosniff", is_suspicious=True)
            test_case_cto.severity = "low"
    except Exception as e:
        test_case_cto.status = "SCANNER_ERROR"
        test_case_cto.evidence = str(e)
    evaluate_and_add(test_case_cto, "Missing X-Content-Type-Options", "The X-Content-Type-Options header is missing or not set to 'nosniff'.", "Browsers may perform MIME sniffing, leading to potential XSS.", ["Add X-Content-Type-Options: nosniff"])

    # Referrer-Policy
    test_case_rp = TestCaseResult(category="headers", target_endpoint=url, http_method="GET", owasp="A05:2021-Security Misconfiguration")
    try:
        if "referrer-policy" not in headers:
            test_case_rp.add_observation("missing_header", "Missing Referrer-Policy header", is_suspicious=True)
            test_case_rp.severity = "low"
    except Exception as e:
        test_case_rp.status = "SCANNER_ERROR"
        test_case_rp.evidence = str(e)
    evaluate_and_add(test_case_rp, "Referrer-Policy Not Set", "No Referrer-Policy header was found.", "Referer headers may leak sensitive information in the URL to third-party sites.", ["Add Referrer-Policy: strict-origin-when-cross-origin"])

    # Permissions-Policy
    test_case_pp = TestCaseResult(category="headers", target_endpoint=url, http_method="GET", owasp="A05:2021-Security Misconfiguration")
    try:
        if "permissions-policy" not in headers and "feature-policy" not in headers:
            test_case_pp.add_observation("missing_header", "Missing Permissions-Policy header", is_suspicious=True)
            test_case_pp.severity = "low"
    except Exception as e:
        test_case_pp.status = "SCANNER_ERROR"
        test_case_pp.evidence = str(e)
    evaluate_and_add(test_case_pp, "Permissions-Policy Not Set", "No Permissions-Policy header was found.", "The site does not restrict which browser features can be used.", ["Add Permissions-Policy to explicitly disable unused features."])
