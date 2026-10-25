from scanner.engine import SecurityScanner
from scanner.test_case import TestCaseResult
import httpx

async def check_cookies(scanner: SecurityScanner, url: str, response: httpx.Response):
    try:
        cookies = response.headers.get_list("set-cookie")
    except Exception:
        cookies = []
        
    if not cookies:
        return
        
    for cookie in cookies:
        try:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0] if "=" in cookie else "SCANNER_ERROR"
            missing_flags = []
            
            test_case = TestCaseResult(
                category="cookies",
                target_endpoint=url,
                http_method=response.request.method if hasattr(response, 'request') else "GET",
                parameter=f"Cookie: {cookie_name}",
                baseline_response={"set-cookie": cookie},
                remediation=["Add the missing attributes to the Set-Cookie header.", "Set HttpOnly to true to prevent XSS access.", "Set Secure to true to prevent transmission over unencrypted connections."],
                owasp="A05:2021-Security Misconfiguration"
            )
            
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")
                
            is_session = any(s in cookie_lower for s in ["session", "token", "auth"])
                
            if missing_flags:
                if is_session:
                    test_case.add_observation("session_cookie_flags", f"Session cookie '{cookie_name}' was set without the following attributes: {', '.join(missing_flags)}.", is_strong_evidence=True)
                    test_case.severity = "high"
                else:
                    test_case.add_observation("cookie_flags", f"Cookie '{cookie_name}' was set without the following attributes: {', '.join(missing_flags)}.", is_suspicious=True)
                    test_case.severity = "low"
                    
            test_case.evaluate()
        except Exception as e:
            test_case.status = "SCANNER_ERROR"
            test_case.evidence = f"Error evaluating cookie: {str(e)}"
            
        if test_case.status in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SCANNER_ERROR"]:
            scanner._add_finding(
                f_type="cookies",
                severity=test_case.severity if test_case.status != "SCANNER_ERROR" else "info",
                status=test_case.status,
                title=f"Cookie Missing Flags: {', '.join(missing_flags)}" if test_case.status != "SCANNER_ERROR" else "Cookie Check Failed",
                description=f"The cookie '{cookie_name}' was set without the {', '.join(missing_flags)} attribute(s).",
                evidence=test_case.evidence,
                impact="Cookies without Secure can be intercepted over HTTP. Cookies without HttpOnly can be accessed via XSS. Missing SameSite can lead to CSRF.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                url=url
            )
