from scanner.engine import SecurityScanner
import httpx

async def check_cookies(scanner: SecurityScanner, url: str, response: httpx.Response):
    cookies = response.headers.get_list("set-cookie")
    
    for cookie in cookies:
        cookie_lower = cookie.lower()
        cookie_name = cookie.split("=")[0] if "=" in cookie else "Unknown"
        missing_flags = []
        
        if "secure" not in cookie_lower:
            missing_flags.append("Secure")
        if "httponly" not in cookie_lower:
            missing_flags.append("HttpOnly")
        if "samesite" not in cookie_lower:
            missing_flags.append("SameSite")
            
        if missing_flags:
            scanner._add_finding(
                f_type="cookies",
                severity="medium" if "httponly" in missing_flags else "low",
                status="open",
                title=f"Cookie Missing Flags: {', '.join(missing_flags)}",
                description=f"The cookie '{cookie_name}' was set without the {', '.join(missing_flags)} attribute(s).",
                evidence=f"Cookie '{cookie_name}' is missing: {', '.join(missing_flags)}",
                impact="Cookies without Secure can be intercepted over HTTP. Cookies without HttpOnly can be accessed via XSS. Missing SameSite can lead to CSRF.",
                remediation=["Add the missing attributes to the Set-Cookie header."],
                owasp="A02:2025",
                url=url
            )
