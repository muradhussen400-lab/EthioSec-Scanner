from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from urllib.parse import urlparse

async def check_auth(
    scanner: SecurityScanner, 
    discovered_urls: list, 
    discovered_forms: list, 
    client: SafeHTTPClient,
    auth_context: dict = None
):
    # 1. Login Transport Security
    for form in discovered_forms:
        inputs = form["inputs"]
        action_url = form["action_url"]
        
        # We assume if the name contains 'password', 'pass', 'pwd', it's an auth form
        is_auth_form = any(word in name.lower() for name in inputs for word in ["password", "pass", "pwd", "login"])
        
        if is_auth_form:
            parsed = urlparse(action_url)
            if parsed.scheme == "http":
                scanner._add_finding(
                    f_type="auth", severity="high", status="open",
                    title="Insecure Authentication Form",
                    description=f"An authentication form at {form['page_url']} submits credentials over insecure HTTP to {action_url}.",
                    evidence=f"Form action: {action_url}\nInputs: {', '.join(inputs)}",
                    impact="Attackers on the network can intercept user credentials.",
                    remediation=["Ensure all authentication endpoints use HTTPS.", "Enforce HSTS."],
                    owasp="A07:2025", url=form['page_url'], parameter=", ".join(inputs),
                    http_method=form['method'], request=None, response_summary=None
                )
                
    # 2. Session Security (If Auth Context provided)
    if not auth_context:
        scanner._add_finding(
            f_type="session", severity="info", status="not_tested",
            title="Session Security Tests: Not Tested",
            description="Session security and authorization endpoints could not be tested because no authentication context was provided.",
            evidence="Missing auth_context in scan configuration.",
            impact="Unknown.",
            remediation=[],
            owasp="A07:2025", url=None, parameter=None,
            http_method=None, request=None, response_summary=None
        )
        return
        
    # Test session cookie flags from the auth context if it relies on cookies
    cookies = auth_context.get("cookies", {})
    if cookies:
        # We can't definitively check Secure/HttpOnly if we just get raw cookie strings, 
        # but if we get them via headers or we fetch an authenticated endpoint, we can observe the Set-Cookie behavior
        # For this prototype, we'll just check if the auth_context successfully authenticates to a basic endpoint
        
        # Example check: Verify if the token allows access to common protected endpoints
        protected_endpoints = ["/api/me", "/profile", "/account", "/dashboard"]
        for ep in discovered_urls:
            if any(p in ep.lower() for p in protected_endpoints):
                try:
                    resp = await client.request("GET", ep, **auth_context)
                    if resp.status_code == 200:
                        scanner._add_finding(
                            f_type="session", severity="info", status="passed",
                            title="Authentication Context Valid",
                            description="The provided authentication context successfully accessed a protected endpoint.",
                            evidence=f"GET {ep} returned HTTP 200 with the provided context.",
                            owasp="A07:2025", url=ep, parameter=None,
                            http_method="GET", request=None, response_summary="HTTP 200"
                        )
                        break
                except Exception:
                    pass
