from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient

async def check_http_methods(scanner: SecurityScanner, url: str, client: SafeHTTPClient):
    try:
        response = await client.options(url)
        methods = response.headers.get("allow", "").upper()
        
        if not methods:
            # Sometimes servers return methods in Access-Control-Allow-Methods
            methods = response.headers.get("access-control-allow-methods", "").upper()

        if methods:
            dangerous_methods = []
            for m in ["PUT", "DELETE", "TRACE", "TRACK", "CONNECT"]:
                if m in methods:
                    dangerous_methods.append(m)
                    
            if dangerous_methods:
                scanner._add_finding(
                    f_type="http_methods",
                    severity="low",
                    status="open",
                    title="Dangerous HTTP Methods Enabled",
                    description=f"The server allows potentially dangerous HTTP methods: {', '.join(dangerous_methods)}",
                    evidence=f"Allow or Access-Control-Allow-Methods header contains: {methods}",
                    impact="Depending on configuration, attackers may modify files (PUT/DELETE) or bypass HttpOnly (TRACE).",
                    remediation=["Disable unused or dangerous HTTP methods on the web server."],
                    owasp="A02:2025",
                    url=url
                )
    except Exception:
        pass
