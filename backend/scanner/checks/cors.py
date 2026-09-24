from scanner.engine import SecurityScanner
import httpx

async def check_cors(scanner: SecurityScanner, url: str, response: httpx.Response):
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")
    
    if acao == "*":
        scanner._add_finding(
            f_type="cors",
            severity="low",
            status="open",
            title="Overly Permissive CORS Configuration",
            description="The Access-Control-Allow-Origin header is set to the wildcard '*'.",
            evidence="Access-Control-Allow-Origin: *",
            impact="Any website can read responses from this endpoint if credentials are not required. If combined with Access-Control-Allow-Credentials: true (which is invalid in most modern browsers but still a misconfiguration sign), it could lead to sensitive data exposure.",
            remediation=["Specify exact trusted domains in the Access-Control-Allow-Origin header instead of using a wildcard."],
            owasp="A02:2025",
            url=url
        )
    elif acao and acao != "*":
        # Usually, if it reflects a random origin or 'null', it's bad. But for passive checking, 
        # we can just flag wildcard or generic misconfigurations.
        if acao == "null":
            scanner._add_finding(
                f_type="cors",
                severity="medium",
                status="open",
                title="CORS Origin set to 'null'",
                description="The Access-Control-Allow-Origin header is explicitly set to 'null'.",
                evidence="Access-Control-Allow-Origin: null",
                impact="An attacker can bypass origin checks using sandbox iframes.",
                remediation=["Do not use 'null' as a permitted origin."],
                owasp="A02:2025",
                url=url
            )
