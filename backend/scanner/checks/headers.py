from scanner.engine import SecurityScanner
import httpx

async def check_security_headers(scanner: SecurityScanner, url: str, response: httpx.Response):
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    # Content-Security-Policy
    if "content-security-policy" not in headers:
        scanner._add_finding(
            f_type="headers",
            severity="medium",
            status="open",
            title="Content-Security-Policy Not Set",
            description="No Content-Security-Policy header was returned by the server.",
            evidence="Missing CSP header",
            impact="Without CSP, an injected <script> tag runs with full page privileges.",
            remediation=["Start with Content-Security-Policy-Report-Only.", "Move to default-src 'self'."],
            owasp="A02:2025",
            url=url
        )
        
    # Strict-Transport-Security (HSTS)
    if url.startswith("https") and "strict-transport-security" not in headers:
        scanner._add_finding(
            f_type="headers",
            severity="medium",
            status="open",
            title="HSTS Not Set",
            description="Strict-Transport-Security header is absent.",
            evidence="Missing HSTS header",
            impact="Browsers may downgrade to HTTP, exposing traffic to interception.",
            remediation=["Add Strict-Transport-Security: max-age=31536000; includeSubDomains."],
            owasp="A02:2025",
            url=url
        )
        
    # X-Content-Type-Options
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        scanner._add_finding(
            f_type="headers",
            severity="low",
            status="open",
            title="Missing X-Content-Type-Options",
            description="The X-Content-Type-Options header is missing or not set to 'nosniff'.",
            evidence="Missing X-Content-Type-Options: nosniff",
            impact="Browsers may perform MIME sniffing, leading to potential XSS.",
            remediation=["Add X-Content-Type-Options: nosniff"],
            owasp="A02:2025",
            url=url
        )

    # Referrer-Policy
    if "referrer-policy" not in headers:
        scanner._add_finding(
            f_type="headers",
            severity="low",
            status="open",
            title="Referrer-Policy Not Set",
            description="No Referrer-Policy header was found.",
            evidence="Missing Referrer-Policy header",
            impact="Referer headers may leak sensitive information in the URL to third-party sites.",
            remediation=["Add Referrer-Policy: strict-origin-when-cross-origin"],
            owasp="A02:2025",
            url=url
        )

    # Permissions-Policy
    if "permissions-policy" not in headers and "feature-policy" not in headers:
        scanner._add_finding(
            f_type="headers",
            severity="low",
            status="open",
            title="Permissions-Policy Not Set",
            description="No Permissions-Policy header was found.",
            evidence="Missing Permissions-Policy header",
            impact="The site does not restrict which browser features can be used.",
            remediation=["Add Permissions-Policy to explicitly disable unused features."],
            owasp="A02:2025",
            url=url
        )
