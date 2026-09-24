from scanner.engine import SecurityScanner
from urllib.parse import urlparse
import httpx

async def check_https(scanner: SecurityScanner, url: str, response: httpx.Response):
    parsed = urlparse(url)
    
    if parsed.scheme == "http":
        scanner._add_finding(
            f_type="https",
            severity="high",
            status="open",
            title="Unencrypted Communication (HTTP)",
            description="The application is communicating over plain HTTP.",
            evidence=f"URL uses HTTP scheme: {url}",
            impact="All data is transmitted in clear text and can be intercepted.",
            remediation=["Configure a TLS certificate and redirect all HTTP traffic to HTTPS."],
            owasp="A04:2025",
            url=url
        )
    elif parsed.scheme == "https":
        scanner._add_finding(
            f_type="https",
            severity="info",
            status="passed",
            title="Encrypted Communication (HTTPS)",
            description="The application uses HTTPS.",
            evidence=f"URL uses HTTPS scheme: {url}",
            owasp="A04:2025",
            url=url
        )
