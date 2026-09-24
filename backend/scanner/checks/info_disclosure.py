from scanner.engine import SecurityScanner
import httpx
import re

async def check_info_disclosure(scanner: SecurityScanner, url: str, response: httpx.Response):
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    # Server Banner
    server_header = headers.get("server", "")
    if server_header and any(char.isdigit() for char in server_header):
        scanner._add_finding(
            f_type="info_disclosure",
            severity="low",
            status="open",
            title="Server Version Disclosed",
            description="The Server header reveals the exact software version in use.",
            evidence=f"Server: {server_header}",
            impact="Attackers can use this information to look up published exploits for this specific version.",
            remediation=["Configure the web server to hide version information."],
            owasp="A02:2025",
            url=url
        )
        
    # X-Powered-By
    x_powered_by = headers.get("x-powered-by", "")
    if x_powered_by:
        scanner._add_finding(
            f_type="info_disclosure",
            severity="low",
            status="open",
            title="X-Powered-By Header Disclosed",
            description="The application reveals its underlying framework via the X-Powered-By header.",
            evidence=f"X-Powered-By: {x_powered_by}",
            impact="Assists attackers in profiling the technology stack.",
            remediation=["Remove the X-Powered-By header from server responses."],
            owasp="A02:2025",
            url=url
        )

    # Check for stack traces and paths in the body
    content = response.text
    stack_trace_indicators = [
        "at org.apache.catalina", 
        "Traceback (most recent call last):", 
        "Stack trace:", 
        "System.Web.HttpException", 
        "SQL syntax", 
        "mysql_fetch_array"
    ]
    
    for indicator in stack_trace_indicators:
        if indicator in content:
            scanner._add_finding(
                f_type="info_disclosure",
                severity="medium",
                status="open",
                title="Stack Trace / Error Message Disclosed",
                description="The application returned verbose error messages or a stack trace.",
                evidence=f"Found indicator: '{indicator}' in response.",
                impact="Disclosing internal errors provides attackers with details on the backend structure and potentially sensitive information.",
                remediation=["Implement a generic error page.", "Disable debug mode."],
                owasp="A02:2025",
                url=url
            )
            break # one finding is enough for this URL
