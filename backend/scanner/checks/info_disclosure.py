from scanner.engine import SecurityScanner
from scanner.test_case import TestCaseResult
import httpx

async def check_info_disclosure(scanner: SecurityScanner, url: str, response: httpx.Response):
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    test_case = TestCaseResult(category="info_disclosure", target_endpoint=url, http_method="GET", owasp="A05:2021-Security Misconfiguration")
    
    try:
        server_header = headers.get("server", "")
        if server_header:
            if any(char.isdigit() for char in server_header):
                test_case.add_observation("server_version", f"Server header reveals exact version: {server_header}", is_strong_evidence=True)
            else:
                test_case.add_observation("server_tech", f"Server header reveals technology: {server_header}", is_suspicious=True)
                
        x_powered_by = headers.get("x-powered-by", "")
        if x_powered_by:
            test_case.add_observation("x_powered_by", f"X-Powered-By: {x_powered_by}", is_suspicious=True)

        content = response.text
        stack_trace_indicators = [
            "at org.apache.catalina", 
            "Traceback (most recent call last):", 
            "Stack trace:", 
            "System.Web.HttpException", 
            "SQL syntax", 
            "mysql_fetch_array"
        ]
        
        path_indicators = ["/var/www/", "C:\\inetpub\\", "/home/user/"]
        
        for indicator in stack_trace_indicators:
            if indicator in content:
                test_case.add_observation("stack_trace", f"Found stack trace indicator: '{indicator}'", is_strong_evidence=True)
                break
                
        for indicator in path_indicators:
            if indicator in content:
                test_case.add_observation("internal_path", f"Found internal path indicator: '{indicator}'", is_strong_evidence=True)
                break
                
    except Exception as e:
        test_case.status = "SCANNER_ERROR"
        test_case.evidence = f"Error analyzing response: {str(e)}"
        
    if test_case.status != "SCANNER_ERROR":
        test_case.evaluate()
        
    if test_case.status in ["HIGH", "LOW", "SCANNER_ERROR"]:
        scanner._add_finding(
            f_type="info_disclosure", 
            severity="medium" if test_case.status == "HIGH" else "low", 
            status="MEDIUM" if test_case.status == "HIGH" else test_case.status,
            title="Information Disclosure",
            description="The application reveals potentially sensitive internal information.",
            evidence=test_case.evidence,
            impact="Assists attackers in profiling the technology stack and discovering internal paths.",
            remediation=["Configure the web server to hide version information.", "Disable debug mode."],
            owasp=test_case.owasp, url=url
        )
