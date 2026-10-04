from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult

async def check_http_methods(scanner: SecurityScanner, url: str, client: SafeHTTPClient):
    test_case = TestCaseResult(
        category="http_methods",
        target_endpoint=url,
        http_method="OPTIONS",
        remediation=["Disable unused or dangerous HTTP methods on the web server."],
        owasp="A05:2021-Security Misconfiguration"
    )

    try:
        response = await client.options(url)
        if response:
            methods = response.headers.get("allow", "").upper()
            
            if not methods:
                methods = response.headers.get("access-control-allow-methods", "").upper()

            if methods:
                test_case.add_observation("methods_discovered", f"Discovered methods: {methods}")
                
                dangerous_methods = []
                for m in ["PUT", "DELETE", "TRACE", "TRACK", "CONNECT"]:
                    if m in methods:
                        dangerous_methods.append(m)
                        
                if dangerous_methods:
                    test_case.add_observation("dangerous_methods", f"Potentially dangerous HTTP methods enabled: {', '.join(dangerous_methods)}", is_suspicious=True)
                    
                    # To verify impact, we'd theoretically send a PUT or TRACE. For safety, we just mark as inconclusive unless we can prove impact.
                    # TRACE could be proven by sending TRACE and seeing reflection.
                    if "TRACE" in dangerous_methods:
                        try:
                            trace_resp = await client.request("TRACE", url)
                            if trace_resp and "TRACE" in trace_resp.text:
                                test_case.add_observation("trace_verified", "TRACE method successfully reflected the request.", is_strong_evidence=True)
                        except Exception:
                            pass
                            
                else:
                    test_case.add_observation("safe_methods", "Only safe methods (e.g. GET, POST, HEAD, OPTIONS) are allowed.", is_suspicious=False)
                    
    except Exception as e:
        test_case.status = "SCANNER_ERROR"
        test_case.evidence = f"Error during OPTIONS request: {str(e)}"
        
    if test_case.status != "SCANNER_ERROR":
        test_case.evaluate()
        
    if test_case.status in ["HIGH", "LOW", "SCANNER_ERROR"]:
        scanner._add_finding(
            f_type="http_methods",
            severity="low" if test_case.status != "SCANNER_ERROR" else "info",
            status=test_case.status,
            title="Dangerous HTTP Methods Enabled" if test_case.status != "SCANNER_ERROR" else "HTTP Methods Check Failed",
            description="The server allows potentially dangerous HTTP methods.",
            evidence=test_case.evidence,
            impact="Depending on configuration, attackers may modify files (PUT/DELETE) or bypass HttpOnly (TRACE).",
            remediation=test_case.remediation,
            owasp=test_case.owasp,
            url=url
        )
