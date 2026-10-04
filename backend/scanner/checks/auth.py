from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from urllib.parse import urlparse
from scanner.test_case import TestCaseResult
from scanner.differential import BaselineEngine

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
        
        is_auth_form = any(word in name.lower() for name in inputs for word in ["password", "pass", "pwd", "login"])
        
        if is_auth_form:
            test_case = TestCaseResult(
                category="auth",
                target_endpoint=action_url,
                http_method=form['method'],
                parameter=", ".join(inputs),
                remediation=["Ensure all authentication endpoints use HTTPS.", "Enforce HSTS."],
                owasp="A07:2021-Identification and Authentication Failures"
            )
            
            parsed = urlparse(action_url)
            if parsed.scheme == "http":
                test_case.add_observation("insecure_transport", f"Form submits credentials over insecure HTTP to {action_url}.", is_strong_evidence=True)
            else:
                test_case.add_observation("secure_transport", "Form submits credentials over HTTPS.")
            
            test_case.evaluate()
            
            if test_case.status == "HIGH":
                scanner._add_finding(
                    f_type="auth", severity="high", status=test_case.status,
                    title="Insecure Authentication Form",
                    description=f"An authentication form submits credentials over insecure HTTP to {action_url}.",
                    evidence=test_case.evidence,
                    impact="Attackers on the network can intercept user credentials.",
                    remediation=test_case.remediation,
                    owasp=test_case.owasp, url=form.get('page_url'), parameter=test_case.parameter,
                    http_method=form['method'], request=None, response_summary=None
                )
                
    # 2. Authentication Bypass / Broken Auth
    if auth_context:
        protected_hints = ["/api/me", "/profile", "/account", "/dashboard", "/settings", "/admin"]
        
        for ep in discovered_urls:
            if any(p in ep.lower() for p in protected_hints):
                test_case = TestCaseResult(
                    category="auth",
                    target_endpoint=ep,
                    http_method="GET",
                    remediation=["Ensure all protected resources verify a valid session or token before granting access."],
                    owasp="A07:2021-Identification and Authentication Failures"
                )
                
                try:
                    # Baseline with auth
                    resp_auth = await client.request("GET", ep, **auth_context)
                    
                    if resp_auth.status_code == 200:
                        test_case.add_observation("baseline", f"Authenticated request to {ep} returned HTTP 200.")
                        
                        # Test without auth
                        resp_no_auth = await client.request("GET", ep)
                        
                        diff = BaselineEngine.compare(resp_auth, resp_no_auth)
                        
                        if diff["test_status"] == 200 and diff["is_body_identical"]:
                            test_case.add_observation("bypass", f"Unauthenticated request to {ep} returned HTTP 200 with identical content to authenticated request.", is_strong_evidence=True)
                        elif diff["test_status"] == 200:
                            test_case.add_observation("bypass_partial", f"Unauthenticated request to {ep} returned HTTP 200, but content differed.", is_suspicious=True)
                        else:
                            test_case.add_observation("enforced", f"Unauthenticated request was rejected (HTTP {diff['test_status']}).")
                            
                        test_case.evaluate()
                        
                        if test_case.status in ["HIGH", "LOW", "SCANNER_ERROR"]:
                            scanner._add_finding(
                                f_type="auth", severity="high" if test_case.status == "HIGH" else "medium", status=test_case.status,
                                title="Authentication Bypass / Missing Authentication",
                                description=f"A potentially protected resource ({ep}) is accessible without authentication.",
                                evidence=test_case.evidence or "Scanner encountered an error.",
                                impact="Attackers can access protected features or data without logging in.",
                                remediation=test_case.remediation,
                                owasp=test_case.owasp, url=ep, parameter=None,
                                http_method="GET", request=None, response_summary=f"HTTP {diff.get('test_status', 'Error')}" if 'diff' in locals() else "Error"
                            )
                            if test_case.status == "HIGH":
                                break
                except Exception as e:
                    test_case.status = "SCANNER_ERROR"
                    test_case.evidence = f"Error during request: {str(e)}"
                    scanner._add_finding(
                        f_type="auth", severity="info", status="SCANNER_ERROR",
                        title="Authentication Check Failed",
                        description=f"Scanner encountered an error while testing {ep}.",
                        evidence=test_case.evidence,
                        impact="SCANNER_ERROR",
                        remediation=[],
                        owasp=test_case.owasp, url=ep, parameter=None,
                        http_method="GET", request=None, response_summary="Error"
                    )
    else:
        # If no auth_context, we can't test bypass reliably.
        scanner._add_finding(
            f_type="auth", severity="info", status="LOW",
            title="Authentication Check Low Confidence",
            description="No authentication context was provided to the scanner.",
            evidence="Cannot establish an authenticated baseline to compare against unauthenticated requests.",
            impact="SCANNER_ERROR",
            remediation=[],
            owasp="A07:2021-Identification and Authentication Failures", url="", parameter=None,
            http_method="GET", request=None, response_summary="N/A"
        )
