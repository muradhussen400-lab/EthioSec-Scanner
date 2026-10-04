from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult

async def check_cors(scanner: SecurityScanner, url: str, client: SafeHTTPClient):
    try:
        baseline_resp = await client.get(url)
    except Exception:
        return
        
    if not baseline_resp:
        return

    test_case = TestCaseResult(
        category="cors",
        target_endpoint=url,
        http_method="GET",
        remediation=["Specify exact trusted domains in the Access-Control-Allow-Origin header instead of using a wildcard or 'null'."],
        owasp="A05:2021-Security Misconfiguration"
    )

    origins_to_test = ["https://attacker.com", "null"]
    
    for origin in origins_to_test:
        try:
            test_resp = await client.get(url, headers={"Origin": origin})
            if test_resp:
                headers = {k.lower(): v for k, v in test_resp.headers.items()}
                acao = headers.get("access-control-allow-origin")
                acac = headers.get("access-control-allow-credentials")

                if acao == "*":
                    test_case.add_observation("wildcard_origin", f"Access-Control-Allow-Origin: * (tested with Origin: {origin})", is_strong_evidence=True)
                    if acac == "true":
                        test_case.add_observation("credentials", "Access-Control-Allow-Credentials: true", is_strong_evidence=True)
                elif acao == origin:
                    test_case.add_observation("origin_reflected", f"Origin '{origin}' was blindly reflected in Access-Control-Allow-Origin.", is_strong_evidence=True)
                    if acac == "true":
                        test_case.add_observation("credentials", "Access-Control-Allow-Credentials: true", is_strong_evidence=True)
        except Exception:
            pass

    test_case.evaluate()
    if test_case.status == "HIGH":
        scanner._add_finding(
            f_type="cors",
            severity="medium" if "credentials" in test_case.evidence.lower() else "low",
            status=test_case.status,
            title="Insecure CORS Configuration",
            description="The application has an insecure Cross-Origin Resource Sharing (CORS) configuration.",
            evidence=test_case.evidence,
            impact="An attacker can read sensitive responses via cross-origin requests.",
            remediation=test_case.remediation,
            owasp=test_case.owasp,
            url=url
        )
