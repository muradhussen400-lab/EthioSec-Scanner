from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from urllib.parse import urlparse, urlencode, urlunparse
import random
import string

async def check_xss(scanner: SecurityScanner, endpoints: list, forms: list, client: SafeHTTPClient):
    
    async def test_parameter(url: str, method: str, params: dict, param_to_inject: str, source: str):
        marker = "ethioxss_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        # Payload designed to test if < and " are encoded
        payload = f'"><{marker}'
        
        test_params = params.copy()
        test_params[param_to_inject] = payload
        
        try:
            if method == "GET":
                test_query = urlencode(test_params)
                parsed = urlparse(url)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
                response = await client.get(test_url)
            else:
                response = await client.post(url, data=test_params)
                test_url = url
                
            if response.status_code == 200:
                content = response.text
                if marker in content:
                    # Check if the exact payload is reflected unmodified (meaning < and " were not encoded)
                    if payload in content:
                        scanner._add_finding(
                            f_type="xss", 
                            severity="high", 
                            status="open",
                            title=f"Potential Reflected XSS via {source.capitalize()} Parameter '{param_to_inject}'",
                            description=f"The parameter '{param_to_inject}' reflects unencoded input into the response.",
                            evidence=f"Injected payload: '{payload}'.\nPayload was found unmodified in the response, indicating lack of HTML entity encoding.",
                            impact="Attackers could execute arbitrary JavaScript in the victim's browser.",
                            remediation=["Use context-aware output encoding (e.g., HTML entity encoding) before reflecting user input."],
                            owasp="A05:2025", 
                            url=url, 
                            parameter=param_to_inject,
                            http_method=method, 
                            request=str(test_params), 
                            response_summary=f"HTTP 200 OK"
                        )
                        return
                    # Optionally, we could check if it's encoded and report as safe/info, but that's noisy.
        except Exception:
            pass

    # Test Endpoints (Query Params)
    for endpoint in endpoints:
        url = endpoint["url"]
        method = endpoint["method"]
        params_list = endpoint["params"]
        
        baseline_params = {p: "test" for p in params_list}
        for param in params_list:
            await test_parameter(url, method, baseline_params, param, "URL query")

    # Test Forms
    for form in forms:
        action_url = form["action_url"]
        method = form["method"]
        inputs = form["inputs"]
        
        baseline_params = {name: "test" for name in inputs}
        for param in inputs:
            await test_parameter(action_url, method, baseline_params, param, "form")
