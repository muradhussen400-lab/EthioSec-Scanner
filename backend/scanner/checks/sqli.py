from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

async def check_sqli(scanner: SecurityScanner, endpoints: list, forms: list, client: SafeHTTPClient):
    payloads = ["'", "\"", "' OR '1'='1", "';--", "1' OR '1'='1", "') OR ('1'='1"]
    
    # Common DB error patterns
    db_errors = {
        "MySQL": ["sql syntax", "mysql_fetch_array", "mysql_fetch_assoc"],
        "PostgreSQL": ["syntax error at or near", "postgresql query failed"],
        "Microsoft SQL Server": ["unclosed quotation mark", "microsoft ole db provider for sql server"],
        "Oracle": ["ora-01756", "quoted string not properly terminated"],
        "SQLite": ["sqlite3.operationalerror", "unrecognized token"]
    }
    all_error_strings = [err for errors in db_errors.values() for err in errors]

    async def test_parameter(url: str, method: str, params: dict, param_to_inject: str, source: str):
        # 1. Baseline Request
        baseline_resp = None
        try:
            if method == "GET":
                baseline_query = urlencode(params)
                parsed = urlparse(url)
                baseline_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, baseline_query, parsed.fragment))
                baseline_resp = await client.get(baseline_url)
            else:
                baseline_resp = await client.post(url, data=params)
        except Exception:
            return
            
        if not baseline_resp:
            return

        baseline_text = baseline_resp.text.lower()
        baseline_status = baseline_resp.status_code
        baseline_length = len(baseline_resp.text)
        
        # Determine if the baseline already has DB errors (if so, we can't reliably use errors as a diff)
        baseline_has_error = any(err in baseline_text for err in all_error_strings)

        for payload in payloads:
            test_params = params.copy()
            test_params[param_to_inject] = (test_params[param_to_inject] or "") + payload
            
            try:
                if method == "GET":
                    test_query = urlencode(test_params)
                    parsed = urlparse(url)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
                    test_resp = await client.get(test_url)
                else:
                    test_resp = await client.post(url, data=test_params)
                    test_url = url
            except Exception:
                continue

            test_text = test_resp.text.lower()
            test_status = test_resp.status_code
            
            # Check for new SQL errors not present in baseline
            found_error = None
            detected_db = None
            if not baseline_has_error:
                for db_name, error_list in db_errors.items():
                    for err in error_list:
                        if err in test_text:
                            found_error = err
                            detected_db = db_name
                            break
                    if found_error:
                        break
                        
            # Check for significant behavioral changes (e.g. 500 when baseline was 200)
            behavior_change = ""
            if test_status == 500 and baseline_status == 200:
                behavior_change = f"Status code changed from 200 to 500."

            if found_error or behavior_change:
                evidence = f"Baseline request returned HTTP {baseline_status}.\n"
                evidence += f"Payload '{payload}' returned HTTP {test_status}.\n"
                if found_error:
                    evidence += f"New database error signature detected: '{found_error}'."
                elif behavior_change:
                    evidence += behavior_change
                    
                desc = f"The parameter '{param_to_inject}' appears to be vulnerable to SQL injection."
                if detected_db:
                    desc += f" Evidence suggests the backend database is {detected_db}."
                    
                scanner._add_finding(
                    f_type="sqli", 
                    severity="high", 
                    status="open",
                    title=f"SQL Injection via {source.capitalize()} Parameter '{param_to_inject}'",
                    description=desc,
                    evidence=evidence,
                    impact="Attackers could read or modify database contents.",
                    remediation=["Use parameterized queries or prepared statements.", "Sanitize and validate input."],
                    owasp="A05:2025", 
                    url=url, 
                    parameter=param_to_inject,
                    http_method=method, 
                    request=str(test_params), 
                    response_summary=f"HTTP {test_status}"
                )
                return # Move to next parameter once found to avoid flooding

    # Test Endpoints (Query Params)
    for endpoint in endpoints:
        url = endpoint["url"]
        method = endpoint["method"]
        params_list = endpoint["params"]
        
        # Build baseline params
        # In a real scenario, we might need valid values. For now we use "test" if empty.
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
