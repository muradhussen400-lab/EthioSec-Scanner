from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from scanner.test_case import TestCaseResult
from scanner.differential import BaselineEngine, BaselineProfile
import asyncio

async def check_sqli(scanner: SecurityScanner, endpoints: list, forms: list, client: SafeHTTPClient, depth: str = "standard"):
    
    # Common DB error patterns
    db_errors = {
        "MySQL": ["sql syntax", "mysql_fetch_array", "mysql_fetch_assoc", "you have an error in your sql syntax"],
        "PostgreSQL": ["syntax error at or near", "postgresql query failed", "unterminated quoted string"],
        "Microsoft SQL Server": ["unclosed quotation mark", "microsoft ole db provider for sql server", "incorrect syntax near"],
        "Oracle": ["ora-01756", "quoted string not properly terminated", "ora-00933"],
        "SQLite": ["sqlite3.operationalerror", "unrecognized token", "near \""]
    }
    
    # Test dictionaries
    syntax_payloads = ["'", "\"", "';", "';--"]
    boolean_payloads_true = ["' OR '1'='1", "' OR 1=1--", "1 OR 1=1"]
    boolean_payloads_false = ["' OR '1'='2", "' OR 1=2--", "1 OR 1=2"]
    
    if depth == "deep":
        syntax_payloads.extend(["\\'\"", "') OR ('a'='a", "\") OR (\"a\"=\"a"])
        boolean_payloads_true.extend(["' OR 'a'='a", "1=1"])
        boolean_payloads_false.extend(["' OR 'a'='b", "1=2"])

    async def _make_request(url: str, method: str, params: dict):
        try:
            if method == "GET":
                query = urlencode(params)
                parsed = urlparse(url)
                full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
                return await client.get(full_url)
            else:
                return await client.post(url, data=params)
        except Exception:
            return None

    def _check_db_errors(text: str):
        text = text.lower()
        for db_name, error_list in db_errors.items():
            for err in error_list:
                if err in text:
                    return db_name, err
        return None, None

    async def test_parameter(url: str, method: str, params: dict, param_to_inject: str, source: str):
        # 1. Parameter profiling & Baseline establishment
        baseline_requests_count = 3 if depth == "deep" else 2
        
        baseline_responses = []
        for _ in range(baseline_requests_count):
            resp = await _make_request(url, method, params)
            if resp:
                baseline_responses.append(resp)
        
        if not baseline_responses:
            return
            
        profile = BaselineProfile(baseline_responses)
        
        baseline_has_db_errors = False
        for b_resp in profile.requests:
            db_name, err = _check_db_errors(b_resp.text)
            if db_name:
                baseline_has_db_errors = True
                break
                
        test_case = TestCaseResult(
            category="sqli",
            target_endpoint=url,
            http_method=method,
            parameter=param_to_inject,
            baseline_request=params,
            remediation=["Use parameterized queries or prepared statements.", "Sanitize and validate input."],
            owasp="A03:2021-Injection"
        )
        test_case.add_observation("baseline", f"Baseline established ({len(profile.requests)} requests). HTTP {profile.baseline_status}. Stable: {profile.is_stable}")
        
        if baseline_has_db_errors:
            test_case.add_observation("baseline_error", "Baseline requests inherently contain database error signatures.", is_suspicious=False)

        detected_db = None
        vulnerable = False
        evidence_payload = None
        evidence_params = None

        # Helper for repeated validation
        async def _validate_payload(payload: str, expected_type: str, compare_against: str = None) -> bool:
            # Re-run the request to see if the behavior persists
            v_test_params = params.copy()
            v_test_params[param_to_inject] = str(v_test_params[param_to_inject] or "") + payload
            v_resp = await _make_request(url, method, v_test_params)
            if not v_resp: return False
            
            if expected_type == "db_error":
                v_db, _ = _check_db_errors(v_resp.text)
                return v_db is not None
            elif expected_type == "boolean_true":
                v_diff = profile.compare_test(v_resp)
                return v_diff["is_body_similar"]
            elif expected_type == "boolean_false":
                v_diff = profile.compare_test(v_resp)
                return not v_diff["is_body_similar"]
            return False

        # 2. Syntax testing (Error-based)
        for payload in syntax_payloads:
            test_params = params.copy()
            test_params[param_to_inject] = str(test_params[param_to_inject] or "") + payload
            
            test_resp = await _make_request(url, method, test_params)
            if not test_resp:
                continue

            diff = profile.compare_test(test_resp)
            
            if diff["test_status"] == 500 and profile.baseline_status == 200:
                test_case.add_observation("behavior", f"Payload '{payload}' caused a 500 Internal Server Error (baseline was 200).", is_suspicious=False)

            if not baseline_has_db_errors:
                db_name, err = _check_db_errors(test_resp.text)
                if db_name:
                    # Control Test: Validate reproducibility
                    is_reproducible = await _validate_payload(payload, "db_error")
                    if is_reproducible:
                        test_case.add_observation("database_error", f"Payload '{payload}' reproducibly revealed {db_name} error signature: '{err}'", is_strong_evidence=True)
                        detected_db = db_name
                        vulnerable = True
                        evidence_payload = payload
                        evidence_params = test_params
                    else:
                        test_case.add_observation("database_error_unstable", f"Payload '{payload}' showed {db_name} error, but was not reproducible.", is_suspicious=True)
                        
            if vulnerable: break
            
        # 3. Boolean differential testing
        if not vulnerable:
            if not profile.is_stable:
                test_case.add_observation("baseline_unstable", "Endpoint baseline is inherently unstable. Skipping boolean differential testing to avoid false positives.", is_suspicious=False)
            else:
                for pt, pf in zip(boolean_payloads_true, boolean_payloads_false):
                    params_true = params.copy()
                    params_true[param_to_inject] = str(params_true[param_to_inject] or "") + pt
                    resp_true = await _make_request(url, method, params_true)
                    
                    params_false = params.copy()
                    params_false[param_to_inject] = str(params_false[param_to_inject] or "") + pf
                    resp_false = await _make_request(url, method, params_false)
                    
                    if resp_true and resp_false:
                        diff_true = profile.compare_test(resp_true)
                        diff_t_f = BaselineEngine.compare(resp_true, resp_false)
                        diff_false = profile.compare_test(resp_false)
                        
                        if diff_true["is_body_similar"] and not diff_t_f["is_body_similar"] and not diff_false["is_body_similar"]:
                            # We have a candidate, now Control Test it
                            val_true = await _validate_payload(pt, "boolean_true")
                            val_false = await _validate_payload(pf, "boolean_false")
                            
                            if val_true and val_false:
                                test_case.add_observation("boolean", f"Stable boolean diff: True payload '{pt}' matches baseline, False payload '{pf}' alters response reproducibly.", is_strong_evidence=True)
                                vulnerable = True
                                evidence_payload = pt
                                evidence_params = params_true
                            else:
                                test_case.add_observation("boolean_unstable", f"Unstable boolean differential detected for '{pt}' / '{pf}'.", is_suspicious=True)
                            
                            break

        test_case.evaluate()
        
        # Determine status and add finding
        if test_case.status in ["HIGH", "LOW"]:
            desc = f"The parameter '{param_to_inject}' exhibited behavior indicating possible SQL injection."
            if detected_db:
                desc += f" Evidence suggests the backend database is {detected_db}."
                
            final_status = "HIGH" if test_case.status == "HIGH" else "LOW"
            final_severity = "high" if test_case.status == "HIGH" else "low"

            scanner._add_finding(
                f_type="sqli", 
                severity=final_severity, 
                status=final_status,
                title=f"SQL Injection via {source.capitalize()} Parameter '{param_to_inject}'",
                description=desc,
                evidence=test_case.evidence,
                impact="Attackers could read or modify database contents.",
                remediation=test_case.remediation,
                owasp=test_case.owasp, 
                url=url, 
                parameter=param_to_inject,
                http_method=method, 
                request=str(evidence_params) if evidence_params else None, 
                response_summary=f"Evaluated via differential testing pipeline"
            )

    for endpoint in endpoints:
        url = endpoint["url"]
        method = endpoint["method"]
        params_list = endpoint["params"]
        # Basic mock value for baseline
        baseline_params = {p: "test" for p in params_list}
        for param in params_list:
            await test_parameter(url, method, baseline_params, param, "URL query")

    for form in forms:
        action_url = form["action_url"]
        method = form["method"]
        inputs = form["inputs"]
        baseline_params = {name: "test" for name in inputs}
        for param in inputs:
            await test_parameter(action_url, method, baseline_params, param, "form")
