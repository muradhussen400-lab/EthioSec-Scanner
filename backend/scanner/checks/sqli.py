import asyncio
import datetime
import logging
import time
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from scanner.engine import SecurityScanner

from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult
from scanner.differential import BaselineEngine, BaselineProfile

logger = logging.getLogger("ethiosec.scanner.sqli")

# Curated, high-fidelity DBMS error signatures mapped to specific engines
DB_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax",
        "sql syntax error",
        "check the manual that corresponds to your mysql server version",
        "check the manual that corresponds to your mariadb server version",
        "mysql_fetch_array",
        "mysql_fetch_assoc",
        "mysql_num_rows",
        "my_print_error",
        "valid mysql result",
    ],
    "PostgreSQL": [
        "syntax error at or near",
        "postgresql query failed",
        "unterminated quoted string",
        "pg_query()",
        "pg_exec()",
        "psycopg2.errors.syntaxerror",
        "pg_catalog.",
    ],
    "Microsoft SQL Server": [
        "unclosed quotation mark after the character string",
        "microsoft ole db provider for sql server",
        "incorrect syntax near",
        "procedure expects parameter",
        "driver][sql server]",
        "native client][sql server]",
    ],
    "Oracle": [
        "ora-01756: quoted string not properly terminated",
        "ora-00933: sql command not properly ended",
        "ora-00936: missing expression",
        "ora-00904:",
        "oracle error",
    ],
    "SQLite": [
        "sqlite3.operationalerror",
        "unrecognized token",
        "near \"",
        "near '",
        "incomplete input",
    ]
}

def check_db_errors(text: str, injected_value: str = None) -> tuple:
    """
    Scans text for authentic database engine error signatures.
    Rejects reflected payload text to avoid false positives on echo endpoints.
    """
    if not text:
        return None, None
    text_lower = text.lower()
    injected_lower = injected_value.lower() if injected_value else ""
    
    for db_name, error_list in DB_ERRORS.items():
        for err in error_list:
            if err in text_lower:
                # If the injected string itself contains the error phrase, it is an echo/reflection
                if injected_lower and err in injected_lower:
                    continue
                return db_name, err
    return None, None

def get_response_duration(resp) -> float:
    """
    Safely retrieves the request duration in seconds from an HTTP response,
    guaranteeing no RuntimeError is raised if .elapsed was not initialized on an unread response.
    """
    if resp is None:
        return 0.0
    if hasattr(resp, "duration"):
        try:
            return float(resp.duration)
        except Exception:
            pass
    try:
        if hasattr(resp, "_elapsed") and resp._elapsed is not None:
            return resp._elapsed.total_seconds()
    except Exception:
        pass
    try:
        el = getattr(resp, "elapsed", None)
        if el is not None:
            return el.total_seconds()
    except (RuntimeError, Exception):
        pass
    return 0.0

class SQLiCoverageRecord:
    """
    Transparent execution and attack surface coverage record for SQL injection testing.
    Ensures report integrity by explicitly recording candidate inputs, tests performed,
    techniques evaluated, and baseline stability rather than relying on finding counts alone.
    """
    def __init__(self):
        self.candidate_inputs_discovered: int = 0
        self.inputs_tested: int = 0
        self.requests_completed: int = 0
        self.techniques_attempted: List[str] = []
        self.techniques_completed: List[str] = []
        self.baseline_stability: str = "not_evaluated"  # "stable", "unstable", "rate_limited", "not_evaluated"
        self.verification_completed: bool = False
        self.blocking_reason: Optional[str] = None
        self.scanner_error: Optional[str] = None
        self.inconclusive_reasons: List[str] = []
        self.tested_parameters: List[str] = []
        self.findings_added: int = 0

async def check_sqli(scanner: "SecurityScanner", endpoints: list, forms: list, client: SafeHTTPClient, depth: str = "standard") -> SQLiCoverageRecord:
    """
    Professional, evidence-driven SQL injection detection pipeline.
    Executes baseline profiling, error-based testing, paired-control boolean differential
    analysis, and bounded timing verification.
    """
    depth = (depth or "standard").lower()
    coverage = SQLiCoverageRecord()
    
    # 1. Probe dictionaries
    syntax_payloads = ["'", "\"", "';", "';-- ", "';--"]
    
    # Paired logical controls (True condition vs False condition)
    boolean_pairs = [
        # Pair 1: Single-quote string with universal comment
        ("' OR 1=1-- ", "' OR 1=2-- "),
        # Pair 2: Single-quote string condition without comment
        ("' OR '1'='1", "' OR '1'='2"),
        # Pair 3: Numeric context condition
        ("1 OR 1=1", "1 OR 1=2"),
    ]
    
    # Time-based blind probes (bounded to 3s delay)
    timing_probes = [
        ("PostgreSQL", "'; SELECT pg_sleep(3)-- "),
        ("MySQL", "' OR SLEEP(3)-- "),
        ("MSSQL", "'; WAITFOR DELAY '0:0:3'-- "),
        ("SQLite", "' OR LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(40000000/2))))-- "),
    ]
    
    if depth == "deep":
        syntax_payloads.extend(["\\'\"", "') OR ('a'='a", "\") OR (\"a\"=\"a", "')-- "])
        boolean_pairs.extend([
            ("') OR ('1'='1", "') OR ('1'='2"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("' OR 'a'='a", "' OR 'a'='b"),
        ])

    def _extract_csrf_from_html(html_text: str, field_name: str) -> Optional[str]:
        if not html_text:
            return None
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            tag = soup.find(["input", "textarea"], attrs={"name": field_name})
            if tag and tag.get("value"):
                return tag["value"]
        except Exception:
            pass
        return None

    async def _fetch_csrf_token(page_url: str, field_name: str) -> Optional[str]:
        try:
            get_resp = await client.get(page_url)
            if get_resp and get_resp.text:
                return _extract_csrf_from_html(get_resp.text, field_name)
        except Exception:
            pass
        return None

    def _is_scan_cancelled() -> bool:
        if scanner:
            if getattr(scanner, "cancelled", False) or getattr(scanner, "is_cancelled", False):
                return True
        if scanner and hasattr(scanner, "db") and scanner.db and hasattr(scanner, "scan_id"):
            try:
                from models import Scan
                s_rec = scanner.db.query(Scan).filter(Scan.id == scanner.scan_id).first()
                if s_rec and s_rec.status == "cancelled":
                    return True
            except Exception:
                pass
        return False

    async def _make_request(url: str, method: str, params: dict, page_url: str = None, csrf_field: str = None):
        """
        Executes HTTP request, managing query parameters, anti-CSRF token lifecycle,
        consistent timing measurement, and diagnostic error handling.
        """
        coverage.requests_completed += 1
        try:
            req_start = time.perf_counter()
            resp = None
            if method == "GET":
                parsed = urlparse(url)
                existing_q = dict(parse_qsl(parsed.query))
                merged = {**existing_q, **params}
                query = urlencode(merged)
                full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
                resp = await client.get(full_url)
            else:
                if csrf_field and page_url:
                    fresh = await _fetch_csrf_token(page_url, csrf_field)
                    if fresh:
                        params[csrf_field] = fresh
                resp = await client.post(url, data=params)

            req_duration = time.perf_counter() - req_start
            if resp is not None:
                if not hasattr(resp, "duration"):
                    setattr(resp, "duration", req_duration)
                if not hasattr(resp, "_elapsed") or resp._elapsed is None:
                    final_dur = getattr(resp, "duration", req_duration)
                    try:
                        resp.elapsed = datetime.timedelta(seconds=final_dur)
                    except Exception:
                        resp._elapsed = datetime.timedelta(seconds=final_dur)
            return resp
        except Exception as e:
            logger.debug(f"Request error for {method} {url}: {e.__class__.__name__} - {e}")
            err_msg = f"{e.__class__.__name__}: {str(e)}"
            if err_msg not in coverage.inconclusive_reasons:
                coverage.inconclusive_reasons.append(err_msg)
            return None

    async def test_parameter(
        url: str, 
        method: str, 
        params: dict, 
        param_to_inject: str, 
        source: str, 
        page_url: str = None, 
        csrf_field: str = None
    ):
        if _is_scan_cancelled():
            return

        request_budget = 35 if depth == "deep" else 20
        requests_made = 0

        # Stage B: Parameter profiling & Baseline establishment
        baseline_requests_count = 3 if depth == "deep" else 2
        baseline_responses = []
        for _ in range(baseline_requests_count):
            if _is_scan_cancelled() or requests_made >= request_budget:
                break
            resp = await _make_request(url, method, params, page_url=page_url, csrf_field=csrf_field)
            requests_made += 1
            if resp:
                baseline_responses.append(resp)
        
        test_case = TestCaseResult(
            category="sqli",
            target_endpoint=url,
            http_method=method,
            parameter=param_to_inject,
            baseline_request=params,
            remediation=[
                "Use parameterized queries, prepared statements, or ORM parameter binding.",
                "Enforce strict allowlist input validation and sanitize all parameters.",
                "Apply least privilege principles to database service accounts."
            ],
            owasp="A03:2021-Injection"
        )

        coverage.inputs_tested += 1
        if param_to_inject not in coverage.tested_parameters:
            coverage.tested_parameters.append(param_to_inject)

        if not baseline_responses:
            test_case.status = "INCONCLUSIVE"
            test_case.add_observation(
                "baseline_empty", 
                f"Could not establish baseline for {source} parameter '{param_to_inject}'; target did not respond.",
                is_suspicious=False
            )
            coverage.inconclusive_reasons.append(f"No baseline response for '{param_to_inject}'")
            test_case.evaluate()
            return
            
        profile = BaselineProfile(baseline_responses, db_error_checker=check_db_errors)
        test_case.add_observation(
            "baseline", 
            f"Baseline established ({len(profile.requests)} requests). Status: HTTP {profile.baseline_status}. Stable: {profile.is_stable} ({profile.stability_reason})."
        )
        
        if profile.baseline_status == 429 or any(getattr(r, 'status_code', None) == 429 for r in baseline_responses):
            test_case.status = "INCONCLUSIVE"
            test_case.add_observation(
                "rate_limited", 
                f"Baseline requests encountered rate limiting (HTTP 429) on parameter '{param_to_inject}'. Inconclusive.",
                is_suspicious=False
            )
            coverage.baseline_stability = "rate_limited"
            coverage.inconclusive_reasons.append(f"Baseline rate-limited (HTTP 429) on '{param_to_inject}'")
            test_case.evaluate()
            return

        if profile.is_stable:
            if coverage.baseline_stability not in ("unstable", "rate_limited"):
                coverage.baseline_stability = "stable"
        else:
            coverage.baseline_stability = "unstable"
            coverage.inconclusive_reasons.append(f"Unstable baseline on '{param_to_inject}': {profile.stability_reason}")

        if profile.baseline_has_db_errors:
            test_case.add_observation(
                "baseline_error", 
                "Baseline requests inherently contain database error signatures; error-based triggers are guarded.", 
                is_suspicious=False
            )

        detected_db = None
        vulnerable = False
        evidence_payload = None
        evidence_params = None
        technique_used = None

        # Helper for repeated validation
        async def _validate_payload(payload: str, expected_type: str, inverted: bool = False, expected_delay: float = 2.5) -> bool:
            nonlocal requests_made
            if _is_scan_cancelled() or requests_made >= request_budget:
                return False
            v_test_params = params.copy()
            v_test_params[param_to_inject] = str(v_test_params[param_to_inject] or "") + payload
            v_resp = await _make_request(url, method, v_test_params, page_url=page_url, csrf_field=csrf_field)
            requests_made += 1
            if not v_resp:
                return False
            
            if expected_type == "db_error":
                v_db, _ = check_db_errors(v_resp.text, payload)
                return v_db is not None
            elif expected_type == "boolean_true":
                v_diff = profile.compare_test(v_resp)
                return (not v_diff["is_body_similar"]) if inverted else v_diff["is_body_similar"]
            elif expected_type == "boolean_false":
                v_diff = profile.compare_test(v_resp)
                return v_diff["is_body_similar"] if inverted else (not v_diff["is_body_similar"])
            elif expected_type == "timing":
                if getattr(v_resp, "status_code", None) == 500:
                    return False
                v_dur = get_response_duration(v_resp)
                return v_dur >= expected_delay
            return False

        # Stage C: Error-based SQL Injection Testing
        for payload in syntax_payloads:
            if _is_scan_cancelled() or requests_made >= request_budget:
                break

            test_params = params.copy()
            test_params[param_to_inject] = str(test_params[param_to_inject] or "") + payload
            
            test_resp = await _make_request(url, method, test_params, page_url=page_url, csrf_field=csrf_field)
            requests_made += 1
            if not test_resp:
                continue

            if getattr(test_resp, "status_code", None) == 429:
                test_case.add_observation(
                    "rate_limited", 
                    f"Target rate-limited requests (HTTP 429) during payload '{payload}'. Inconclusive.",
                    is_suspicious=False
                )
                break
            elif getattr(test_resp, "status_code", None) == 403 and profile.baseline_status == 200:
                test_case.add_observation(
                    "waf_block", 
                    f"Target returned HTTP 403 (possible WAF block) for payload '{payload}'.",
                    is_suspicious=False
                )

            diff = profile.compare_test(test_resp)
            
            if diff["test_status"] == 500 and profile.baseline_status == 200:
                test_case.add_observation(
                    "server_500", 
                    f"Payload '{payload}' caused a 500 Internal Server Error (baseline was 200). Unconfirmed without DB signature.", 
                    is_suspicious=False
                )

            if not profile.baseline_has_db_errors:
                db_name, err = check_db_errors(test_resp.text, payload)
                if db_name:
                    # Control Test: Validate reproducibility
                    is_reproducible = await _validate_payload(payload, "db_error")
                    if is_reproducible:
                        test_case.add_observation(
                            "database_error", 
                            f"Payload '{payload}' reproducibly triggered {db_name} error signature: '{err}'", 
                            is_strong_evidence=True,
                            technique="Error-Based SQLi",
                            payload=payload
                        )
                        detected_db = db_name
                        vulnerable = True
                        technique_used = "Error-Based SQL Injection"
                        evidence_payload = payload
                        evidence_params = test_params
                        break
                    else:
                        test_case.add_observation(
                            "database_error_unstable", 
                            f"Payload '{payload}' disclosed {db_name} error signature '{err}', but was not reproducible.", 
                            is_suspicious=True
                        )
                        
            if vulnerable:
                break
            
        # Stage D: Paired-Control Boolean Differential Testing
        if not vulnerable:
            if not profile.is_stable:
                test_case.add_observation(
                    "baseline_unstable", 
                    f"Skipping boolean differential testing: {profile.stability_reason}.", 
                    is_suspicious=False
                )
            else:
                for pt, pf in boolean_pairs:
                    if _is_scan_cancelled() or requests_made >= request_budget:
                        break

                    params_true = params.copy()
                    params_true[param_to_inject] = str(params_true[param_to_inject] or "") + pt
                    resp_true = await _make_request(url, method, params_true, page_url=page_url, csrf_field=csrf_field)
                    requests_made += 1
                    
                    params_false = params.copy()
                    params_false[param_to_inject] = str(params_false[param_to_inject] or "") + pf
                    resp_false = await _make_request(url, method, params_false, page_url=page_url, csrf_field=csrf_field)
                    requests_made += 1
                    
                    if resp_true and resp_false:
                        if getattr(resp_true, "status_code", None) == 429 or getattr(resp_false, "status_code", None) == 429:
                            test_case.add_observation(
                                "rate_limited", 
                                "Target rate-limited requests (HTTP 429) during boolean differential tests. Inconclusive.",
                                is_suspicious=False
                            )
                            break
                        if (getattr(resp_true, "status_code", None) == 403 or getattr(resp_false, "status_code", None) == 403) and profile.baseline_status == 200:
                            test_case.add_observation(
                                "waf_block", 
                                f"Target returned HTTP 403 for boolean test inputs '{pt}' / '{pf}'.",
                                is_suspicious=False
                            )
                        if getattr(resp_true, "status_code", None) == 500 or getattr(resp_false, "status_code", None) == 500:
                            test_case.add_observation(
                                "boolean_500",
                                f"Boolean inputs '{pt}' / '{pf}' triggered an HTTP 500 server error. Server errors do not confirm differential SQLi.",
                                is_suspicious=False
                            )
                            continue

                        diff_true = profile.compare_test(resp_true)
                        diff_false = profile.compare_test(resp_false)
                        diff_t_f = BaselineEngine.compare(resp_true, resp_false)
                        
                        # Pattern 1 (Standard): Baseline is truthy. True matches baseline; False diverges.
                        # Pattern 2 (Inverted / Auth): Baseline is falsy (e.g. login failed). False matches baseline; True diverges/bypasses.
                        is_standard_diff = diff_true["is_body_similar"] and not diff_false["is_body_similar"]
                        is_inverted_diff = not diff_true["is_body_similar"] and diff_false["is_body_similar"]

                        if (is_standard_diff or is_inverted_diff) and not diff_t_f["is_body_similar"]:
                            # Control Test: Verify reproducibility with independent test
                            val_true = await _validate_payload(pt, "boolean_true", inverted=is_inverted_diff)
                            val_false = await _validate_payload(pf, "boolean_false", inverted=is_inverted_diff)
                            
                            if val_true and val_false:
                                if is_standard_diff:
                                    obs_msg = f"Paired boolean diff: True payload '{pt}' matches baseline, False payload '{pf}' alters response reproducibly."
                                else:
                                    obs_msg = f"Paired boolean diff (Authentication / Inverted): True payload '{pt}' alters response / bypasses check, False payload '{pf}' matches baseline reproducibly."
                                
                                test_case.add_observation(
                                    "boolean_differential", 
                                    obs_msg, 
                                    is_strong_evidence=True,
                                    technique="Boolean Differential",
                                    payload=pt
                                )
                                vulnerable = True
                                technique_used = "Boolean Differential SQL Injection"
                                evidence_payload = pt
                                evidence_params = params_true
                                break
                            else:
                                test_case.add_observation(
                                    "boolean_unstable", 
                                    f"Observed differential between '{pt}' and '{pf}', but divergence was not reproducible upon re-test.", 
                                    is_suspicious=True
                                )

        # Stage E: Bounded Time-Based Blind SQLi Testing (Deep mode only)
        if not vulnerable and depth == "deep" and profile.is_stable:
            try:
                for db_hint, delay_payload in timing_probes:
                    if _is_scan_cancelled() or requests_made >= request_budget:
                        break

                    t_params = params.copy()
                    t_params[param_to_inject] = str(t_params[param_to_inject] or "") + delay_payload
                    
                    t_resp = await _make_request(url, method, t_params, page_url=page_url, csrf_field=csrf_field)
                    requests_made += 1
                    if not t_resp:
                        continue
                    
                    t_duration = get_response_duration(t_resp)
                    
                    # 1. Server errors (HTTP 500) must never confirm time-based SQLi
                    if getattr(t_resp, "status_code", None) == 500:
                        test_case.add_observation(
                            "timing_500",
                            f"Time probe '{delay_payload}' returned HTTP 500 after {round(t_duration, 2)}s. Server error delays do not confirm SQLi.",
                            is_suspicious=False
                        )
                        continue

                    # 2. Timing threshold: delay must be >= 2.5s AND significantly higher than baseline mean
                    if t_duration >= 2.5 and (t_duration >= profile.mean_response_time + 1.8):
                        # 3. Control test: dispatch un-injected request to ensure server isn't globally lagging
                        c_resp = await _make_request(url, method, params, page_url=page_url, csrf_field=csrf_field)
                        requests_made += 1
                        c_duration = get_response_duration(c_resp) if c_resp else 0.0

                        # Control must complete promptly and cannot also be delayed
                        if c_resp and c_duration < 1.8 and (t_duration >= c_duration + 1.5):
                            # 4. Secondary reproducibility test: verify delay reproduces with independent re-test
                            is_reproduced = await _validate_payload(delay_payload, "timing", expected_delay=2.5)
                            if is_reproduced:
                                test_case.add_observation(
                                    "time_delay", 
                                    f"Time-based blind delay: Payload '{delay_payload}' reproducibly induced a {round(t_duration, 2)}s delay (baseline: {round(profile.mean_response_time, 2)}s, control: {round(c_duration, 2)}s). Prompt control completed normally.",
                                    is_strong_evidence=True,
                                    technique="Time-Based Blind SQLi",
                                    payload=delay_payload
                                )
                                vulnerable = True
                                technique_used = "Time-Based Blind SQL Injection"
                                detected_db = db_hint
                                evidence_payload = delay_payload
                                evidence_params = t_params
                                break
                            else:
                                test_case.add_observation(
                                    "timing_jitter", 
                                    f"Transient delay of {round(t_duration, 2)}s observed with '{delay_payload}', but failed reproducibility check.", 
                                    is_suspicious=True
                                )
                        else:
                            test_case.add_observation(
                                "timing_congested",
                                f"Observed delay of {round(t_duration, 2)}s on probe, but un-injected control was also slow ({round(c_duration, 2)}s). Attributed to general network/server latency.",
                                is_suspicious=False
                            )
            except Exception as e:
                logger.warning(f"Error during time-based testing on {param_to_inject}: {e}")
                err_msg = f"Timing check exception ({e.__class__.__name__}: {str(e)})"
                if err_msg not in coverage.inconclusive_reasons:
                    coverage.inconclusive_reasons.append(err_msg)
                test_case.add_observation(
                    "timing_error",
                    f"Timing probe encountered an unexpected condition ({e.__class__.__name__}: {str(e)}). Continued safely.",
                    is_suspicious=False
                )

        test_case.evaluate()
        
        # Assemble finding for persistence
        if test_case.status in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            desc = f"The parameter '{param_to_inject}' exhibited behavior confirming SQL injection via {technique_used or 'behavioral probes'}."
            if detected_db:
                desc += f" Evidence suggests the backend database is {detected_db}."
                
            final_status = test_case.status
            final_severity = "high" if final_status in ["CRITICAL", "HIGH"] else ("medium" if final_status == "MEDIUM" else "low")

            scanner._add_finding(
                f_type="sqli", 
                severity=final_severity, 
                status=final_status,
                title=f"SQL Injection via {source.capitalize()} Parameter '{param_to_inject}'",
                description=desc,
                evidence=test_case.evidence,
                impact="Attackers can bypass authentication, extract database contents, or alter system state.",
                remediation=test_case.remediation,
                owasp=test_case.owasp, 
                cwe="CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                url=url, 
                parameter=param_to_inject,
                http_method=method, 
                request=str(evidence_params) if evidence_params else str(params), 
                response_summary=f"Evaluated via {technique_used or 'differential testing pipeline'}",
                confidence=test_case.confidence
            )
            coverage.findings_added += 1

    # Stage A: Discover and extract candidate inputs
    candidate_endpoints = []
    for endpoint in (endpoints or []):
        if endpoint.get("source") == "form" and forms:
            continue
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET")
        params_list = list(endpoint.get("params", []))
        param_values = dict(endpoint.get("param_values", {}))
        parsed_url = urlparse(url)
        url_query_dict = dict(parse_qsl(parsed_url.query))
        all_param_names = params_list or list(url_query_dict.keys())
        merged_values = {**url_query_dict, **param_values}
        if all_param_names:
            candidate_endpoints.append({
                "url": url,
                "method": method,
                "params": all_param_names,
                "values": merged_values
            })
            coverage.candidate_inputs_discovered += len(all_param_names)

    candidate_forms = []
    for form in (forms or []):
        action_url = form.get("action_url", "")
        page_url = form.get("page_url", action_url)
        method = form.get("method", "POST")
        inputs = list(form.get("inputs", []))
        fields = dict(form.get("fields", {}))
        if inputs:
            candidate_forms.append({
                "action_url": action_url,
                "page_url": page_url,
                "method": method,
                "inputs": inputs,
                "fields": fields
            })
            coverage.candidate_inputs_discovered += len(inputs)

    # If no candidate inputs exist across the crawled attack surface, return immediately
    if coverage.candidate_inputs_discovered == 0:
        coverage.blocking_reason = "No candidate query parameters or HTML form inputs were discovered on target endpoints."
        coverage.baseline_stability = "not_evaluated"
        coverage.verification_completed = False
        return coverage

    if "error_based" not in coverage.techniques_attempted:
        coverage.techniques_attempted.extend(["error_based", "boolean_differential", "timing_delay"])

    # Stage B: Process GET Endpoints
    for ep in candidate_endpoints:
        if _is_scan_cancelled():
            break
        url = ep["url"]
        method = ep["method"]
        all_param_names = ep["params"]
        merged_values = ep["values"]
        
        baseline_params = {}
        for p in all_param_names:
            observed_val = merged_values.get(p)
            baseline_params[p] = observed_val if (observed_val is not None and observed_val != "") else "test"
            
        for param in all_param_names:
            try:
                await test_parameter(url, method, baseline_params, param, "URL query")
            except Exception as pe:
                logger.warning(f"Error testing parameter '{param}' on {url}: {pe}")
                coverage.scanner_error = str(pe)
                coverage.inconclusive_reasons.append(f"Scanner exception on '{param}': {pe}")

    # Stage C: Process Forms
    for form_item in candidate_forms:
        if _is_scan_cancelled():
            break
            
        action_url = form_item["action_url"]
        page_url = form_item["page_url"]
        method = form_item["method"]
        inputs = form_item["inputs"]
        fields = form_item["fields"]
        
        baseline_params = {}
        csrf_field_name = None
        for name in inputs:
            f_info = fields.get(name, {})
            val = f_info.get("value", "") if isinstance(f_info, dict) else str(f_info or "")
            f_type = f_info.get("type", "text").lower() if isinstance(f_info, dict) else "text"
            
            is_csrf = any(k in name.lower() for k in ["csrf", "xsrf", "token", "nonce", "__requestverificationtoken"])
            if is_csrf:
                baseline_params[name] = val
                csrf_field_name = name
            elif f_type == "hidden" and val:
                baseline_params[name] = val
            else:
                baseline_params[name] = val if val else "test"

        params_to_test = [name for name in inputs if name != csrf_field_name] or inputs
        for param in params_to_test:
            try:
                await test_parameter(
                    action_url, 
                    method, 
                    baseline_params, 
                    param, 
                    "form", 
                    page_url=page_url, 
                    csrf_field=csrf_field_name
                )
            except Exception as pe:
                logger.warning(f"Error testing form parameter '{param}' on {action_url}: {pe}")
                coverage.scanner_error = str(pe)
                coverage.inconclusive_reasons.append(f"Scanner exception on form parameter '{param}': {pe}")

    if coverage.inputs_tested > 0 and not coverage.scanner_error:
        coverage.verification_completed = True
        coverage.techniques_completed = list(coverage.techniques_attempted)

    return coverage
