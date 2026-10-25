from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from scanner.engine import SecurityScanner

from scanner.http_client import SafeHTTPClient
from urllib.parse import urlparse, urlencode, urlunparse
from scanner.test_case import TestCaseResult
from scanner.differential import BaselineProfile
from bs4 import BeautifulSoup
import random
import string

class XSSCoverageRecord:
    """
    Transparent execution and attack surface coverage record for XSS testing.
    Tracks candidate inputs, executed tests, and completed requests independently from SQLi.
    """
    def __init__(self):
        self.candidate_inputs_discovered: int = 0
        self.inputs_tested: int = 0
        self.requests_completed: int = 0
        self.tested_parameters: list = []
        self.blocking_reason: str = None
        self.scanner_error: str = None
        self.findings_added: int = 0
        self.verification_completed: bool = False

async def check_xss(scanner: "SecurityScanner", endpoints: list, forms: list, client: SafeHTTPClient, depth: str = "standard") -> XSSCoverageRecord:
    coverage = XSSCoverageRecord()

    async def _make_request(url: str, method: str, params: dict):
        coverage.requests_completed += 1
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

    def _determine_contexts(html: str, marker: str) -> list:
        contexts = []
        start = 0
        html_lower = html.lower()
        while True:
            idx = html.find(marker, start)
            if idx == -1: break
            
            prefix = html[:idx]
            prefix_lower = html_lower[:idx]
            
            last_open = prefix.rfind('<')
            last_close = prefix.rfind('>')
            
            context = "html_text"
            
            if last_open > last_close:
                tag_text = prefix[last_open:]
                single_quotes = tag_text.count("'")
                double_quotes = tag_text.count('"')
                
                in_single = single_quotes % 2 != 0
                in_double = double_quotes % 2 != 0
                
                if in_double:
                    context = "attribute_double_quoted"
                elif in_single:
                    context = "attribute_single_quoted"
                else:
                    last_equals = tag_text.rfind('=')
                    last_space = tag_text.rfind(' ')
                    if last_equals > last_space:
                        context = "attribute_unquoted"
                    else:
                        context = "inside_tag_unknown"
            else:
                script_open = prefix_lower.rfind('<script')
                script_close = prefix_lower.rfind('</script>')
                if script_open > script_close:
                    context = "javascript"
                else:
                    style_open = prefix_lower.rfind('<style')
                    style_close = prefix_lower.rfind('</style>')
                    if style_open > style_close:
                        context = "css"
                    else:
                        comment_open = prefix.rfind('<!--')
                        comment_close = prefix.rfind('-->')
                        if comment_open > comment_close:
                            context = "comment"
                            
            contexts.append({"index": idx, "context": context, "snippet": _extract_snippet(html, idx, len(marker))})
            start = idx + len(marker)
            
        return contexts

    def _extract_snippet(html: str, idx: int, marker_len: int) -> str:
        start = max(0, idx - 40)
        end = min(len(html), idx + marker_len + 40)
        return html[start:end]

    async def test_parameter(url: str, method: str, baseline_params: dict, param_to_inject: str, source: str):
        baseline_requests_count = 3 if depth == "deep" else 2
        
        baseline_responses = []
        for _ in range(baseline_requests_count):
            resp = await _make_request(url, method, baseline_params)
            if resp:
                baseline_responses.append(resp)
            else:
                break
        
        coverage.inputs_tested += 1
        if param_to_inject not in coverage.tested_parameters:
            coverage.tested_parameters.append(param_to_inject)

        test_case = TestCaseResult(
            category="xss",
            target_endpoint=url,
            http_method=method,
            parameter=param_to_inject,
            baseline_request=baseline_params,
            remediation=["Use context-aware output encoding (e.g., HTML entity encoding) before reflecting user input."],
            owasp="A03:2021-Injection"
        )
        
        if len(baseline_responses) < baseline_requests_count:
            test_case.status = "SCANNER_ERROR"
            test_case.add_observation("scanner_error", "Technical failure prevented reliable baseline establishment.")
            
            scanner._add_finding(
                f_type="xss", severity="info", status="SCANNER_ERROR",
                title=f"Scanner Error via {source.capitalize()} Parameter '{param_to_inject}'",
                description="Technical failure prevented reliable testing.",
                evidence=test_case.evidence, url=url, parameter=param_to_inject, http_method=method
            )
            coverage.scanner_error = "Technical failure during baseline establishment."
            return
            
        profile = BaselineProfile(baseline_responses)
        test_case.add_observation("baseline", f"Baseline established ({len(profile.requests)} requests). HTTP {profile.baseline_status}. Stable: {profile.is_stable}")

        base_resp = baseline_responses[0]
        csp = base_resp.headers.get("Content-Security-Policy")
        content_type = base_resp.headers.get("Content-Type", "")
        
        if csp:
            test_case.add_observation("csp_present", f"CSP Header found: {csp}", is_suspicious=False)
        if "application/json" in content_type:
            test_case.add_observation("json_response", "Response is JSON data context.", is_suspicious=False)

        # 2. Reflection Testing
        marker = "ethioxss_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        marker_params = baseline_params.copy()
        marker_params[param_to_inject] = str(marker_params[param_to_inject] or "") + marker
        
        marker_resp = await _make_request(url, method, marker_params)
        if not marker_resp:
            test_case.status = "SCANNER_ERROR"
            scanner._add_finding(f_type="xss", severity="info", status="SCANNER_ERROR", title=f"Scanner Error via {source.capitalize()} Parameter '{param_to_inject}'", description="Technical failure during reflection testing.", url=url, parameter=param_to_inject, http_method=method)
            return
            
        if marker not in marker_resp.text:
            test_case.add_observation("no_reflection", "Harmless marker was not reflected in the response.")
            test_case.evaluate()
            return
            
        reflections = _determine_contexts(marker_resp.text, marker)
        unique_contexts = set(r["context"] for r in reflections)
        test_case.add_observation("reflection_found", f"Marker '{marker}' reflected {len(reflections)} times. Contexts: {', '.join(unique_contexts)}")

        # 3. Encoding / Sanitization Analysis
        encoding_marker = f"{marker}<>\"'&/"
        enc_params = baseline_params.copy()
        enc_params[param_to_inject] = str(enc_params[param_to_inject] or "") + encoding_marker
        enc_resp = await _make_request(url, method, enc_params)
        
        if not enc_resp:
            test_case.status = "SCANNER_ERROR"
            scanner._add_finding(f_type="xss", severity="info", status="SCANNER_ERROR", title=f"Scanner Error via {source.capitalize()} Parameter '{param_to_inject}'", description="Technical failure during encoding analysis.", url=url, parameter=param_to_inject, http_method=method)
            return
            
        is_encoded = False
        survives_raw = False
        
        if enc_resp:
            resp_text = enc_resp.text
            if encoding_marker in resp_text:
                survives_raw = True
                test_case.add_observation("encoding_analysis", "Dangerous characters (<>\"'&/) were reflected raw without encoding.", is_suspicious=True)
            elif marker in resp_text:
                is_encoded = True
                if f"{marker}&lt;&gt;&quot;&#39;&amp;&#x2F;" in resp_text or f"{marker}&lt;&gt;&quot;'&amp;/" in resp_text or f"{marker}&lt;&gt;" in resp_text:
                    test_case.add_observation("encoding_analysis", "Dangerous characters were properly encoded or safely sanitized.")
                else:
                    test_case.add_observation("encoding_analysis", "Dangerous characters were partially encoded, stripped, or altered.", is_suspicious=True)

        if not survives_raw and not is_encoded:
            test_case.add_observation("filtering_detected", "Input was heavily filtered or dropped when dangerous characters were introduced.", is_suspicious=False)
            test_case.evaluate()
            return

        # 4. Context-Aware Controlled Injection Test & Validation
        vulnerable = False
        evidence_payload = None
        evidence_params = None
        final_snippet = ""
        
        for context in unique_contexts:
            test_payloads = []
            if context == "html_text":
                test_payloads = [f"<{marker}tag>"]
                if depth == "deep": test_payloads.append(f"<svg/onload={marker}()>")
            elif context == "attribute_double_quoted":
                test_payloads = [f"\"><{marker}tag>"]
                if depth == "deep": test_payloads.append(f"\" autofocus onfocus=\"{marker}()")
            elif context == "attribute_single_quoted":
                test_payloads = [f"'><{marker}tag>"]
                if depth == "deep": test_payloads.append(f"' autofocus onfocus='{marker}()")
            elif context == "attribute_unquoted":
                test_payloads = [f"><{marker}tag>", f" autofocus onfocus={marker}()"]
            elif context == "javascript":
                test_payloads = [f"';{marker}();//", f"\";{marker}();//", f"-{marker}()-"]
            elif context == "comment":
                test_payloads = [f"--><{marker}tag>"]
            else:
                test_payloads = [f"\"><{marker}tag>", f"<{marker}tag>"]
                
            for payload in test_payloads:
                inj_params = baseline_params.copy()
                inj_params[param_to_inject] = str(inj_params[param_to_inject] or "") + payload
                inj_resp = await _make_request(url, method, inj_params)
                
                if not inj_resp:
                    continue
                    
                text = inj_resp.text
                breakout_success = False
                
                # Check for structural transformation
                soup = BeautifulSoup(text, "html.parser")
                
                if f"<{marker}tag>" in payload:
                    if soup.find(f"{marker}tag".lower()): # HTML tags are lowercased by bs4
                        breakout_success = True
                elif f"<svg" in payload:
                    if soup.find("svg"):
                        breakout_success = True
                elif f"{marker}()" in payload:
                    # Require that it's not just in the raw text, but that we actually broke out.
                    # If quotes were escaped, we wouldn't have an autofocus attribute on any tag.
                    for tag in soup.find_all(True):
                        if tag.has_attr("onfocus") and marker in tag["onfocus"]:
                            breakout_success = True
                            break
                        if tag.has_attr("autofocus") and tag.get("onfocus") == f"{marker}()":
                            breakout_success = True
                            break
                    # Also check for javascript context execution
                    if context == "javascript" and survives_raw and f"{marker}()" in text:
                         breakout_success = True
                elif payload in text and survives_raw:
                    breakout_success = True
                    
                if breakout_success:
                    val_resp = await _make_request(url, method, inj_params)
                    if val_resp:
                        val_text = val_resp.text
                        val_success = False
                        val_soup = BeautifulSoup(val_text, "html.parser")
                        
                        if f"<{marker}tag>" in payload:
                            if val_soup.find(f"{marker}tag".lower()):
                                val_success = True
                        elif f"<svg" in payload:
                            if val_soup.find("svg"):
                                val_success = True
                        elif f"{marker}()" in payload:
                            for tag in val_soup.find_all(True):
                                if tag.has_attr("onfocus") and marker in tag["onfocus"]:
                                    val_success = True
                                    break
                            if context == "javascript" and survives_raw and f"{marker}()" in val_text:
                                 val_success = True
                        elif payload in val_text and survives_raw:
                            val_success = True
                        
                        if val_success:
                            idx = val_text.find(payload) if payload in val_text else val_text.find(marker)
                            final_snippet = _extract_snippet(val_text, max(0, idx), len(payload))
                            test_case.add_observation("controlled_validation", f"Payload '{payload}' successfully structurally transformed the document and reproduced reliably. Snippet: ...{final_snippet}...", is_strong_evidence=True)
                            vulnerable = True
                            evidence_payload = payload
                            evidence_params = inj_params
                            break
                        else:
                            test_case.add_observation("validation_failed", f"Payload '{payload}' showed breakout, but failed to structurally reproduce on validation.", is_suspicious=True)
            if vulnerable:
                break

        test_case.evaluate()
        
        if not vulnerable and survives_raw:
             test_case.add_observation("raw_survival", "Raw dangerous characters survive, but controlled context breakout payloads failed or were blocked.", is_suspicious=True)
             test_case.evaluate()

        # Enforce exact status mapping to HIGH, MEDIUM, LOW, NOT_DETECTED, SCANNER_ERROR
        if test_case.status in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            finding_status = "MEDIUM" if vulnerable else "LOW"
            finding_severity = "medium" if vulnerable else "low"
            title = ""
            desc = f"The parameter '{param_to_inject}' reflects input into a '{', '.join(unique_contexts)}' context. "
            
            if vulnerable:
                title = f"Potential Reflected XSS / HTML Injection via {source.capitalize()} Parameter '{param_to_inject}'"
                desc += "HTTP-level structural injection was reproduced, but browser JavaScript execution was not validated by the HTTP-only scanner."
            else:
                title = f"Potential Unsafe Input Reflection via {source.capitalize()} Parameter '{param_to_inject}'"
                desc += "Dangerous characters were partially sanitized or survived raw, indicating a potential security weakness, but full context breakout could not be structurally validated."
            
            scanner._add_finding(
                f_type="xss", 
                severity=finding_severity, 
                status=finding_status,
                title=title,
                description=desc,
                evidence=test_case.evidence,
                impact="Attackers could execute arbitrary JavaScript in the victim's browser if the injection context executes.",
                remediation=test_case.remediation,
                owasp=test_case.owasp, 
                url=url, 
                parameter=param_to_inject,
                http_method=method, 
                request=str(evidence_params) if evidence_params else str(enc_params), 
                response_summary=f"Evaluated via Context Analysis Pipeline"
            )
            coverage.findings_added += 1

    # Discover candidate inputs
    candidate_endpoints = []
    for ep in (endpoints or []):
        params_list = list(ep.get("params", []))
        if params_list:
            candidate_endpoints.append(ep)
            coverage.candidate_inputs_discovered += len(params_list)

    candidate_forms = []
    for form in (forms or []):
        inputs = list(form.get("inputs", []))
        if inputs:
            candidate_forms.append(form)
            coverage.candidate_inputs_discovered += len(inputs)

    if coverage.candidate_inputs_discovered == 0:
        coverage.blocking_reason = "No candidate query parameters or HTML form inputs were discovered on target endpoints."
        coverage.verification_completed = False
        return coverage

    for endpoint in candidate_endpoints:
        url = endpoint["url"]
        method = endpoint["method"]
        params_list = endpoint["params"]
        baseline_params = {p: "test" for p in params_list}
        for param in params_list:
            try:
                await test_parameter(url, method, baseline_params, param, "URL query")
            except Exception as pe:
                coverage.scanner_error = str(pe)

    for form in candidate_forms:
        action_url = form["action_url"]
        method = form["method"]
        inputs = form["inputs"]
        baseline_params = {name: "test" for name in inputs}
        for param in inputs:
            try:
                await test_parameter(action_url, method, baseline_params, param, "form")
            except Exception as pe:
                coverage.scanner_error = str(pe)

    if coverage.inputs_tested > 0 and not coverage.scanner_error:
        coverage.verification_completed = True

    return coverage
