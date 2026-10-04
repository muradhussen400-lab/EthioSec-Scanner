import re
import json
import asyncio
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
import uuid

from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult
from scanner.differential import BaselineEngine

class EndpointCandidate:
    def __init__(self, endpoint: dict, ref_type: str, ref_key: str, orig_val: str, location: str):
        self.endpoint = endpoint
        self.ref_type = ref_type
        self.ref_key = ref_key
        self.orig_val = orig_val
        self.location = location

class AccessControlScanner:
    def __init__(self, scanner: SecurityScanner, client: SafeHTTPClient, mode: str):
        self.scanner = scanner
        self.client = client
        self.mode = mode
        
    async def run(self, endpoints: list, auth_context_1: dict = None, auth_context_2: dict = None):
        if not auth_context_1 and not auth_context_2:
            return

        candidates = self._discover_candidates(endpoints)
        max_tests = 50 if self.mode == "deep" else 20
        tested = 0

        for candidate in candidates:
            if tested >= max_tests:
                break
            await self._test_candidate(candidate, auth_context_1, auth_context_2)
            tested += 1

    def _discover_candidates(self, endpoints: list) -> List[EndpointCandidate]:
        candidates = []
        id_pattern = re.compile(r'/(\d+)(/|$)')
        uuid_pattern = re.compile(r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(/|$)', re.IGNORECASE)
        
        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            params = ep.get("params", [])
            
            # 1. Path Numeric
            match = id_pattern.search(url)
            if match:
                candidates.append(EndpointCandidate(ep, "numeric", "path", match.group(1), "path"))
            
            # 2. Path UUID
            match = uuid_pattern.search(url)
            if match:
                candidates.append(EndpointCandidate(ep, "uuid", "path", match.group(1), "path"))
                
            # 3. Query Params
            for p in params:
                if isinstance(p, str) and (p.endswith("_id") or p == "id"):
                    candidates.append(EndpointCandidate(ep, "numeric", p, "1", "query")) # Assume 1 as dummy default if value isn't provided
                    
            # 4. JSON and Form Body
            if method in ["POST", "PUT", "PATCH"]:
                data = ep.get("data", {})
                json_data = ep.get("json", {})
                
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(k, str) and (k.endswith("_id") or k == "id"):
                            candidates.append(EndpointCandidate(ep, "numeric", k, str(v), "form"))
                if isinstance(json_data, dict):
                    # We only extract flat json for now, or assume nested is flattened in test
                    def extract_json(d, prefix=""):
                        for k, v in d.items():
                            if isinstance(k, str) and (k.endswith("_id") or k == "id"):
                                candidates.append(EndpointCandidate(ep, "numeric", k, str(v), "json"))
                            elif isinstance(v, dict):
                                extract_json(v, prefix=f"{k}.")
                            elif isinstance(v, list) and v and isinstance(v[0], (int, str)):
                                if isinstance(k, str) and (k.endswith("ids") or k.endswith("_id") or k == "id"):
                                    candidates.append(EndpointCandidate(ep, "numeric", k, str(v[0]), "json"))
                    extract_json(json_data)

        return candidates
        
    async def _test_candidate(self, candidate: EndpointCandidate, auth_a: dict, auth_b: dict):
        url = candidate.endpoint.get("url")
        method = candidate.endpoint.get("method", "GET")
        
        test_case = TestCaseResult(
            category="access_control", target_endpoint=url, http_method=method,
            baseline_request={}, remediation=["Implement strict ownership checks."],
            owasp="A01:2025-Broken Access Control"
        )
        
        if auth_a and auth_b:
            await self._horizontal_test(test_case, candidate, auth_a, auth_b)
        elif auth_a:
            await self._vertical_test(test_case, candidate, auth_a)
            
    async def _horizontal_test(self, test_case, candidate, auth_a, auth_b):
        url = candidate.endpoint.get("url")
        method = candidate.endpoint.get("method", "GET")
        
        req_x = self._build_request(candidate, candidate.orig_val)
        
        # A -> X
        resp_a_x = await self._send_request(method, req_x, auth_a)
        if not resp_a_x:
            return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
        if resp_a_x.status_code != 200:
            return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
        if self._is_generic_200(resp_a_x):
            return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
            
        # B -> Y
        y_val = self._mutate_id(candidate.ref_type, candidate.orig_val)
        if not y_val:
            return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
            
        req_y = self._build_request(candidate, y_val)
        resp_b_y = await self._send_request(method, req_y, auth_b)
        print(f"DEBUG: B->Y {req_y['url']} status: {resp_b_y.status_code if resp_b_y else 'None'} text: {resp_b_y.text if resp_b_y else ''}")
        
        if not resp_b_y or resp_b_y.status_code != 200 or self._is_generic_200(resp_b_y):
            return await self._vertical_test(test_case, candidate, auth_a)
            
        # Check if X is equally accessible to B (Shared Resource)
        resp_b_x = await self._send_request(method, req_x, auth_b)
        if resp_b_x and resp_b_x.status_code == 200 and not self._is_generic_200(resp_b_x):
            diff_shared = BaselineEngine.compare(resp_a_x, resp_b_x)
            if diff_shared["is_body_similar"]:
                test_case.add_observation("shared_resource", f"Resource X is accessible to B. Likely shared.", False)
                return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
            
        # Anonymous -> Y (Check if Public)
        resp_anon_y = await self._send_request(method, req_y, {})
        if resp_anon_y and resp_anon_y.status_code == 200 and not self._is_generic_200(resp_anon_y):
            diff_pub = BaselineEngine.compare(resp_b_y, resp_anon_y)
            if diff_pub["is_body_similar"]:
                test_case.add_observation("public_resource", f"Resource Y is public.", False)
                return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
                
        # Identity Extraction
        id_b_y = self._extract_identity(resp_b_y, y_val)
        
        # A -> Y
        resp_a_y = await self._send_request(method, req_y, auth_a)
        if not resp_a_y or resp_a_y.status_code != 200 or self._is_generic_200(resp_a_y):
            return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
            
        # Property level auth check
        prop_diff = self._verify_property_level(resp_a_y, resp_b_y)
        
        # Resource Identity check
        id_a_y = self._extract_identity(resp_a_y, y_val)
        
        
        if id_b_y and id_a_y and id_a_y == id_b_y:
            if prop_diff:
                test_case.add_observation("property_auth", f"Property auth difference: {prop_diff}", True)
                test_case.evidence = f"Property-level authorization difference detected: {prop_diff}"
                return self._finalize_finding(test_case, url, method, "MEDIUM")
            else:
                test_case.add_observation("horizontal_bypass", f"A accessed B's resource {y_val}.", True)
                test_case.evidence = f"Context A successfully accessed object {y_val} belonging to B. Resource identity verification confirmed exact resource matching."
                return self._finalize_finding(test_case, url, method, "MEDIUM")
            
        diff_y = BaselineEngine.compare(resp_b_y, resp_a_y)
        if diff_y["is_body_similar"]:
            if prop_diff:
                test_case.add_observation("property_auth", f"Property auth difference: {prop_diff}", True)
                test_case.evidence = f"Property-level authorization difference detected: {prop_diff}"
                return self._finalize_finding(test_case, url, method, "MEDIUM")
            else:
                test_case.add_observation("horizontal_bypass", f"A accessed B's resource structure.", True)
                test_case.evidence = f"Context A accessed B's resource structure but exact identity extraction failed. Flagged as suspicious."
                return self._finalize_finding(test_case, url, method, "LOW")
                
        return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
        
    async def _vertical_test(self, test_case, candidate, auth):
        url = candidate.endpoint.get("url")
        method = candidate.endpoint.get("method", "GET")
        
        req_orig = self._build_request(candidate, candidate.orig_val)
        resp_orig = await self._send_request(method, req_orig, auth)
        
        y_val = self._mutate_id(candidate.ref_type, candidate.orig_val)
        if not y_val: return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
        
        req_mod = self._build_request(candidate, y_val)
        resp_mod = await self._send_request(method, req_mod, auth)
        
        if resp_orig and resp_mod and resp_orig.status_code == 200 and resp_mod.status_code == 200:
            if self._is_generic_200(resp_mod):
                return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
                
            resp_anon = await self._send_request(method, req_mod, {})
            if resp_anon and resp_anon.status_code == 200:
                diff_pub = BaselineEngine.compare(resp_mod, resp_anon)
                if diff_pub["is_body_similar"]:
                    return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
                    
            diff = BaselineEngine.compare(resp_orig, resp_mod)
            if not diff["is_body_identical"]:
                test_case.add_observation("missing_ownership", "Suspicious cross-object access, but ownership cannot be verified.", True)
                test_case.evidence = "Single context accessed a mutated object reference successfully, but cross-account boundaries could not be verified."
                return self._finalize_finding(test_case, url, method, "LOW")
                
        return self._finalize_finding(test_case, url, method, "NOT_DETECTED")
        
    def _build_request(self, candidate: EndpointCandidate, val: str) -> dict:
        import copy
        url = candidate.endpoint.get("url")
        ep_params = copy.deepcopy(candidate.endpoint.get("params"))
        ep_json = copy.deepcopy(candidate.endpoint.get("json"))
        ep_data = copy.deepcopy(candidate.endpoint.get("data"))
        
        if candidate.location == "path":
            url = url.replace(f"/{candidate.orig_val}", f"/{val}")
        elif candidate.location == "query":
            # If it's a list of strings like ["order_id=1"], this is harder to parse, but let's assume it's dict or string list
            if isinstance(ep_params, dict):
                ep_params[candidate.ref_key] = val
            elif isinstance(ep_params, list):
                # Just fallback to appending for simplicity in scanner
                if not any(candidate.ref_key in p for p in ep_params):
                    ep_params.append(f"{candidate.ref_key}={val}")
        elif candidate.location == "json":
            if isinstance(ep_json, dict):
                def mutate_json(d):
                    for k, v in d.items():
                        if k == candidate.ref_key:
                            if isinstance(v, list):
                                d[k] = [val] if v else []
                            else:
                                d[k] = val
                        elif isinstance(v, dict):
                            mutate_json(v)
                mutate_json(ep_json)
        elif candidate.location == "form":
            if isinstance(ep_data, dict):
                ep_data[candidate.ref_key] = val
                
        return {"url": url, "params": ep_params, "json": ep_json, "data": ep_data}
        
    async def _send_request(self, method, req_opts, auth):
        try:
            return await self.client.request(
                method, req_opts["url"],
                params=req_opts.get("params"),
                json=req_opts.get("json"),
                data=req_opts.get("data"),
                **auth
            )
        except Exception as e:
            print(f"Exception in _send_request: {e}")
            return None
            
    def _mutate_id(self, ref_type, orig_val):
        if ref_type == "numeric":
            try: return str(int(orig_val) + 1)
            except: return "2"
        elif ref_type == "uuid":
            return "123e4567-e89b-12d3-a456-426614174000" if orig_val != "123e4567-e89b-12d3-a456-426614174000" else "123e4567-e89b-12d3-a456-426614174001"
        return None
        
    def _extract_identity(self, resp, target_id):
        try:
            data = resp.json()
            if isinstance(data, dict):
                for k in data.keys():
                    if (k in ["id", "uuid"] or k.endswith("_id")) and str(data[k]) == str(target_id):
                        return str(target_id)
        except:
            pass
        return None
        
    def _verify_property_level(self, resp_a, resp_b):
        try:
            da = resp_a.json()
            db = resp_b.json()
            if isinstance(da, dict) and isinstance(db, dict):
                keys_a = set(da.keys())
                keys_b = set(db.keys())
                diff = keys_b - keys_a
                if diff:
                    return f"Missing properties: {', '.join(diff)}"
        except:
            pass
        return None
        
    def _is_generic_200(self, resp):
        text = resp.text.lower()
        if len(text) < 1000 and ("not found" in text or "error" in text or "unauthorized" in text):
            return True
        if "<div id='app'>" in text or "<div id=\"app\">" in text or "loading..." in text:
            return True
        return False
        
    def _finalize_finding(self, test_case, url, method, status):
        test_case.status = status
        if test_case.status == "NOT_DETECTED":
            return
            
        if test_case.status == "HIGH":
            final_status, final_severity = "HIGH", "high"
        elif test_case.status == "MEDIUM":
            final_status, final_severity = "MEDIUM", "medium"
        elif test_case.status == "LOW":
            final_status, final_severity = "LOW", "low"
        else:
            final_status, final_severity = "SCANNER_ERROR", "info"
            
        # Check for property level (map to MEDIUM)
        if test_case.evidence and "property" in test_case.evidence.lower():
            final_status = "MEDIUM"
            final_severity = "medium"
            test_case.title = "Object Property Authorization Failure"
            
        self.scanner._add_finding(
            f_type="access_control", 
            severity=final_severity, 
            status=final_status,
            title=test_case.title if getattr(test_case, "title", "") else "Insecure Direct Object Reference (IDOR)",
            description="The application failed to properly enforce authorization on object references.",
            evidence=test_case.evidence,
            impact="Attackers can view or modify data belonging to other users.",
            remediation=test_case.remediation,
            owasp=test_case.owasp, url=url, parameter="URL Path",
            http_method=method, request=None, response_summary=f"Evaluated via differential authorization tests"
        )

async def check_access_control(
    scanner: SecurityScanner, 
    endpoints: list, 
    client: SafeHTTPClient, 
    auth_context_1: dict = None, 
    auth_context_2: dict = None,
    mode: str = "standard"
):
    ac_scanner = AccessControlScanner(scanner, client, mode)
    await ac_scanner.run(endpoints, auth_context_1, auth_context_2)
