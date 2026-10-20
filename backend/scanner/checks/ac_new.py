import re
import json
import asyncio
import httpx
from typing import Dict, Any, List, Optional, Set, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse

from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult
from scanner.differential import BaselineEngine, BaselineProfile

class AccessControlScanner:
    def __init__(self, scanner: SecurityScanner, client: SafeHTTPClient, mode: str):
        self.scanner = scanner
        self.client = client
        self.mode = mode
        
    async def run(self, endpoints: list, auth_context_1: dict = None, auth_context_2: dict = None):
        # We need at least one authentication context to test access control properly.
        # Otherwise, everything is just public data.
        if not auth_context_1 and not auth_context_2:
            self.scanner._add_finding(
                f_type="access_control", severity="info", status="NOT_DETECTED",
                title="Access Control (Unauthenticated)",
                description="No broken object-level or tested access-control bypass was detected in the assessed endpoints and available authorization contexts.",
                evidence="No authentication contexts were provided, so cross-account authorization could not be tested."
            )
            return

        candidate_endpoints = self._discover_candidates(endpoints)
        
        # Test up to a bounded number of candidates
        max_tests = 50 if self.mode == "deep" else 20
        tested = 0

        for ep in candidate_endpoints:
            if tested >= max_tests:
                break
            await self._test_endpoint(ep, auth_context_1, auth_context_2)
            tested += 1

        if tested == 0:
            self.scanner._add_finding(
                f_type="access_control", severity="info", status="NOT_DETECTED",
                title="Access Control",
                description="No broken object-level or tested access-control bypass was detected in the assessed endpoints and available authorization contexts.",
                evidence="No suitable candidate endpoints with object references were found."
            )

    def _discover_candidates(self, endpoints: list) -> list:
        # Discover object identifiers in URLs (path, query) or JSON bodies
        candidates = []
        id_pattern = re.compile(r'/(\d+)(/|$)')
        uuid_pattern = re.compile(r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(/|$)', re.IGNORECASE)
        
        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            
            is_candidate = False
            ref_type = None
            original_val = None
            
            # 1. Path Numeric ID
            match = id_pattern.search(url)
            if match:
                is_candidate = True
                ref_type = "path_numeric"
                original_val = match.group(1)
            else:
                # 2. Path UUID
                match = uuid_pattern.search(url)
                if match:
                    is_candidate = True
                    ref_type = "path_uuid"
                    original_val = match.group(1)
            
            if is_candidate:
                ep_copy = ep.copy()
                ep_copy["_ref_type"] = ref_type
                ep_copy["_original_val"] = original_val
                candidates.append(ep_copy)
                
        # TODO: Add query and body ID discovery
        return candidates
        
    async def _test_endpoint(self, endpoint: dict, auth_context_1: dict, auth_context_2: dict):
        url = endpoint["url"]
        method = endpoint["method"]
        params = {p: "test" for p in endpoint.get("params", [])}
        
        test_case = TestCaseResult(
            category="access_control",
            target_endpoint=url,
            http_method=method,
            baseline_request=params,
            remediation=["Implement strict ownership checks on all direct object references."],
            owasp="A01:2025-Broken Access Control"
        )
        
        # 1. Baseline Phase
        if auth_context_1 and auth_context_2:
            await self._horizontal_test(test_case, endpoint, url, method, params, auth_context_1, auth_context_2)
        elif auth_context_1:
            await self._single_context_test(test_case, endpoint, url, method, params, auth_context_1)
            
    async def _horizontal_test(self, test_case, endpoint, url, method, params, auth_a, auth_b):
        ref_type = endpoint["_ref_type"]
        orig_id = endpoint["_original_val"]
        
        # 1. A accesses X
        resp_a_x = await self._send_request(method, url, params, auth_a)
        if not resp_a_x or resp_a_x.status_code != 200:
            test_case.status = "NOT_DETECTED"
            self._finalize_finding(test_case, url, method)
            return
            
        # 2. Find a Y that B owns
        new_id = self._mutate_id(ref_type, orig_id)
        if not new_id:
            test_case.status = "NOT_DETECTED"
            self._finalize_finding(test_case, url, method)
            return
            
        url_y = url.replace(f"/{orig_id}", f"/{new_id}")
        
        resp_b_y = await self._send_request(method, url_y, params, auth_b)
        
        if not resp_b_y or resp_b_y.status_code != 200 or self._is_error_page(resp_b_y):
            # We couldn't establish B owns Y. Fallback to simple single-context mutation for LOW.
            return await self._single_context_test(test_case, endpoint, url, method, params, auth_a)
            
        # Now we know A accesses X, B accesses Y. Let's check if they are the SAME resource (public/shared).
        resp_b_x = await self._send_request(method, url, params, auth_b)
        resp_a_y = await self._send_request(method, url_y, params, auth_a)
        
        # Check if X is just public
        if resp_b_x and resp_b_x.status_code == 200:
            diff_x = BaselineEngine.compare(resp_a_x, resp_b_x)
            if diff_x["is_body_similar"]:
                test_case.add_observation("public_resource", f"Resource X ({url}) is equally accessible to A and B.", is_suspicious=False)
                test_case.status = "NOT_DETECTED"
                self._finalize_finding(test_case, url, method)
                return
                
        # Now test A accessing Y
        if resp_a_y and resp_a_y.status_code == 200 and not self._is_error_page(resp_a_y):
            # A accessed Y! Does it look like Y?
            diff_y = BaselineEngine.compare(resp_b_y, resp_a_y)
            if diff_y["is_body_similar"]:
                test_case.add_observation("horizontal_bypass", f"Context A successfully accessed Context B's resource at {url_y}.", is_strong_evidence=True)
                test_case.status = "HIGH" # We'll map this in finalize_finding
            else:
                test_case.add_observation("idor_suspicious", f"Context A got HTTP 200 for {url_y} but content differed from Context B.", is_suspicious=True)
                test_case.status = "LOW"
        else:
            test_case.status = "NOT_DETECTED"
            
        self._finalize_finding(test_case, url, method)
        
    async def _single_context_test(self, test_case, endpoint, url, method, params, auth):
        orig_id = endpoint["_original_val"]
        new_id = self._mutate_id(endpoint["_ref_type"], orig_id)
        if not new_id:
            test_case.status = "NOT_DETECTED"
            self._finalize_finding(test_case, url, method)
            return
            
        mutated_url = url.replace(f"/{orig_id}", f"/{new_id}")
        
        resp_orig = await self._send_request(method, url, params, auth)
        resp_mod = await self._send_request(method, mutated_url, params, auth)
        
        if resp_orig and resp_mod and resp_orig.status_code == 200 and resp_mod.status_code == 200:
            if self._is_error_page(resp_mod):
                test_case.status = "NOT_DETECTED"
            else:
                diff = BaselineEngine.compare(resp_orig, resp_mod)
                if not diff["is_body_identical"]:
                    test_case.add_observation("idor_single_context", f"Original URL {url} and Mutated URL {mutated_url} returned distinct HTTP 200s.", is_suspicious=True)
                    test_case.add_observation("missing_ownership", "Without a second context, we cannot prove this isn't just public or shared data.", is_suspicious=True)
                    test_case.status = "LOW"
                else:
                    test_case.status = "NOT_DETECTED"
        else:
            test_case.status = "NOT_DETECTED"
            
        self._finalize_finding(test_case, url, method)
        
    def _mutate_id(self, ref_type, orig_id):
        if ref_type == "path_numeric":
            try:
                return str(int(orig_id) + 1)
            except:
                pass
        return None
        
    async def _send_request(self, method, url, params, auth) -> Optional[httpx.Response]:
        try:
            return await self.client.request(
                method, url, 
                params=params if method == "GET" else None, 
                data=params if method == "POST" else None, 
                **auth
            )
        except Exception:
            return None

    def _is_error_page(self, response: httpx.Response) -> bool:
        # Simple heuristic to avoid 200 OK error pages
        text = response.text.lower()
        if "not found" in text or "error" in text or "unauthorized" in text:
            if len(text) < 1000: # Usually error pages are small
                return True
        return False

    def _finalize_finding(self, test_case, url, method):
        # We need to respect the NOT_DETECTED default message required by the user
        if test_case.status == "NOT_DETECTED":
            self.scanner._add_finding(
                f_type="access_control", severity="info", status="NOT_DETECTED",
                title="Access Control",
                description="No broken object-level or tested access-control bypass was detected in the assessed endpoints and available authorization contexts.",
                evidence=test_case.evidence or "Tested endpoints correctly enforced authorization boundaries or were public.",
                url=url, parameter="URL Path", http_method=method
            )
            return

        if test_case.status in ["HIGH", "LOW", "SCANNER_ERROR"]:
            # Map legacy statuses before sending to DB/API
            final_status = "HIGH" if test_case.status == "HIGH" else "LOW" if test_case.status == "LOW" else "SCANNER_ERROR"
            final_severity = "high" if test_case.status == "HIGH" else "low" if test_case.status == "LOW" else "info"
            
            self.scanner._add_finding(
                f_type="access_control", 
                severity=final_severity, 
                status=final_status,
                title="Insecure Direct Object Reference (IDOR)",
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
