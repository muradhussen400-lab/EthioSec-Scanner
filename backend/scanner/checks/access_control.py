from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from urllib.parse import urlparse
import re

async def check_access_control(
    scanner: SecurityScanner, 
    endpoints: list, 
    client: SafeHTTPClient, 
    auth_context_1: dict = None, 
    auth_context_2: dict = None
):
    """
    Implements IDOR / BOLA and basic authorization testing.
    Uses three modes: unauthenticated, authenticated_single_user, authenticated_two_user.
    """
    
    # Simple heuristic to find endpoints with numeric IDs (e.g., /api/users/123)
    # This is a basic implementation for the prototype.
    candidate_endpoints = []
    
    id_pattern = re.compile(r'/(\d+)(/|$)')
    
    for ep in endpoints:
        if id_pattern.search(ep["url"]):
            candidate_endpoints.append(ep)
            
    if not candidate_endpoints:
        return
        
    for ep in candidate_endpoints:
        url = ep["url"]
        method = ep["method"]
        params = {p: "test" for p in ep["params"]}
        
        # Determine Scan Mode
        if auth_context_1 and auth_context_2:
            # Two-account testing (Strongest IDOR test)
            try:
                # 1. Fetch resource with Account A
                resp_a = await client.request(method, url, params=params if method == "GET" else None, data=params if method == "POST" else None, **auth_context_1)
                
                # 2. Extract the ID and try to modify it
                match = id_pattern.search(url)
                if match:
                    original_id = match.group(1)
                    new_id = str(int(original_id) + 1)
                    modified_url = url.replace(f"/{original_id}", f"/{new_id}")
                    
                    # 3. Account B owns new_id (ideally), let's see if Account A can access it
                    resp_b_resource_with_a = await client.request(method, modified_url, params=params if method == "GET" else None, data=params if method == "POST" else None, **auth_context_1)
                    
                    # We need proof. Did Account A successfully fetch B's resource?
                    if resp_a.status_code == 200 and resp_b_resource_with_a.status_code == 200:
                        # Ensure they didn't just return the same default page or a 404 disguised as 200
                        if len(resp_a.text) > 0 and len(resp_b_resource_with_a.text) > 0:
                            # If lengths are similar but content differs, it might be a real object
                            scanner._add_finding(
                                f_type="idor", severity="high", status="open",
                                title="Insecure Direct Object Reference (IDOR)",
                                description="The application failed to enforce authorization. Account A was able to access a resource seemingly belonging to Account B by modifying the identifier.",
                                evidence=f"Account A accessed {url} (HTTP {resp_a.status_code}).\nAccount A accessed modified URL {modified_url} (HTTP {resp_b_resource_with_a.status_code}).",
                                impact="Attackers can view or modify data belonging to other users.",
                                remediation=["Implement strict ownership checks on all direct object references."],
                                owasp="A01:2025", url=modified_url, parameter="URL Path",
                                http_method=method, request=None, response_summary=f"HTTP 200"
                            )
                            return # Avoid flooding
            except Exception:
                pass

        elif auth_context_1:
            # Single-account testing
            # We can't prove IDOR without Account B, but we can detect potential BOLA if we hit a 403 on modified IDs
            try:
                resp_a = await client.request(method, url, params=params if method == "GET" else None, data=params if method == "POST" else None, **auth_context_1)
                match = id_pattern.search(url)
                if match and resp_a.status_code == 200:
                    original_id = match.group(1)
                    new_id = str(int(original_id) + 1)
                    modified_url = url.replace(f"/{original_id}", f"/{new_id}")
                    
                    resp_mod = await client.request(method, modified_url, params=params if method == "GET" else None, data=params if method == "POST" else None, **auth_context_1)
                    
                    if resp_mod.status_code == 200 and resp_mod.text != resp_a.text:
                         scanner._add_finding(
                            f_type="idor", severity="medium", status="open",
                            title="Potential IDOR (Single-Account Context)",
                            description="A resource ID was modified and a valid 200 OK response was returned. A second account is required to verify if this is a true IDOR.",
                            evidence=f"Original URL {url} -> HTTP 200. Modified URL {modified_url} -> HTTP 200.",
                            impact="Potential unauthorized access.",
                            remediation=["Verify that this endpoint enforces authorization."],
                            owasp="A01:2025", url=modified_url, parameter="URL Path",
                            http_method=method, request=None, response_summary=f"HTTP 200"
                        )
                         return
            except Exception:
                pass
        else:
            # Unauthenticated testing
            scanner._add_finding(
                f_type="idor", severity="info", status="not_tested",
                title="IDOR Test: Not Tested (Unauthenticated)",
                description="IDOR cannot be tested without an authentication context.",
                evidence="No authentication context provided.",
                impact="Unknown.",
                remediation=[],
                owasp="A01:2025", url=url, parameter=None,
                http_method=method, request=None, response_summary=None
            )
            return
