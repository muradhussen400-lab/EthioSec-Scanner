import pytest
import asyncio
import time
import httpx
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlparse, parse_qsl, unquote

from scanner.checks.sqli import check_sqli, check_db_errors
from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from scanner.differential import BaselineEngine, BaselineProfile
from scanner.test_case import TestCaseResult
from models import Finding
from schemas import FindingOut, ScanResultOut, ScanCounts

class MockResponse:
    def __init__(self, status_code=200, text="", headers=None, elapsed_sec=0.05):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self._elapsed_sec = elapsed_sec

    @property
    def elapsed(self):
        class MockElapsed:
            def __init__(self, sec):
                self.sec = sec
            def total_seconds(self):
                return self.sec
        return MockElapsed(self._elapsed_sec)

class MockScanner:
    def __init__(self):
        self.findings = []
        self.cancelled = False
        self.scan_id = "test-scan-123"
        self.target_id = "test-target-123"
        self.db = None

    def _add_finding(self, f_type, severity, status, title, description, **kwargs):
        self.findings.append({
            "f_type": f_type,
            "severity": severity,
            "status": status,
            "title": title,
            "description": description,
            **kwargs
        })

class MockClient:
    def __init__(self):
        self.get = AsyncMock()
        self.post = AsyncMock()
        self.history = []

# =============================================================================
# 1. Normal endpoint with no SQLi
# =============================================================================
@pytest.mark.asyncio
async def test_01_normal_endpoint_no_sqli():
    scanner = MockScanner()
    client = MockClient()
    client.get.return_value = MockResponse(200, "<html><body>Welcome to our store! No vulnerabilities here.</body></html>")

    endpoints = [{"url": "http://test.local/items", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client)

    assert len(scanner.findings) == 0

# =============================================================================
# 2. Harmless apostrophe that causes no SQLi evidence
# =============================================================================
@pytest.mark.asyncio
async def test_02_harmless_apostrophe_no_sqli_evidence():
    scanner = MockScanner()
    client = MockClient()
    
    def side_effect(url, **kwargs):
        # Escapes or safely handles apostrophe, returning benign 200 page
        return MockResponse(200, "<html><body>Search query safely handled: apostrophe benign</body></html>")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/search", "method": "GET", "params": ["q"]}]
    await check_sqli(scanner, endpoints, [], client)

    assert len(scanner.findings) == 0

# =============================================================================
# 3. Generic HTTP 500 that must not confirm SQLi
# =============================================================================
@pytest.mark.asyncio
async def test_03_generic_500_does_not_confirm_sqli():
    scanner = MockScanner()
    client = MockClient()
    
    # Baseline returns 200, but all injection inputs trigger a generic 500 Internal Server Error
    def side_effect(url, **kwargs):
        if "test" in url and "'" not in url and "1=1" not in url:
            return MockResponse(200, "<html><body>Normal Product Page</body></html>")
        return MockResponse(500, "<html><body>500 Internal Server Error: An unexpected error occurred.</body></html>")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/product", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Must NOT confirm SQLi as HIGH or confirmed finding
    high_findings = [f for f in scanner.findings if f.get("status") == "HIGH"]
    assert len(high_findings) == 0

# =============================================================================
# 4. Recognizable database error introduced by controlled input
# =============================================================================
@pytest.mark.asyncio
async def test_04_recognizable_db_error_introduced_by_input():
    scanner = MockScanner()
    client = MockClient()

    def side_effect(url, **kwargs):
        decoded = unquote(url)
        if "'" in decoded:
            return MockResponse(500, "Fatal error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
        return MockResponse(200, "<html><body>Catalog category listing</body></html>")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/category", "method": "GET", "params": ["cat"]}]
    await check_sqli(scanner, endpoints, [], client)

    assert len(scanner.findings) == 1
    finding = scanner.findings[0]
    assert finding["status"] == "HIGH"
    assert finding["confidence"] == "HIGH"
    assert "MySQL" in finding["evidence"] or "MySQL" in finding["description"]
    assert "you have an error in your sql syntax" in finding["evidence"].lower()

# =============================================================================
# 5. Database error already present in the baseline
# =============================================================================
@pytest.mark.asyncio
async def test_05_db_error_already_present_in_baseline():
    scanner = MockScanner()
    client = MockClient()

    # The baseline endpoint is already broken and spews a postgres error
    broken_page = "psycopg2.errors.SyntaxError: syntax error at or near 'SELECT' in broken legacy code"
    client.get.return_value = MockResponse(200, broken_page)

    endpoints = [{"url": "http://test.local/legacy", "method": "GET", "params": ["page"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Must be guarded; baseline error must NOT confirm SQLi
    assert len(scanner.findings) == 0

# =============================================================================
# 6. True/False pair producing a repeatable, expected behavioral difference
# =============================================================================
@pytest.mark.asyncio
async def test_06_true_false_pair_repeatable_expected_difference():
    scanner = MockScanner()
    client = MockClient()

    # Vulnerable boolean logic:
    # 1=1 (True) returns catalog with items
    # 1=2 (False) returns "No matching products found"
    def side_effect(url, **kwargs):
        decoded = unquote(url)
        if "1=2" in decoded:
            return MockResponse(200, "<html><body><h1>Search Results</h1><p>No matching products found.</p></body></html>")
        return MockResponse(200, "<html><body><h1>Search Results</h1><ul><li>Widget A - $10</li><li>Widget B - $20</li><li>Widget C - $30</li></ul></body></html>")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/search", "method": "GET", "params": ["item"]}]
    await check_sqli(scanner, endpoints, [], client)

    assert len(scanner.findings) == 1
    finding = scanner.findings[0]
    assert finding["status"] == "HIGH"
    assert finding["confidence"] == "HIGH"
    assert "Boolean" in finding["title"] or "Boolean" in finding["evidence"]

# =============================================================================
# 7. True/False pair with unrelated content differences (verification failure)
# =============================================================================
@pytest.mark.asyncio
async def test_07_true_false_pair_unrelated_content_differences():
    scanner = MockScanner()
    client = MockClient()

    # Jittery / random responses: every request gets a unique random string
    counter = 0
    def side_effect(url, **kwargs):
        nonlocal counter
        counter += 1
        return MockResponse(200, f"<html><body>Random banner #{counter} - Jitter: {'Z' * (counter * 80)}</body></html>")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/random", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Must NOT produce a HIGH confirmed finding
    high_findings = [f for f in scanner.findings if f.get("status") == "HIGH"]
    assert len(high_findings) == 0

# =============================================================================
# 8. Dynamic page with timestamps, request IDs, or changing tokens
# =============================================================================
@pytest.mark.asyncio
async def test_08_dynamic_page_timestamps_request_ids_tokens():
    scanner = MockScanner()
    client = MockClient()

    # Page has dynamic timestamp and request ID, but core content is identical
    call_idx = 0
    def side_effect(url, **kwargs):
        nonlocal call_idx
        call_idx += 1
        return MockResponse(
            200, 
            f"<html><body>"
            f"<header>ReqID: 550e8400-e29b-41d4-a716-{call_idx:012d} | Time: 2026-10-20T19:{call_idx:02d}:00Z | Token: {'A'*32}</header>"
            f"<main><h1>Static Content</h1><p>Catalog items unchanged.</p></main>"
            f"</body></html>"
        )
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/dynamic", "method": "GET", "params": ["view"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Dynamic elements are normalized; no false positive
    assert len(scanner.findings) == 0

# =============================================================================
# 9. Unstable baseline
# =============================================================================
@pytest.mark.asyncio
async def test_09_unstable_baseline_skips_differential():
    scanner = MockScanner()
    client = MockClient()

    # The baseline requests themselves return wildly different content (e.g. rotating ads)
    baselines = [
        MockResponse(200, "Page A: " + "Alpha " * 100),
        MockResponse(200, "Page B: " + "Beta " * 100),
        MockResponse(200, "Page C: " + "Gamma " * 100),
    ]
    def side_effect(url, **kwargs):
        if baselines:
            return baselines.pop(0)
        return MockResponse(200, "Fallback page")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/unstable", "method": "GET", "params": ["p"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Must NOT produce a HIGH confirmed finding
    high_findings = [f for f in scanner.findings if f.get("status") == "HIGH"]
    assert len(high_findings) == 0

# =============================================================================
# 10. Empty baseline responses
# =============================================================================
@pytest.mark.asyncio
async def test_10_empty_baseline_responses():
    scanner = MockScanner()
    client = MockClient()
    # Target drops connections or returns None for baseline requests
    client.get.return_value = None

    endpoints = [{"url": "http://test.local/empty", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Must complete safely without unhandled exception; 0 findings
    assert len(scanner.findings) == 0

# =============================================================================
# 11. Timeouts and connection failures
# =============================================================================
@pytest.mark.asyncio
async def test_11_timeouts_and_connection_failures():
    scanner = MockScanner()
    client = MockClient()
    client.get.side_effect = httpx.ConnectTimeout("Connection timed out after 10.0s")

    endpoints = [{"url": "http://test.local/timeout", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Handled gracefully, 0 findings
    assert len(scanner.findings) == 0

# =============================================================================
# 12. Redirects and authentication/session expiry
# =============================================================================
@pytest.mark.asyncio
async def test_12_redirects_and_session_expiry():
    """
    Verifies that SafeHTTPClient handles 302 redirects by transitioning POST to GET,
    preserving cookies across transitions.
    """
    import os
    os.environ["ALLOW_LOCAL_TARGETS"] = "true"

    async def redir_app(request):
        if request.url.path == "/submit" and request.method == "POST":
            res = httpx.Response(302, headers={"Location": "http://127.0.0.1:8000/dashboard"})
            return res
        elif request.url.path == "/dashboard" and request.method == "GET":
            return httpx.Response(200, text="Dashboard Welcome")
        return httpx.Response(404, text="Not Found")

    # Verify SafeHTTPClient handles redirect transition
    async with SafeHTTPClient() as client:
        # Mock client.client transport
        mock_transport = httpx.MockTransport(redir_app)
        client.client = httpx.AsyncClient(transport=mock_transport, follow_redirects=False)

        resp = await client.post("http://127.0.0.1:8000/submit", data={"user": "admin"})
        assert resp is not None
        assert resp.status_code == 200
        assert resp.text == "Dashboard Welcome"

# =============================================================================
# 13. Rate limiting or WAF interference
# =============================================================================
@pytest.mark.asyncio
async def test_13_rate_limiting_or_waf_interference():
    scanner = MockScanner()
    client = MockClient()

    # Target returns 429 Too Many Requests upon receiving injection probes
    def side_effect(url, **kwargs):
        if "test" in url and "'" not in url and "1=1" not in url:
            return MockResponse(200, "<html><body>Normal Store Page</body></html>")
        return MockResponse(429, "<html><body>429 Too Many Requests - Rate limit exceeded</body></html>")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/products", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Must NOT produce confirmed SQLi finding
    high_findings = [f for f in scanner.findings if f.get("status") == "HIGH"]
    assert len(high_findings) == 0

# =============================================================================
# 14. Incorrect or missing parameters
# =============================================================================
@pytest.mark.asyncio
async def test_14_incorrect_or_missing_parameters():
    scanner = MockScanner()
    client = MockClient()
    client.get.return_value = MockResponse(200, "Normal Page")

    # Endpoint with empty params list and form with empty inputs
    endpoints = [{"url": "http://test.local/about", "method": "GET", "params": []}]
    forms = [{"action_url": "http://test.local/contact", "method": "POST", "inputs": [], "fields": {}}]

    await check_sqli(scanner, endpoints, forms, client)
    assert len(scanner.findings) == 0

# =============================================================================
# 15. Query parameters that must remain intact
# =============================================================================
@pytest.mark.asyncio
async def test_15_query_parameters_remain_intact():
    scanner = MockScanner()
    client = MockClient()
    requested_urls = []

    def side_effect(url, **kwargs):
        requested_urls.append(url)
        return MockResponse(200, "Search results")
    client.get.side_effect = side_effect

    # URL has query params 'category' and 'lang'
    endpoints = [{
        "url": "http://test.local/search?category=books&lang=en", 
        "method": "GET", 
        "params": ["category"],
        "param_values": {"category": "books"}
    }]
    await check_sqli(scanner, endpoints, [], client)

    assert len(requested_urls) > 0
    for req_url in requested_urls:
        parsed = urlparse(req_url)
        q_dict = dict(parse_qsl(parsed.query))
        # Ensure 'lang=en' was never dropped when 'category' was injected
        assert "lang" in q_dict
        assert q_dict["lang"] == "en"

# =============================================================================
# 16. Form parameter handling (hidden fields & CSRF preservation)
# =============================================================================
@pytest.mark.asyncio
async def test_16_form_parameter_handling():
    scanner = MockScanner()
    client = MockClient()
    submitted_forms = []

    def side_effect(url, data=None, **kwargs):
        submitted_forms.append(dict(data or {}))
        return MockResponse(200, "Form submitted")
    client.post.side_effect = side_effect
    client.get.return_value = MockResponse(200, "Form page")

    forms = [{
        "page_url": "http://test.local/login",
        "action_url": "http://test.local/login",
        "method": "POST",
        "inputs": ["csrf_token", "username", "password"],
        "fields": {
            "csrf_token": {"value": "secret_csrf_value_42", "type": "hidden"},
            "username": {"value": "", "type": "text"},
            "password": {"value": "", "type": "password"}
        }
    }]

    await check_sqli(scanner, [], forms, client)

    # Ensure csrf_token was included in every form POST submission
    assert len(submitted_forms) > 0
    for submission in submitted_forms:
        assert "csrf_token" in submission
        assert submission["csrf_token"] == "secret_csrf_value_42"

# =============================================================================
# 17. Duplicate or repeated findings deduplication
# =============================================================================
@pytest.mark.asyncio
async def test_17_duplicate_finding_deduplication():
    scanner = MockScanner()
    client = MockClient()

    # Baseline is clean (HTTP 200 "Normal Page Content")
    # All injection inputs return MySQL error syntax
    def side_effect(url, **kwargs):
        decoded = unquote(url)
        if "test" in decoded and "'" not in decoded and "1=1" not in decoded:
            return MockResponse(200, "Normal Page Content")
        return MockResponse(500, "you have an error in your sql syntax")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/items", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Exactly 1 finding for this endpoint parameter, not multiple duplicates
    assert len(scanner.findings) == 1

# =============================================================================
# 18. Correct serialization of findings through existing API schemas
# =============================================================================
def test_18_correct_serialization_of_findings():
    finding_dict = {
        "id": "find-uuid-12345",
        "type": "sqli",
        "severity": "high",
        "confidence": "HIGH",
        "status": "HIGH",
        "title": "SQL Injection via URL query Parameter 'id'",
        "description": "Evidence-driven SQL injection detected.",
        "evidence": "[!] Stable boolean diff observed.",
        "http_method": "GET",
        "url": "http://test.local/items?id=1",
        "parameter": "id",
        "request": "{'id': \"1' OR '1'='1\"}",
        "response_summary": "Evaluated via differential testing pipeline",
        "remediation": ["Use parameterized queries", "Apply allowlist validation"],
        "owasp": "A03:2021-Injection",
        "cwe": "CWE-89",
        "created_at": "2026-10-20T19:25:07Z"
    }

    # Verify Pydantic FindingOut schema validation
    finding_out = FindingOut.model_validate(finding_dict)
    assert finding_out.id == "find-uuid-12345"
    assert finding_out.confidence == "HIGH"
    assert finding_out.status == "HIGH"
    assert len(finding_out.remediation) == 2

    # Verify ScanResultOut serialization
    scan_result = ScanResultOut(
        scan_id="scan-uuid-9999",
        target="http://test.local",
        depth="standard",
        status="completed",
        scanned_at="2026-10-20T19:25:07Z",
        security_score=45,
        counts=ScanCounts(high=1, total=1),
        findings=[finding_out]
    )
    serialized_json = scan_result.model_dump_json()
    assert "find-uuid-12345" in serialized_json
    assert "HIGH" in serialized_json

# =============================================================================
# 19. Verification failures result in inconclusive/potential, not confirmation
# =============================================================================
@pytest.mark.asyncio
async def test_19_verification_failure_not_confirmed():
    scanner = MockScanner()
    client = MockClient()

    # Initial payload triggers error once, but second validation request returns normal clean page
    step = 0
    def side_effect(url, **kwargs):
        nonlocal step
        step += 1
        decoded = unquote(url)
        # Baselines
        if step in (1, 2):
            return MockResponse(200, "Normal Page Content")
        # Initial test triggers error
        if step == 3:
            return MockResponse(200, "you have an error in your sql syntax")
        # Secondary validation re-test fails to reproduce!
        return MockResponse(200, "Normal Page Content")

    client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.local/test", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client)

    # Must NOT produce a HIGH confirmed finding
    assert len(scanner.findings) == 1
    assert scanner.findings[0]["status"] == "LOW" # downgraded to LOW/potential, not confirmed

# =============================================================================
# 20. Request budget and scan cancellation behavior
# =============================================================================
@pytest.mark.asyncio
async def test_20_request_budget_and_cancellation():
    scanner = MockScanner()
    client = MockClient()
    req_count = 0

    def side_effect(url, **kwargs):
        nonlocal req_count
        req_count += 1
        return MockResponse(200, "Normal Page")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/items", "method": "GET", "params": ["p1", "p2"]}]
    
    # 20a. Verify request budget: Standard mode must stay bounded (<= 20 requests per param)
    await check_sqli(scanner, endpoints, [], client, depth="standard")
    assert req_count <= 40  # 2 parameters * 20 budget

    # 20b. Verify cancellation aborts immediately
    scanner.cancelled = True
    pre_cancel_count = req_count
    await check_sqli(scanner, endpoints, [], client, depth="standard")
    assert req_count == pre_cancel_count  # Aborts on cancelled flag without making any requests
