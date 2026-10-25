import pytest
import os
import asyncio
import datetime
import html
import httpx
from unittest.mock import patch, AsyncMock
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from scanner.http_client import SafeHTTPClient
from scanner.checks.xss import (
    check_xss, 
    XSSCoverageRecord,
    mutate_url_parameter,
    analyze_reflection_contexts,
    analyze_encoding_transformations,
    evaluate_context_vulnerability
)
from scanner.differential import BaselineEngine, BaselineProfile
from scanner.test_case import TestCaseResult
from models import Finding, Scan, ScanTarget, User, generate_uuid
from schemas import FindingOut

@pytest.fixture(autouse=True)
def mock_is_safe():
    with patch("scanner.engine.is_safe_url", return_value=True), \
         patch("scanner.safety.is_safe_url", return_value=True), \
         patch("scanner.http_client.is_safe_url", return_value=True):
        yield

class MockScanner:
    def __init__(self, target_url="https://test.local/"):
        self.target_url = target_url
        self.findings = []
        self.inventory = {}
        self.cancelled = False
        self.scan_id = f"test-scan-{generate_uuid()}"
        self.target_id = f"test-target-{generate_uuid()}"
        self.db = None

    def _add_finding(self, **kwargs):
        self.findings.append(kwargs)

    def _redact_evidence(self, text):
        return text


# ==============================================================================
# CASE 1: A marker reflected as HTML-encoded text (No confirmed XSS)
# ==============================================================================
@pytest.mark.asyncio
async def test_01_marker_reflected_as_html_encoded_text():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        # Safely entity encoded
        return HTMLResponse(f"<html><body>Results for: {html.escape(q)}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/search", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/search?q=test")
        endpoints = [{"url": "https://test.local/search", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.inputs_tested == 1
        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0


# ==============================================================================
# CASE 2: A marker reflected as plain text: no confirmed XSS on reflection alone
# ==============================================================================
@pytest.mark.asyncio
async def test_02_marker_reflected_as_plain_text():
    async def app_handler(request):
        name = request.query_params.get("name", "")
        # Neutralizes HTML tags (< > stripped), plain text reflection only
        clean_name = name.replace("<", "").replace(">", "").replace('"', "&quot;").replace("'", "&#39;")
        return HTMLResponse(f"<html><body>Hello, {clean_name}!</body></html>", status_code=200)

    app = Starlette(routes=[Route("/greet", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/greet?name=alice")
        endpoints = [{"url": "https://test.local/greet", "method": "GET", "params": ["name"], "param_values": {"name": "alice"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        # Reflection alone must NOT produce a vulnerability finding
        assert coverage.inputs_tested == 1
        assert len(scanner.findings) == 0


# ==============================================================================
# CASE 3: A harmless reflected marker that is absent from the baseline
# ==============================================================================
@pytest.mark.asyncio
async def test_03_harmless_reflected_marker_absent_from_baseline():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        # Baseline response is clean
        if not q or q == "test":
            return HTMLResponse("<html><body>Welcome to search</body></html>", status_code=200)
        # Reflects strictly harmless characters, strips brackets & quotes
        safe_reflected = q.replace("<", "").replace(">", "").replace('"', "").replace("'", "")
        return HTMLResponse(f"<html><body>Welcome to search. Query: {safe_reflected}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/search", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/search?q=test")
        endpoints = [{"url": "https://test.local/search", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        # Marker was absent in baseline and present in probe, but properly neutralized -> no finding
        assert coverage.inputs_tested == 1
        assert len(scanner.findings) == 0


# ==============================================================================
# CASE 4: Input reflected in a quoted HTML attribute (safe vs breakout)
# ==============================================================================
@pytest.mark.asyncio
async def test_04_input_reflected_in_quoted_html_attribute():
    async def app_handler(request):
        search = request.query_params.get("search", "")
        # Vulnerable double-quoted attribute breakout
        return HTMLResponse(f'<html><body><input type="text" name="search" value="{search}"></body></html>', status_code=200)

    app = Starlette(routes=[Route("/items", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/items?search=shoes")
        endpoints = [{"url": "https://test.local/items", "method": "GET", "params": ["search"], "param_values": {"search": "shoes"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        assert len(scanner.findings) == 1
        f = scanner.findings[0]
        assert f["f_type"] == "xss"
        assert f["parameter"] == "search"
        assert f["status"] == "MEDIUM"
        assert f["verification_status"] == "POTENTIAL"
        assert "attribute_double_quoted" in f["evidence"] or "controlled_validation" in f["evidence"]


# ==============================================================================
# CASE 5: Input reflected in an unquoted attribute
# ==============================================================================
@pytest.mark.asyncio
async def test_05_input_reflected_in_unquoted_attribute():
    async def app_handler(request):
        color = request.query_params.get("color", "blue")
        # Unquoted attribute value
        return HTMLResponse(f'<html><body><div class={color}>Content</div></body></html>', status_code=200)

    app = Starlette(routes=[Route("/profile", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/profile?color=blue")
        endpoints = [{"url": "https://test.local/profile", "method": "GET", "params": ["color"], "param_values": {"color": "blue"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        f = scanner.findings[0]
        assert f["parameter"] == "color"
        assert f["verification_status"] == "POTENTIAL"


# ==============================================================================
# CASE 6: Input reflected in a JavaScript context
# ==============================================================================
@pytest.mark.asyncio
async def test_06_input_reflected_in_javascript_context():
    async def app_handler(request):
        user = request.query_params.get("user", "")
        # Raw unescaped quote in JS string
        return HTMLResponse(f"<html><body><script>var currentUser = '{user}';</script></body></html>", status_code=200)

    app = Starlette(routes=[Route("/app", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/app?user=guest")
        endpoints = [{"url": "https://test.local/app", "method": "GET", "params": ["user"], "param_values": {"user": "guest"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        f = scanner.findings[0]
        assert f["parameter"] == "user"
        assert f["verification_status"] == "POTENTIAL"
        assert "javascript_single_quoted" in f["evidence"] or "controlled_validation" in f["evidence"]


# ==============================================================================
# CASE 7: Input reflected inside an HTML comment
# ==============================================================================
@pytest.mark.asyncio
async def test_07_input_reflected_inside_html_comment():
    async def app_handler(request):
        debug = request.query_params.get("debug", "")
        return HTMLResponse(f"<html><body><!-- Debug info: {debug} --><h1>Home</h1></body></html>", status_code=200)

    app = Starlette(routes=[Route("/debug", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/debug?debug=test")
        endpoints = [{"url": "https://test.local/debug", "method": "GET", "params": ["debug"], "param_values": {"debug": "test"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        f = scanner.findings[0]
        assert f["parameter"] == "debug"
        assert f["verification_status"] == "POTENTIAL"
        assert "comment" in f["evidence"]


# ==============================================================================
# CASE 8: Input placed in a JSON response (Safe, no HTML injection)
# ==============================================================================
@pytest.mark.asyncio
async def test_08_input_placed_in_json_response():
    async def app_handler(request):
        term = request.query_params.get("term", "")
        # Content-Type: application/json. Raw HTML characters in JSON strings are NOT executable XSS.
        return JSONResponse({"status": "success", "query": term, "results": []})

    app = Starlette(routes=[Route("/api/items", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/api/items?term=shoes")
        endpoints = [{"url": "https://test.local/api/items", "method": "GET", "content_type": "application/json", "params": ["term"], "param_values": {"term": "shoes"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        # Must not report JSON reflection as XSS vulnerability
        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0


# ==============================================================================
# CASE 9: Input removed or transformed by a sanitizer
# ==============================================================================
@pytest.mark.asyncio
async def test_09_input_removed_or_transformed_by_sanitizer():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        # Sanitizer removes all tags completely
        clean = q.replace("<script>", "").replace("</script>", "").replace("<", "").replace(">", "")
        return HTMLResponse(f"<html><body>Search results: {clean}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/search", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/search?q=test")
        endpoints = [{"url": "https://test.local/search", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        # Sanitizer neutralized the tags -> no breakout -> no finding
        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0


# ==============================================================================
# CASE 10: Injected HTML element without browser execution evidence
# ==============================================================================
@pytest.mark.asyncio
async def test_10_injected_html_element_without_browser_execution():
    async def app_handler(request):
        msg = request.query_params.get("msg", "")
        # Allows HTML markup (e.g. <b>Hello</b>), but browser execution was not verified
        return HTMLResponse(f"<html><body>Notice: {msg}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/notice", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/notice?msg=welcome")
        endpoints = [{"url": "https://test.local/notice", "method": "GET", "params": ["msg"], "param_values": {"msg": "welcome"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert len(scanner.findings) == 1
        f = scanner.findings[0]
        # Defensible evidence hierarchy: reported as POTENTIAL / Structural HTML Injection, NOT CONFIRMED
        assert f["verification_status"] == "POTENTIAL"
        assert f["status"] == "MEDIUM"
        assert "Potential Reflected XSS / Structural HTML Injection" in f["title"]
        assert "Browser-side script execution was not validated" in f["description"]


# ==============================================================================
# CASE 11: Browser execution signal contract test (Mocked verification signal)
# NOTE: Uses a mocked verify_browser_execution response to test the signal handling contract.
# This test does NOT launch a live browser instance.
# ==============================================================================
@pytest.mark.asyncio
async def test_11_simulated_browser_execution_signal_contract():
    async def app_handler(request):
        payload = request.query_params.get("q", "")
        return HTMLResponse(f"<html><body>Search: {payload}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/exec", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/exec?q=test")
        endpoints = [{"url": "https://test.local/exec", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]

        # Simulate browser execution verification succeeding via Canary signal
        with patch("scanner.checks.xss.verify_browser_execution", AsyncMock(return_value=("CONFIRMED", "Canary signal window.__ethioxss_token fired"))):
            coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert len(scanner.findings) == 1
        f = scanner.findings[0]
        assert f["verification_status"] == "CONFIRMED"
        assert f["status"] == "HIGH"
        assert f["severity"] == "high"
        assert "Reflected Cross-Site Scripting (XSS) Executable" in f["title"]
        assert "Canary signal" in f["evidence"]


# ==============================================================================
# CASE 12: CSP-restricted case, distinguishing blocking from injection absence
# ==============================================================================
@pytest.mark.asyncio
async def test_12_csp_restricted_injection():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        # Reflects raw HTML, but enforces strict CSP blocking inline scripts
        headers = {"Content-Security-Policy": "default-src 'self'; script-src 'self'"}
        return HTMLResponse(f"<html><body>Search: {q}</body></html>", status_code=200, headers=headers)

    app = Starlette(routes=[Route("/secure_csp", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/secure_csp?q=test")
        endpoints = [{"url": "https://test.local/secure_csp", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert len(scanner.findings) == 1
        f = scanner.findings[0]
        assert f["verification_status"] == "POTENTIAL"
        assert f["severity"] == "low"
        assert "Mitigated by CSP" in f["title"]
        assert "Content-Security-Policy restricts inline script execution" in f["description"]


# ==============================================================================
# CASE 13: Flaky or unstable baseline
# ==============================================================================
@pytest.mark.asyncio
async def test_13_flaky_or_unstable_baseline():
    req_count = 0
    async def app_handler(request):
        nonlocal req_count
        req_count += 1
        # Erratic responses: odd requests return 200, even return 500
        if req_count % 2 == 0:
            return HTMLResponse("<html><body>Server Flake</body></html>", status_code=500)
        return HTMLResponse("<html><body>Normal Page Content</body></html>", status_code=200)

    app = Starlette(routes=[Route("/flaky", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/flaky?q=test")
        endpoints = [{"url": "https://test.local/flaky", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.baseline_stability == "unstable"
        # Must not report an XSS vulnerability due to baseline flakiness
        vuln_findings = [f for f in scanner.findings if f["verification_status"] in ("CONFIRMED", "POTENTIAL")]
        assert len(vuln_findings) == 0


# ==============================================================================
# CASE 14: Server returning HTTP 500 without proof of XSS
# ==============================================================================
@pytest.mark.asyncio
async def test_14_server_returning_500_without_proof_of_xss():
    async def app_handler(request):
        return HTMLResponse("<html><body>Internal Server Error: Database Connection Failed</body></html>", status_code=500)

    app = Starlette(routes=[Route("/error", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/error?id=1")
        endpoints = [{"url": "https://test.local/error", "method": "GET", "params": ["id"], "param_values": {"id": "1"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        # 500 error alone is NOT an XSS vulnerability
        vuln_findings = [f for f in scanner.findings if f["verification_status"] in ("CONFIRMED", "POTENTIAL")]
        assert len(vuln_findings) == 0


# ==============================================================================
# CASE 15: Timeout or network failure (Records ERROR, no clean bill of health)
# ==============================================================================
@pytest.mark.asyncio
async def test_15_timeout_or_network_failure():
    async def app_handler(request):
        raise httpx.RequestError("Connection reset by peer")

    app = Starlette(routes=[Route("/timeout", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/timeout?q=test")
        endpoints = [{"url": "https://test.local/timeout", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        
        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.scanner_error is not None
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["status"] == "SCANNER_ERROR"
        assert scanner.findings[0]["verification_status"] == "ERROR"


# ==============================================================================
# CASE 16: An endpoint with no discovered inputs (INCONCLUSIVE / Untested Scope)
# ==============================================================================
@pytest.mark.asyncio
async def test_16_endpoint_with_no_discovered_inputs():
    mock_safe_client = SafeHTTPClient()
    scanner = MockScanner("https://test.local/static")
    
    # 0 query parameters, 0 forms
    endpoints = [{"url": "https://test.local/static", "method": "GET", "params": []}]
    forms = []

    coverage = await check_xss(scanner, endpoints, forms, mock_safe_client, depth="standard")

    assert coverage.candidate_inputs_discovered == 0
    assert coverage.inputs_tested == 0
    assert "No candidate" in coverage.blocking_reason
    assert coverage.verification_completed is False


# ==============================================================================
# CASE 17: Form with several parameters (Preserves other inputs and hidden fields)
# ==============================================================================
@pytest.mark.asyncio
async def test_17_form_with_several_parameters_mutates_target_only():
    received_requests = []

    async def form_handler(request):
        form_data = await request.form()
        received_requests.append(dict(form_data))
        username = form_data.get("username", "")
        # Reflects username without escaping
        return HTMLResponse(f"<html><body>User: {username}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/login", form_handler, methods=["POST"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/login")
        forms = [{
            "action_url": "https://test.local/login",
            "page_url": "https://test.local/login",
            "method": "POST",
            "inputs": ["username", "password", "csrf_token"],
            "fields": {
                "username": {"value": "admin", "type": "text"},
                "password": {"value": "secret123", "type": "password"},
                "csrf_token": {"value": "csrf_token_xyz_999", "type": "hidden"}
            }
        }]

        coverage = await check_xss(scanner, [], forms, mock_safe_client, depth="standard")

        assert len(received_requests) > 0
        # Verify hidden csrf_token was preserved across all requests
        for req in received_requests:
            assert req.get("csrf_token") == "csrf_token_xyz_999"

        # Verify that when 'username' was targeted, 'password' remained untouched at 'secret123'
        username_targeted_reqs = [r for r in received_requests if r.get("username") != "admin"]
        assert len(username_targeted_reqs) > 0
        for r in username_targeted_reqs:
            assert r.get("password") == "secret123"

        # Verify that when 'password' was targeted, 'username' remained untouched at 'admin'
        password_targeted_reqs = [r for r in received_requests if r.get("password") != "secret123"]
        assert len(password_targeted_reqs) > 0
        for r in password_targeted_reqs:
            assert r.get("username") == "admin"

        assert coverage.findings_added >= 1
        assert any(f["parameter"] == "username" for f in scanner.findings)


# ==============================================================================
# CASE 18: URL with existing query parameters (Must be preserved)
# ==============================================================================
@pytest.mark.asyncio
async def test_18_url_preserves_existing_query_parameters():
    captured_urls = []

    async def app_handler(request):
        captured_urls.append(str(request.url))
        q = request.query_params.get("q", "")
        return HTMLResponse(f"<html><body>Search results: {q}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/catalog", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/catalog?page=2&sort=desc&q=shoes")
        endpoints = [{
            "url": "https://test.local/catalog?page=2&sort=desc&q=shoes",
            "method": "GET",
            "params": ["q"],
            "param_values": {"page": "2", "sort": "desc", "q": "shoes"}
        }]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert len(captured_urls) > 0
        for u in captured_urls:
            assert "page=2" in u
            assert "sort=desc" in u
            assert "q=" in u


# ==============================================================================
# CASE 19: Repeated verification mismatch (Transient breakout fails repeat)
# ==============================================================================
@pytest.mark.asyncio
async def test_19_repeated_verification_mismatch():
    attempt = 0
    async def app_handler(request):
        nonlocal attempt
        attempt += 1
        q = request.query_params.get("q", "")
        # First attempt reflects tag unescaped, but subsequent attempts safely encode
        if attempt == 4: # First injection probe
            return HTMLResponse(f"<html><body>Notice: {q}</body></html>", status_code=200)
        return HTMLResponse(f"<html><body>Notice: {html.escape(q)}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/transient", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/transient?q=test")
        endpoints = [{"url": "https://test.local/transient", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        # Transient breakout failed validation -> must NOT be reported as confirmed or potential XSS
        vuln_findings = [f for f in scanner.findings if f["verification_status"] in ("CONFIRMED", "POTENTIAL") and f["status"] == "MEDIUM"]
        assert len(vuln_findings) == 0


# ==============================================================================
# CASE 20: Unusual response content where no finding is appropriate
# ==============================================================================
@pytest.mark.asyncio
async def test_20_unusual_response_content_no_finding():
    async def app_handler(request):
        # Contains words like 'alert(', 'script', 'onerror' in static content, but doesn't reflect user input
        return HTMLResponse("<html><body>Welcome to our security center. Learn how <script> elements and alert() calls are protected.</body></html>", status_code=200)

    app = Starlette(routes=[Route("/docs", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/docs?topic=xss")
        endpoints = [{"url": "https://test.local/docs", "method": "GET", "params": ["topic"], "param_values": {"topic": "xss"}}]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        # No user reflection -> no findings
        assert len(scanner.findings) == 0
        assert coverage.inputs_tested == 1


# ==============================================================================
# CASE 21: JSON request body input tested and handled cleanly
# ==============================================================================
@pytest.mark.asyncio
async def test_21_json_input_tested_and_handled():
    received_payloads = []

    async def api_handler(request):
        data = await request.json()
        received_payloads.append(data)
        query_val = data.get("query", "")
        # Returns JSON response
        return JSONResponse({"results": [], "query": query_val})

    app = Starlette(routes=[Route("/api/search", api_handler, methods=["POST"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/api/search")
        endpoints = [{
            "url": "https://test.local/api/search",
            "method": "POST",
            "content_type": "application/json",
            "params": ["query"],
            "param_values": {"query": "initial_search"}
        }]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.json_parameters_tested >= 1
        assert len(received_payloads) > 0
        # In JSON API, reflection does not lead to HTML injection finding
        assert len(scanner.findings) == 0


# ==============================================================================
# CASE 22: Multiple marker reflections across different contexts
# ==============================================================================
@pytest.mark.asyncio
async def test_22_multiple_reflections_across_different_contexts():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        # Reflected in HTML text AND in attribute value
        return HTMLResponse(f'<html><body><h1>Results for: {q}</h1><input name="q" value="{q}"></body></html>', status_code=200)

    app = Starlette(routes=[Route("/multi", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/multi?q=test")
        endpoints = [{"url": "https://test.local/multi", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert len(scanner.findings) >= 1
        f = scanner.findings[0]
        assert f["parameter"] == "q"
        assert "html_text" in f["evidence"] or "attribute_double_quoted" in f["evidence"]


# ==============================================================================
# CASE 23: Finding persistence and API serialization contract
# ==============================================================================
@pytest.mark.asyncio
async def test_23_finding_persistence_and_api_serialization():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from database import Base
    from models import Finding, Scan, ScanTarget, User

    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine)
    db = Session()

    u = User(id="user_123", email="xss_test@test.local", password_hash="hash")
    db.add(u)
    t = ScanTarget(id="target_123", user_id="user_123", url="https://test.local/", authorized=True)
    db.add(t)
    s = Scan(id="scan_123", user_id="user_123", target_url="https://test.local/", status="running")
    db.add(s)
    db.commit()

    f = Finding(
        id=generate_uuid(),
        scan_id=s.id,
        target_id=t.id,
        type="xss",
        severity="medium",
        confidence="HIGH",
        status="MEDIUM",
        verification_status="POTENTIAL",
        title="Potential Reflected XSS / Structural HTML Injection via URL Query Parameter 'q'",
        description="The parameter 'q' permits reproducible structural HTML injection.",
        evidence="Location: query\nParameter: q\n[!] Payload '<ethioxsstag>' reproduced structural transformation.",
        url="https://test.local/search?q=test",
        parameter="q",
        http_method="GET"
    )
    db.add(f)
    db.commit()

    retrieved = db.query(Finding).filter(Finding.id == f.id).first()
    assert retrieved is not None
    assert retrieved.location == "query"
    assert retrieved.verification_status == "POTENTIAL"

    # Verify Pydantic API serialization
    serialized = FindingOut.model_validate(retrieved)
    assert serialized.id == f.id
    assert serialized.verification_status == "POTENTIAL"
    assert serialized.status == "MEDIUM"
    assert serialized.severity == "medium"
    assert serialized.confidence == "HIGH"
    assert serialized.location == "query"

    db.close()
 
 
# ==============================================================================
# CASE 24: Plain text / non-HTML response reflecting raw tags (Must NOT flag XSS)
# ==============================================================================
@pytest.mark.asyncio
async def test_24_plain_text_response_does_not_flag_xss():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        # Returns Content-Type: text/plain with raw reflect
        return PlainTextResponse(f"Search results for: {q}", status_code=200)

    app = Starlette(routes=[Route("/api/log", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/api/log?q=test")
        endpoints = [{
            "url": "https://test.local/api/log",
            "method": "GET",
            "params": ["q"],
            "param_values": {"q": "test"}
        }]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        # Must NOT report XSS vulnerability for plain text responses
        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0


# ==============================================================================
# CASE 25: Attribute value containing literal '>' correctly identified
# ==============================================================================
@pytest.mark.asyncio
async def test_25_attribute_containing_gt_correctly_classified():
    async def app_handler(request):
        val = request.query_params.get("expr", "")
        # Attribute value contains > before user reflection
        return HTMLResponse(f'<html><body><input type="text" name="calc" value="5 > 3 and {val}"></body></html>', status_code=200)

    app = Starlette(routes=[Route("/calc", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/calc?expr=test")
        endpoints = [{
            "url": "https://test.local/calc",
            "method": "GET",
            "params": ["expr"],
            "param_values": {"expr": "test"}
        }]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.inputs_tested == 1
        assert "attribute_double_quoted" in coverage.contexts_discovered
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["verification_status"] == "POTENTIAL"


# ==============================================================================
# CASE 26: JavaScript single-quote string with preceding comment quote
# ==============================================================================
@pytest.mark.asyncio
async def test_26_js_context_quote_counting_robust_against_comments():
    async def app_handler(request):
        val = request.query_params.get("user", "")
        # Preceding line has an apostrophe in a JS comment, but user is in double-quoted string
        html_content = f"""<html><body><script>
// don't quote me on this
var currentUser = "{val}";
</script></body></html>"""
        return HTMLResponse(html_content, status_code=200)

    app = Starlette(routes=[Route("/js_test", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/js_test?user=guest")
        endpoints = [{
            "url": "https://test.local/js_test",
            "method": "GET",
            "params": ["user"],
            "param_values": {"user": "guest"}
        }]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.inputs_tested == 1
        # Correctly identified as double-quoted string, NOT single-quoted string
        assert "javascript_double_quoted" in coverage.contexts_discovered
        assert "javascript_single_quoted" not in coverage.contexts_discovered


# ==============================================================================
# CASE 27: Cookie XSS testing mutates cookies and preserves query parameters
# ==============================================================================
@pytest.mark.asyncio
async def test_27_cookie_mutation_preserves_query_and_other_cookies():
    received_requests = []

    async def app_handler(request):
        received_requests.append({
            "url": str(request.url),
            "cookies": dict(request.cookies)
        })
        theme = request.cookies.get("theme", "light")
        return HTMLResponse(f"<html><body>Current theme: {theme}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/settings", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/settings?page=1&sort=asc")
        candidate_cookies = [
            {"name": "theme", "value": "light", "url": "https://test.local/settings?page=1&sort=asc"},
            {"name": "session_id", "value": "secret_sess_123", "url": "https://test.local/settings"}
        ]

        coverage = await check_xss(
            scanner,
            endpoints=[],
            forms=[],
            client=mock_safe_client,
            depth="standard",
            cookies=candidate_cookies,
            allow_session_cookie_testing=False
        )

        assert coverage.candidate_cookies_discovered == 2
        assert "session_id" in coverage.cookies_excluded_policy
        assert coverage.cookies_tested == 1

        # Verify that theme was mutated in cookies, while query remained 'page=1&sort=asc'
        theme_mutated_requests = [r for r in received_requests if r["cookies"].get("theme") != "light"]
        assert len(theme_mutated_requests) > 0
        for r in theme_mutated_requests:
            assert "theme=" not in r["url"]  # Cookie was NOT placed into URL query
            assert "session_id" in r["cookies"]  # Unrelated cookies preserved


# ==============================================================================
# CASE 28: CSP with nonce overrides unsafe-inline
# ==============================================================================
@pytest.mark.asyncio
async def test_28_csp_with_nonce_overrides_unsafe_inline():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        # CSP includes nonce along with unsafe-inline (modern browsers ignore unsafe-inline when nonce is present)
        headers = {"Content-Security-Policy": "default-src 'self'; script-src 'nonce-rAnd0m123' 'unsafe-inline'"}
        return HTMLResponse(f"<html><body>Search: {q}</body></html>", status_code=200, headers=headers)

    app = Starlette(routes=[Route("/nonce_csp", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/nonce_csp?q=test")
        endpoints = [{"url": "https://test.local/nonce_csp", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert len(scanner.findings) == 1
        f = scanner.findings[0]
        # Must recognize that CSP blocks inline execution
        assert f["verification_status"] == "POTENTIAL"
        assert f["severity"] == "low"
        assert "Mitigated by CSP" in f["title"]


# ==============================================================================
# CASE 29: Truthful telemetry counters across completed techniques
# ==============================================================================
@pytest.mark.asyncio
async def test_29_truthful_telemetry_counters():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        return HTMLResponse(f"<html><body>Search: {q}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/telemetry", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/telemetry?q=test")
        endpoints = [{"url": "https://test.local/telemetry", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]

        coverage = await check_xss(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.requests_attempted >= coverage.requests_completed
        assert coverage.requests_completed > 0
        assert "baseline_profiling" in coverage.techniques_attempted
        assert "baseline_profiling" in coverage.techniques_completed
        assert "canary_reflection" in coverage.techniques_attempted
        assert "canary_reflection" in coverage.techniques_completed
        assert "encoding_analysis" in coverage.techniques_attempted
        assert "encoding_analysis" in coverage.techniques_completed
        assert "structural_breakout_validation" in coverage.techniques_attempted
        assert "structural_breakout_validation" in coverage.techniques_completed
        assert coverage.verification_completed is True

