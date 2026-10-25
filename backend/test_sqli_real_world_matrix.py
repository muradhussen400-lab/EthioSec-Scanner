import pytest
import os
import asyncio
import datetime
import httpx
from urllib.parse import unquote
from unittest.mock import patch, AsyncMock
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from scanner.http_client import SafeHTTPClient
from scanner.checks.sqli import (
    check_sqli, 
    check_db_errors, 
    is_sensitive_cookie, 
    SQLiCoverageRecord,
    get_response_duration
)
from scanner.differential import BaselineEngine, BaselineProfile
from scanner.test_case import TestCaseResult
from models import Finding, Scan, ScanTarget, User, generate_uuid
from schemas import FindingOut
from database import SessionLocal

@pytest.fixture(autouse=True)
def mock_is_safe():
    with patch("scanner.engine.is_safe_url", return_value=True), \
         patch("scanner.safety.is_safe_url", return_value=True), \
         patch("scanner.http_client.is_safe_url", return_value=True):
        yield

class MockResponse:
    def __init__(self, status_code=200, text="Normal Page Content", headers=None, duration=0.05):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self.duration = duration
        self._elapsed = datetime.timedelta(seconds=duration)

    @property
    def elapsed(self):
        return self._elapsed

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

class MockClient:
    def __init__(self):
        self.get = AsyncMock()
        self.post = AsyncMock()

# ==============================================================================
# CASE 1: Known vulnerable error-based SQLi fixture
# ==============================================================================
@pytest.mark.asyncio
async def test_01_known_vulnerable_error_based_sqli_fixture():
    async def app_handler(request):
        q = request.query_params.get("id", "")
        if "'" in q:
            return HTMLResponse("<html><body>pg_catalog.pg_class: syntax error at or near 'foo'</body></html>", status_code=500)
        return HTMLResponse("<html><body>Product 123 details</body></html>", status_code=200)

    app = Starlette(routes=[Route("/product", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/product?id=123")
        endpoints = [{"url": "https://test.local/product", "method": "GET", "params": ["id"], "param_values": {"id": "123"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        assert len(scanner.findings) == 1
        f = scanner.findings[0]
        assert f["f_type"] == "sqli"
        assert f["parameter"] == "id"
        assert f["status"] in ("HIGH", "CRITICAL")
        assert f["severity"] in ("high", "critical")
        assert "syntax error at or near" in f["evidence"]
        assert "PostgreSQL" in f["description"]

# ==============================================================================
# CASE 2: Known safe fixture
# ==============================================================================
@pytest.mark.asyncio
async def test_02_known_safe_fixture():
    async def app_handler(request):
        return HTMLResponse("<html><body>Safe parameterized response</body></html>", status_code=200)

    app = Starlette(routes=[Route("/safe", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/safe?q=test")
        endpoints = [{"url": "https://test.local/safe", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added == 0
        assert coverage.inputs_tested == 1
        assert len(scanner.findings) == 0

# ==============================================================================
# CASE 3: SQLi in a cookie (PortSwigger TrackingId style)
# ==============================================================================
@pytest.mark.asyncio
async def test_03_sqli_in_a_cookie():
    async def app_handler(request):
        cookie = request.cookies.get("TrackingId", "")
        if "'" in cookie:
            return HTMLResponse("<h4>Unterminated string literal started at position 42 in SQL SELECT * FROM tracking WHERE id = '" + cookie + "'</h4>", status_code=500)
        return HTMLResponse("<html><body>Store Homepage</body></html>", status_code=200)

    app = Starlette(routes=[Route("/", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/")
        endpoints = [{"url": "https://test.local/", "method": "GET", "params": [], "param_values": {}}]
        cookies = [{"name": "TrackingId", "value": "orig_track_123", "url": "https://test.local/"}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard", cookies=cookies)

        assert coverage.findings_added >= 1
        assert len(scanner.findings) == 1
        f = scanner.findings[0]
        assert f["parameter"] == "TrackingId"
        assert "Cookie" in f["title"]
        assert "Location: cookie" in f["evidence"]
        assert "unterminated string literal" in f["evidence"].lower()

# ==============================================================================
# CASE 4: SQLi in a query parameter
# ==============================================================================
@pytest.mark.asyncio
async def test_04_sqli_in_a_query_parameter():
    async def app_handler(request):
        cat = request.query_params.get("category", "")
        if "'" in cat:
            return HTMLResponse("<div>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</div>", status_code=500)
        return HTMLResponse("<div>Category listings</div>", status_code=200)

    app = Starlette(routes=[Route("/filter", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/filter?category=Gifts")
        endpoints = [{"url": "https://test.local/filter", "method": "GET", "params": ["category"], "param_values": {"category": "Gifts"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        f = scanner.findings[0]
        assert f["parameter"] == "category"
        assert "URL Query" in f["title"]
        assert "Location: query" in f["evidence"]
        assert "MySQL" in f["description"]

# ==============================================================================
# CASE 5: SQLi in a form parameter
# ==============================================================================
@pytest.mark.asyncio
async def test_05_sqli_in_a_form_parameter():
    async def form_handler(request):
        form_data = await request.form()
        username = form_data.get("username", "")
        if "'" in username:
            return HTMLResponse("<div>Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string</div>", status_code=500)
        return HTMLResponse("<div>Login page</div>", status_code=200)

    app = Starlette(routes=[Route("/login", form_handler, methods=["POST"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/login")
        forms = [{
            "action_url": "https://test.local/login",
            "page_url": "https://test.local/login",
            "method": "POST",
            "inputs": ["username", "password"],
            "fields": {"username": {"value": "admin", "type": "text"}, "password": {"value": "secret", "type": "password"}}
        }]
        
        coverage = await check_sqli(scanner, [], forms, mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        f = scanner.findings[0]
        assert f["parameter"] == "username"
        assert "Form" in f["title"]
        assert "Location: form" in f["evidence"]
        assert "Microsoft SQL Server" in f["description"]

# ==============================================================================
# CASE 6: JSON input, supported and tested
# ==============================================================================
@pytest.mark.asyncio
async def test_06_json_input_supported_and_tested():
    async def api_handler(request):
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid json"}, status_code=400)
        query_val = data.get("query", "")
        if "'" in query_val:
            return JSONResponse({"error": "sqlite3.operationalerror: syntax error near 'foo'"}, status_code=500)
        return JSONResponse({"results": ["item1", "item2"]}, status_code=200)

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
            "param_values": {"query": "test"}
        }]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        assert coverage.json_parameters_tested >= 1
        f = scanner.findings[0]
        assert f["parameter"] == "query"
        assert "JSON" in f["title"]
        assert "Location: json" in f["evidence"]
        assert "SQLite" in f["description"]

# ==============================================================================
# CASE 7: Boolean differential positive case
# ==============================================================================
@pytest.mark.asyncio
async def test_07_boolean_differential_positive_case():
    async def app_handler(request):
        pref = request.query_params.get("user", "")
        # False condition: shows 0 items (diverges from baseline by > 200 bytes)
        if "' OR 1=2-- " in pref or "1 OR 1=2" in pref or "' OR '1'='2" in pref:
            return HTMLResponse("<html><body><p>No products found</p></body></html>", status_code=200)
        # Baseline and True condition: shows 10 items (matches baseline)
        return HTMLResponse("<html><body><h1>Product Catalog</h1>" + "<p>Product Item Details</p>" * 10 + "</body></html>", status_code=200)

    app = Starlette(routes=[Route("/profile", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/profile?user=alice")
        endpoints = [{"url": "https://test.local/profile", "method": "GET", "params": ["user"], "param_values": {"user": "alice"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        f = scanner.findings[0]
        assert "Boolean Differential" in f["description"]
        assert f["status"] in ("HIGH", "CRITICAL")
        assert "boolean diff" in f["evidence"].lower()

# ==============================================================================
# CASE 8: Boolean differential negative case
# ==============================================================================
@pytest.mark.asyncio
async def test_08_boolean_differential_negative_case():
    async def app_handler(request):
        # Both true and false injected conditions return the exact same content
        return HTMLResponse("<html><body><h1>Static Search Catalog</h1><p>Results unchanging</p></body></html>", status_code=200)

    app = Starlette(routes=[Route("/catalog", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/catalog?item=1")
        endpoints = [{"url": "https://test.local/catalog", "method": "GET", "params": ["item"], "param_values": {"item": "1"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0

# ==============================================================================
# CASE 9: Timing positive fixture
# ==============================================================================
@pytest.mark.asyncio
async def test_09_timing_positive_fixture():
    scanner = MockScanner("http://test.local/item?id=10")
    client = MockClient()

    def side_effect(url, **kwargs):
        decoded = unquote(url)
        # Injected sleep probes: return 3.0s duration
        if "pg_sleep" in decoded or "SLEEP(" in decoded or "WAITFOR" in decoded:
            return MockResponse(200, "Catalog items", duration=3.0)
        # Baselines and prompt un-injected controls: return 0.05s
        return MockResponse(200, "Catalog items", duration=0.05)
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/item", "method": "GET", "params": ["id"], "param_values": {"id": "10"}}]
    coverage = await check_sqli(scanner, endpoints, [], client, depth="deep")

    assert coverage.findings_added >= 1
    f = scanner.findings[0]
    assert "Time-Based Blind" in f["description"]
    assert "PostgreSQL" in f["description"]
    assert f["status"] in ("HIGH", "CRITICAL")

# ==============================================================================
# CASE 10: Timing noise and ordinary slow-response negative cases
# ==============================================================================
@pytest.mark.asyncio
async def test_10_timing_noise_and_ordinary_slow_response_negative():
    scanner = MockScanner("http://test.local/item?id=10")
    client = MockClient()

    # Congested network: both probe AND un-injected control are slow
    def side_effect(url, **kwargs):
        return MockResponse(200, "Catalog items", duration=2.9)
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://test.local/item", "method": "GET", "params": ["id"], "param_values": {"id": "10"}}]
    coverage = await check_sqli(scanner, endpoints, [], client, depth="deep")

    # Guarded by congestion check: must NOT confirm SQLi
    assert coverage.findings_added == 0
    assert len(scanner.findings) == 0

# ==============================================================================
# CASE 11: Generic HTTP 500 without database evidence
# ==============================================================================
@pytest.mark.asyncio
async def test_11_generic_500_without_database_evidence():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        if "'" in q:
            return HTMLResponse("<html><body><h1>500 Internal Server Error</h1><p>Unhandled application exception</p></body></html>", status_code=500)
        return HTMLResponse("<html><body>Normal Page</body></html>", status_code=200)

    app = Starlette(routes=[Route("/search", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/search?q=hello")
        endpoints = [{"url": "https://test.local/search", "method": "GET", "params": ["q"], "param_values": {"q": "hello"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0

# ==============================================================================
# CASE 12: Database error already present in the baseline
# ==============================================================================
@pytest.mark.asyncio
async def test_12_database_error_already_present_in_the_baseline():
    async def app_handler(request):
        # Baseline itself has a DB error
        return HTMLResponse("<html><body>sqlite3.operationalerror: table users does not exist</body></html>", status_code=500)

    app = Starlette(routes=[Route("/broken", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/broken?id=1")
        endpoints = [{"url": "https://test.local/broken", "method": "GET", "params": ["id"], "param_values": {"id": "1"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        # Must not report pre-existing error as a newly injected finding
        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0

# ==============================================================================
# CASE 13: Reflected input without SQL execution evidence
# ==============================================================================
@pytest.mark.asyncio
async def test_13_reflected_input_without_sql_execution_evidence():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        # Merely echoes the payload back
        return HTMLResponse(f"<html><body>Search Results for: {q}</body></html>", status_code=200)

    app = Starlette(routes=[Route("/echo", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/echo?q=test")
        endpoints = [{"url": "https://test.local/echo", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0

# ==============================================================================
# CASE 14: Inconsistent or non-reproducible behavior
# ==============================================================================
@pytest.mark.asyncio
async def test_14_inconsistent_or_non_reproducible_behavior():
    flaky_count = 0
    async def app_handler(request):
        nonlocal flaky_count
        q = request.query_params.get("id", "")
        # Only trigger on the very first probe attempt, never on reproducibility re-test
        if "'" in q:
            flaky_count += 1
            if flaky_count == 1:
                return HTMLResponse("<html><body>pg_catalog.pg_class: syntax error at or near 'foo'</body></html>", status_code=500)
        return HTMLResponse("<html><body>Normal response</body></html>", status_code=200)

    app = Starlette(routes=[Route("/flaky", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/flaky?id=1")
        endpoints = [{"url": "https://test.local/flaky", "method": "GET", "params": ["id"], "param_values": {"id": "1"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        # Non-reproducible anomaly must never produce a CONFIRMED or HIGH finding
        for f in scanner.findings:
            assert f["status"] not in ("HIGH", "CRITICAL")
            assert f["severity"] not in ("high", "critical")
            assert f["confidence"] == "LOW"

# ==============================================================================
# CASE 15: Target timeout or HTTP 504
# ==============================================================================
@pytest.mark.asyncio
async def test_15_target_timeout_or_http_504():
    async def app_handler(request):
        return HTMLResponse("Gateway Timeout", status_code=504)

    app = Starlette(routes=[Route("/timeout", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/timeout?id=1")
        endpoints = [{"url": "https://test.local/timeout", "method": "GET", "params": ["id"], "param_values": {"id": "1"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        # 504 baseline marks baseline unstable / not evaluated without false clean status
        assert coverage.findings_added == 0
        assert coverage.baseline_stability in ("unstable", "not_evaluated")
        assert len(coverage.inconclusive_reasons) > 0

# ==============================================================================
# CASE 16: Blocked target or prohibited scope
# ==============================================================================
@pytest.mark.asyncio
async def test_16_blocked_target_or_prohibited_scope():
    async def app_handler(request):
        return HTMLResponse("Forbidden by WAF", status_code=403)

    app = Starlette(routes=[Route("/blocked", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/blocked?id=1")
        endpoints = [{"url": "https://test.local/blocked", "method": "GET", "params": ["id"], "param_values": {"id": "1"}}]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

        assert coverage.findings_added == 0
        assert coverage.baseline_stability in ("unstable", "not_evaluated")
        assert any("403" in r for r in coverage.inconclusive_reasons)

# ==============================================================================
# CASE 17: No candidate inputs discovered
# ==============================================================================
@pytest.mark.asyncio
async def test_17_no_candidate_inputs_discovered():
    scanner = MockScanner("https://test.local/")
    mock_safe_client = SafeHTTPClient()

    endpoints = [{"url": "https://test.local/", "method": "GET", "params": [], "param_values": {}}]
    
    coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard")

    assert coverage.candidate_inputs_discovered == 0
    assert coverage.verification_completed is False
    assert "No candidate" in coverage.blocking_reason
    assert coverage.findings_added == 0

# ==============================================================================
# CASE 18: Preservation of unrelated cookies and request data
# ==============================================================================
@pytest.mark.asyncio
async def test_18_preservation_of_unrelated_cookies_and_request_data():
    captured_requests = []
    async def app_handler(request):
        captured_requests.append({
            "cookies": dict(request.cookies),
            "params": dict(request.query_params)
        })
        return HTMLResponse("OK", status_code=200)

    app = Starlette(routes=[Route("/secure-area", app_handler, methods=["GET"])])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/secure-area?filter=1")
        endpoints = [{"url": "https://test.local/secure-area", "method": "GET", "params": ["filter"], "param_values": {"filter": "1"}}]
        cookies = [
            {"name": "session", "value": "SECRET_JWT_AUTH_TOKEN"},
            {"name": "theme", "value": "dark"},
            {"name": "TrackingId", "value": "trk_999"}
        ]
        
        coverage = await check_sqli(scanner, endpoints, [], mock_safe_client, depth="standard", cookies=cookies)

        assert len(captured_requests) > 0
        for req in captured_requests:
            c = req["cookies"]
            # Session cookie must NEVER be mutated
            assert c.get("session") == "SECRET_JWT_AUTH_TOKEN"
            # When filter param is tested, cookies are unchanged
            # When TrackingId is tested, theme is unchanged and session is unchanged
            if c.get("TrackingId") != "trk_999":
                assert c.get("theme") == "dark"

# ==============================================================================
# CASE 19: Correct persistence and API serialization
# ==============================================================================
@pytest.mark.asyncio
async def test_19_correct_persistence_and_api_serialization():
    from models import Finding, Scan, ScanTarget
    db = SessionLocal()
    try:
        target = ScanTarget(id=f"target-{generate_uuid()}", url="https://test.local", authorized=True)
        db.add(target)
        db.commit()

        scan = Scan(id=f"scan-test-{generate_uuid()}", user_id=None, target_url="https://test.local", status="completed")
        db.add(scan)
        db.commit()

        f_db = Finding(
            id=f"finding-{generate_uuid()}",
            scan_id=scan.id,
            target_id=target.id,
            type="sqli",
            severity="high",
            confidence="HIGH",
            status="HIGH",
            verification_status="CONFIRMED",
            title="SQL Injection via JSON Parameter 'query'",
            description="Vulnerability verified via SQLite error signature.",
            evidence="Location: json\nParameter: query\n[!] Payload triggered syntax error near 'foo'",
            http_method="POST",
            parameter="query"
        )
        db.add(f_db)
        db.commit()
        db.refresh(f_db)

        # Check ORM location property recognizes json
        assert f_db.location == "json"

        # Check API serialization with Pydantic
        out = FindingOut.model_validate(f_db)
        assert out.severity == "high"
        assert out.confidence == "HIGH"
        assert out.verification_status == "CONFIRMED"
        assert out.status == "HIGH"
        assert out.location == "json"
        assert out.parameter == "query"

    finally:
        db.close()

# ==============================================================================
# CASE 20: Correct frontend distinction between status, severity, and confidence
# ==============================================================================
def test_20_correct_frontend_distinction_between_status_severity_confidence():
    # Read frontend JS to ensure status, severity, and confidence are rendered in distinct UI elements
    candidates = [
        "ETHIOSEC SCANNER 2/resultsjava.js",
        "../ETHIOSEC SCANNER 2/resultsjava.js",
        os.path.join(os.path.dirname(__file__), "..", "ETHIOSEC SCANNER 2", "resultsjava.js")
    ]
    js_path = next((p for p in candidates if os.path.exists(p)), None)
    assert js_path is not None, f"Could not find resultsjava.js in {candidates}"
    with open(js_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    # 1. Finding cards have distinct severity badge and verification status badge
    assert 'class="sev-badge ${badgeClass}"' in js_code
    assert 'class="status-badge-outline ${verif.toLowerCase().replace(/_/g, "-")}"' in js_code

    # 2. Modal has separate badges for severity, verification status, and confidence
    assert 'dSeverityBadge.textContent = sev.toUpperCase()' in js_code
    assert 'dStatusBadge.textContent = verif.replace(/_/g, " ")' in js_code
    assert 'dConfidence.textContent = `Confidence: ${finding.confidence || "HIGH"}`' in js_code
