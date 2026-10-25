import pytest
import os
import re
import datetime
import httpx
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from unittest.mock import patch

from scanner.http_client import SafeHTTPClient
from scanner.checks.sqli import check_sqli, check_db_errors, is_sensitive_cookie, SQLiCoverageRecord, get_response_duration
from scanner.differential import BaselineEngine, BaselineProfile
from scanner.test_case import TestCaseResult
from models import Finding, Scan, User
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

    def _add_finding(self, **kwargs):
        self.findings.append(kwargs)

    def _redact_evidence(self, text):
        return text

# ==============================================================================
# TEST 1: Simulated vulnerable cookie causes database-specific SQL error
# ==============================================================================
@pytest.mark.asyncio
async def test_cookie_error_based_sqli_detected_with_reproducible_db_error():
    async def app_handler(request):
        cookie_val = request.cookies.get("TrackingId", "")
        # Simulating PortSwigger Visible error-based SQLi
        if "'" in cookie_val:
            # PostgreSQL error message
            return HTMLResponse(
                f"<h4>Unterminated string literal started at position 39 in SQL SELECT * FROM tracking WHERE id = '{cookie_val}'. Expected char</h4>",
                status_code=500
            )
        return HTMLResponse("<html><body><h1>Welcome Store</h1><p>Items catalog</p></body></html>", status_code=200)

    app = Starlette(routes=[Route("/", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/")
        endpoints = [{"url": "https://test.local/", "method": "GET", "params": [], "param_values": {}}]
        forms = []
        cookies = [{"name": "TrackingId", "value": "xyz123", "url": "https://test.local/"}]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

        assert coverage.findings_added >= 1
        assert len(scanner.findings) == 1
        finding = scanner.findings[0]
        assert finding["f_type"] == "sqli"
        assert finding["parameter"] == "TrackingId"
        assert "Cookie" in finding["title"]
        assert "TrackingId" in finding["title"]
        assert "Location: cookie" in finding["evidence"]
        assert "unterminated string literal" in finding["evidence"].lower()
        assert finding["status"] in ("HIGH", "CRITICAL")
        assert finding["severity"] in ("high", "critical")

# ==============================================================================
# TEST 2: Secure endpoint handling cookie without error -> NOT detected
# ==============================================================================
@pytest.mark.asyncio
async def test_cookie_secure_endpoint_not_detected():
    async def app_handler(request):
        # Parameterized query: never produces SQL errors regardless of payload
        return HTMLResponse("<html><body><h1>Welcome Secure Store</h1><p>Items catalog</p></body></html>", status_code=200)

    app = Starlette(routes=[Route("/", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/")
        endpoints = [{"url": "https://test.local/", "method": "GET", "params": [], "param_values": {}}]
        forms = []
        cookies = [{"name": "TrackingId", "value": "xyz123", "url": "https://test.local/"}]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

        assert coverage.findings_added == 0
        assert coverage.inputs_tested == 1
        assert coverage.cookies_tested == 1
        assert "cookie:TrackingId" in coverage.tested_parameters

# ==============================================================================
# TEST 3: Generic HTTP 500 must not confirm SQL injection
# ==============================================================================
@pytest.mark.asyncio
async def test_generic_500_response_does_not_confirm_sqli():
    async def app_handler(request):
        cookie_val = request.cookies.get("TrackingId", "")
        if "'" in cookie_val:
            # Generic 500 without any database error signature
            return HTMLResponse("<html><body><h1>500 Internal Server Error</h1><p>Application crashed</p></body></html>", status_code=500)
        return HTMLResponse("<html><body><h1>Welcome Store</h1><p>Normal page</p></body></html>", status_code=200)

    app = Starlette(routes=[Route("/", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/")
        endpoints = [{"url": "https://test.local/", "method": "GET", "params": [], "param_values": {}}]
        forms = []
        cookies = [{"name": "TrackingId", "value": "xyz123", "url": "https://test.local/"}]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

        # Must not report SQLi finding on generic 500
        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0

# ==============================================================================
# TEST 4: Response that merely reflects the mutated cookie does not trigger false positive
# ==============================================================================
@pytest.mark.asyncio
async def test_reflected_cookie_does_not_trigger_false_positive():
    async def app_handler(request):
        cookie_val = request.cookies.get("theme", "")
        # Echoing input back to user
        return HTMLResponse(f"<html><body><h1>Theme Chooser</h1><p>Current theme: {cookie_val}</p></body></html>", status_code=200)

    app = Starlette(routes=[Route("/", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/")
        endpoints = [{"url": "https://test.local/", "method": "GET", "params": [], "param_values": {}}]
        forms = []
        cookies = [{"name": "theme", "value": "dark", "url": "https://test.local/"}]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0

    # Direct unit test on check_db_errors reflection rejection
    db, err = check_db_errors("Current: ' unterminated string literal", injected_value="' unterminated string literal")
    assert db is None
    assert err is None

# ==============================================================================
# TEST 5: Baseline that already contains an error is guarded against false attribution
# ==============================================================================
@pytest.mark.asyncio
async def test_baseline_with_preexisting_db_error_not_falsely_flagged():
    async def app_handler(request):
        # Server always returns a DB error due to broken configuration
        return HTMLResponse("<html><body><p>Database Error: sqlite3.operationalerror: database is locked</p></body></html>", status_code=500)

    app = Starlette(routes=[Route("/", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/")
        endpoints = [{"url": "https://test.local/", "method": "GET", "params": [], "param_values": {}}]
        forms = []
        cookies = [{"name": "TrackingId", "value": "xyz123", "url": "https://test.local/"}]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

        # Baseline already has the error -> must NOT be reported as a new finding
        assert coverage.findings_added == 0
        assert len(scanner.findings) == 0

# ==============================================================================
# TEST 6: Multiple cookies - only candidate is mutated, others preserved
# ==============================================================================
@pytest.mark.asyncio
async def test_multiple_cookies_mutates_only_candidate_and_preserves_others():
    received_requests = []

    async def app_handler(request):
        received_requests.append({
            "cookies": dict(request.cookies),
            "raw_cookie_header": request.headers.get("cookie", "")
        })
        return HTMLResponse("<html><body><h1>OK</h1></body></html>", status_code=200)

    app = Starlette(routes=[Route("/account", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/account")
        endpoints = [{"url": "https://test.local/account", "method": "GET", "params": [], "param_values": {}}]
        forms = []
        cookies = [
            {"name": "session", "value": "AUTH_SECRET_TOKEN_999"},
            {"name": "TrackingId", "value": "track_original"},
            {"name": "theme", "value": "nordic"}
        ]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

        # Verify that in every single request:
        # 1. session was preserved as AUTH_SECRET_TOKEN_999
        # 2. theme was preserved as nordic
        # 3. TrackingId was mutated with SQL probes
        assert len(received_requests) > 0
        for req in received_requests:
            c = req["cookies"]
            # 1. Sensitive session cookie is never mutated
            assert c.get("session") == "AUTH_SECRET_TOKEN_999", f"Session cookie modified: {c}"
            # 2. At most one candidate is mutated per request (preserving other cookies)
            theme_mutated = (c.get("theme") != "nordic")
            tracking_mutated = (c.get("TrackingId") != "track_original")
            assert not (theme_mutated and tracking_mutated), "Multiple cookies mutated simultaneously!"


        # Confirm mutational probes reached the server
        mutated_tracking_values = [r["cookies"]["TrackingId"] for r in received_requests]
        assert any("'" in v for v in mutated_tracking_values)
        assert any("'" in r["raw_cookie_header"] for r in received_requests)

# ==============================================================================
# TEST 7: Preservation of query parameters, request bodies, and headers
# ==============================================================================
@pytest.mark.asyncio
async def test_preservation_of_query_params_and_headers_when_testing_cookies():
    received_requests = []

    async def app_handler(request):
        received_requests.append({
            "params": dict(request.query_params),
            "cookies": dict(request.cookies),
            "custom_header": request.headers.get("x-custom-scanner-test")
        })
        return HTMLResponse("<html><body><h1>Shop</h1></body></html>", status_code=200)

    app = Starlette(routes=[Route("/shop", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/shop?category=shoes&sort=price")
        endpoints = [{
            "url": "https://test.local/shop?category=shoes&sort=price",
            "method": "GET",
            "params": ["category", "sort"],
            "param_values": {"category": "shoes", "sort": "price"}
        }]
        forms = []
        cookies = [{"name": "TrackingId", "value": "123", "url": "https://test.local/shop?category=shoes&sort=price"}]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

        # Check requests made during cookie testing: query params must remain intact
        cookie_requests = [r for r in received_requests if r["cookies"].get("TrackingId") and r["cookies"]["TrackingId"] != "123"]
        assert len(cookie_requests) > 0
        for r in cookie_requests:
            assert r["params"].get("category") == "shoes"
            assert r["params"].get("sort") == "price"


# ==============================================================================
# TEST 8: Exclusion of sensitive session cookies under default policy
# ==============================================================================
@pytest.mark.asyncio
async def test_exclusion_of_sensitive_session_cookies():
    assert is_sensitive_cookie("session") is True
    assert is_sensitive_cookie("sessionid") is True
    assert is_sensitive_cookie("PHPSESSID") is True
    assert is_sensitive_cookie("JSESSIONID") is True
    assert is_sensitive_cookie("jwt") is True
    assert is_sensitive_cookie("auth_token") is True
    assert is_sensitive_cookie("csrf_token") is True
    assert is_sensitive_cookie("xsrf") is True

    # Non-sensitive cookies
    assert is_sensitive_cookie("TrackingId") is False
    assert is_sensitive_cookie("tracking_id") is False
    assert is_sensitive_cookie("theme") is False
    assert is_sensitive_cookie("cart_id") is False
    assert is_sensitive_cookie("visitor_id") is False
    assert is_sensitive_cookie("analytics") is False

    scanner = MockScanner("https://test.local/")
    mock_safe_client = SafeHTTPClient()
    endpoints = []
    forms = []
    cookies = [
        {"name": "session", "value": "secret1"},
        {"name": "jwt", "value": "tok2"},
        {"name": "csrf", "value": "tok3"}
    ]

    coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

    assert coverage.candidate_inputs_discovered == 0
    assert coverage.inputs_tested == 0
    assert "session" in coverage.cookies_excluded_policy
    assert "jwt" in coverage.cookies_excluded_policy
    assert "csrf" in coverage.cookies_excluded_policy
    assert "excluded by authentication preservation policy" in coverage.blocking_reason

# ==============================================================================
# TEST 9: Missing or inaccessible cookie candidates produces honest coverage
# ==============================================================================
@pytest.mark.asyncio
async def test_missing_cookie_candidates_honest_status():
    scanner = MockScanner("https://test.local/")
    mock_safe_client = SafeHTTPClient()
    endpoints = []
    forms = []
    cookies = []

    coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

    assert coverage.candidate_inputs_discovered == 0
    assert coverage.inputs_tested == 0
    assert coverage.baseline_stability == "not_evaluated"
    assert coverage.verification_completed is False
    assert "No candidate" in coverage.blocking_reason

# ==============================================================================
# TEST 10: Existing query-parameter SQLi tests continue to function
# ==============================================================================
@pytest.mark.asyncio
async def test_existing_query_parameter_sqli():
    async def app_handler(request):
        q = request.query_params.get("q", "")
        if "'" in q:
            return HTMLResponse("syntax error at or near '...' in PostgreSQL query", status_code=500)
        return HTMLResponse("<html><body><p>Search results</p></body></html>", status_code=200)

    app = Starlette(routes=[Route("/search", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/search?q=test")
        endpoints = [{"url": "https://test.local/search", "method": "GET", "params": ["q"], "param_values": {"q": "test"}}]
        forms = []

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        finding = scanner.findings[0]
        assert finding["parameter"] == "q"
        assert "URL Query" in finding["title"]
        assert "Location: query" in finding["evidence"]

# ==============================================================================
# TEST 11: Existing form-body SQLi tests continue to function
# ==============================================================================
@pytest.mark.asyncio
async def test_existing_form_body_sqli():
    async def app_handler(request):
        form_data = await request.form()
        user = form_data.get("username", "")
        if "'" in user:
            return HTMLResponse("you have an error in your sql syntax; check the manual that corresponds to your MySQL server", status_code=500)
        return HTMLResponse("<html><body><p>Login failed</p></body></html>", status_code=200)

    app = Starlette(routes=[Route("/login", app_handler, methods=["POST"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/login")
        endpoints = []
        forms = [{
            "action_url": "https://test.local/login",
            "page_url": "https://test.local/login",
            "method": "POST",
            "inputs": ["username", "password"],
            "fields": {"username": "admin", "password": "123"}
        }]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard")

        assert coverage.findings_added >= 1
        finding = scanner.findings[0]
        assert finding["parameter"] == "username"
        assert "Form" in finding["title"]
        assert "Location: form" in finding["evidence"]

# ==============================================================================
# TEST 12: Boolean differential testing on cookie parameter
# ==============================================================================
@pytest.mark.asyncio
async def test_boolean_differential_on_cookie():
    async def app_handler(request):
        pref = request.cookies.get("filter_id", "")
        # False condition: shows 0 items (diverges from baseline)
        if "' OR 1=2-- " in pref or "1 OR 1=2" in pref:
            return HTMLResponse("<html><body><p>No products found</p></body></html>", status_code=200)
        # Baseline and True condition: shows 5 items (matches baseline)
        return HTMLResponse("<html><body>" + "<p>Product Item</p>" * 5 + "</body></html>", status_code=200)


    app = Starlette(routes=[Route("/catalog", app_handler, methods=["GET"])])

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test.local") as raw_client:
        mock_safe_client = SafeHTTPClient()
        mock_safe_client.client = raw_client

        scanner = MockScanner("https://test.local/catalog")
        endpoints = [{"url": "https://test.local/catalog", "method": "GET", "params": [], "param_values": {}}]
        forms = []
        cookies = [{"name": "filter_id", "value": "1", "url": "https://test.local/catalog"}]

        coverage = await check_sqli(scanner, endpoints, forms, mock_safe_client, depth="standard", cookies=cookies)

        assert coverage.findings_added >= 1
        finding = scanner.findings[0]
        assert finding["parameter"] == "filter_id"
        assert "Cookie" in finding["title"]
        assert ("Boolean Differential" in finding.get("description", "")) or ("Boolean Differential" in finding.get("evidence", ""))
        assert "Location: cookie" in finding["evidence"]


# ==============================================================================
# TEST 13: Timing checks handle responses correctly without accessing response.elapsed unsafely
# ==============================================================================
def test_get_response_duration_safety():
    # 1. None response
    assert get_response_duration(None) == 0.0

    # 2. Response with duration attribute
    class DummyResp:
        duration = 3.14
    assert get_response_duration(DummyResp()) == 3.14

    # 3. Response with _elapsed timedelta
    class DummyResp2:
        _elapsed = datetime.timedelta(seconds=2.5)
    assert get_response_duration(DummyResp2()) == 2.5

    # 4. Response raising RuntimeError on .elapsed access (unread streaming response simulation)
    class BrokenElapsedResp:
        @property
        def elapsed(self):
            raise RuntimeError("Response has not been read")
    assert get_response_duration(BrokenElapsedResp()) == 0.0

# ==============================================================================
# TEST 14: Persistence and API serialization of cookie location, parameter, status
# ==============================================================================
def test_finding_persistence_and_api_serialization():
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # 1. ORM Finding model property
    f_orm = Finding(
        id="find-123",
        scan_id="scan-123",
        type="sqli",
        severity="high",
        confidence="HIGH",
        status="HIGH",
        verification_status="CONFIRMED",
        url="https://target.test/catalog",
        parameter="TrackingId",
        title="SQL Injection via Cookie Parameter 'TrackingId'",
        description="A reproducible SQL injection vulnerability was verified in cookie 'TrackingId'.",
        evidence="Location: cookie\nParameter: TrackingId\n[!] [Error-Based SQLi] PostgreSQL error signature detected.",
        created_at=now_str
    )

    assert f_orm.location == "cookie"
    assert f_orm.parameter == "TrackingId"

    # 2. Schema serialization via FindingOut
    f_out = FindingOut.model_validate(f_orm)
    assert f_out.location == "cookie"
    assert f_out.parameter == "TrackingId"
    assert f_out.verification_status == "CONFIRMED"
    assert f_out.confidence == "HIGH"

    # 3. Query finding serialization
    f_query = Finding(
        id="find-456",
        scan_id="scan-123",
        type="sqli",
        severity="high",
        status="HIGH",
        url="https://target.test/search",
        parameter="q",
        title="SQL Injection via URL Query Parameter 'q'",
        description="SQL injection in query parameter q.",
        evidence="Location: query\nParameter: q\n[!] Database error.",
        created_at=now_str
    )
    assert f_query.location == "query"
    f_query_out = FindingOut.model_validate(f_query)
    assert f_query_out.location == "query"
    assert f_query_out.verification_status == "CONFIRMED"
    assert f_query_out.severity == "high"

# ==============================================================================
# TEST 15: Broad phrases (e.g. "in sql select") rejected as false positives
# ==============================================================================
def test_broad_generic_signatures_rejected():
    # 1. Prose referencing SQL SELECT should NOT trigger error-based SQLi
    db, err = check_db_errors("This article discusses performance optimizations in SQL SELECT queries.")
    assert db is None and err is None

    # 2. English sentences with "near '...'" should NOT trigger SQLite error
    db2, err2 = check_db_errors("The convention center is located near 'Main Street' and 5th Avenue.")
    assert db2 is None and err2 is None

    # 3. Authentic PostgreSQL unterminated string literal MUST trigger
    db3, err3 = check_db_errors("ERROR: unterminated string literal at or near 'xyz'")
    assert db3 == "PostgreSQL"
    assert err3 == "unterminated string literal"

# ==============================================================================
# TEST 16: Separate severity, status, and verification_status concepts
# ==============================================================================
def test_status_and_severity_concept_separation():
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Confirmed Finding
    f_confirmed = Finding(
        id="f-conf",
        scan_id="s-1",
        type="sqli",
        severity="high",
        status="HIGH",
        url="https://test.local/catalog",
        parameter="TrackingId",
        title="SQL Injection via Cookie Parameter 'TrackingId'",
        description="Verified SQL injection",
        created_at=now_str
    )
    out_c = FindingOut.model_validate(f_confirmed)
    assert out_c.severity == "high"
    assert out_c.status == "HIGH"
    assert out_c.verification_status == "CONFIRMED"

    # Potential / Suspicious Finding (LOW severity & LOW confidence)
    f_potential = Finding(
        id="f-pot",
        scan_id="s-1",
        type="sqli",
        severity="low",
        confidence="LOW",
        status="LOW",
        url="https://test.local/catalog",
        parameter="filter",
        title="Potential SQL Injection Anomaly",
        description="Unverified differential anomaly",
        created_at=now_str
    )
    out_p = FindingOut.model_validate(f_potential)
    assert out_p.severity == "low"
    assert out_p.verification_status == "POTENTIAL"
    assert out_p.confidence == "LOW"

    # Negative Result (NOT_DETECTED)
    f_not_det = Finding(
        id="f-not",
        scan_id="s-1",
        type="sqli",
        severity="info",
        confidence="HIGH",
        status="NOT_DETECTED",
        url="https://test.local/catalog",
        parameter="sort",
        title="SQL Injection Not Detected",
        description="Tested cleanly",
        created_at=now_str
    )
    out_n = FindingOut.model_validate(f_not_det)
    assert out_n.severity == "info"
    assert out_n.status == "NOT_DETECTED"
    assert out_n.verification_status == "NOT_DETECTED"


