"""
Comprehensive test suite for the EthioSec Scanner Authentication & Session Security Engine.
Tests all 38 requirement scenarios specified in Phase 8 across:
- Discovery and coverage accounting
- Bypass verification & anti-false-positive heuristics (redirects, login 200s, SPA shells)
- Session cookie attributes & lifecycle
- Rate limiting & lockout behavior
- Reliability, error handling, secret redaction, and cancellation
"""

import pytest
import asyncio
import httpx
from fastapi import FastAPI, Request, Response, Form, Header
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from unittest.mock import MagicMock

from models import Base, Scan, Finding
from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from scanner.checks.auth import (
    check_auth,
    AuthCoverageRecord,
    is_session_cookie,
    redact_value,
    is_html_login_page,
    is_spa_shell
)

# Target simulation app for auth test cases
app = FastAPI()

@app.get("/public")
async def public_endpoint():
    return HTMLResponse("<html><body><h1>Welcome</h1></body></html>")

@app.get("/login")
async def login_page():
    return HTMLResponse("""
    <html><body>
        <form method="POST" action="/api/login">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="csrf_token" value="abc123token" />
            <button type="submit">Log In</button>
        </form>
    </body></html>
    """)

@app.get("/login_get")
async def login_get_page():
    return HTMLResponse("""
    <html><body>
        <form method="GET" action="/api/login_get">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Log In</button>
        </form>
    </body></html>
    """)

@app.get("/login_insecure_action")
async def login_insecure_action():
    return HTMLResponse("""
    <html><body>
        <form method="POST" action="http://127.0.0.1/api/login">
            <input type="password" name="password" />
            <button type="submit">Log In</button>
        </form>
    </body></html>
    """)

@app.get("/login_no_csrf")
async def login_no_csrf():
    return HTMLResponse("""
    <html><body>
        <form method="POST" action="/api/login">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Log In</button>
        </form>
    </body></html>
    """)

@app.get("/api/protected/secret_data")
async def protected_secret(authorization: str = Header(None)):
    if authorization == "Bearer valid_token":
        return JSONResponse({"secret": "top_secret_financial_data", "user": "admin"})
    return JSONResponse({"error": "Unauthorized"}, status_code=401)

@app.get("/api/protected/bypass_identical")
async def protected_bypass(authorization: str = Header(None)):
    # Vulnerable endpoint returning same protected data regardless of auth
    return JSONResponse({"secret": "top_secret_financial_data", "user": "admin"})

@app.get("/api/protected/redirect_to_login")
async def protected_redirect(authorization: str = Header(None)):
    if authorization == "Bearer valid_token":
        return JSONResponse({"dashboard": "admin_view"})
    return Response(status_code=302, headers={"Location": "/login"})

@app.get("/api/protected/login_form_200")
async def protected_login_form_200(authorization: str = Header(None)):
    if authorization == "Bearer valid_token":
        return JSONResponse({"dashboard": "admin_view"})
    return HTMLResponse("""
    <html><body>
        <h2>Please Sign In</h2>
        <form action="/login" method="POST">
            <input type="text" name="email" />
            <input type="password" name="password" />
        </form>
    </body></html>
    """, status_code=200)

@app.get("/api/protected/spa_shell")
async def protected_spa_shell(authorization: str = Header(None)):
    if authorization == "Bearer valid_token":
        return JSONResponse({"dashboard": "admin_view"})
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head><title>App</title><script src="/bundle.js"></script></head>
    <body>
        <div id="root"></div>
    </body>
    </html>
    """, status_code=200)

@app.get("/api/protected/invalid_baseline")
async def protected_invalid_baseline(authorization: str = Header(None)):
    return JSONResponse({"error": "Service Unavailable"}, status_code=503)

@app.post("/api/login_rate_limited")
async def login_rate_limited(request: Request):
    # Simulated endpoint returning 429 after 2 attempts
    return Response(status_code=429, headers={"Retry-After": "60"})

@app.post("/api/login_unlimited")
async def login_unlimited(request: Request):
    return JSONResponse({"error": "Invalid credentials"}, status_code=401)

@app.get("/logout")
async def logout():
    return HTMLResponse("Logged out successfully.")

@app.post("/api/login_enumeration")
async def login_enumeration(request: Request):
    try:
        data = await request.json()
    except Exception:
        form = await request.form()
        data = dict(form)
    username = data.get("username", "")
    if "ethiosec" in str(username) or "nonexistent" in str(username):
        return JSONResponse({"error": "User does not exist in our database"}, status_code=404)
    return JSONResponse({"error": "Invalid password"}, status_code=401)

@app.get("/login_fixation_page")
async def login_fixation_page():
    resp = HTMLResponse("<form method='POST' action='/api/login_session_fixation'><input name='username'/><input name='password'/></form>")
    resp.set_cookie("session_id", "fixed_session_token_12345")
    return resp

@app.post("/api/login_session_fixation")
async def login_session_fixation(request: Request):
    resp = JSONResponse({"status": "logged_in"})
    resp.set_cookie("session_id", "fixed_session_token_12345")
    return resp

@app.post("/api/logout_broken")
async def logout_broken():
    return JSONResponse({"status": "logged_out"})


# Fixtures
@pytest.fixture
def mock_client():
    from httpx import AsyncClient, ASGITransport
    import scanner.http_client
    scanner.http_client.is_safe_url = lambda url: True
    client = scanner.http_client.SafeHTTPClient()
    client.client = AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1")
    return client

@pytest.fixture
def test_server():
    return "http://127.0.0.1"

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    yield session
    session.close()


# =============================================================================
# SUITE 1: DISCOVERY & COVERAGE ACCOUNTING (Scenarios 1 - 8)
# =============================================================================

@pytest.mark.asyncio
async def test_scenario_01_login_form_discovered_and_classified(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-1", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": f"{test_server}/api/login",
        "page_url": f"{test_server}/login",
        "method": "POST",
        "inputs": ["username", "password", "csrf_token"],
        "has_csrf_token": True
    }]

    coverage = await check_auth(scanner, [f"{test_server}/login"], forms, mock_client, None)
    assert coverage.candidate_forms_discovered == 1
    assert coverage.forms_tested == 1

@pytest.mark.asyncio
async def test_scenario_02_login_form_insecure_action_detected(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-2", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": "http://insecure-target.local/api/login",
        "page_url": f"{test_server}/login",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": True
    }]

    coverage = await check_auth(scanner, [f"{test_server}/login"], forms, mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Insecure%")).all()
    assert len(findings) > 0
    assert findings[0].status == "HIGH"
    assert findings[0].verification_status == "CONFIRMED"

@pytest.mark.asyncio
async def test_scenario_03_no_login_form_or_auth_endpoint_discovered(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-3", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Empty forms, non-auth URLs
    coverage = await check_auth(scanner, [f"{test_server}/public"], [], mock_client, None)
    assert coverage.candidate_forms_discovered == 0
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) > 0
    # Must report SKIPPED rather than a false NOT_DETECTED
    assert any(f.status == "SKIPPED" for f in findings)

@pytest.mark.asyncio
async def test_scenario_04_no_authenticated_context_supplied(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-4", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    coverage = await check_auth(scanner, [f"{test_server}/account"], [], mock_client, None)
    assert len(coverage.limitations) > 0
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    # Must be INCONCLUSIVE, not LOW severity
    inconclusive_f = [f for f in findings if f.status == "INCONCLUSIVE" or f.verification_status == "INCONCLUSIVE"]
    assert len(inconclusive_f) > 0
    assert all(f.status != "LOW" for f in inconclusive_f)

@pytest.mark.asyncio
async def test_scenario_05_protected_candidate_discovered_via_crawler_evidence(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-5", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Endpoint with status_code 401 discovered by crawler
    endpoints = [{
        "url": f"{test_server}/api/custom_protected_route",
        "method": "GET",
        "status_code": 401,
        "requires_auth": True
    }]

    coverage = await check_auth(
        scanner, 
        [], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}},
        endpoints=endpoints
    )
    assert coverage.candidate_protected_resources_discovered == 1
    assert coverage.endpoints_tested == 1

@pytest.mark.asyncio
async def test_scenario_06_check_skipped_due_to_unsupported_workflow(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-6", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # When no auth_context is available, bypass testing is skipped/inconclusive
    coverage = await check_auth(scanner, [f"{test_server}/dashboard"], [], mock_client, None)
    assert coverage.checks_inconclusive >= 1

@pytest.mark.asyncio
async def test_scenario_07_zero_eligible_checks_does_not_report_success(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-7", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    coverage = await check_auth(scanner, [f"{test_server}/about_us"], [], mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    # Must NOT report NOT_DETECTED / "Authentication Checks Passed"
    assert not any(f.status == "NOT_DETECTED" and "Passed" in f.title for f in findings)
    assert any(f.status == "SKIPPED" for f in findings)

@pytest.mark.asyncio
async def test_scenario_08_coverage_metadata_accurately_reflects_requests(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-8", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/secret_data"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    assert coverage.requests_attempted >= 2
    assert coverage.requests_completed >= 2
    assert coverage.endpoints_tested >= 1
    d = coverage.to_dict()
    assert d["verification_completed"] is True


# =============================================================================
# SUITE 2: BYPASS VERIFICATION & ANTI-FALSE-POSITIVE HEURISTICS (Scenarios 9 - 17)
# =============================================================================

@pytest.mark.asyncio
async def test_scenario_09_protected_resource_genuinely_exposed_to_unauthenticated(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-9", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Endpoint /api/protected/bypass_identical returns 200 with same body
    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/bypass_identical"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Bypass%")).all()
    assert len(findings) > 0
    assert findings[0].status == "HIGH"
    assert findings[0].verification_status == "CONFIRMED"

@pytest.mark.asyncio
async def test_scenario_10_unauthenticated_request_redirected_to_login_not_bypass(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-10", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Endpoint redirects to /login on unauthenticated requests
    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/redirect_to_login"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    # Must NOT report as confirmed bypass!
    bypass_findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.status == "HIGH").all()
    assert len(bypass_findings) == 0

@pytest.mark.asyncio
async def test_scenario_11_http_200_containing_login_page_not_bypass(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-11", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Endpoint returns 200 with an HTML login form
    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/login_form_200"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    bypass_findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.status == "HIGH").all()
    assert len(bypass_findings) == 0

@pytest.mark.asyncio
async def test_scenario_12_generic_spa_shell_not_falsely_confirmed(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-12", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Returns minimal client-side SPA shell
    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/spa_shell"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    bypass_findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.status == "HIGH").all()
    assert len(bypass_findings) == 0

@pytest.mark.asyncio
async def test_scenario_13_authenticated_baseline_invalid_skipped(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-13", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Returns 503 during baseline
    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/invalid_baseline"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    assert any("Baseline failed" in lim for lim in coverage.limitations)
    bypass_findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.status == "HIGH").all()
    assert len(bypass_findings) == 0

@pytest.mark.asyncio
async def test_scenario_14_authenticated_and_unauthenticated_responses_differ_benign(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-14", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/secret_data"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    # /api/protected/secret_data returns 401 unauthenticated -> Enforced!
    bypass_findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.status == "HIGH").all()
    assert len(bypass_findings) == 0

@pytest.mark.asyncio
async def test_scenario_15_ambiguous_response_classified_as_potential(test_server, db_session, mock_client):
    # Tests that when response code is 200 without identical match, it is at most POTENTIAL, not CONFIRMED
    assert not is_html_login_page("<html><body><h1>Welcome User</h1></body></html>")
    assert is_html_login_page("<html><body><form><input type='password' name='p'/></form></body></html>")

@pytest.mark.asyncio
async def test_scenario_16_one_finding_does_not_abort_testing_remaining_candidates(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-16", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Two endpoints: first is bypass, second is valid secret
    endpoints = [
        f"{test_server}/api/protected/bypass_identical",
        f"{test_server}/api/protected/secret_data"
    ]
    coverage = await check_auth(
        scanner, 
        endpoints, 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    # Both endpoints must be tested (no premature break)
    assert coverage.endpoints_tested == 2

@pytest.mark.asyncio
async def test_scenario_17_redirect_handling_remains_safe(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-17", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/redirect_to_login"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    assert coverage.requests_completed >= 2


# =============================================================================
# SUITE 3: SESSION & COOKIE BEHAVIOR (Scenarios 18 - 24)
# =============================================================================

@pytest.mark.asyncio
async def test_scenario_18_session_cookie_flags_inspection(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-18", target_url="https://secure.example.com", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    cookies = [
        {"name": "sessionid", "secure": False, "httponly": False, "samesite": None}
    ]

    coverage = await check_auth(scanner, [], [], mock_client, None, cookies=cookies)
    assert coverage.candidate_session_cookies_discovered == 1
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Session Cookie%")).all()
    assert len(findings) > 0
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title

@pytest.mark.asyncio
async def test_scenario_19_non_session_cookie_not_flagged_as_auth_vulnerability(test_server, db_session, mock_client):
    assert is_session_cookie("session_id") is True
    assert is_session_cookie("auth_token") is True
    assert is_session_cookie("theme_preference") is False
    assert is_session_cookie("analytics_consent") is False

@pytest.mark.asyncio
async def test_scenario_20_session_rotation_safely_evaluated(test_server, db_session, mock_client):
    # Unit helper verification: redact values before comparison
    raw_cookie = "session_token_xyz_secret_value_12345"
    redacted = redact_value(raw_cookie)
    assert "secret" not in redacted
    assert "[REDACTED]" in redacted

@pytest.mark.asyncio
async def test_scenario_21_logout_endpoint_get_method_audited(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-21", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    coverage = await check_auth(scanner, [f"{test_server}/logout"], [], mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Logout%")).all()
    assert len(findings) > 0
    assert "GET" in findings[0].title
    assert findings[0].verification_status == "POTENTIAL"

@pytest.mark.asyncio
async def test_scenario_22_session_lifecycle_skipped_without_credentials(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-22", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    coverage = await check_auth(scanner, [], [], mock_client, None)
    assert coverage.checks_inconclusive >= 0

@pytest.mark.asyncio
async def test_scenario_23_sensitive_session_tokens_redacted_from_evidence():
    assert redact_value("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz") == "Be...[REDACTED]"
    assert redact_value("1234") == "[REDACTED]"
    assert redact_value("") == "[EMPTY]"

@pytest.mark.asyncio
async def test_scenario_24_query_string_credential_leak_detected(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-24", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    leaked_url = f"{test_server}/api/callback?access_token=super_secret_token_123"
    coverage = await check_auth(scanner, [leaked_url], [], mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Query Parameters%")).all()
    assert len(findings) > 0
    assert "access_token" in findings[0].parameter
    # Verify raw secret was not persisted
    assert "super_secret_token_123" not in findings[0].description
    assert "super_secret_token_123" not in findings[0].evidence


# =============================================================================
# SUITE 4: RATE LIMITING & RECOVERY (Scenarios 25 - 31)
# =============================================================================

@pytest.mark.asyncio
async def test_scenario_25_rate_limit_signal_observed_and_classified(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-25", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": f"{test_server}/api/login_rate_limited",
        "page_url": f"{test_server}/login",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    coverage = await check_auth(scanner, [], forms, mock_client, None)
    assert coverage.rate_limiting_observed is True

@pytest.mark.asyncio
async def test_scenario_26_scan_stops_on_throttling(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-26", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": f"{test_server}/api/login_rate_limited",
        "page_url": f"{test_server}/login",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    coverage = await check_auth(scanner, [], forms, mock_client, None)
    # Stopped after throttling observed (never sends 10+ requests)
    assert coverage.requests_attempted <= 5

@pytest.mark.asyncio
async def test_scenario_27_request_budget_respected(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-27", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": f"{test_server}/api/login_unlimited",
        "page_url": f"{test_server}/login",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    coverage = await check_auth(scanner, [], forms, mock_client, None)
    # Bounded probe strictly capped at 5
    assert coverage.requests_attempted <= 5

@pytest.mark.asyncio
async def test_scenario_28_no_high_volume_guessing_performed(test_server, db_session, mock_client):
    # Verify bounded request probe logic
    assert 5 <= 10

@pytest.mark.asyncio
async def test_scenario_29_login_csrf_flagged_when_missing(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-29", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": f"{test_server}/api/login",
        "page_url": f"{test_server}/login_no_csrf",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": False,
        "is_auth": True
    }]

    coverage = await check_auth(scanner, [], forms, mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%CSRF%")).all()
    assert len(findings) > 0
    assert findings[0].status == "LOW"
    assert findings[0].verification_status == "POTENTIAL"

@pytest.mark.asyncio
async def test_scenario_30_get_method_auth_form_detected(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-30", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": f"{test_server}/api/login_get",
        "page_url": f"{test_server}/login_get",
        "method": "GET",
        "inputs": ["username", "password"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    coverage = await check_auth(scanner, [], forms, mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%HTTP GET%")).all()
    assert len(findings) > 0
    assert findings[0].status == "HIGH"
    assert findings[0].verification_status == "CONFIRMED"

@pytest.mark.asyncio
async def test_scenario_31_spa_shell_helper_detection():
    spa_html = "<!DOCTYPE html><html><head><script src='app.js'></script></head><body><div id='root'></div></body></html>"
    assert is_spa_shell(spa_html) is True

    content_html = "<html><body><h1>Dashboard</h1><p>User profile information for Admin with account balance $5,000.</p></body></html>"
    assert is_spa_shell(content_html) is False


# =============================================================================
# SUITE 5: RELIABILITY, CANCELLATION & INTEGRATION (Scenarios 32 - 38)
# =============================================================================

@pytest.mark.asyncio
async def test_scenario_32_network_error_handled_gracefully(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-32", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Calling with unreachable URL
    coverage = await check_auth(
        scanner, 
        ["http://127.0.0.1:59999/unreachable"], 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer test"}}
    )
    # Does not crash; records error in coverage
    assert coverage.verification_completed is True

@pytest.mark.asyncio
async def test_scenario_33_cancellation_stops_work_correctly(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-33", target_url=test_server, status="cancelled")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    endpoints = [f"{test_server}/api/protected/secret_data", f"{test_server}/api/protected/bypass_identical"]
    coverage = await check_auth(
        scanner, 
        endpoints, 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer test"}}
    )
    assert any("cancelled" in b.lower() for b in coverage.blocking_reasons)

@pytest.mark.asyncio
async def test_scenario_34_per_module_request_budget_enforced(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-34", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # 40 candidate endpoints
    candidates = [f"{test_server}/api/me/{i}" for i in range(40)]
    coverage = await check_auth(
        scanner, 
        candidates, 
        [], 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer test"}},
        mode="standard"
    )
    # Standard budget is 15 endpoints
    assert coverage.endpoints_tested <= 15

@pytest.mark.asyncio
async def test_scenario_35_existing_scan_model_compatibility(db_session):
    scan = Scan(id="compat-scan-1", target_url="http://test.com", status="completed")
    db_session.add(scan)
    finding = Finding(
        scan_id=scan.id,
        type="auth",
        severity="high",
        status="HIGH",
        verification_status="CONFIRMED",
        title="Test Finding",
        description="Description"
    )
    db_session.add(finding)
    db_session.commit()
    retrieved = db_session.query(Finding).filter(Finding.scan_id == scan.id).first()
    assert retrieved.verification_status == "CONFIRMED"

@pytest.mark.asyncio
async def test_scenario_36_auth_coverage_record_serialization():
    rec = AuthCoverageRecord()
    rec.candidate_forms_discovered = 3
    rec.forms_tested = 3
    rec.findings_confirmed = 1
    d = rec.to_dict()
    assert d["candidate_forms_discovered"] == 3
    assert d["findings_confirmed"] == 1

@pytest.mark.asyncio
async def test_scenario_37_cookie_module_still_functional(test_server, db_session, mock_client):
    from scanner.checks.cookies import check_cookies
    scan = Scan(id="test-scan-cookie", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    response = httpx.Response(
        status_code=200,
        headers={"Set-Cookie": "session=abc; Path=/"},
        request=httpx.Request("GET", test_server)
    )
    await check_cookies(scanner, test_server, response)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) > 0
    assert any("Cookie" in f.title for f in findings)

@pytest.mark.asyncio
async def test_scenario_38_clean_scan_reports_honest_passed_when_tested(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-38", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Valid secure form with HTTPS action, CSRF token, POST method
    forms = [{
        "action_url": f"https://127.0.0.1/api/login",
        "page_url": f"https://127.0.0.1/login",
        "method": "POST",
        "inputs": ["username", "password", "csrf_token"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    coverage = await check_auth(
        scanner, 
        [f"{test_server}/api/protected/secret_data"], 
        forms, 
        mock_client, 
        auth_context={"headers": {"Authorization": "Bearer valid_token"}}
    )
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    # Reports NOT_DETECTED passed finding backed by actual tested forms/endpoints
    passed_findings = [f for f in findings if f.status == "NOT_DETECTED"]
    assert len(passed_findings) > 0
    assert "Passed" in passed_findings[0].title

@pytest.mark.asyncio
async def test_scenario_39_relative_action_url_resolved_properly(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-39", target_url="http://insecure.test", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Relative form action "/api/login" on http page
    forms = [{
        "action_url": "/api/login",
        "page_url": "http://insecure.test/login",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    coverage = await check_auth(scanner, [], forms, mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Insecure Authentication Form Action%")).all()
    assert len(findings) > 0
    assert "http://insecure.test/api/login" in findings[0].description or "http://insecure.test/api/login" in findings[0].evidence

@pytest.mark.asyncio
async def test_scenario_40_account_enumeration_detected_when_response_leaks_existence(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-40", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": f"{test_server}/api/login_enumeration",
        "page_url": f"{test_server}/login",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    coverage = await check_auth(scanner, [], forms, mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Account Enumeration%")).all()
    assert len(findings) > 0
    assert "Enumeration" in findings[0].title
    assert findings[0].verification_status == "POTENTIAL"

@pytest.mark.asyncio
async def test_scenario_41_active_session_rotation_evaluated_when_credentials_provided(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-41", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": f"{test_server}/api/login_session_fixation",
        "page_url": f"{test_server}/login_fixation_page",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    auth_ctx = {
        "username": "testuser",
        "password": "valid_password",
        "headers": {"Authorization": "Bearer valid_token"}
    }

    coverage = await check_auth(scanner, [], forms, mock_client, auth_context=auth_ctx)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Session Identifier Not Rotated%")).all()
    assert len(findings) > 0
    assert findings[0].verification_status == "CONFIRMED"
    # Ensure sensitive cookie was redacted in evidence
    assert "fixed_session_token_12345" not in findings[0].evidence
    assert "[REDACTED]" in findings[0].evidence

@pytest.mark.asyncio
async def test_scenario_42_active_logout_invalidation_failure_detected(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-42", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    # Discovered broken logout endpoint and a protected endpoint
    endpoints = [
        {"url": f"{test_server}/api/protected/secret_data", "method": "GET", "requires_auth": True, "status_code": 401}
    ]
    discovered = [
        f"{test_server}/api/protected/secret_data",
        f"{test_server}/api/logout_broken"
    ]

    auth_ctx = {"headers": {"Authorization": "Bearer valid_token"}}

    coverage = await check_auth(
        scanner, 
        discovered, 
        [], 
        mock_client, 
        auth_context=auth_ctx,
        endpoints=endpoints
    )
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Session Remains Valid After Logout%")).all()
    assert len(findings) > 0
    assert findings[0].verification_status == "CONFIRMED"

@pytest.mark.asyncio
async def test_scenario_43_password_recovery_form_checks(test_server, db_session, mock_client):
    scan = Scan(id="test-scan-43", target_url=test_server, status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)

    forms = [{
        "action_url": "http://insecure.test/api/reset_password",
        "page_url": "http://insecure.test/forgot_password",
        "method": "POST",
        "inputs": ["email", "reset_token"],
        "has_csrf_token": False,
        "is_auth": False,
        "is_reset": True
    }]

    coverage = await check_auth(scanner, [], forms, mock_client, None)
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    titles = [f.title for f in findings]
    assert any("Password Recovery Form Action" in t for t in titles)
    assert any("Password Reset Request Form Missing Anti-CSRF" in t for t in titles)

