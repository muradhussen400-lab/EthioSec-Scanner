import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from database import SessionLocal, engine, Base
from models import Scan, Finding, ScanTarget, User
from scanner.registry import CANONICAL_MODULES, resolve_module_selection
from scanner.crawler import Crawler
from scanner.checks.csrf import check_csrf
from scanner.checks.ssrf import check_ssrf
from scanner.checks.sqli import check_sqli, SQLiCoverageRecord
from scanner.checks.xss import check_xss
from scanner.engine import SecurityScanner
import datetime
import uuid


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Ensure test user exists
    user = db.query(User).filter(User.email == "prof_scanner_test@ethiosec.com").first()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            email="prof_scanner_test@ethiosec.com",
            password_hash="hashed_pass_test",
            is_verified=True
        )
        db.add(user)
        db.commit()
    yield db, user.id
    db.close()


def test_canonical_12_categories_registered():
    """Verify all 12 security categories required by Section 5 are properly registered."""
    required = [
        "sqli", "xss", "auth", "access_control", "csrf", "cors",
        "https", "headers", "cookies", "exposed_files", "info_disclosure", "ssrf"
    ]
    for category in required:
        assert category in CANONICAL_MODULES, f"Category '{category}' must be in CANONICAL_MODULES"
        meta = CANONICAL_MODULES[category]
        assert "name" in meta
        assert "owasp" in meta
        assert "type" in meta


def test_module_selection_aliases():
    """Verify aliases such as xsrf, anti-csrf, ssrf_safe map accurately."""
    resolved = resolve_module_selection({"xsrf": True, "ssrf_safe": True})
    assert resolved.get("csrf") is True
    assert resolved.get("ssrf") is True


@pytest.mark.asyncio
async def test_crawler_attack_surface_inventory():
    """Verify Crawler inventories attack surface with parameters, repeated keys, and cookies."""
    mock_client = AsyncMock()

    # Mock response with links, inline API routes, cookies, and forms
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Test App</title></head>
    <body>
        <a href="/profile?user_id=101&user_id=102&action=view">Profile Multi-Param</a>
        <form action="/update-email" method="POST">
            <input type="email" name="new_email" value="test@test.com">
            <input type="hidden" name="_token" value="abc123token">
            <button type="submit">Update</button>
        </form>
        <script>
            fetch('/api/v1/user/details?format=json');
        </script>
    </body>
    </html>
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = html_content
    mock_response.headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": "session_id=mock_session_12345; Secure; HttpOnly"
    }
    mock_client.get.return_value = mock_response

    crawler = Crawler(start_url="https://test-target.com", client=mock_client, max_pages=5, max_depth=2)
    results = await crawler.run()

    inventory = results.get("inventory", {})
    assert inventory["total_endpoints"] >= 1
    assert "content_types" in inventory
    assert "cookies" in inventory
    assert any(c.get("name") == "session_id" for c in inventory["cookies"])
    
    # Check repeated query parameter preservation
    endpoints = results.get("endpoints", [])
    has_multi_param = any(
        "user_id" in ep.get("repeated_params", {}) and len(ep["repeated_params"]["user_id"]) == 2
        for ep in endpoints
    )
    assert has_multi_param, "Repeated query parameters ?user_id=101&user_id=102 must be preserved in repeated_params"


@pytest.mark.asyncio
async def test_csrf_vulnerable_and_safe_controls(setup_db):
    """Test CSRF check generates findings for unprotected forms and verifies protected forms."""
    db, user_id = setup_db
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id=user_id,
        target_url="https://test-target.com",
        status="running",
        depth="standard",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan)
    db.commit()

    scanner = SecurityScanner(db, scan.id)

    # Form 1: Vulnerable (no anti-CSRF token, state-changing POST)
    form_vuln = {
        "page_url": "https://test-target.com/account",
        "action_url": "https://test-target.com/account/change-password",
        "method": "POST",
        "inputs": ["new_password"],
        "fields": {"new_password": {"value": "", "type": "password"}},
        "has_csrf_token": False,
        "csrf_field_name": None
    }

    # Form 2: Safe (has anti-CSRF token)
    form_safe = {
        "page_url": "https://test-target.com/account",
        "action_url": "https://test-target.com/account/transfer",
        "method": "POST",
        "inputs": ["csrf_token", "amount"],
        "fields": {
            "csrf_token": {"value": "secure_random_csrf_token_xyz", "type": "hidden"},
            "amount": {"value": "100", "type": "number"}
        },
        "has_csrf_token": True,
        "csrf_field_name": "csrf_token"
    }

    mock_client = AsyncMock()
    await check_csrf(scanner, [form_vuln, form_safe], mock_client)

    findings = db.query(Finding).filter(Finding.scan_id == scan.id, Finding.type == "csrf").all()
    assert len(findings) == 1, "Only the form without anti-CSRF token should produce a finding"
    finding = findings[0]
    assert "Missing Anti-CSRF Protection" in finding.title
    assert "change-password" in finding.url
    assert finding.severity in ("high", "medium")
    assert finding.confidence == "HIGH"


@pytest.mark.asyncio
async def test_ssrf_safe_probe_and_scheme_check(setup_db):
    """Verify SSRF check tests parameters safely without internal IP probing."""
    db, user_id = setup_db
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id=user_id,
        target_url="https://test-target.com",
        status="running",
        depth="standard",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan)
    db.commit()

    scanner = SecurityScanner(db, scan.id)

    class MockEndpoint:
        def __init__(self, url, params):
            self.url = url
            self.params = params
            self.method = "GET"

    # Endpoint with URL/webhook parameter
    endpoint = MockEndpoint("https://test-target.com/fetch-report", {"webhook_url": "https://callback.com"})

    mock_client = AsyncMock()
    # Mock that server accepts non-http gopher scheme (vulnerable)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "Accepted URI: gopher://probe"
    mock_client.get.return_value = mock_resp

    await check_ssrf(scanner, [endpoint], mock_client)

    findings = db.query(Finding).filter(Finding.scan_id == scan.id, Finding.type == "ssrf").all()
    assert len(findings) >= 1
    finding = findings[0]
    assert "SSRF" in finding.title
    assert "webhook_url" in finding.parameter


def test_evidence_sanitization(setup_db):
    """Ensure passwords, tokens, and cookies are redacted from stored findings."""
    db, user_id = setup_db
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id=user_id,
        target_url="https://test-target.com",
        status="running",
        depth="standard",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan)
    db.commit()

    scanner = SecurityScanner(db, scan.id)
    raw_evidence = "password=SuperSecretPassword123&api_key=sk_live_abcdef123456; Set-Cookie: session=secret_cookie_val;"
    scanner._add_finding(
        f_type="info_disclosure",
        severity="medium",
        status="MEDIUM",
        title="Sensitive Parameter Test",
        description="Testing redaction",
        evidence=raw_evidence,
        url="https://test-target.com"
    )

    finding = db.query(Finding).filter(Finding.scan_id == scan.id).first()
    assert finding is not None
    assert "SuperSecretPassword123" not in finding.evidence
    assert "[REDACTED]" in finding.evidence


@pytest.mark.asyncio
async def test_full_lifecycle_state_transitions(setup_db):
    """Verify scan transitions cleanly and records terminal status with inventory."""
    db, user_id = setup_db
    scan = Scan(
        id=str(uuid.uuid4()),
        user_id=user_id,
        target_url="https://example.com",
        status="queued",
        depth="standard",
        modules={"headers": True, "cookies": True},
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan)
    db.commit()

    scanner = SecurityScanner(db, scan.id)

    with patch.object(scanner, "_calculate_progress", return_value=50):
        # Emulate lifecycle transitions
        scanner._persist_state("Validating")
        scan_db = db.query(Scan).filter(Scan.id == scan.id).first()
        assert scan_db.checks is not None
        assert "timeline" in scan_db.checks
        assert "pipeline_stages" in scan_db.checks

    # Simulate completed scan
    scan.status = "completed"
    scan.stage = "Assessment completed successfully"
    scanner.inventory = {"total_endpoints": 3, "total_inputs": 5}
    scanner._persist_state()

    scan_final = db.query(Scan).filter(Scan.id == scan.id).first()
    assert scan_final.checks.get("inventory") == {"total_endpoints": 3, "total_inputs": 5}
