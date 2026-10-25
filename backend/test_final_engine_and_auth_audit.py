"""
Comprehensive Verification Suite: Final Engine and Authentication Audit & Repair.
Tests anti-false-positive authentication logic, credential transport, engine orchestration,
status consistency, and honest coverage accounting.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Scan, Finding
from scanner.engine import SecurityScanner
from scanner.checks.auth import check_auth, is_generic_error_page, has_access_denied_indicator, extract_protected_markers
from scanner.checks.misconfig import check_misconfig
from scanner.safety import is_safe_url, UnsafeTargetError
from scanner.checks.sqli import SQLiCoverageRecord
from scanner.checks.xss import XSSCoverageRecord


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.mark.asyncio
async def test_auth_bypass_public_page_not_false_positive(test_db):
    """Verifies that identical 200 responses on a public page are NOT falsely confirmed as authentication bypass."""
    scan = Scan(id="scan-public-page", target_url="http://test.local", status="running")
    test_db.add(scan)
    test_db.commit()
    scanner = SecurityScanner(test_db, scan.id)

    # Mock client where both authenticated and unauthenticated return identical public HTML
    public_html = "<html><body><h1>Welcome to Our Public Services</h1><p>General information for visitors.</p></body></html>"
    mock_resp = httpx.Response(200, text=public_html, request=httpx.Request("GET", "http://test.local/about"))

    client = MagicMock()
    client.request = AsyncMock(return_value=mock_resp)

    # Discovered URL with NO prior auth requirement
    discovered = ["http://test.local/about"]
    endpoints = [{"url": "http://test.local/about", "method": "GET", "requires_auth": False, "status_code": 200}]

    coverage = await check_auth(
        scanner=scanner,
        discovered_urls=discovered,
        discovered_forms=[],
        client=client,
        auth_context={"headers": {"Authorization": "Bearer token123"}},
        endpoints=endpoints
    )

    findings = test_db.query(Finding).filter(Finding.scan_id == scan.id).all()
    bypass_findings = [f for f in findings if "Bypass" in f.title]
    assert len(bypass_findings) == 0, f"Expected 0 bypass findings on public page, got: {[f.title for f in bypass_findings]}"


@pytest.mark.asyncio
async def test_auth_bypass_login_page_200_not_false_positive(test_db):
    """Verifies that an unauthenticated HTTP 200 containing a login form is treated as enforcement, NOT bypass."""
    scan = Scan(id="scan-login-200", target_url="http://test.local", status="running")
    test_db.add(scan)
    test_db.commit()
    scanner = SecurityScanner(test_db, scan.id)

    auth_resp = httpx.Response(200, text='{"profile": "user_data", "user_id": 42}', request=httpx.Request("GET", "http://test.local/profile"))
    login_html = '<html><body><h2>Sign In</h2><form action="/login" method="POST"><input type="password" name="password"></form></body></html>'
    no_auth_resp = httpx.Response(200, text=login_html, request=httpx.Request("GET", "http://test.local/profile"))

    client = MagicMock()
    client.request = AsyncMock(side_effect=[auth_resp, no_auth_resp])

    endpoints = [{"url": "http://test.local/profile", "method": "GET", "requires_auth": True, "status_code": 401}]

    await check_auth(
        scanner=scanner,
        discovered_urls=["http://test.local/profile"],
        discovered_forms=[],
        client=client,
        auth_context={"headers": {"Authorization": "Bearer token123"}},
        endpoints=endpoints
    )

    bypass_findings = test_db.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Bypass%")).all()
    assert len(bypass_findings) == 0


@pytest.mark.asyncio
async def test_auth_bypass_access_denied_200_not_false_positive(test_db):
    """Verifies that an HTTP 200 containing an access-denied indicator is not reported as bypass."""
    scan = Scan(id="scan-denied-200", target_url="http://test.local", status="running")
    test_db.add(scan)
    test_db.commit()
    scanner = SecurityScanner(test_db, scan.id)

    auth_resp = httpx.Response(200, text='{"secret": "privileged_doc"}', request=httpx.Request("GET", "http://test.local/private/doc"))
    denied_resp = httpx.Response(200, text='<html><body><h3>Access Denied: You must be logged in to view this document</h3></body></html>', request=httpx.Request("GET", "http://test.local/private/doc"))

    client = MagicMock()
    client.request = AsyncMock(side_effect=[auth_resp, denied_resp])

    endpoints = [{"url": "http://test.local/private/doc", "method": "GET", "requires_auth": True, "status_code": 403}]

    await check_auth(
        scanner=scanner,
        discovered_urls=["http://test.local/private/doc"],
        discovered_forms=[],
        client=client,
        auth_context={"headers": {"Authorization": "Bearer token123"}},
        endpoints=endpoints
    )

    bypass_findings = test_db.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Bypass%")).all()
    assert len(bypass_findings) == 0


@pytest.mark.asyncio
async def test_auth_bypass_generic_error_200_not_false_positive(test_db):
    """Verifies that an unauthenticated 200 containing a generic 404/error template is not reported as bypass."""
    scan = Scan(id="scan-err-200", target_url="http://test.local", status="running")
    test_db.add(scan)
    test_db.commit()
    scanner = SecurityScanner(test_db, scan.id)

    auth_resp = httpx.Response(200, text='{"balance": 1000, "user_id": 99}', request=httpx.Request("GET", "http://test.local/billing"))
    err_resp = httpx.Response(200, text='<html><head><title>404 Not Found</title></head><body>Resource not found.</body></html>', request=httpx.Request("GET", "http://test.local/billing"))

    client = MagicMock()
    client.request = AsyncMock(side_effect=[auth_resp, err_resp])

    endpoints = [{"url": "http://test.local/billing", "method": "GET", "requires_auth": True, "status_code": 401}]

    await check_auth(
        scanner=scanner,
        discovered_urls=["http://test.local/billing"],
        discovered_forms=[],
        client=client,
        auth_context={"headers": {"Authorization": "Bearer token123"}},
        endpoints=endpoints
    )

    bypass_findings = test_db.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Bypass%")).all()
    assert len(bypass_findings) == 0


@pytest.mark.asyncio
async def test_auth_bypass_confirmed_on_genuine_protected_resource(test_db):
    """Verifies that a genuine protected endpoint returning verified protected content anonymously IS confirmed."""
    scan = Scan(id="scan-genuine-bypass", target_url="http://test.local", status="running")
    test_db.add(scan)
    test_db.commit()
    scanner = SecurityScanner(test_db, scan.id)

    # Target returns protected financial / account data to both authenticated and unauthenticated
    data_payload = '{"user_id": 101, "balance": 5000, "roles": ["admin"], "secret": "internal_token"}'
    resp = httpx.Response(200, text=data_payload, request=httpx.Request("GET", "http://test.local/api/protected/wallet"))

    client = MagicMock()
    client.request = AsyncMock(return_value=resp)

    endpoints = [{"url": "http://test.local/api/protected/wallet", "method": "GET", "requires_auth": True, "status_code": 401}]

    await check_auth(
        scanner=scanner,
        discovered_urls=["http://test.local/api/protected/wallet"],
        discovered_forms=[],
        client=client,
        auth_context={"headers": {"Authorization": "Bearer token123"}},
        endpoints=endpoints
    )

    bypass_findings = test_db.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Bypass%")).all()
    assert len(bypass_findings) == 1
    assert bypass_findings[0].verification_status == "CONFIRMED"
    assert bypass_findings[0].severity == "high"


@pytest.mark.asyncio
async def test_insecure_form_action_ignores_non_credential_forms(test_db):
    """Verifies that forms lacking credential fields (e.g. search bar) are NOT reported as insecure authentication forms."""
    scan = Scan(id="scan-search-form", target_url="http://test.local", status="running")
    test_db.add(scan)
    test_db.commit()
    scanner = SecurityScanner(test_db, scan.id)

    forms = [{
        "action_url": "http://test.local/search",
        "page_url": "http://test.local/index",
        "method": "GET",
        "inputs": ["q", "category"],
        "has_csrf_token": False,
        "is_auth": False,
        "is_reset": False
    }]

    client = MagicMock()
    await check_auth(scanner, [], forms, client, None)

    findings = test_db.query(Finding).filter(Finding.scan_id == scan.id).all()
    auth_action_findings = [f for f in findings if "Form Action" in f.title]
    assert len(auth_action_findings) == 0


@pytest.mark.asyncio
async def test_insecure_form_action_detects_credential_forms(test_db):
    """Verifies that an authentication form submitting credentials over plain HTTP IS reported as confirmed."""
    scan = Scan(id="scan-insecure-cred-form", target_url="http://test.local", status="running")
    test_db.add(scan)
    test_db.commit()
    scanner = SecurityScanner(test_db, scan.id)

    forms = [{
        "action_url": "http://test.local/api/login",
        "page_url": "http://test.local/login",
        "method": "POST",
        "inputs": ["username", "password"],
        "has_csrf_token": True,
        "is_auth": True
    }]

    client = MagicMock()
    await check_auth(scanner, [], forms, client, None)

    findings = test_db.query(Finding).filter(Finding.scan_id == scan.id, Finding.title.like("%Insecure Authentication Form Action%")).all()
    assert len(findings) == 1
    assert findings[0].verification_status == "CONFIRMED"
    assert findings[0].severity == "high"


def test_target_url_safety_embedded_credentials():
    """Verifies that URLs with embedded credentials raise UnsafeTargetError."""
    with pytest.raises(UnsafeTargetError):
        is_safe_url("http://admin:secret123@example.com/test")


def test_coverage_records_importable_and_instantiable():
    """Verifies SQLiCoverageRecord and XSSCoverageRecord are imported and have expected attributes."""
    sqli_rec = SQLiCoverageRecord()
    assert hasattr(sqli_rec, "candidate_inputs_discovered")
    assert hasattr(sqli_rec, "inputs_tested")
    assert hasattr(sqli_rec, "requests_completed")

    xss_rec = XSSCoverageRecord()
    assert hasattr(xss_rec, "candidate_inputs_discovered")
    assert hasattr(xss_rec, "inputs_tested")
    assert hasattr(xss_rec, "requests_completed")


@pytest.mark.asyncio
async def test_misconfig_module_clean_and_detected(test_db):
    """Verifies that misconfig module executes real probes and reports clean NOT_DETECTED or CONFIRMED finding."""
    scan = Scan(id="scan-misconfig-clean", target_url="http://test.local", status="running")
    test_db.add(scan)
    test_db.commit()
    scanner = SecurityScanner(test_db, scan.id)

    # 1. Clean responses
    client = MagicMock()
    clean_resp = httpx.Response(404, text="Not Found", request=httpx.Request("GET", "http://test.local/static/"))
    client.get = AsyncMock(return_value=clean_resp)

    await check_misconfig(scanner, "http://test.local", client)
    clean_findings = test_db.query(Finding).filter(Finding.scan_id == scan.id, Finding.type == "misconfig").all()
    assert len(clean_findings) == 1
    assert clean_findings[0].verification_status == "NOT_DETECTED"

    # 2. Directory listing enabled
    scan2 = Scan(id="scan-misconfig-dir", target_url="http://test.local", status="running")
    test_db.add(scan2)
    test_db.commit()
    scanner2 = SecurityScanner(test_db, scan2.id)

    dir_listing_html = "<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1><pre><a href='file.txt'>file.txt</a></pre></body></html>"
    dir_resp = httpx.Response(200, text=dir_listing_html, request=httpx.Request("GET", "http://test.local/static/"))
    client2 = MagicMock()
    client2.get = AsyncMock(return_value=dir_resp)

    await check_misconfig(scanner2, "http://test.local", client2)
    dir_findings = test_db.query(Finding).filter(Finding.scan_id == scan2.id, Finding.title.like("%Directory Listing%")).all()
    assert len(dir_findings) == 1
    assert dir_findings[0].verification_status == "CONFIRMED"
