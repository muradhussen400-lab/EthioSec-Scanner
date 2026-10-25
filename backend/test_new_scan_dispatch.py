import os
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from main import app
from database import Base, SessionLocal
from models import User, ScanTarget, Scan, Finding
from scanner.engine import SecurityScanner
from schemas import ScanCreate

client = TestClient(app)

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def create_test_user_and_target(db):
    user = User(email="dispatch_tester@example.com", password_hash="hash", is_verified=True)
    db.add(user)
    db.commit()
    target = ScanTarget(user_id=user.id, url="http://127.0.0.1:3000", authorized=True)
    db.add(target)
    db.commit()
    return user, target

# 1. Selecting only SQL Injection runs only SQL Injection checks
@pytest.mark.asyncio
async def test_sqli_only_runs_sqli(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"sqli": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.sqli.check_sqli", new_callable=AsyncMock) as mock_sqli, \
         patch("scanner.checks.xss.check_xss", new_callable=AsyncMock) as mock_xss, \
         patch("scanner.checks.headers.check_security_headers", new_callable=AsyncMock) as mock_headers, \
         patch("scanner.checks.exposed_files.check_exposed_files", new_callable=AsyncMock) as mock_exposed:
        
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        await scanner.run_scan()

        assert mock_sqli.called, "SQLi check should be executed"
        assert not mock_xss.called, "XSS check should NOT be executed"
        assert not mock_headers.called, "Headers check should NOT be executed"
        assert not mock_exposed.called, "Exposed files check should NOT be executed"

# 2. Selecting only XSS runs only XSS checks
@pytest.mark.asyncio
async def test_xss_only_runs_xss(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"xss": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.sqli.check_sqli", new_callable=AsyncMock) as mock_sqli, \
         patch("scanner.checks.xss.check_xss", new_callable=AsyncMock) as mock_xss:
        
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        await scanner.run_scan()

        assert not mock_sqli.called, "SQLi check should NOT be executed"
        assert mock_xss.called, "XSS check should be executed"

# 3. Selecting two categories runs only those categories
@pytest.mark.asyncio
async def test_two_categories_only_runs_selected(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"sqli": True, "xss": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.sqli.check_sqli", new_callable=AsyncMock) as mock_sqli, \
         patch("scanner.checks.xss.check_xss", new_callable=AsyncMock) as mock_xss, \
         patch("scanner.checks.headers.check_security_headers", new_callable=AsyncMock) as mock_headers:
        
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        await scanner.run_scan()

        assert mock_sqli.called, "SQLi check should be executed"
        assert mock_xss.called, "XSS check should be executed"
        assert not mock_headers.called, "Headers check should NOT be executed"

# 4. Explicitly false modules are not executed
@pytest.mark.asyncio
async def test_explicitly_false_modules_not_executed(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"sqli": True, "xss": False, "headers": False},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.sqli.check_sqli", new_callable=AsyncMock) as mock_sqli, \
         patch("scanner.checks.xss.check_xss", new_callable=AsyncMock) as mock_xss, \
         patch("scanner.checks.headers.check_security_headers", new_callable=AsyncMock) as mock_headers:
        
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        await scanner.run_scan()

        assert mock_sqli.called
        assert not mock_xss.called
        assert not mock_headers.called

# 5. Empty module selection cannot accidentally trigger all checks
@pytest.mark.asyncio
async def test_empty_modules_does_not_trigger_all_checks(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.sqli.check_sqli", new_callable=AsyncMock) as mock_sqli, \
         patch("scanner.checks.xss.check_xss", new_callable=AsyncMock) as mock_xss, \
         patch("scanner.checks.headers.check_security_headers", new_callable=AsyncMock) as mock_headers, \
         patch("scanner.checks.exposed_files.check_exposed_files", new_callable=AsyncMock) as mock_exposed:
        
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        await scanner.run_scan()

        assert not mock_sqli.called, "Empty modules must not trigger SQLi"
        assert not mock_xss.called, "Empty modules must not trigger XSS"
        assert not mock_headers.called, "Empty modules must not trigger Headers"
        assert not mock_exposed.called, "Empty modules must not trigger Exposed files"

# 6. Unknown module keys are rejected by validation
def test_unknown_module_keys_rejected():
    with pytest.raises(Exception) as exc_info:
        ScanCreate(
            target_id="test-id",
            depth="standard",
            modules={"unknown_exploit_module": True},
            authorized=True
        )
    assert "Unknown module(s)" in str(exc_info.value)

# 7. Selecting all supported modules behaves correctly
@pytest.mark.asyncio
async def test_select_all_supported_modules(db_session):
    user, target = create_test_user_and_target(db_session)
    all_modules = {
        "sqli": True,
        "xss": True,
        "headers": True,
        "cookies": True,
        "cors": True,
        "https": True,
        "auth": True,
        "access_control": True,
        "exposed_files": True,
        "http_methods": True,
        "info_disclosure": True
    }
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules=all_modules,
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    dummy_resp = MagicMock()
    dummy_resp.status_code = 200
    dummy_resp.text = "<html>Test</html>"
    dummy_resp.headers = {"Content-Type": "text/html"}

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.SafeHTTPClient.get", new_callable=AsyncMock, return_value=dummy_resp), \
         patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.sqli.check_sqli", new_callable=AsyncMock) as mock_sqli, \
         patch("scanner.checks.xss.check_xss", new_callable=AsyncMock) as mock_xss, \
         patch("scanner.checks.headers.check_security_headers", new_callable=AsyncMock) as mock_headers, \
         patch("scanner.checks.cookies.check_cookies", new_callable=AsyncMock) as mock_cookies, \
         patch("scanner.checks.cors.check_cors", new_callable=AsyncMock) as mock_cors, \
         patch("scanner.checks.https.check_https", new_callable=AsyncMock) as mock_https, \
         patch("scanner.checks.auth.check_auth", new_callable=AsyncMock) as mock_auth, \
         patch("scanner.checks.exposed_files.check_exposed_files", new_callable=AsyncMock) as mock_exposed, \
         patch("scanner.checks.http_methods.check_http_methods", new_callable=AsyncMock) as mock_methods, \
         patch("scanner.checks.info_disclosure.check_info_disclosure", new_callable=AsyncMock) as mock_info:
        
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        await scanner.run_scan()

        assert mock_sqli.called
        assert mock_xss.called
        assert mock_headers.called
        assert mock_cookies.called
        assert mock_cors.called
        assert mock_https.called
        assert mock_auth.called
        assert mock_exposed.called
        assert mock_methods.called
        assert mock_info.called

# 8. Exposed Files does not unintentionally trigger unrelated checks
@pytest.mark.asyncio
async def test_exposed_files_does_not_trigger_unrelated_checks(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"exposed_files": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.exposed_files.check_exposed_files", new_callable=AsyncMock) as mock_exposed, \
         patch("scanner.checks.headers.check_security_headers", new_callable=AsyncMock) as mock_headers, \
         patch("scanner.checks.cookies.check_cookies", new_callable=AsyncMock) as mock_cookies, \
         patch("scanner.checks.cors.check_cors", new_callable=AsyncMock) as mock_cors, \
         patch("scanner.checks.info_disclosure.check_info_disclosure", new_callable=AsyncMock) as mock_info, \
         patch("scanner.checks.http_methods.check_http_methods", new_callable=AsyncMock) as mock_methods:
        
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        await scanner.run_scan()

        assert mock_exposed.called, "Exposed files check should be executed"
        assert not mock_headers.called, "Headers check should NOT be executed"
        assert not mock_cookies.called, "Cookies check should NOT be executed"
        assert not mock_cors.called, "CORS check should NOT be executed"
        assert not mock_info.called, "Info disclosure check should NOT be executed"
        assert not mock_methods.called, "HTTP methods check should NOT be executed"

# 9. Standard Scan uses verified Standard profile configuration (max_pages=15, max_depth=2)
@pytest.mark.asyncio
async def test_standard_scan_profile_limits(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"sqli": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler") as mock_crawler_class:
        instance = mock_crawler_class.return_value
        instance.run = AsyncMock(return_value={"urls": [target.url], "endpoints": [], "forms": []})
        await scanner.run_scan()

        args, kwargs = mock_crawler_class.call_args
        assert kwargs.get("max_pages") == 15, f"Expected max_pages=15, got {kwargs.get('max_pages')}"
        assert kwargs.get("max_depth") == 2, f"Expected max_depth=2, got {kwargs.get('max_depth')}"

# 10. Deep Scan uses verified Deep profile configuration (max_pages=50, max_depth=4)
@pytest.mark.asyncio
async def test_deep_scan_profile_limits(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="deep",
        modules={"sqli": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler") as mock_crawler_class:
        instance = mock_crawler_class.return_value
        instance.run = AsyncMock(return_value={"urls": [target.url], "endpoints": [], "forms": []})
        await scanner.run_scan()

        args, kwargs = mock_crawler_class.call_args
        assert kwargs.get("max_pages") == 50, f"Expected max_pages=50, got {kwargs.get('max_pages')}"
        assert kwargs.get("max_depth") == 4, f"Expected max_depth=4, got {kwargs.get('max_depth')}"

# 11. Super Scan cannot be submitted as an available profile
def test_super_scan_profile_rejected():
    with pytest.raises(Exception) as exc_info:
        ScanCreate(
            target_id="test-id",
            depth="super",
            modules={"sqli": True},
            authorized=True
        )
    assert "Invalid scan profile 'super'" in str(exc_info.value)

# 12. Missing authentication contexts do not produce a misleading successful access-control assessment
@pytest.mark.asyncio
async def test_missing_auth_contexts_marks_inconclusive_not_verified(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"access_control": True},
        status="queued",
        auth_context_1=None,
        auth_context_2=None
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl:
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [{"url": f"{target.url}/user/1", "method": "GET"}], "forms": []}
        await scanner.run_scan()

    finding = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.type == "access_control").first()
    assert finding is not None, "Finding must be recorded for access_control"
    assert finding.status == "INCONCLUSIVE", f"Expected INCONCLUSIVE but got {finding.status}"
    assert "Verified" not in finding.title, "Must not claim Access Control Verified when no auth contexts were configured"
    assert "Inconclusive" in finding.title or "Configuration" in finding.title

# 13. Target ownership and authorization protections remain enforced
def test_target_ownership_and_authorization_protections():
    from security import create_access_token
    from schemas import TargetCreate
    from email_service import email_service

    # Target URL requires http or https
    tc = TargetCreate(url="https://example.com")
    assert tc.url == "https://example.com"

    import uuid
    uid_a = uuid.uuid4().hex[:8]
    uid_b = uuid.uuid4().hex[:8]
    email_a = f"own_a_{uid_a}@example.com"
    email_b = f"own_b_{uid_b}@example.com"

    # User A registration & target creation
    db = SessionLocal()
    try:
        user_a = User(email=email_a, password_hash="hash", is_verified=True)
        user_b = User(email=email_b, password_hash="hash", is_verified=True)
        db.add(user_a)
        db.add(user_b)
        db.commit()

        target_a = ScanTarget(user_id=user_a.id, url="https://example.com", authorized=True)
        db.add(target_a)
        db.commit()

        token_a = create_access_token({"sub": user_a.email})
        token_b = create_access_token({"sub": user_b.email})

        # 1. User A tries to create scan with authorized=False -> 403 Forbidden
        res_unauth = client.post("/api/scans", json={
            "target_id": target_a.id,
            "depth": "standard",
            "modules": {"sqli": True},
            "authorized": False
        }, headers={"Authorization": f"Bearer {token_a}"})
        assert res_unauth.status_code == 403, f"Expected 403, got {res_unauth.status_code}: {res_unauth.text}"
        assert "authorize" in res_unauth.text.lower()

        # 2. User B tries to scan User A's target -> 404 Not Found
        res_cross = client.post("/api/scans", json={
            "target_id": target_a.id,
            "depth": "standard",
            "modules": {"sqli": True},
            "authorized": True
        }, headers={"Authorization": f"Bearer {token_b}"})
        assert res_cross.status_code == 404, f"Expected 404, got {res_cross.status_code}: {res_cross.text}"
    finally:
        db.close()

# 14. Existing scan API contracts remain compatible
def test_scan_create_schema_compatibility():
    valid_scan = ScanCreate(
        target_id="valid-target-uuid",
        depth="standard",
        modules={"sqli": True, "xss": True},
        authorized=True,
        auth_context_1=None,
        auth_context_2=None
    )
    assert valid_scan.depth == "standard"
    assert valid_scan.modules["sqli"] is True
    assert valid_scan.authorized is True

# 15. The frontend payload structure is accepted
def test_frontend_payload_structure():
    frontend_payload = {
        "target_id": "target-123",
        "depth": "deep",
        "modules": {
            "sqli": True,
            "xss": True,
            "headers": True,
            "cookies": True,
            "cors": True,
            "https": True,
            "auth": False,
            "access_control": False,
            "exposed_files": True,
            "http_methods": False,
            "info_disclosure": True
        },
        "authorized": True,
        "auth_context_1": None,
        "auth_context_2": None
    }
    model = ScanCreate(**frontend_payload)
    assert model.depth == "deep"
    assert model.modules["cookies"] is True
    assert model.modules["cors"] is True
    assert model.modules["info_disclosure"] is True
    assert model.modules["auth"] is False

# 16. Module statuses change truthfully and unselected modules are marked skipped with reason
@pytest.mark.asyncio
async def test_module_states_and_skip_reasons(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"sqli": True, "xss": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.sqli.check_sqli", new_callable=AsyncMock) as mock_sqli, \
         patch("scanner.checks.xss.check_xss", new_callable=AsyncMock) as mock_xss:
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        await scanner.run_scan()

    db_session.refresh(scan)
    assert scan.status == "completed"
    assert scan.progress == 100

    details = scanner.module_details
    assert details["sqli"]["status"] == "completed"
    assert details["sqli"]["selected"] is True
    assert details["xss"]["status"] == "completed"
    assert details["xss"]["selected"] is True

    # Unselected modules must be truthfully marked skipped with reason
    assert details["headers"]["status"] == "skipped"
    assert details["headers"]["selected"] is False
    assert "not selected" in details["headers"]["message"].lower()

    assert details["https"]["status"] == "skipped"
    assert details["https"]["selected"] is False
    assert "not selected" in details["https"]["message"].lower()

# 17. Individual module exception is persisted as failed and does not leave scan hanging
@pytest.mark.asyncio
async def test_module_exception_does_not_hang_scan(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"sqli": True, "xss": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.Crawler.run", new_callable=AsyncMock) as mock_crawl, \
         patch("scanner.checks.sqli.check_sqli", new_callable=AsyncMock) as mock_sqli, \
         patch("scanner.checks.xss.check_xss", new_callable=AsyncMock) as mock_xss:
        mock_crawl.return_value = {"urls": [target.url], "endpoints": [], "forms": []}
        # Simulate unhandled exception in SQLi check
        mock_sqli.side_effect = RuntimeError("Simulated database driver failure")
        await scanner.run_scan()

    db_session.refresh(scan)
    # The scan should finish cleanly without hanging
    assert scan.status == "completed"
    assert scanner.module_details["sqli"]["status"] == "failed"
    assert "failed" in scanner.module_details["sqli"]["message"].lower()
    # Subsequent module (XSS) must still have executed
    assert mock_xss.called
    assert scanner.module_details["xss"]["status"] == "completed"

# 18. Background task exception results in truthful scan failure
@pytest.mark.asyncio
async def test_background_task_exception_persists_failure():
    from scanner.engine import run_scan_task
    import uuid

    db = SessionLocal()
    try:
        user = User(email=f"bg_err_{uuid.uuid4().hex[:6]}@example.com", password_hash="hash", is_verified=True)
        db.add(user)
        db.commit()

        scan = Scan(user_id=user.id, target_url="https://example.com", status="running", progress=5)
        db.add(scan)
        db.commit()
        scan_id = scan.id

        with patch("scanner.engine.SecurityScanner.run_scan", side_effect=Exception("Critical system worker panic")):
            await run_scan_task(scan_id)

        db.refresh(scan)
        assert scan.status == "failed"
        assert "Error" in scan.stage or "failed" in scan.stage.lower()
        assert scan.finished_at is not None
    finally:
        db.close()

# 19. Stage timestamps represent real persisted UTC events
@pytest.mark.asyncio
async def test_dynamic_progress_and_stage_timestamps(db_session):
    user, target = create_test_user_and_target(db_session)
    scan = Scan(
        user_id=user.id,
        target_url=target.url,
        depth="standard",
        modules={"headers": True},
        status="queued"
    )
    db_session.add(scan)
    db_session.commit()

    dummy_resp = MagicMock()
    dummy_resp.status_code = 200
    dummy_resp.text = "<html>Test</html>"
    dummy_resp.headers = {"Content-Type": "text/html"}

    scanner = SecurityScanner(db_session, scan.id)
    with patch("scanner.engine.SafeHTTPClient.get", new_callable=AsyncMock, return_value=dummy_resp), \
         patch("scanner.checks.headers.check_security_headers", new_callable=AsyncMock):
        await scanner.run_scan()

    db_session.refresh(scan)
    assert scan.status == "completed"
    assert scan.progress == 100

    timeline = scanner.timeline
    val_stage = next(s for s in timeline if s["id"] == "validation")
    assert val_stage["status"] == "completed"
    assert val_stage["started_at"] is not None
    assert val_stage["finished_at"] is not None
    assert "T" in val_stage["started_at"], "Must be ISO-8601 UTC timestamp"

    # Discovery stage was skipped because only passive headers was selected
    disc_stage = next(s for s in timeline if s["id"] == "discovery")
    assert disc_stage["status"] == "skipped"

