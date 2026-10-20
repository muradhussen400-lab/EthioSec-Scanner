import pytest
from fastapi import FastAPI, Response, Request
import httpx
from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from models import Scan, Finding

app = FastAPI()

@app.get("/info/sensitive")
async def info_sensitive():
    return Response(content="Traceback (most recent call last):")
    
@app.get("/info/safe")
async def info_safe():
    return Response(content="An error occurred.")
    
@app.get("/info/ambiguous")
async def info_ambiguous():
    return Response(content="Welcome", headers={"Server": "nginx"})
    
@app.get("/.env")
async def env_vuln():
    return Response(content="SECRET_KEY=123\nDB_PASS=456")
    
@app.get("/.git/HEAD")
async def git_vuln():
    return Response(content="ref: refs/heads/master")
    
@app.get("/not_found_custom/.env")
async def env_custom_404():
    return Response(content="Oops, not found here but 200 OK")
    
@app.get("/robots.txt")
async def robots_safe():
    return Response(content="User-agent: *\nDisallow: /admin")

@app.get("/https_redirect")
async def https_redirect(response: Response):
    response.status_code = 301
    response.headers["Location"] = "https://127.0.0.1/"
    return {"status": "redirecting"}

@pytest.fixture
def mock_client():
    from httpx import ASGITransport, AsyncClient
    client = SafeHTTPClient()
    client.client = AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1")
    return client

@pytest.fixture
def test_server():
    return "http://example.com"

@pytest.fixture
def db_session():
    from sqlalchemy.orm import Session
    from sqlalchemy import create_engine
    from models import Base
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    yield session
    session.close()

@pytest.mark.asyncio
async def test_info_disclosure(test_server, db_session, mock_client):
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    
    from scanner.checks.info_disclosure import check_info_disclosure
    
    # Sensitive
    resp = await mock_client.get(f"{test_server}/info/sensitive")
    await check_info_disclosure(scanner, f"{test_server}/info/sensitive", resp)
    assert db_session.query(Finding).filter(Finding.status == "MEDIUM").count() > 0
    db_session.query(Finding).delete()
    db_session.commit()
    
    # Safe
    resp = await mock_client.get(f"{test_server}/info/safe")
    await check_info_disclosure(scanner, f"{test_server}/info/safe", resp)
    assert db_session.query(Finding).count() == 0
    db_session.query(Finding).delete()
    db_session.commit()
    
    # Ambiguous
    resp = await mock_client.get(f"{test_server}/info/ambiguous")
    await check_info_disclosure(scanner, f"{test_server}/info/ambiguous", resp)
    assert db_session.query(Finding).filter(Finding.status == "LOW").count() > 0

@pytest.mark.asyncio
async def test_exposed_files(test_server, db_session, mock_client):
    scan = Scan(id=2, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    
    from scanner.checks.exposed_files import check_exposed_files
    
    # Sensitive .env
    await check_exposed_files(scanner, f"{test_server}/", mock_client)
    findings = db_session.query(Finding).filter(Finding.title.contains(".env")).all()
    assert len(findings) > 0
    print("EVIDENCE:", findings[0].evidence)
    assert findings[0].status == "HIGH"
    db_session.query(Finding).delete()
    db_session.commit()
    
    # Custom 404 .env
    await check_exposed_files(scanner, f"{test_server}/not_found_custom/", mock_client)
    findings = db_session.query(Finding).filter(Finding.title.contains(".env")).all()
    # It should not confirm a finding, either NOT_DETECTED or no finding added (we dropped them if not HIGH/MEDIUM except for errors)
    assert len([f for f in findings if f.status in ["HIGH", "MEDIUM"]]) == 0

@pytest.mark.asyncio
async def test_https(test_server, db_session, mock_client):
    scan = Scan(id=3, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    
    from scanner.checks.https import check_https
    
    # Insecure HTTP
    resp = await mock_client.get(f"{test_server}/info/safe")
    await check_https(scanner, f"{test_server}/info/safe", resp)
    assert db_session.query(Finding).filter(Finding.status == "HIGH").count() > 0
    db_session.query(Finding).delete()
    db_session.commit()
    
    # Secure HTTPS
    resp = await mock_client.get(f"https://127.0.0.1/info/safe")
    await check_https(scanner, "https://127.0.0.1/info/safe", resp)
    # Status becomes NOT_DETECTED, so it's not saved (unless we saved it). check_https saves only HIGH/MEDIUM/LOW/SCANNER_ERROR.
    assert db_session.query(Finding).count() == 0
    
    # HTTP -> HTTPS redirect (mocked)
    resp = httpx.Response(status_code=301, headers={"Location": "https://127.0.0.1/"})
    resp.request = httpx.Request("GET", "http://127.0.0.1/https_redirect")
    await check_https(scanner, "http://127.0.0.1/https_redirect", resp)
    assert db_session.query(Finding).count() == 0


@pytest.mark.asyncio
async def test_exposed_files_spa_fallback_and_redaction(test_server, db_session, mock_client, monkeypatch):
    monkeypatch.setenv("ALLOW_LOCAL_TARGETS", "true")
    scan = Scan(id=4, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client

    from scanner.checks.exposed_files import _is_html_response, _validate_env_content, _validate_git_head

    # 1. SPA fallback HTML detection
    spa_html = "<!DOCTYPE html><html><head><title>Cafeteria SPA</title></head><body><div id='app'></div></body></html>"
    mock_resp = httpx.Response(200, headers={"Content-Type": "text/html; charset=utf-8"}, text=spa_html)
    assert _is_html_response(mock_resp, spa_html) is True

    # 2. False positive check: SPA HTML returned for .env
    is_valid, evidence = _validate_env_content(spa_html)
    assert is_valid is False
    assert evidence == ""

    # 3. False positive check: Bogus or HTML returned for .git/HEAD
    is_valid_git, git_ev = _validate_git_head(spa_html)
    assert is_valid_git is False
    assert git_ev == ""

    bogus_git = "<html>404 Not Found but 200 OK</html>"
    is_valid_bogus, _ = _validate_git_head(bogus_git)
    assert is_valid_bogus is False

    # 4. Valid .git/HEAD test
    valid_head = "ref: refs/heads/main\n"
    is_head, head_ev = _validate_git_head(valid_head)
    assert is_head is True
    assert "ref: refs/heads/main" in head_ev

    # 5. Detached HEAD test (40 hex chars)
    detached_head = "d670460b4b4aece5915caf5c68d12f560a9fe3e4\n"
    is_detached, det_ev = _validate_git_head(detached_head)
    assert is_detached is True
    assert "d670460b4b4aece5915caf5c68d12f560a9fe3e4" in det_ev

    # 6. Valid .env with secret values must REDACT all values in evidence
    raw_env = (
        "APP_ENV=production\n"
        "DATABASE_URL=postgresql://admin:SuperSecretPass123!@localhost:5432/db\n"
        "JWT_SECRET=super-secret-jwt-token-999\n"
        "PORT=8000\n"
    )
    is_env_valid, env_ev = _validate_env_content(raw_env)
    assert is_env_valid is True
    # Verify raw secret strings are strictly REDACTED and never contained in evidence
    assert "SuperSecretPass123!" not in env_ev
    assert "super-secret-jwt-token-999" not in env_ev
    assert "[REDACTED]" in env_ev
    assert "DATABASE_URL=[REDACTED]" in env_ev
    assert "JWT_SECRET=[REDACTED]" in env_ev

