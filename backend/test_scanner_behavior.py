import pytest
import asyncio
import httpx
import uvicorn
from fastapi import FastAPI, Request, Response, Form, Header
from fastapi.responses import HTMLResponse, JSONResponse
from threading import Thread
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
import os
os.environ["ALLOW_LOCAL_TARGETS"] = "true"
from models import Base, Scan, ScanTarget, Finding

app = FastAPI()

# --- FIXTURE ENDPOINTS ---

@app.get("/sqli/vulnerable")
async def sqli_vuln(id: str = "1"):
    # Simple simulated SQL injection behavior
    if "'" in id or '"' in id:
        return JSONResponse({"error": "sql syntax error"}, status_code=500)
    if "1=1" in id.replace(" ", ""):
        return JSONResponse({"data": "secret_data"})
    if "1=2" in id.replace(" ", ""):
        return JSONResponse({"data": "no_data"})
    return JSONResponse({"data": "normal_data"})

@app.get("/sqli/secure")
async def sqli_secure(id: str = "1"):
    return JSONResponse({"data": "normal_data"})

@app.get("/xss/vulnerable")
async def xss_vuln(q: str = ""):
    return HTMLResponse(f"<html><body>Search results for: {q}</body></html>")

@app.get("/xss/secure")
async def xss_secure(q: str = ""):
    import html
    return HTMLResponse(f"<html><body>Search results for: {html.escape(q)}</body></html>")

@app.get("/xss/ambiguous")
async def xss_ambiguous(q: str = ""):
    # Strips < and >, but still reflects.
    clean = q.replace("<", "").replace(">", "")
    return HTMLResponse(f"<html><body>Search results for: {clean}</body></html>")

@app.get("/api/me")
async def api_me(authorization: str = Header(None)):
    if authorization == "Bearer valid":
        return JSONResponse({"user": "Account A"})
    return JSONResponse({"error": "Unauthorized"}, status_code=401)

@app.get("/api/me_bypass")
async def api_me_bypass(authorization: str = Header(None)):
    # Bypassed endpoint
    return JSONResponse({"user": "Account A"})

@app.get("/users/{user_id}")
async def get_user(user_id: int, authorization: str = Header(None)):
    if not authorization:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if authorization == "Bearer b" and user_id == 1:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    # Vulnerable IDOR
    return JSONResponse({"user_id": user_id, "data": f"Secret {user_id}"})

@app.get("/users_secure/{user_id}")
async def get_user_secure(user_id: int, authorization: str = Header(None)):
    if not authorization:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if authorization == "Bearer a" and user_id != 1:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    if authorization == "Bearer b" and user_id != 2:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    return JSONResponse({"user_id": user_id, "data": f"Secret {user_id}"})


@app.get("/timeout")
async def timeout():
    await asyncio.sleep(5)
    return JSONResponse({"data": "ok"})


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
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

# --- TESTS ---

@pytest.mark.asyncio
async def test_sqli_vulnerable(test_server, db_session, mock_client):
    client = mock_client
    target = ScanTarget(url=f"{test_server}", id=1)
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(target)
    db_session.add(scan)
    db_session.commit()
    
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = client
    
    from scanner.checks.sqli import check_sqli
    endpoints = [{"url": f"{test_server}/sqli/vulnerable", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client, "standard")
    
    findings = db_session.query(Finding).all()
    assert len(findings) > 0
    assert findings[0].type == "sqli"
    assert findings[0].status == "HIGH"
    assert "syntax error" in findings[0].evidence.lower() or "structural" in findings[0].evidence.lower() or "500" in findings[0].evidence.lower()

@pytest.mark.asyncio
async def test_sqli_secure(test_server, db_session, mock_client):
    client = mock_client
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = client
    
    from scanner.checks.sqli import check_sqli
    endpoints = [{"url": f"{test_server}/sqli/secure", "method": "GET", "params": ["id"]}]
    await check_sqli(scanner, endpoints, [], client, "standard")
    
    # Should not produce confirmed finding
    findings = db_session.query(Finding).all()
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_xss_vulnerable(test_server, db_session, mock_client):
    client = mock_client
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = client
    
    from scanner.checks.xss import check_xss
    endpoints = [{"url": f"{test_server}/xss/vulnerable", "method": "GET", "params": ["q"]}]
    await check_xss(scanner, endpoints, [], client, "standard")
    
    findings = db_session.query(Finding).all()
    assert len(findings) > 0
    assert findings[0].status == "MEDIUM"

@pytest.mark.asyncio
async def test_xss_secure(test_server, db_session, mock_client):
    client = mock_client
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = client
    
    from scanner.checks.xss import check_xss
    endpoints = [{"url": f"{test_server}/xss/secure", "method": "GET", "params": ["q"]}]
    await check_xss(scanner, endpoints, [], client, "standard")
    
    findings = db_session.query(Finding).all()
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_xss_ambiguous(test_server, db_session, mock_client):
    client = mock_client
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = client
    
    from scanner.checks.xss import check_xss
    endpoints = [{"url": f"{test_server}/xss/ambiguous", "method": "GET", "params": ["q"]}]
    await check_xss(scanner, endpoints, [], client, "standard")
    
    findings_list = db_session.query(Finding).all()
    findings = [f for f in findings_list if f.status == "MEDIUM"]
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_idor_vulnerable(test_server, db_session, mock_client):
    client = mock_client
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = client
    
    from scanner.checks.access_control import check_access_control
    endpoints = [{"url": f"{test_server}/users/1", "method": "GET", "params": []}]
    
    auth1 = {"headers": {"Authorization": "Bearer a"}}
    auth2 = {"headers": {"Authorization": "Bearer b"}}
    
    await check_access_control(scanner, endpoints, client, auth1, auth2)
    
    findings = db_session.query(Finding).all()
    assert len(findings) > 0
    assert findings[0].status == "MEDIUM"

@pytest.mark.asyncio
async def test_idor_secure(test_server, db_session, mock_client):
    client = mock_client
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = client
    
    from scanner.checks.access_control import check_access_control
    endpoints = [{"url": f"{test_server}/users_secure/1", "method": "GET", "params": []}]
    
    auth1 = {"headers": {"Authorization": "Bearer a"}}
    auth2 = {"headers": {"Authorization": "Bearer b"}}
    
    await check_access_control(scanner, endpoints, client, auth1, auth2)
    findings = db_session.query(Finding).all()
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_auth_bypass(test_server, db_session, mock_client):
    client = mock_client
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = client
    
    from scanner.checks.auth import check_auth
    
    endpoints = [f"{test_server}/api/me_bypass"]
    auth = {"headers": {"Authorization": "Bearer valid"}}
    
    await check_auth(scanner, endpoints, [], client, auth)
    findings = db_session.query(Finding).all()
    assert len(findings) > 0
    assert findings[0].status == "HIGH"

@pytest.mark.asyncio
async def test_auth_inconclusive(test_server, db_session, mock_client):
    from models import Scan, Finding
    from scanner.checks.auth import check_auth
    scan = Scan(id=4, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    from scanner.engine import SecurityScanner
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    
    # Missing auth_context triggers LOW
    await check_auth(scanner, [f"{test_server}/account"], [], mock_client, None)
    findings = db_session.query(Finding).all()
    assert len(findings) > 0
    assert findings[-1].status == "LOW"

@pytest.mark.asyncio
async def test_idor_low(test_server, db_session, mock_client):
    from models import Scan, Finding
    from scanner.checks.access_control import check_access_control
    scan = Scan(id=5, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    from scanner.engine import SecurityScanner
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    
    endpoints = [{"url": f"{test_server}/users/1", "method": "GET", "params": []}]
    # Missing auth_context_2 triggers LOW if a mutation succeeds but cannot be proven to belong to someone else.
    await check_access_control(scanner, endpoints, mock_client, {"headers": {"Authorization": "Bearer a"}}, None)
    findings = db_session.query(Finding).all()
    assert len(findings) > 0
    assert findings[-1].status == "LOW"
