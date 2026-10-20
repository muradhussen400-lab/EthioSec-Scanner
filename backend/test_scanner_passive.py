import pytest
import httpx
from scanner.engine import SecurityScanner
from models import Finding
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from models import Base
from fastapi import FastAPI
from fastapi.responses import Response

app = FastAPI()

@app.get("/cookies/vulnerable")
async def cookies_vuln(response: Response):
    response.set_cookie(key="session", value="abc")
    return {"status": "ok"}

@app.get("/cookies/secure")
async def cookies_secure(response: Response):
    response.set_cookie(key="session", value="abc", secure=True, httponly=True, samesite="strict")
    return {"status": "ok"}

@app.get("/headers/vulnerable")
async def headers_vuln():
    return Response(content="ok")

@app.get("/headers/secure")
async def headers_secure(response: Response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=()"
    return {"status": "ok"}

@app.get("/cors/vulnerable")
async def cors_vuln(response: Response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return {"status": "ok"}

@app.get("/cors/secure")
async def cors_secure(response: Response):
    response.headers["Access-Control-Allow-Origin"] = "https://trusted.com"
    return {"status": "ok"}

@pytest.fixture
def mock_client():
    from scanner.http_client import SafeHTTPClient
    from httpx import AsyncClient, ASGITransport
    client = SafeHTTPClient()
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

@pytest.mark.asyncio
async def test_cookies(test_server, db_session, mock_client):
    from models import Scan
    from scanner.checks.cookies import check_cookies
    
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    
    # Vulnerable
    resp = await mock_client.get(f"{test_server}/cookies/vulnerable")
    await check_cookies(scanner, f"{test_server}/cookies/vulnerable", resp)
    findings = db_session.query(Finding).filter(Finding.title.contains("Cookie Missing")).all()
    assert len(findings) > 0
    
    # Secure
    db_session.query(Finding).delete()
    db_session.commit()
    resp = await mock_client.get(f"{test_server}/cookies/secure")
    await check_cookies(scanner, f"{test_server}/cookies/secure", resp)
    findings = db_session.query(Finding).filter(Finding.title.contains("Cookie Missing")).all()
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_headers(test_server, db_session, mock_client):
    from models import Scan
    from scanner.checks.headers import check_security_headers
    
    scan = Scan(id=1, target_url="https://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    
    # Vulnerable
    resp = await mock_client.get(f"{test_server}/headers/vulnerable")
    await check_security_headers(scanner, f"https://localhost/headers/vulnerable", resp)
    findings = db_session.query(Finding).filter(Finding.title.contains("Not Set")).all()
    assert len(findings) > 0
    
    # Secure
    db_session.query(Finding).delete()
    db_session.commit()
    resp = await mock_client.get(f"{test_server}/headers/secure")
    await check_security_headers(scanner, f"https://localhost/headers/secure", resp)
    findings = db_session.query(Finding).filter(Finding.title.contains("Not Set")).all()
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_cors(test_server, db_session, mock_client):
    from models import Scan
    from scanner.checks.cors import check_cors
    
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    
    # Vulnerable
    resp = await mock_client.get(f"{test_server}/cors/vulnerable")
    await check_cors(scanner, f"{test_server}/cors/vulnerable", mock_client)
    findings = db_session.query(Finding).filter(Finding.title.contains("CORS")).all()
    assert len(findings) > 0
    
    # Secure
    db_session.query(Finding).delete()
    db_session.commit()
    resp = await mock_client.get(f"{test_server}/cors/secure")
    await check_cors(scanner, f"{test_server}/cors/secure", mock_client)
    findings = db_session.query(Finding).filter(Finding.title.contains("CORS")).all()
    assert len(findings) == 0

@app.get('/https/secure')
async def https_secure(): return Response(content='ok')

@app.options('/methods/vulnerable')
async def methods_vuln(response: Response):
    response.headers['Allow'] = 'GET, POST, PUT, DELETE, TRACE'
    return {'status': 'ok'}
    
@app.options('/methods/secure')
async def methods_secure(response: Response):
    response.headers['Allow'] = 'GET, POST'
    return {'status': 'ok'}

@pytest.mark.asyncio
async def test_methods(test_server, db_session, mock_client):
    from models import Scan
    from scanner.checks.http_methods import check_http_methods
    scan = Scan(id=1, target_url='http://localhost', status='RUNNING')
    db_session.add(scan)
    db_session.commit()
    from scanner.engine import SecurityScanner
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client
    await check_http_methods(scanner, f'{test_server}/methods/vulnerable', mock_client)
    from models import Finding
    assert len(db_session.query(Finding).all()) > 0
    db_session.query(Finding).delete()
    db_session.commit()
    await check_http_methods(scanner, f'{test_server}/methods/secure', mock_client)
    assert len(db_session.query(Finding).all()) == 0
