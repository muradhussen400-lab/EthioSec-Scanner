import pytest
from fastapi import FastAPI, Response, Request
import json
from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from models import Scan, Finding

app = FastAPI()

@app.get("/api/user/1")
async def get_user_1(request: Request):
    auth = request.headers.get("Authorization")
    if auth == "Bearer user2":
        # Directional BOLA: User2 cannot access 1, but User1 can access 2.
        return Response(status_code=403)
    if auth == "Bearer user1":
        return {"id": 1, "data": "sensitive_user1_data"}
    return Response(status_code=401)

@app.get("/api/user/2")
async def get_user_2(request: Request):
    auth = request.headers.get("Authorization")
    if auth == "Bearer user1":
        # Vulnerable IDOR
        return {"id": 2, "data": "sensitive_user2_data_accessed_by_user1"}
    if auth == "Bearer user2":
        return {"id": 2, "data": "sensitive_user2_data"}
    return Response(status_code=401)
    
@app.get("/api/user/3")
async def get_user_3(request: Request):
    auth = request.headers.get("Authorization")
    if auth == "Bearer user1":
        # Vulnerable IDOR
        return {"id": 3, "data": "sensitive_user3_data"}
    return Response(status_code=401)
    
@app.post("/api/login")
async def login():
    return {"token": "user1"}

@pytest.fixture
def mock_client():
    from httpx import ASGITransport, AsyncClient
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
    from sqlalchemy.orm import Session
    from sqlalchemy import create_engine
    from models import Base
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    yield session
    session.close()

@pytest.mark.asyncio
async def test_api_security(test_server, db_session, mock_client):
    scan = Scan(id=1, target_url="http://localhost", status="RUNNING", auth_context_1={"headers": {"Authorization": "Bearer user1"}}, auth_context_2={"headers": {"Authorization": "Bearer user2"}})
    db_session.add(scan)
    db_session.commit()
    scanner = SecurityScanner(db_session, scan.id)
    scanner.client = mock_client

    from scanner.checks.access_control import check_access_control
    
    endpoints = [
        {"url": f"{test_server}/api/user/1", "method": "GET", "params": []},
        {"url": f"{test_server}/api/user/2", "method": "GET", "params": []}
    ]
    
    await check_access_control(scanner, endpoints, mock_client, scan.auth_context_1, scan.auth_context_2)
    findings = db_session.query(Finding).all()
    for f in findings:
        print(f"FINDING: {f.status} - {f.title} - {f.description} - {f.evidence}")
    assert len(findings) > 0
    assert findings[0].status == "MEDIUM"
    
    # Test Auth Bypass on API
    from scanner.checks.auth import check_auth
    db_session.query(Finding).delete()
    db_session.commit()
    
    # We'll make /api/user/1 vulnerable to auth bypass (no token -> returns 200)
    @app.get("/api/dashboard")
    async def get_dashboard(request: Request):
        return {"data": "super_secret"}
        
    endpoints_auth = [f"{test_server}/api/dashboard"]
    await check_auth(scanner, endpoints_auth, [], mock_client, scan.auth_context_1)
    findings = db_session.query(Finding).all()
    assert len(findings) > 0
    assert findings[0].status == "HIGH"
