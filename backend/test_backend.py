import pytest
from fastapi.testclient import TestClient
from main import app
from database import Base, engine, SessionLocal
from models import User, ScanTarget, Scan, Finding

client = TestClient(app)

def setup_module(module):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # Mock the scanner task to prevent background SQLite race conditions during teardown
    import routers
    routers.run_scan_task = lambda scan_id: None

def teardown_module(module):
    Base.metadata.drop_all(bind=engine)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "EthioSec API"}

def test_register_login_user_a():
    # Register
    res = client.post("/api/auth/register", json={
        "email": "userA@test.com", "password": "passwordA", "full_name": "User A"
    })
    assert res.status_code == 200
    token = res.json()["token"]
    
    # Login
    res2 = client.post("/api/auth/login", json={"email": "userA@test.com", "password": "passwordA"})
    assert res2.status_code == 200
    
    # Get Me
    res3 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res3.status_code == 200
    assert res3.json()["user"]["email"] == "userA@test.com"

def test_register_user_b():
    res = client.post("/api/auth/register", json={
        "email": "userB@test.com", "password": "passwordB", "full_name": "User B"
    })
    assert res.status_code == 200

def test_authorization_isolation():
    # Login again since we already registered
    res_a = client.post("/api/auth/login", json={"email": "userA@test.com", "password": "passwordA"})
    token_a = res_a.json()["token"]
    
    res_b = client.post("/api/auth/login", json={"email": "userB@test.com", "password": "passwordB"})
    token_b = res_b.json()["token"]
    
    # User A creates a target
    res_t = client.post("/api/targets", json={"url": "http://127.0.0.1:3000"}, headers={"Authorization": f"Bearer {token_a}"})
    assert res_t.status_code == 200
    target_id = res_t.json()["id"]
    
    # User B tries to get User A's target
    res_b_get = client.get(f"/api/targets/{target_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert res_b_get.status_code == 404 # EthioSec correctly hides it
    
    # User A creates a scan
    res_s = client.post("/api/scans", json={"target_id": target_id, "authorized": True}, headers={"Authorization": f"Bearer {token_a}"})
    assert res_s.status_code == 200
    scan_id = res_s.json()["scan_id"]
    
    # User B tries to get User A's scan status
    res_b_scan = client.get(f"/api/scans/{scan_id}/status", headers={"Authorization": f"Bearer {token_b}"})
    assert res_b_scan.status_code == 404
    
    # Verify User A can start scan (It will fail in test env because of background task, but endpoint works)
    res_start = client.post(f"/api/scans/{scan_id}/start", headers={"Authorization": f"Bearer {token_a}"})
    assert res_start.status_code == 200

def test_ai_authorization():
    res_a = client.post("/api/auth/login", json={"email": "userA@test.com", "password": "passwordA"})
    token_a = res_a.json()["token"]
    
    res_b = client.post("/api/auth/login", json={"email": "userB@test.com", "password": "passwordB"})
    token_b = res_b.json()["token"]
    
    # Get User A's scan
    res_s = client.get("/api/scans", headers={"Authorization": f"Bearer {token_a}"})
    scans = res_s.json()["scans"]
    assert len(scans) > 0
    scan_id = scans[0]["id"]
    
    # User B tries to ask AI about User A's scan
    res_ai_b = client.post("/api/ai/chat", json={"message": "Summarize this scan", "scan_id": scan_id}, headers={"Authorization": f"Bearer {token_b}"})
    assert res_ai_b.status_code == 403
