import pytest
from fastapi.testclient import TestClient
from main import app
from database import Base, engine, SessionLocal
from models import User, ScanTarget, Scan, Finding
from email_service import email_service
from rate_limiter import _limiter

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_rate_limits():
    _limiter.clear()
    yield
    _limiter.clear()

def setup_module(module):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # Mock the scanner task to prevent background SQLite race conditions during teardown
    import routers
    module._orig_run_scan_task = getattr(routers, "run_scan_task", None)
    routers.run_scan_task = lambda scan_id: None

def teardown_module(module):
    import routers
    if hasattr(module, "_orig_run_scan_task") and module._orig_run_scan_task:
        routers.run_scan_task = module._orig_run_scan_task

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
    
    # Verify email
    code_a = email_service.get_last_sent_code("userA@test.com")
    if code_a:
        ver_res = client.post("/api/auth/verify-email", json={"email": "userA@test.com", "code": code_a})
        assert ver_res.status_code == 200
        token = ver_res.json()["token"]
    else:
        token = res.json()["token"]
    
    # Login
    res2 = client.post("/api/auth/login", json={"email": "userA@test.com", "password": "passwordA"})
    assert res2.status_code == 200
    
    # Get Me
    res3 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res3.status_code == 200
    assert res3.json()["user"]["email"].lower() == "userA@test.com".lower()

def test_register_user_b():
    res = client.post("/api/auth/register", json={
        "email": "userB@test.com", "password": "passwordB", "full_name": "User B"
    })
    assert res.status_code == 200
    code_b = email_service.get_last_sent_code("userB@test.com")
    if code_b:
        ver_res = client.post("/api/auth/verify-email", json={"email": "userB@test.com", "code": code_b})
        assert ver_res.status_code == 200

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

def test_user_profile_and_settings():
    res_a = client.post("/api/auth/login", json={"email": "userA@test.com", "password": "passwordA"})
    token_a = res_a.json()["token"]
    
    # Update profile
    res_prof = client.put("/api/user/profile", json={"full_name": "Updated User A", "website": "https://example.com"}, headers={"Authorization": f"Bearer {token_a}"})
    assert res_prof.status_code == 200
    assert res_prof.json()["full_name"] == "Updated User A"
    assert res_prof.json()["website"] == "https://example.com"
    
    # Update settings
    res_sett = client.put("/api/user/settings", json={"default_scan_depth": "deep", "notif_scan_completed": True}, headers={"Authorization": f"Bearer {token_a}"})
    assert res_sett.status_code == 200
    assert res_sett.json()["default_scan_depth"] == "deep"

def test_scan_modules_and_deletion():
    res_a = client.post("/api/auth/login", json={"email": "userA@test.com", "password": "passwordA"})
    token_a = res_a.json()["token"]
    
    # Create target
    res_t = client.post("/api/targets", json={"url": "http://127.0.0.1:3000"}, headers={"Authorization": f"Bearer {token_a}"})
    target_id = res_t.json()["id"]
    
    # Create scan with specific modules
    res_s = client.post("/api/scans", json={
        "target_id": target_id,
        "authorized": True,
        "scan_depth": "standard",
        "modules": {"sqli": True, "xss": False, "headers": False, "tls": False}
    }, headers={"Authorization": f"Bearer {token_a}"})
    assert res_s.status_code == 200
    scan_id = res_s.json()["scan_id"]
    
    # Verify scan status and modules
    res_status = client.get(f"/api/scans/{scan_id}/status", headers={"Authorization": f"Bearer {token_a}"})
    assert res_status.status_code == 200
    assert res_status.json()["checks"]["sqli"] is True
    assert res_status.json()["checks"]["xss"] is False
    
    # Dashboard summary
    res_dash = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {token_a}"})
    assert res_dash.status_code == 200
    assert "total_scans" in res_dash.json()
    
    # Complete the scan for reporting test
    db_session = SessionLocal()
    scan_obj = db_session.query(Scan).filter(Scan.id == scan_id).first()
    scan_obj.status = "completed"
    scan_obj.security_score = 95
    db_session.commit()
    db_session.close()

    # Reports list and detail
    res_reps = client.get("/api/reports", headers={"Authorization": f"Bearer {token_a}"})
    assert res_reps.status_code == 200
    res_rep = client.get(f"/api/reports/{scan_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert res_rep.status_code == 200
    assert res_rep.json()["scan_id"] == scan_id
    
    # Delete single scan
    res_del = client.delete(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert res_del.status_code == 200
    
    # Bulk delete remaining scans
    res_bulk_del = client.delete("/api/scans", headers={"Authorization": f"Bearer {token_a}"})
    assert res_bulk_del.status_code == 200
    assert res_bulk_del.json()["status"] == "success"
    
    # Verify history is empty
    res_empty = client.get("/api/scans", headers={"Authorization": f"Bearer {token_a}"})
    assert res_empty.status_code == 200
    assert len(res_empty.json()["scans"]) == 0

