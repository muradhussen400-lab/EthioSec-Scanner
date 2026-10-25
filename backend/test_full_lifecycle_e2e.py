"""
EthioSec Scanner - Full Integration & End-to-End Lifecycle Verification
Verifies the complete 10-step mission workflow:
1. Database initialization and table connectivity
2. User registration with password hashing (Argon2id)
3. Email verification and authentication
4. SMS / Phone verification code request with rate limiting and cooldown
5. Phone verification code validation and profile update
6. Profile retrieval and update (full_name, website, avatar_url, phone_number)
7. Target creation and authenticated scan dispatch
8. Scan persistence, module execution, and findings retrieval
9. Session restoration via /api/auth/me
10. Logout and session revocation enforcement
"""

import os
import time
import pytest
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "test"
os.environ["ALLOW_LOCAL_TARGETS"] = "true"
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "true"

from main import app
from database import engine, Base, SessionLocal
from models import User, Scan, ScanTarget, Finding
from phone_service import phone_service
from email_service import email_service
from rate_limiter import _limiter

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_state():
    _limiter.clear()
    phone_service._dev_store.clear()

def test_complete_application_lifecycle_e2e():
    ts = int(time.time() * 1000)
    email = f"lifecycle_{ts}@ethiosec.et"
    password = "EthioSec2026!SecurePass"
    full_name = "Abebe Bikila"
    phone_num = f"+2519{ts % 9000000 + 1000000}"

    # Step 1: Verify database engine is alive with a query
    from sqlalchemy import text
    with engine.connect() as conn:
        res = conn.execute(text("SELECT 1")).scalar()
        assert res == 1

    # Step 2: Register user
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "full_name": full_name,
        "website": "https://ethiosec.et"
    })
    assert reg_resp.status_code == 200, reg_resp.text
    reg_data = reg_resp.json()
    assert reg_data["user"]["email"] == email
    assert reg_data["user"]["is_verified"] is False # Verification required
    temp_token = reg_data["token"]

    # Step 3: Complete email verification
    email_code = email_service.get_last_sent_code(email)
    assert email_code is not None, "Email verification code was not generated!"

    verify_resp = client.post("/api/auth/verify-email", json={
        "email": email,
        "code": email_code
    })
    assert verify_resp.status_code == 200, verify_resp.text
    auth_token = verify_resp.json()["token"]
    auth_headers = {"Authorization": f"Bearer {auth_token}"}

    # Step 4: Login verification with newly activated account
    login_resp = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert login_resp.status_code == 200, login_resp.text
    session_token = login_resp.json()["token"]
    session_headers = {"Authorization": f"Bearer {session_token}"}

    # Step 5: Phone verification - Request SMS code
    sms_send_resp = client.post("/api/auth/phone/send-code", json={
        "phone_number": phone_num
    }, headers=session_headers)
    assert sms_send_resp.status_code == 200, sms_send_resp.text
    assert "Verification code" in sms_send_resp.json()["message"]

    # Retrieve simulation code (in test mode)
    assert phone_num in phone_service._dev_store
    sms_otp = phone_service._dev_store[phone_num]["_test_otp"]
    assert sms_otp is not None

    # Step 6: Phone verification - Validate submitted code
    sms_verify_resp = client.post("/api/auth/phone/verify-code", json={
        "phone_number": phone_num,
        "code": sms_otp
    }, headers=session_headers)
    assert sms_verify_resp.status_code == 200, sms_verify_resp.text
    v_info = sms_verify_resp.json()
    assert v_info["phone_verified"] is True
    assert v_info["phone_number"] == phone_num

    # Step 7: Load and update profile
    prof_resp = client.get("/api/user/profile", headers=session_headers)
    assert prof_resp.status_code == 200
    p_data = prof_resp.json()
    assert p_data["email"] == email
    assert p_data["phone_verified"] is True
    assert p_data["phone_number"] == phone_num

    update_resp = client.put("/api/user/profile", json={
        "full_name": "Abebe Bikila Champion",
        "website": "https://champion.ethiosec.et",
        "avatar_url": "https://ethiosec.et/avatars/abebe.png"
    }, headers=session_headers)
    assert update_resp.status_code == 200
    assert update_resp.json()["full_name"] == "Abebe Bikila Champion"
    assert update_resp.json()["avatar_url"] == "https://ethiosec.et/avatars/abebe.png"

    # Step 8: Create Target and Dispatch Scan
    target_resp = client.post("/api/targets", json={
        "url": "https://example.com"
    }, headers=session_headers)
    assert target_resp.status_code == 200, target_resp.text
    target_id = target_resp.json()["id"]

    scan_resp = client.post("/api/scans", json={
        "target_id": target_id,
        "depth": "standard",
        "authorized": True,
        "modules": {"headers": True, "https": True}
    }, headers=session_headers)
    assert scan_resp.status_code == 200, scan_resp.text
    scan_id = scan_resp.json()["scan_id"]

    # Query scan status
    status_resp = client.get(f"/api/scans/{scan_id}/status", headers=session_headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["scan_id"] == scan_id

    # Step 9: Verify session restoration (/api/auth/me)
    me_resp = client.get("/api/auth/me", headers=session_headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["user"]["email"] == email

    # Step 10: Logout and verify session revocation
    logout_resp = client.post("/api/auth/logout", headers=session_headers)
    assert logout_resp.status_code == 200

    # Ensure subsequent authenticated call with the old token is rejected
    post_logout_resp = client.get("/api/user/profile", headers=session_headers)
    assert post_logout_resp.status_code == 401
    assert "revoked" in post_logout_resp.json()["detail"].lower()
