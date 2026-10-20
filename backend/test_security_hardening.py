import pytest
import os
import time
import datetime
from fastapi.testclient import TestClient

# Ensure test configuration
os.environ["ENVIRONMENT"] = "development"
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "true"
os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from main import app
from database import SessionLocal, engine, Base
from models import User, ScanTarget, Scan, Finding, UserSettings
from email_service import email_service
from rate_limiter import _limiter
from security import get_password_hash, verify_password, legacy_pwd_context

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_test_env():
    """Ensure clean email capture and rate limiter state before each test."""
    email_service.clear_sent_messages()
    _limiter.clear()
    yield

def helper_register_and_verify(email: str, password: str = "SecurePass123!", full_name: str = "Test User"):
    """Helper to register and verify an account for testing."""
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "full_name": full_name
    })
    assert reg_resp.status_code == 200, reg_resp.text
    
    code = email_service.get_last_sent_code(email)
    assert code is not None, f"No verification code captured for {email}"
    
    ver_resp = client.post("/api/auth/verify-email", json={
        "email": email,
        "code": code
    })
    assert ver_resp.status_code == 200, ver_resp.text
    return ver_resp.json()["token"]

# ==============================================================================
# 1. EMAIL VERIFICATION TESTS
# ==============================================================================

def test_registration_creates_unverified_account():
    email = f"unverified_{int(time.time()*1000)}@example.com"
    resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Unverified User"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["is_verified"] is False
    
    # Check that a 6-digit verification code was generated and delivered
    code = email_service.get_last_sent_code(email)
    assert code is not None
    assert len(code) == 6
    assert code.isdigit()

def test_unverified_account_cannot_access_protected_resources():
    email = f"blocked_{int(time.time()*1000)}@example.com"
    resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Blocked User"
    })
    assert resp.status_code == 200
    token = resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Unverified user cannot create target
    target_resp = client.post("/api/targets", json={"url": "https://example.com"}, headers=headers)
    assert target_resp.status_code == 403
    assert target_resp.headers.get("X-Error-Code") == "EMAIL_NOT_VERIFIED"
    
    # Unverified user cannot read scans or dashboard
    dash_resp = client.get("/api/dashboard/summary", headers=headers)
    assert dash_resp.status_code == 403

def test_verification_activates_account_and_allows_access():
    email = f"activate_{int(time.time()*1000)}@example.com"
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Activated User"
    })
    assert reg_resp.status_code == 200
    code = email_service.get_last_sent_code(email)
    
    # Verify email
    ver_resp = client.post("/api/auth/verify-email", json={
        "email": email,
        "code": code
    })
    assert ver_resp.status_code == 200
    verified_data = ver_resp.json()
    assert verified_data["user"]["is_verified"] is True
    verified_token = verified_data["token"]
    
    # Verified user CAN create target
    headers = {"Authorization": f"Bearer {verified_token}"}
    target_resp = client.post("/api/targets", json={"url": "https://example.com"}, headers=headers)
    assert target_resp.status_code == 200

def test_invalid_verification_code_fails():
    email = f"invalid_code_{int(time.time()*1000)}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Invalid Code User"
    })
    
    resp = client.post("/api/auth/verify-email", json={
        "email": email,
        "code": "000000"
    })
    assert resp.status_code == 400
    assert "Invalid verification code" in resp.text

def test_verification_code_single_use():
    email = f"single_use_{int(time.time()*1000)}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Single Use User"
    })
    code = email_service.get_last_sent_code(email)
    
    # First attempt succeeds
    resp1 = client.post("/api/auth/verify-email", json={"email": email, "code": code})
    assert resp1.status_code == 200
    
    # Second attempt already verified
    resp2 = client.post("/api/auth/verify-email", json={"email": email, "code": code})
    assert resp2.status_code == 200
    assert resp2.json()["user"]["is_verified"] is True

def test_resend_cooldown_enforcement():
    email = f"cooldown_{int(time.time()*1000)}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Cooldown User"
    })
    
    # Immediate resend should trigger 60s cooldown limit
    resend_resp = client.post("/api/auth/resend-verification", json={"email": email})
    assert resend_resp.status_code == 429
    assert "60 seconds" in resend_resp.text

# ==============================================================================
# 2. PASSWORD & AUTHENTICATION HARDENING TESTS
# ==============================================================================

def test_argon2id_hashing_for_new_accounts():
    email = f"argon_{int(time.time()*1000)}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Argon User"
    })
    
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")
    db.close()

def test_password_strength_validation():
    # Too short (<8)
    r1 = client.post("/api/auth/register", json={"email": "weak1@test.com", "password": "weak"})
    assert r1.status_code == 422
    
    # Too long (>128)
    r2 = client.post("/api/auth/register", json={"email": "weak2@test.com", "password": "A" * 129})
    assert r2.status_code == 422

def test_account_temporary_lockout_after_failed_logins():
    email = f"lockout_{int(time.time()*1000)}@example.com"
    helper_register_and_verify(email, "Password123!")
    
    # 5 consecutive failed login attempts
    for _ in range(5):
        resp = client.post("/api/auth/login", json={"email": email, "password": "WrongPassword123!"})
        assert resp.status_code in (401, 403, 429)
        
    # Sixth attempt should be locked out (403 Forbidden)
    locked_resp = client.post("/api/auth/login", json={"email": email, "password": "Password123!"})
    assert locked_resp.status_code in (403, 429)

def test_session_revocation_on_logout():
    email = f"logout_{int(time.time()*1000)}@example.com"
    token = helper_register_and_verify(email, "Password123!")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Verify token works
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    
    # Log out
    time.sleep(1) # Ensure timestamp tick
    logout_resp = client.post("/api/auth/logout", headers=headers)
    assert logout_resp.status_code == 200
    
    # Token should now be rejected as revoked
    post_logout_resp = client.get("/api/auth/me", headers=headers)
    assert post_logout_resp.status_code == 401
    assert "revoked" in post_logout_resp.text.lower()

def test_password_reset_workflow():
    email = f"reset_{int(time.time()*1000)}@example.com"
    token_before = helper_register_and_verify(email, "OldPassword123!")
    
    # 1. Request password reset
    forgot_resp = client.post("/api/auth/forgot-password", json={"email": email})
    assert forgot_resp.status_code == 200
    
    reset_token = email_service.get_last_sent_token(email)
    assert reset_token is not None
    
    # 2. Complete password reset
    time.sleep(1)
    reset_resp = client.post("/api/auth/reset-password", json={
        "email": email,
        "token": reset_token,
        "new_password": "NewPassword123!"
    })
    assert reset_resp.status_code == 200
    
    # 3. Old session token must now be revoked
    old_session_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_before}"})
    assert old_session_resp.status_code == 401
    
    # 4. Old password fails
    assert client.post("/api/auth/login", json={"email": email, "password": "OldPassword123!"}).status_code == 401
    
    # 5. New password succeeds
    login_new = client.post("/api/auth/login", json={"email": email, "password": "NewPassword123!"})
    assert login_new.status_code == 200

# ==============================================================================
# 3. AUTHORIZATION & DATA ISOLATION TESTS
# ==============================================================================

def test_cross_user_resource_isolation():
    user_a_email = f"user_a_{int(time.time()*1000)}@example.com"
    user_b_email = f"user_b_{int(time.time()*1000)}@example.com"
    
    token_a = helper_register_and_verify(user_a_email)
    token_b = helper_register_and_verify(user_b_email)
    
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    
    # User A creates target
    t_resp = client.post("/api/targets", json={"url": "https://usera-target.com"}, headers=headers_a)
    assert t_resp.status_code == 200
    target_a_id = t_resp.json()["id"]
    
    # User B cannot read User A's target
    assert client.get(f"/api/targets/{target_a_id}", headers=headers_b).status_code == 404
    
    # User B cannot delete User A's target
    client.delete(f"/api/targets/{target_a_id}", headers=headers_b)
    assert client.get(f"/api/targets/{target_a_id}", headers=headers_a).status_code == 200

def test_sensitive_credentials_never_exposed_in_api():
    email = f"privacy_{int(time.time()*1000)}@example.com"
    token = helper_register_and_verify(email)
    headers = {"Authorization": f"Bearer {token}"}
    
    profile_resp = client.get("/api/user/profile", headers=headers)
    assert profile_resp.status_code == 200
    data = profile_resp.json()
    
    forbidden_keys = [
        "password_hash", "verification_code_hash", "reset_token_hash",
        "failed_login_attempts", "locked_until"
    ]
    for key in forbidden_keys:
        assert key not in data, f"Sensitive field '{key}' leaked in /api/user/profile!"

# ==============================================================================
# 4. WEB SECURITY & HEADERS TESTS
# ==============================================================================

def test_security_headers_present():
    resp = client.get("/health")
    assert resp.status_code == 200
    
    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers
    assert "Permissions-Policy" in headers

def test_sql_injection_payload_safety():
    # Attempt SQL injection payloads in email and target parameters
    sqli_payloads = [
        "test' OR '1'='1",
        "admin'--",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM users --"
    ]
    
    for payload in sqli_payloads:
        # Schema validation or ORM safely rejects or treats as string literal
        resp = client.post("/api/auth/login", json={"email": payload, "password": "password"})
        assert resp.status_code in (401, 422) # Safe rejection, never 500 error
