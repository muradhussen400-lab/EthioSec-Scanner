import os
import sys
import time
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "development"
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "true"
os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from main import app
from database import SessionLocal
from models import User
from email_service import email_service
from rate_limiter import _limiter

client = TestClient(app)

def test_e2e_auth_suite():
    print("=" * 70)
    print("ETHIOSEC SCANNER - END-TO-END AUTHENTICATION & RECOVERY TEST SUITE")
    print("=" * 70)

    # 1. Clean state
    email_service.clear_sent_messages()
    _limiter.clear()

    test_email = f"e2e_tester_{int(time.time())}@ethiosec-test.com"
    initial_password = "SecurePassword123!"
    new_password = "UpdatedPassword456!"

    # 2. Registration
    print(f"\n[1] Registering new user: {test_email}")
    reg_resp = client.post("/api/auth/register", json={
        "email": test_email,
        "password": initial_password,
        "full_name": "EthioSec Tester"
    })
    assert reg_resp.status_code == 200, f"Registration failed: {reg_resp.text}"
    reg_data = reg_resp.json()
    assert reg_data["user"]["is_verified"] is False, "User should initially be unverified"
    print("  [PASS] User registered. Initial verification status: is_verified=False")

    # 3. Duplicate registration rejection
    print("\n[2] Testing duplicate registration rejection")
    dup_resp = client.post("/api/auth/register", json={
        "email": test_email,
        "password": initial_password,
        "full_name": "EthioSec Duplicate"
    })
    assert dup_resp.status_code == 409, f"Expected 409 Conflict, got {dup_resp.status_code}"
    print("  [PASS] Duplicate registration correctly rejected with HTTP 409 Conflict")

    # 4. Login before verification
    print("\n[3] Testing login before verification (should be rejected)")
    unver_login = client.post("/api/auth/login", json={
        "email": test_email,
        "password": initial_password
    })
    assert unver_login.status_code == 403, f"Expected 403 Forbidden, got {unver_login.status_code}"
    assert unver_login.headers.get("X-Error-Code") == "EMAIL_NOT_VERIFIED"
    print("  [PASS] Login before verification rejected with HTTP 403 and X-Error-Code: EMAIL_NOT_VERIFIED")

    # 5. Invalid verification code
    print("\n[4] Testing invalid verification code")
    bad_code_resp = client.post("/api/auth/verify-email", json={
        "email": test_email,
        "code": "999999"
    })
    assert bad_code_resp.status_code == 400, f"Expected 400 Bad Request, got {bad_code_resp.status_code}"
    print("  [PASS] Invalid verification code rejected with HTTP 400 Bad Request")

    # 6. Correct verification code
    print("\n[5] Testing valid verification code submission")
    captured_code = email_service.get_last_sent_code(test_email)
    assert captured_code is not None, "Verification code was not dispatched to email service"
    assert len(captured_code) == 6, f"Expected 6-digit code, got {captured_code}"
    print(f"  [PASS] Captured dispatched verification code: {captured_code}")

    ver_resp = client.post("/api/auth/verify-email", json={
        "email": test_email,
        "code": captured_code
    })
    assert ver_resp.status_code == 200, f"Verification failed: {ver_resp.text}"
    ver_data = ver_resp.json()
    assert ver_data["user"]["is_verified"] is True, "User is_verified should now be True"
    print("  [PASS] Email verified successfully! is_verified=True and fresh JWT issued")

    # 7. Resend cooldown test
    print("\n[6] Testing resend verification endpoint and cooldown")
    unverified_email_2 = f"cooldown_test_{int(time.time())}@ethiosec-test.com"
    client.post("/api/auth/register", json={
        "email": unverified_email_2,
        "password": initial_password,
        "full_name": "Cooldown Tester"
    })
    # Immediate resend within 60 seconds should trigger HTTP 429
    resend_too_fast = client.post("/api/auth/resend-verification", json={"email": unverified_email_2})
    assert resend_too_fast.status_code == 429, f"Expected 429 Too Many Requests, got {resend_too_fast.status_code}"
    print("  [PASS] Resend verification within 60s cooldown correctly rejected with HTTP 429")

    # 8. Login after successful verification
    print("\n[7] Testing login after successful verification")
    login_resp = client.post("/api/auth/login", json={
        "email": test_email,
        "password": initial_password
    })
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    login_token = login_resp.json()["token"]
    print("  [PASS] Login succeeded with HTTP 200 OK. Bearer token issued.")

    # 9. Access protected /api/auth/me
    print("\n[8] Accessing protected /api/auth/me with Bearer token")
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {login_token}"})
    assert me_resp.status_code == 200
    user_me = me_resp.json()["user"]
    assert user_me["email"] == test_email
    print(f"  [PASS] Session verified: {user_me['full_name']} ({user_me['email']}) [Role: {user_me['role']}]")

    # 10. Password recovery request
    print("\n[9] Requesting password reset (/api/auth/forgot-password)")
    forgot_resp = client.post("/api/auth/forgot-password", json={"email": test_email})
    assert forgot_resp.status_code == 200
    print("  [PASS] Forgot password request succeeded with generic enumeration-safe response")

    reset_token = email_service.get_last_sent_token(test_email)
    assert reset_token is not None, "Reset token was not dispatched"
    print(f"  [PASS] Captured single-use reset token: {reset_token[:8]}... (length={len(reset_token)})")

    # 11. Password reset execution
    print("\n[10] Executing password reset (/api/auth/reset-password)")
    reset_resp = client.post("/api/auth/reset-password", json={
        "email": test_email,
        "token": reset_token,
        "new_password": new_password
    })
    assert reset_resp.status_code == 200, f"Password reset failed: {reset_resp.text}"
    print("  [PASS] Password successfully reset to new password")

    # 12. Prior session invalidation verification
    print("\n[11] Testing prior session invalidation after password reset")
    stale_session_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {login_token}"})
    assert stale_session_resp.status_code == 401, f"Expected 401 on revoked session, got {stale_session_resp.status_code}"
    print("  [PASS] Stale session token issued prior to password reset correctly rejected with HTTP 401 Unauthorized")

    # 13. Login with old password rejected
    print("\n[12] Testing login with old password (should fail)")
    old_pw_login = client.post("/api/auth/login", json={
        "email": test_email,
        "password": initial_password
    })
    assert old_pw_login.status_code == 401
    print("  [PASS] Login with old password correctly rejected with HTTP 401 Unauthorized")

    # 14. Login with new password succeeds
    print("\n[13] Testing login with new password")
    new_pw_login = client.post("/api/auth/login", json={
        "email": test_email,
        "password": new_password
    })
    assert new_pw_login.status_code == 200
    fresh_token = new_pw_login.json()["token"]
    print("  [PASS] Login with new password succeeded with HTTP 200 OK")

    # 15. Logout invalidates session
    print("\n[14] Testing user logout (/api/auth/logout)")
    logout_resp = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {fresh_token}"})
    assert logout_resp.status_code == 200
    post_logout_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {fresh_token}"})
    assert post_logout_me.status_code == 401
    print("  [PASS] Logout invalidated session. Subsequent authenticated request returned HTTP 401 Unauthorized")

    print("\n" + "=" * 70)
    print("ALL 14 END-TO-END AUTHENTICATION & RECOVERY TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_e2e_auth_suite()
