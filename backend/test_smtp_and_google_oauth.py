import pytest
import os
import time
import datetime
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "development"
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "true"
os.environ["ALLOW_LOCAL_TARGETS"] = "true"
os.environ["GOOGLE_CLIENT_ID"] = "mock-client-id.apps.googleusercontent.com"
os.environ["GOOGLE_CLIENT_SECRET"] = "mock-client-secret"
os.environ["GOOGLE_REDIRECT_URI"] = "http://127.0.0.1:8000/api/auth/google/callback"

from main import app
from database import SessionLocal
from models import User
from email_service import email_service
from rate_limiter import _limiter
import routers

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_state():
    email_service.clear_sent_messages()
    _limiter.clear()
    routers._oauth_states.clear()
    routers._oauth_exchange_codes.clear()
    yield

# ==============================================================================
# 1. SMTP DELIVERY TESTS (Success and Failure)
# ==============================================================================

def test_smtp_delivery_success():
    """Verify that when SMTP is configured, send_verification_email calls SMTP successfully."""
    with patch.object(email_service, "is_smtp_configured", return_value=True), \
         patch("smtplib.SMTP") as mock_smtp_cls:
        
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_server

        email = "smtp_test_ok@ethiosec.com"
        success = email_service.send_verification_email(email, "123456")
        assert success is True
        assert mock_server.send_message.called

def test_smtp_delivery_failure_rolls_back_registration():
    """Verify that SMTP failure causes registration to roll back and return HTTP 503."""
    with patch.object(email_service, "is_smtp_configured", return_value=True), \
         patch("smtplib.SMTP") as mock_smtp_cls:
        
        mock_server = MagicMock()
        mock_server.send_message.side_effect = Exception("SMTP Connection Refused (test)")
        mock_smtp_cls.return_value.__enter__.return_value = mock_server

        fail_email = f"smtp_fail_{int(time.time()*1000)}@ethiosec.com"
        resp = client.post("/api/auth/register", json={
            "email": fail_email,
            "password": "Password123!",
            "full_name": "SMTP Fail User"
        })
        assert resp.status_code == 503
        assert "Unable to send verification email" in resp.text

        # Verify user was NOT committed in DB
        db = SessionLocal()
        user = db.query(User).filter(User.email == fail_email).first()
        db.close()
        assert user is None

# ==============================================================================
# 2. REGISTRATION & VERIFICATION LIFECYCLE
# ==============================================================================

def test_registration_and_actual_email_verification():
    email = f"verified_cycle_{int(time.time()*1000)}@ethiosec.com"
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Verified Cycle User"
    })
    assert reg_resp.status_code == 200
    assert reg_resp.json()["user"]["is_verified"] is False

    code = email_service.get_last_sent_code(email)
    assert code is not None and len(code) == 6

    ver_resp = client.post("/api/auth/verify-email", json={
        "email": email,
        "code": code
    })
    assert ver_resp.status_code == 200
    assert ver_resp.json()["user"]["is_verified"] is True

    # User can now log in
    login_resp = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    assert login_resp.status_code == 200

def test_expired_and_incorrect_verification_codes():
    email = f"codes_test_{int(time.time()*1000)}@ethiosec.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Code Tester"
    })
    
    # 1. Incorrect code
    bad_resp = client.post("/api/auth/verify-email", json={"email": email, "code": "000000"})
    assert bad_resp.status_code == 400

    # 2. Expired code simulation
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    past_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30)).isoformat()
    user.verification_expires_at = past_time
    db.commit()
    db.close()

    code = email_service.get_last_sent_code(email)
    expired_resp = client.post("/api/auth/verify-email", json={"email": email, "code": code})
    assert expired_resp.status_code == 400
    assert "expired" in expired_resp.text.lower()

def test_resend_cooldown_and_rate_limiting():
    email = f"cooldown_{int(time.time()*1000)}@ethiosec.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Cooldown User"
    })
    
    # Immediate resend triggers 429
    resend_resp = client.post("/api/auth/resend-verification", json={"email": email})
    assert resend_resp.status_code == 429

def test_password_recovery_and_single_use_token():
    email = f"recovery_{int(time.time()*1000)}@ethiosec.com"
    # Create user
    client.post("/api/auth/register", json={
        "email": email,
        "password": "InitialPass123!",
        "full_name": "Recovery User"
    })
    code = email_service.get_last_sent_code(email)
    client.post("/api/auth/verify-email", json={"email": email, "code": code})

    # Request reset
    forgot_resp = client.post("/api/auth/forgot-password", json={"email": email})
    assert forgot_resp.status_code == 200

    token = email_service.get_last_sent_token(email)
    assert token is not None

    # Reset password with token
    reset_resp = client.post("/api/auth/reset-password", json={
        "email": email,
        "token": token,
        "new_password": "NewSecretPass123!"
    })
    assert reset_resp.status_code == 200

    # Reusing the token must fail (single-use)
    reuse_resp = client.post("/api/auth/reset-password", json={
        "email": email,
        "token": token,
        "new_password": "AnotherSecret123!"
    })
    assert reuse_resp.status_code == 400

# ==============================================================================
# 3. GOOGLE OAUTH 2.0 / OPENID CONNECT TESTS
# ==============================================================================

def test_google_login_generates_pkce_and_redirects():
    """Verify that /api/auth/google/login generates state, PKCE challenge, and redirects."""
    resp = client.get("/api/auth/google/login", follow_redirects=False)
    assert resp.status_code == 307
    location = resp.headers.get("location")
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth")
    assert "client_id=" in location
    assert "code_challenge=" in location
    assert "code_challenge_method=S256" in location
    assert "state=" in location

    # Verify state was saved
    assert len(routers._oauth_states) == 1

def test_google_oauth_state_mismatch_and_replay():
    """Verify that callback rejects invalid or replayed state."""
    # 1. Missing state
    resp1 = client.get("/api/auth/google/callback?code=mock_code", follow_redirects=False)
    assert "oauth_error=invalid_request" in resp1.headers.get("location")

    # 2. Fake/unrecognized state
    resp2 = client.get("/api/auth/google/callback?code=mock_code&state=fake_state_123", follow_redirects=False)
    assert "oauth_error=invalid_state" in resp2.headers.get("location")

def test_google_oauth_invalid_id_token():
    """Verify that an invalid ID token signature is rejected."""
    # Initiate login to obtain legitimate state
    login_resp = client.get("/api/auth/google/login", follow_redirects=False)
    state = list(routers._oauth_states.keys())[0]

    # Mock token exchange to succeed, but verify_oauth2_token to raise ValueError
    with patch("httpx.AsyncClient.post") as mock_post, \
         patch("google.oauth2.id_token.verify_oauth2_token", side_effect=ValueError("Invalid cryptographic signature")):
        
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id_token": "malformed_token"})

        cb_resp = client.get(f"/api/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert cb_resp.status_code == 307
        assert "oauth_error=invalid_token" in cb_resp.headers.get("location")

def test_google_oauth_unverified_email():
    """Verify that Google accounts with email_verified=False are rejected."""
    client.get("/api/auth/google/login", follow_redirects=False)
    state = list(routers._oauth_states.keys())[0]

    mock_claims = {
        "sub": "google-sub-unverified-123",
        "email": "unverified@gmail.com",
        "email_verified": False,
        "name": "Unverified Google User"
    }

    with patch("httpx.AsyncClient.post") as mock_post, \
         patch("google.oauth2.id_token.verify_oauth2_token", return_value=mock_claims):
        
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id_token": "valid_token"})

        cb_resp = client.get(f"/api/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert cb_resp.status_code == 307
        assert "oauth_error=unverified_google_email" in cb_resp.headers.get("location")

def test_google_oauth_new_user_registration_and_exchange():
    """Verify that a new Google user is registered, is_verified=True, and exchanges code for session."""
    client.get("/api/auth/google/login", follow_redirects=False)
    state = list(routers._oauth_states.keys())[0]

    google_sub = f"sub_{int(time.time()*1000)}"
    google_email = f"new_google_{int(time.time()*1000)}@gmail.com"

    mock_claims = {
        "sub": google_sub,
        "email": google_email,
        "email_verified": True,
        "name": "Brand New Google User"
    }

    with patch("httpx.AsyncClient.post") as mock_post, \
         patch("google.oauth2.id_token.verify_oauth2_token", return_value=mock_claims):
        
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id_token": "valid_token"})

        cb_resp = client.get(f"/api/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert cb_resp.status_code == 307
        redirect_url = cb_resp.headers.get("location")
        assert "oauth_code=" in redirect_url

        # Extract exchange code from URL
        exchange_code = redirect_url.split("oauth_code=")[1]

        # Exchange code for token
        exch_resp = client.post("/api/auth/google/exchange", json={"code": exchange_code})
        assert exch_resp.status_code == 200
        data = exch_resp.json()
        assert "token" in data
        assert data["user"]["email"] == google_email
        assert data["user"]["google_id"] == google_sub
        assert data["user"]["auth_provider"] == "google"
        assert data["user"]["is_verified"] is True

        # Re-exchanging the same code fails (single-use)
        replay_resp = client.post("/api/auth/google/exchange", json={"code": exchange_code})
        assert replay_resp.status_code == 400

def test_google_oauth_existing_account_safe_linking():
    """Verify that an existing password account safely links Google sub when email is verified."""
    email = f"local_user_{int(time.time()*1000)}@gmail.com"
    # Create local user
    client.post("/api/auth/register", json={
        "email": email,
        "password": "OriginalPassword123!",
        "full_name": "Original Name"
    })
    code = email_service.get_last_sent_code(email)
    client.post("/api/auth/verify-email", json={"email": email, "code": code})

    # User now clicks "Sign in with Google" with same verified email
    client.get("/api/auth/google/login", follow_redirects=False)
    state = list(routers._oauth_states.keys())[0]

    google_sub = f"sub_link_{int(time.time()*1000)}"
    mock_claims = {
        "sub": google_sub,
        "email": email,
        "email_verified": True,
        "name": "Linked Name"
    }

    with patch("httpx.AsyncClient.post") as mock_post, \
         patch("google.oauth2.id_token.verify_oauth2_token", return_value=mock_claims):
        
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id_token": "valid_token"})

        cb_resp = client.get(f"/api/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert cb_resp.status_code == 307
        exchange_code = cb_resp.headers.get("location").split("oauth_code=")[1]

        exch_resp = client.post("/api/auth/google/exchange", json={"code": exchange_code})
        assert exch_resp.status_code == 200
        assert exch_resp.json()["user"]["google_id"] == google_sub

        # Verify password login STILL works with original password
        pw_login = client.post("/api/auth/login", json={
            "email": email,
            "password": "OriginalPassword123!"
        })
        assert pw_login.status_code == 200

def test_google_oauth_account_collision_different_sub():
    """Verify that an existing user already linked to sub A rejects collision with sub B."""
    ts = int(time.time()*1000)
    email = f"collision_{ts}@gmail.com"
    db = SessionLocal()
    user = User(
        email=email,
        full_name="Linked User",
        google_id=f"existing-sub-AAA-{ts}",
        auth_provider="google",
        password_hash="dummy_hash",
        is_verified=True
    )
    db.add(user)
    db.commit()
    db.close()

    # Now someone with Google sub BBB attempts to claim this email
    client.get("/api/auth/google/login", follow_redirects=False)
    state = list(routers._oauth_states.keys())[0]

    mock_claims = {
        "sub": "intruder-sub-BBB",
        "email": email,
        "email_verified": True,
        "name": "Intruder"
    }

    with patch("httpx.AsyncClient.post") as mock_post, \
         patch("google.oauth2.id_token.verify_oauth2_token", return_value=mock_claims):
        
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id_token": "valid_token"})

        cb_resp = client.get(f"/api/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert cb_resp.status_code == 307
        assert "oauth_error=account_linked_to_different_google_id" in cb_resp.headers.get("location")

def test_unauthorized_access_unverified_email_blocked():
    """Verify that unverified users cannot access protected scanner and dashboard routes."""
    email = f"unverified_{int(time.time()*1000)}@ethiosec.com"
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "ValidPassword123!",
        "full_name": "Unverified User"
    })
    assert reg_resp.status_code == 200
    token = reg_resp.json()["token"]

    # Try accessing protected dashboard endpoint
    dash_resp = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {token}"})
    assert dash_resp.status_code == 403
    assert dash_resp.json()["detail"] == "Email verification required. Please verify your email to access this feature."
    assert dash_resp.headers.get("x-error-code") == "EMAIL_NOT_VERIFIED"

def test_google_oauth_role_escalation_prevention():
    """Verify that Google OAuth claims cannot escalate user role to superadmin or custom privileges."""
    client.get("/api/auth/google/login", follow_redirects=False)
    state = list(routers._oauth_states.keys())[0]

    email = f"attacker_{int(time.time()*1000)}@gmail.com"
    mock_claims = {
        "sub": f"sub_attacker_{int(time.time()*1000)}",
        "email": email,
        "email_verified": True,
        "name": "Attacker",
        "role": "SuperAdministrator",
        "is_admin": True,
        "admin": True
    }

    with patch("httpx.AsyncClient.post") as mock_post, \
         patch("google.oauth2.id_token.verify_oauth2_token", return_value=mock_claims):
        
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id_token": "valid_token"})

        cb_resp = client.get(f"/api/auth/google/callback?code=good_code&state={state}", follow_redirects=False)
        assert cb_resp.status_code == 307
        exchange_code = cb_resp.headers.get("location").split("oauth_code=")[1]

        exch_resp = client.post("/api/auth/google/exchange", json={"code": exchange_code})
        assert exch_resp.status_code == 200
        user_data = exch_resp.json()["user"]
        # Must NOT be escalated to SuperAdministrator
        assert user_data["role"] == "Security Administrator"

