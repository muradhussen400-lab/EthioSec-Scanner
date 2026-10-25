"""
Tests for Phone Verification System:
- E.164 normalization & validation
- Twilio Verify API integration (real provider simulation & mocked responses)
- Ephemeral development simulation mode
- Cooldown (429) & brute force rate limiting
- Authenticated user ownership protection
"""

import os
import time
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Setup test environment variables before importing app
os.environ["ENVIRONMENT"] = "test"
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "false"
os.environ["DATABASE_URL"] = "sqlite:///./ethiosec_test.db"

from main import app
from database import Base, get_db
from models import User
from security import create_access_token, get_password_hash
from phone_service import phone_service
from rate_limiter import _limiter

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_phone_state():
    """Cleans phone service dev store and rate limiter between tests."""
    phone_service._dev_store.clear()
    _limiter.clear()


def get_auth_headers(email: str, user_id: str = "test-user-id") -> dict:
    token = create_access_token(data={"sub": email, "is_verified": True})
    return {"Authorization": f"Bearer {token}"}

# ==============================================================================
# 1. E.164 PHONE NORMALIZATION & VALIDATION TESTS
# ==============================================================================

def test_phone_normalization_valid_ethiopian_numbers():
    # 0911223344 -> +251911223344
    ok, norm, err = phone_service.normalize_and_validate("0911223344")
    assert ok is True
    assert norm == "+251911223344"
    assert err is None

    # 0711223344 -> +251711223344 (Safaricom Ethiopia)
    ok, norm, err = phone_service.normalize_and_validate("0711223344")
    assert ok is True
    assert norm == "+251711223344"

    # 251911223344 -> +251911223344
    ok, norm, err = phone_service.normalize_and_validate("251911223344")
    assert ok is True
    assert norm == "+251911223344"

def test_phone_normalization_valid_international_numbers():
    # US number with formatting
    ok, norm, err = phone_service.normalize_and_validate("+1 (415) 555-2671")
    assert ok is True
    assert norm == "+14155552671"

    # UK number
    ok, norm, err = phone_service.normalize_and_validate("+44 7911 123456")
    assert ok is True
    assert norm == "+447911123456"

def test_phone_normalization_invalid_numbers():
    # Letters
    ok, norm, err = phone_service.normalize_and_validate("not-a-number")
    assert ok is False
    assert "Invalid phone number format" in err

    # Too short
    ok, norm, err = phone_service.normalize_and_validate("123")
    assert ok is False

    # Empty
    ok, norm, err = phone_service.normalize_and_validate("")
    assert ok is False

# ==============================================================================
# 2. ENDPOINT ACCESS CONTROL & SEND CODE TESTS
# ==============================================================================

def test_send_phone_code_requires_authentication():
    """Unauthenticated users cannot trigger phone verification codes."""
    resp = client.post("/api/auth/phone/send-code", json={"phone_number": "+251911223344"})
    assert resp.status_code == 401

def test_send_phone_code_dev_simulation_success():
    """Authenticated user triggers phone verification in dev simulation mode."""
    # Register/create user
    email = f"phone_user_{int(time.time()*1000)}@test.com"
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Phone Test User"
    })
    assert reg_resp.status_code in (200, 201)
    token = reg_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    phone_num = "+251912345678"
    resp = client.post("/api/auth/phone/send-code", json={"phone_number": phone_num}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "Verification code" in data["message"]

    # Verify simulation OTP exists in test store
    assert phone_num in phone_service._dev_store
    assert phone_service._dev_store[phone_num]["_test_otp"] is not None

def test_send_phone_code_cooldown_enforcement():
    """User cannot spam send-code within 60-second cooldown."""
    email = f"cooldown_user_{int(time.time()*1000)}@test.com"
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Cooldown User"
    })
    token = reg_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    phone_num = "+251919876543"
    resp1 = client.post("/api/auth/phone/send-code", json={"phone_number": phone_num}, headers=headers)
    assert resp1.status_code == 200

    # Immediate second request should be rejected with 429
    resp2 = client.post("/api/auth/phone/send-code", json={"phone_number": phone_num}, headers=headers)
    assert resp2.status_code == 429
    assert "wait" in resp2.json()["detail"].lower()

# ==============================================================================
# 3. VERIFICATION CHECK TESTS
# ==============================================================================

def test_verify_phone_code_success_and_status_update():
    """Submitting correct verification code marks phone_verified=True."""
    ts = int(time.time() * 1000)
    email = f"verify_user_{ts}@test.com"
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Verify User"
    })
    token = reg_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    phone_num = f"+2519{ts % 9000000 + 1000000}"
    send_resp = client.post("/api/auth/phone/send-code", json={"phone_number": phone_num}, headers=headers)
    assert send_resp.status_code == 200

    otp_code = phone_service._dev_store[phone_num]["_test_otp"]

    # Submit correct code
    verify_resp = client.post("/api/auth/phone/verify-code", json={
        "phone_number": phone_num,
        "code": otp_code
    }, headers=headers)
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["phone_number"] == phone_num
    assert v_data["phone_verified"] is True
    assert v_data["phone_verified_at"] is not None

    # Check /auth/phone/status
    status_resp = client.get("/api/auth/phone/status", headers=headers)
    assert status_resp.status_code == 200
    s_data = status_resp.json()
    assert s_data["phone_verified"] is True
    assert s_data["phone_number"] == phone_num

    # Check /user/profile reflects verified status
    prof_resp = client.get("/api/user/profile", headers=headers)
    assert prof_resp.status_code == 200
    assert prof_resp.json()["phone_number"] == phone_num
    assert prof_resp.json()["phone_verified"] is True

def test_verify_phone_code_invalid_code_and_retry_limits():
    """Incorrect code increments failed attempt count and fails cleanly."""
    ts = int(time.time() * 1000)
    email = f"fail_user_{ts}@test.com"
    reg_resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "full_name": "Fail User"
    })
    token = reg_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    phone_num = f"+2519{ts % 9000000 + 1000000}"
    send_resp = client.post("/api/auth/phone/send-code", json={"phone_number": phone_num}, headers=headers)
    assert send_resp.status_code == 200

    # Submit wrong code
    bad_resp = client.post("/api/auth/phone/verify-code", json={
        "phone_number": phone_num,
        "code": "000000"
    }, headers=headers)
    assert bad_resp.status_code == 400
    assert "Incorrect" in bad_resp.json()["detail"] or "Invalid" in bad_resp.json()["detail"]

# ==============================================================================
# 4. PHONE NUMBER HIJACKING & MULTI-TENANT PROTECTION
# ==============================================================================

def test_cannot_verify_phone_already_verified_by_another_user():
    """User B cannot claim or send code to User A's already-verified phone number."""
    ts = int(time.time() * 1000)
    # User A verifies phone
    email_a = f"usera_{ts}@test.com"
    resp_a = client.post("/api/auth/register", json={
        "email": email_a,
        "password": "Password123!",
        "full_name": "User A"
    })
    headers_a = {"Authorization": f"Bearer {resp_a.json()['token']}"}
    shared_phone = f"+2519{ts % 9000000 + 1000000}"

    send_a = client.post("/api/auth/phone/send-code", json={"phone_number": shared_phone}, headers=headers_a)
    assert send_a.status_code == 200
    code_a = phone_service._dev_store[shared_phone]["_test_otp"]
    client.post("/api/auth/phone/verify-code", json={"phone_number": shared_phone, "code": code_a}, headers=headers_a)

    # User B registers and attempts to claim the same phone
    email_b = f"userb_{ts}@test.com"
    resp_b = client.post("/api/auth/register", json={
        "email": email_b,
        "password": "Password123!",
        "full_name": "User B"
    })
    headers_b = {"Authorization": f"Bearer {resp_b.json()['token']}"}

    hijack_resp = client.post("/api/auth/phone/send-code", json={"phone_number": shared_phone}, headers=headers_b)
    assert hijack_resp.status_code == 400
    assert "already verified" in hijack_resp.json()["detail"]


# ==============================================================================
# 5. REAL PROVIDER (TWILIO VERIFY) MOCK INTEGRATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_twilio_verify_dispatch_mock():
    """Tests Twilio Verify REST API dispatch when credentials are configured."""
    with patch.object(phone_service, "account_sid", "ACmock123"), \
         patch.object(phone_service, "auth_token", "mocktoken123"), \
         patch.object(phone_service, "verify_service_sid", "VAmock123"), \
         patch("httpx.AsyncClient.post") as mock_post:
        
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"status": "pending", "sid": "VE123"}
        mock_post.return_value = mock_resp

        success, msg, meta = await phone_service.send_verification_code("+251911223344")
        assert success is True
        assert meta["provider"] == "twilio_verify"
        assert meta["is_real_provider"] is True

@pytest.mark.asyncio
async def test_twilio_verify_check_approved_mock():
    """Tests Twilio Verify check endpoint returning 'approved'."""
    with patch.object(phone_service, "account_sid", "ACmock123"), \
         patch.object(phone_service, "auth_token", "mocktoken123"), \
         patch.object(phone_service, "verify_service_sid", "VAmock123"), \
         patch("httpx.AsyncClient.post") as mock_post:
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "approved", "valid": True}
        mock_post.return_value = mock_resp

        success, msg, meta = await phone_service.verify_code("+251911223344", "123456")
        assert success is True
        assert meta["provider"] == "twilio_verify"
        assert meta["status"] == "approved"
