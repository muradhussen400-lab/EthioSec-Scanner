import time
from datetime import datetime, timezone, timedelta
from jose import jwt
import pytest
from fastapi.testclient import TestClient

from main import app
from database import SessionLocal
from models import User
from security import (
    SECRET_KEY, ALGORITHM, create_access_token, get_password_hash
)

client = TestClient(app)

@pytest.fixture
def test_user():
    db = SessionLocal()
    email = f"jwt_test_{int(time.time()*1000)}@example.com"
    user = User(
        email=email,
        full_name="JWT Tester",
        website="https://jwt.example.com",
        password_hash=get_password_hash("Password123!"),
        is_verified=True,
        role="user"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    yield user
    db.delete(user)
    db.commit()
    db.close()

def test_valid_token_allowed(test_user):
    token = create_access_token({"sub": test_user.email})
    res = client.get("/api/user/profile", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["email"] == test_user.email

def test_same_second_revocation_invalidates_pre_revocation_token(test_user):
    db = SessionLocal()
    u = db.query(User).filter(User.id == test_user.id).first()

    # 1. Issue Token A
    token_a = create_access_token({"sub": test_user.email})

    # Small sleep (e.g. 10ms) to ensure revocation time > token_a iat, within same second
    time.sleep(0.02)

    # 2. Revoke session in same second
    now_revoked = datetime.now(timezone.utc)
    u.session_revoked_at = now_revoked.isoformat()
    db.commit()

    # 3. Verify Token A is rejected (same-second revocation)
    res_a = client.get("/api/user/profile", headers={"Authorization": f"Bearer {token_a}"})
    assert res_a.status_code == 401
    assert "revoked" in res_a.text.lower()

    # 4. Small sleep, then issue Token B (new login after revocation)
    time.sleep(0.02)
    token_b = create_access_token({"sub": test_user.email})

    # 5. Token B MUST succeed even if in the same calendar second!
    res_b = client.get("/api/user/profile", headers={"Authorization": f"Bearer {token_b}"})
    assert res_b.status_code == 200
    assert res_b.json()["email"] == test_user.email
    db.close()

def test_legacy_integer_iat_token(test_user):
    db = SessionLocal()
    u = db.query(User).filter(User.id == test_user.id).first()

    now = datetime.now(timezone.utc)
    # Token issued 10 seconds ago with integer iat
    legacy_iat = int((now - timedelta(seconds=10)).timestamp())
    legacy_exp = now + timedelta(hours=1)
    payload = {"sub": test_user.email, "iat": legacy_iat, "exp": legacy_exp}
    legacy_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    # User revoked session 5 seconds ago
    revoked_time = now - timedelta(seconds=5)
    u.session_revoked_at = revoked_time.isoformat()
    db.commit()

    res = client.get("/api/user/profile", headers={"Authorization": f"Bearer {legacy_token}"})
    assert res.status_code == 401
    assert "revoked" in res.text.lower()
    db.close()

def test_expired_token_rejected(test_user):
    now = datetime.now(timezone.utc)
    expired_token = jwt.encode(
        {"sub": test_user.email, "iat": now.timestamp() - 7200, "exp": now - timedelta(hours=1)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    res = client.get("/api/user/profile", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
