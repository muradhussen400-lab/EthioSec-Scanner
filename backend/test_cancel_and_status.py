import uuid
import pytest
from fastapi.testclient import TestClient

from main import app
from database import SessionLocal
from models import User, Scan, ScanTarget
from security import get_password_hash, create_access_token

client = TestClient(app)

def test_cancel_flow():
    db = SessionLocal()
    try:
        user_email = f"cancel_user_{uuid.uuid4().hex[:8]}@example.com"
        user = User(
            email=user_email,
            full_name="Cancel Tester",
            password_hash=get_password_hash("Password123!"),
            role="Security Analyst",
            is_verified=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token({"sub": user.email})
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Create target
        target_res = client.post("/api/targets", json={"url": "https://example.com"}, headers=headers)
        assert target_res.status_code == 200, target_res.text
        target_id = target_res.json()["id"]

        # 2. Create scan
        scan_res = client.post(
            "/api/scans",
            json={"target_id": target_id, "depth": "standard", "authorized": True},
            headers=headers
        )
        assert scan_res.status_code == 200, scan_res.text
        scan_id = scan_res.json()["scan_id"]

        # 3. Cancel scan
        cancel_res = client.post(f"/api/scans/{scan_id}/cancel", headers=headers)
        assert cancel_res.status_code == 200, cancel_res.text
        cancel_data = cancel_res.json()
        assert cancel_data["ok"] is True
        assert cancel_data["status"] == "cancelled"

        # 4. Status reflects cancellation
        status_res = client.get(f"/api/scans/{scan_id}/status", headers=headers)
        assert status_res.status_code == 200, status_res.text
        status_data = status_res.json()
        assert status_data["status"] == "cancelled"
        assert status_data["scan_id"] == scan_id

    finally:
        db.close()
