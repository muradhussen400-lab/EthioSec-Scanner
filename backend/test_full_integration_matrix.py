import uuid
import pytest
from fastapi.testclient import TestClient

from main import app
from database import SessionLocal
from models import User, Scan, Finding, ScanTarget, UserSettings
from security import get_password_hash, create_access_token

client = TestClient(app)

@pytest.fixture
def auth_user():
    db = SessionLocal()
    user_email = f"matrix_tester_{uuid.uuid4().hex[:8]}@example.com"
    user = User(
        email=user_email,
        full_name="Matrix Tester",
        password_hash=get_password_hash("Password123!"),
        role="Security Administrator",
        is_verified=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.email})
    headers = {"Authorization": f"Bearer {token}"}
    
    yield {"user": user, "token": token, "headers": headers}
    db.close()

@pytest.fixture
def other_user():
    db = SessionLocal()
    other_email = f"other_user_{uuid.uuid4().hex[:8]}@example.com"
    user = User(
        email=other_email,
        full_name="Other User",
        password_hash=get_password_hash("Password123!"),
        role="User",
        is_verified=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.email})
    headers = {"Authorization": f"Bearer {token}"}
    
    yield {"user": user, "token": token, "headers": headers}
    db.close()

# ==============================================================================
# 1. AUTHENTICATION & IDENTITY INTEGRATION
# ==============================================================================

def test_auth_lifecycle(auth_user):
    headers = auth_user["headers"]

    # GET /api/auth/me
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()
    user_data = data.get("user", data)
    assert user_data["email"] == auth_user["user"].email
    assert user_data["full_name"] == "Matrix Tester"
    assert user_data["role"] == "Security Administrator"

    # Unauthenticated request fails
    res_unauth = client.get("/api/auth/me")
    assert res_unauth.status_code == 401

def test_password_change(auth_user):
    headers = auth_user["headers"]
    
    # Change password
    res = client.post("/api/auth/change-password", headers=headers, json={
        "current_password": "Password123!",
        "new_password": "NewSecretPass456!"
    })
    assert res.status_code == 200, res.text

    # Login with new password
    res_login = client.post("/api/auth/login", json={
        "email": auth_user["user"].email,
        "password": "NewSecretPass456!"
    })
    assert res_login.status_code == 200, res_login.text
    assert "token" in res_login.json()

# ==============================================================================
# 2. DASHBOARD & ZERO-DATA INTEGRATION
# ==============================================================================

def test_dashboard_empty_and_populated(auth_user):
    headers = auth_user["headers"]

    # Clean new user has 0 scans
    res_empty = client.get("/api/scans?limit=100", headers=headers)
    assert res_empty.status_code == 200
    empty_data = res_empty.json()
    assert empty_data["scans"] == []
    assert empty_data["total"] == 0

    # Dashboard summary for clean new user
    res_summary = client.get("/api/dashboard/summary", headers=headers)
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert summary_data["total_scans"] == 0
    assert summary_data["vulnerabilities"] == 0

# ==============================================================================
# 3. SCAN CREATION, TELEMETRY, & CANCELLATION
# ==============================================================================

def test_scan_full_lifecycle(auth_user, other_user):
    headers = auth_user["headers"]

    # Step 1: Create Target
    t_res = client.post("/api/targets", headers=headers, json={"url": "https://audit-test.local"})
    assert t_res.status_code == 200
    target_id = t_res.json()["id"]

    # Step 2: Create Scan
    s_res = client.post("/api/scans", headers=headers, json={
        "target_id": target_id,
        "depth": "standard",
        "authorized": True,
        "modules": {"sqli": True, "headers": True}
    })
    assert s_res.status_code == 200
    scan_id = s_res.json()["scan_id"]

    # Step 3: Check Scan Status (Telemetry Model)
    stat_res = client.get(f"/api/scans/{scan_id}/status", headers=headers)
    assert stat_res.status_code == 200
    stat_data = stat_res.json()
    assert stat_data["scan_id"] == scan_id
    assert stat_data["status"] == "queued"
    assert "pipeline_stages" in stat_data

    # Multi-tenant isolation: other user cannot view this scan
    stat_other = client.get(f"/api/scans/{scan_id}/status", headers=other_user["headers"])
    assert stat_other.status_code == 404

    # Step 4: Cancel Scan
    cancel_res = client.post(f"/api/scans/{scan_id}/cancel", headers=headers)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["ok"] is True

    # Step 5: Verify Cancelled State
    stat_cancelled = client.get(f"/api/scans/{scan_id}/status", headers=headers)
    assert stat_cancelled.json()["status"] == "cancelled"

# ==============================================================================
# 4. RESULTS & FINDINGS ISOLATION
# ==============================================================================

def test_results_and_reports_endpoints(auth_user):
    headers = auth_user["headers"]
    db = SessionLocal()
    try:
        # Seed a completed scan for this user
        scan = Scan(
            user_id=auth_user["user"].id,
            target_url="https://completed-audit.local",
            depth="standard",
            status="completed",
            progress=100,
            security_score=85,
            checks={
                "pipeline_stages": [
                    {"id": "target_validation", "status": "completed"},
                    {"id": "dns_reachability", "status": "completed"},
                    {"id": "security_headers", "status": "completed"},
                    {"id": "auth", "status": "completed"},
                    {"id": "access_control", "status": "completed"},
                    {"id": "vuln_checks", "status": "completed"},
                    {"id": "report_generation", "status": "completed"}
                ]
            }
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Add a real finding
        finding = Finding(
            scan_id=scan.id,
            type="headers",
            severity="medium",
            title="Missing Content-Security-Policy",
            description="The HTTP response headers do not contain a Content-Security-Policy header.",
            confidence="HIGH",
            status="NOT_DETECTED"
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        # GET /api/scans/{id}/results
        res_results = client.get(f"/api/scans/{scan.id}/results", headers=headers)
        assert res_results.status_code == 200, res_results.text
        res_data = res_results.json()
        assert res_data["scan_id"] == scan.id
        assert res_data["security_score"] == 85
        assert len(res_data["findings"]) == 1
        assert res_data["findings"][0]["title"] == "Missing Content-Security-Policy"

        # GET /api/reports
        res_reports = client.get("/api/reports", headers=headers)
        assert res_reports.status_code == 200
        reports_data = res_reports.json()
        assert len(reports_data["reports"]) >= 1

        # GET /api/reports/{id}
        report_id = f"r{scan.id}"
        res_single_report = client.get(f"/api/reports/{report_id}", headers=headers)
        assert res_single_report.status_code == 200

        # Export JSON & CSV
        res_json = client.get(f"/api/reports/{report_id}/export/json", headers=headers)
        assert res_json.status_code == 200
        res_csv = client.get(f"/api/reports/{report_id}/export/csv", headers=headers)
        assert res_csv.status_code == 200

    finally:
        db.close()

# ==============================================================================
# 5. USER PROFILE & SETTINGS INTEGRATION
# ==============================================================================

def test_user_settings_and_profile(auth_user):
    headers = auth_user["headers"]

    # PUT /api/user/profile
    res_prof = client.put("/api/user/profile", headers=headers, json={
        "full_name": "Updated Analyst Name",
        "website": "https://analyst-firm.et"
    })
    assert res_prof.status_code == 200, res_prof.text
    prof_data = res_prof.json()
    assert prof_data["full_name"] == "Updated Analyst Name"
    assert prof_data["website"] == "https://analyst-firm.et"

    # GET /api/user/settings
    res_set = client.get("/api/user/settings", headers=headers)
    assert res_set.status_code == 200
    
    # PUT /api/user/settings
    res_update_set = client.put("/api/user/settings", headers=headers, json={
        "default_scan_depth": "deep",
        "notif_scan_completed": True,
        "notif_scan_failed": False,
        "notif_security_findings": True
    })
    assert res_update_set.status_code == 200
    updated_set = res_update_set.json()
    assert updated_set["default_scan_depth"] == "deep"
    assert updated_set["notif_scan_failed"] is False

# ==============================================================================
# 6. SCAN HISTORY & DELETION INTEGRATION
# ==============================================================================

def test_scan_history_and_deletion(auth_user):
    headers = auth_user["headers"]
    db = SessionLocal()
    try:
        # Create a scan to delete
        scan = Scan(
            user_id=auth_user["user"].id,
            target_url="https://to-be-deleted.local",
            depth="standard",
            status="completed"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Verify listed in scan history
        res_list = client.get("/api/scans?limit=50", headers=headers)
        assert any(s["id"] == scan.id for s in res_list.json()["scans"])

        # DELETE /api/scans/{id}
        res_del = client.delete(f"/api/scans/{scan.id}", headers=headers)
        assert res_del.status_code == 200

        # Verify no longer in scan history
        res_list_after = client.get("/api/scans?limit=50", headers=headers)
        assert not any(s["id"] == scan.id for s in res_list_after.json()["scans"])

    finally:
        db.close()
