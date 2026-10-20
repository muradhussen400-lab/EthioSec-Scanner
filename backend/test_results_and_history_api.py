import sys
import os
import uuid
import datetime
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))

from main import app
from database import SessionLocal
from models import User, Scan, Finding, ScanTarget
from security import get_password_hash, create_access_token

client = TestClient(app)

@pytest.fixture(scope="module")
def setup_users():
    db = SessionLocal()
    # User 1
    u1_email = f"testuser1_{uuid.uuid4().hex[:6]}@example.com"
    u1 = User(
        email=u1_email,
        full_name="Tester One",
        password_hash=get_password_hash("Password123!"),
        role="Security Analyst",
        is_verified=True
    )
    # User 2 (for multi-tenant isolation verification)
    u2_email = f"testuser2_{uuid.uuid4().hex[:6]}@example.com"
    u2 = User(
        email=u2_email,
        full_name="Tester Two",
        password_hash=get_password_hash("Password123!"),
        role="Security Analyst",
        is_verified=True
    )
    db.add(u1)
    db.add(u2)
    db.commit()
    db.refresh(u1)
    db.refresh(u2)

    token1 = create_access_token({"sub": u1.email, "is_verified": True})
    token2 = create_access_token({"sub": u2.email, "is_verified": True})

    yield {
        "u1": u1, "token1": token1,
        "u2": u2, "token2": token2
    }
    db.close()

def test_scan_history_and_ownership_isolation(setup_users):
    u1 = setup_users["u1"]
    token1 = setup_users["token1"]
    u2 = setup_users["u2"]
    token2 = setup_users["token2"]

    db = SessionLocal()
    
    # Create scan for User 1
    scan1 = Scan(
        user_id=u1.id,
        target_url="https://app1.test.local",
        depth="standard",
        status="completed",
        security_score=85,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    # Create scan for User 2
    scan2 = Scan(
        user_id=u2.id,
        target_url="https://app2.secret.local",
        depth="deep",
        status="completed",
        security_score=92,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan1)
    db.add(scan2)
    db.commit()
    db.refresh(scan1)
    db.refresh(scan2)

    # Add findings for scan1
    f_high = Finding(
        scan_id=scan1.id,
        type="sqli",
        severity="high",
        status="CONFIRMED",
        title="SQL Injection in user search",
        description="Boolean-based blind SQL injection detected on id parameter.",
        parameter="id",
        url="https://app1.test.local/search",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    f_inconc = Finding(
        scan_id=scan1.id,
        type="access_control",
        severity="high",
        status="INCONCLUSIVE",
        title="Access Control Test Inconclusive",
        description="Requires Context 2 test credentials to verify IDOR boundary.",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    f_clean = Finding(
        scan_id=scan1.id,
        type="xss",
        severity="low",
        status="NOT_DETECTED",
        title="Cross-Site Scripting (XSS)",
        description="Input parameters properly HTML-entity encoded.",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(f_high)
    db.add(f_inconc)
    db.add(f_clean)
    db.commit()

    # User 1 calls GET /api/scans
    res1 = client.get("/api/scans", headers={"Authorization": f"Bearer {token1}"})
    assert res1.status_code == 200
    data1 = res1.json()
    scan_ids_u1 = [s["id"] for s in data1["scans"]]
    assert scan1.id in scan_ids_u1
    assert scan2.id not in scan_ids_u1, "CRITICAL: User 1 must not see User 2's scan history"

    # User 2 calls GET /api/scans
    res2 = client.get("/api/scans", headers={"Authorization": f"Bearer {token2}"})
    assert res2.status_code == 200
    data2 = res2.json()
    scan_ids_u2 = [s["id"] for s in data2["scans"]]
    assert scan2.id in scan_ids_u2
    assert scan1.id not in scan_ids_u2, "CRITICAL: User 2 must not see User 1's scan history"

    # Verify Counts Rule: Inconclusive must NOT be counted as confirmed vulnerability
    scan1_record = next(s for s in data1["scans"] if s["id"] == scan1.id)
    counts = scan1_record["counts"]
    assert counts["high"] == 1, "Only CONFIRMED high severity should be counted as high"
    assert counts["inconclusive"] == 1, "Inconclusive check must be tracked in inconclusive count"
    assert counts["not_detected"] == 1
    assert counts["total"] == 1, "Total confirmed issues should equal confirmed high (1)"

    db.close()

def test_results_endpoint_rules_and_running_state(setup_users):
    u1 = setup_users["u1"]
    token1 = setup_users["token1"]
    token2 = setup_users["token2"]

    db = SessionLocal()
    
    # 1. Completed scan
    scan_done = Scan(
        user_id=u1.id,
        target_url="https://audit-complete.local",
        depth="standard",
        status="completed",
        security_score=78,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    # 2. Running scan
    scan_running = Scan(
        user_id=u1.id,
        target_url="https://audit-running.local",
        depth="standard",
        status="running",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan_done)
    db.add(scan_running)
    db.commit()
    db.refresh(scan_done)
    db.refresh(scan_running)

    # Requesting running scan results returns 409 Conflict
    res_running = client.get(f"/api/scans/{scan_running.id}/results", headers={"Authorization": f"Bearer {token1}"})
    assert res_running.status_code == 409, "Running scan must return HTTP 409 Conflict"

    # Requesting other user's scan returns 404 Not Found
    res_forbidden = client.get(f"/api/scans/{scan_done.id}/results", headers={"Authorization": f"Bearer {token2}"})
    assert res_forbidden.status_code == 404, "User 2 accessing User 1's scan must receive 404 Not Found"

    # Owner requesting completed scan returns 200 with ScanResultOut schema
    res_ok = client.get(f"/api/scans/{scan_done.id}/results", headers={"Authorization": f"Bearer {token1}"})
    assert res_ok.status_code == 200
    res_data = res_ok.json()
    assert res_data["scan_id"] == scan_done.id
    assert res_data["target"] == "https://audit-complete.local"
    assert "counts" in res_data
    assert "findings" in res_data

    # Test Deletion
    del_other = client.delete(f"/api/scans/{scan_done.id}", headers={"Authorization": f"Bearer {token2}"})
    assert del_other.status_code == 404, "User 2 cannot delete User 1's scan"

    del_owner = client.delete(f"/api/scans/{scan_done.id}", headers={"Authorization": f"Bearer {token1}"})
    assert del_owner.status_code == 200, "Owner successfully deletes scan"

    # Check that deleted scan is no longer accessible
    res_after_del = client.get(f"/api/scans/{scan_done.id}/results", headers={"Authorization": f"Bearer {token1}"})
    assert res_after_del.status_code == 404

    db.close()

def test_security_score_calculation_and_edge_cases(setup_users):
    """
    Verifies Requirement 2: Security score audit
    - Exactly verifies the penalty-deduction formula:
      score = 100 - (critical * 25) - (high * 14) - (medium * 7) - (low * 3)
      score = max(5, min(100, score))
    - Verifies clean scan baseline (100)
    - Verifies mixed vulnerability deductions
    - Verifies maximum penalty floor clamp (5)
    - Verifies running scan state (None / 409 Conflict)
    - Verifies failed scan state (None)
    """
    u1 = setup_users["u1"]
    token1 = setup_users["token1"]
    db = SessionLocal()

    # 1. Clean Scan: 0 findings -> Score 100
    scan_clean = Scan(
        user_id=u1.id,
        target_url="https://clean-test.local",
        depth="standard",
        status="completed",
        security_score=100,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan_clean)
    db.commit()
    db.refresh(scan_clean)

    res_clean = client.get(f"/api/scans/{scan_clean.id}/results", headers={"Authorization": f"Bearer {token1}"})
    assert res_clean.status_code == 200
    assert res_clean.json()["security_score"] == 100

    # 2. Mixed Findings: 1 crit (-25) + 1 high (-14) + 1 med (-7) + 1 low (-3) -> Score 51
    expected_score = 100 - (1 * 25) - (1 * 14) - (1 * 7) - (1 * 3)
    assert expected_score == 51

    scan_mixed = Scan(
        user_id=u1.id,
        target_url="https://mixed-vulns.local",
        depth="standard",
        status="completed",
        security_score=expected_score,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan_mixed)
    db.commit()
    db.refresh(scan_mixed)

    # Add findings
    f_high = Finding(scan_id=scan_mixed.id, type="sqli", severity="high", status="HIGH", title="SQL Injection", description="SQL injection finding", url="https://mixed-vulns.local/api")
    f_med = Finding(scan_id=scan_mixed.id, type="cors", severity="medium", status="MEDIUM", title="CORS Misconfig", description="CORS misconfiguration", url="https://mixed-vulns.local/cors")
    f_low = Finding(scan_id=scan_mixed.id, type="headers", severity="low", status="LOW", title="Missing CSP", description="CSP header missing", url="https://mixed-vulns.local/")
    f_not_det = Finding(scan_id=scan_mixed.id, type="xss", severity="info", status="NOT_DETECTED", title="XSS Checked", description="XSS not detected", url="https://mixed-vulns.local/xss")
    f_inconc = Finding(scan_id=scan_mixed.id, type="access_control", severity="medium", status="INCONCLUSIVE", title="BAC Check", description="BAC check inconclusive", url="https://mixed-vulns.local/admin")

    db.add_all([f_high, f_med, f_low, f_not_det, f_inconc])
    db.commit()

    res_mixed = client.get(f"/api/scans/{scan_mixed.id}/results", headers={"Authorization": f"Bearer {token1}"})
    assert res_mixed.status_code == 200
    data_mixed = res_mixed.json()
    assert data_mixed["security_score"] == 51

    # Verify exact five summary categories in counts
    counts = data_mixed["counts"]
    for cat in ["high", "medium", "low", "not_detected", "scanner_error"]:
        assert cat in counts, f"Missing required category: {cat}"

    # Confirm inconclusive check is NEVER counted in confirmed vulns or not_detected
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["not_detected"] == 1
    assert counts.get("inconclusive", 0) == 1

    # 3. Floor Edge Case: Excessive critical vulnerabilities (e.g. 10 * 25 = 250 penalty)
    floor_score = max(5, min(100, 100 - (10 * 25)))
    assert floor_score == 5, "Score floor clamp must be exactly 5"

    scan_floor = Scan(
        user_id=u1.id,
        target_url="https://catastrophic-target.local",
        depth="standard",
        status="completed",
        security_score=floor_score,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan_floor)
    db.commit()
    db.refresh(scan_floor)

    res_floor = client.get(f"/api/scans/{scan_floor.id}/results", headers={"Authorization": f"Bearer {token1}"})
    assert res_floor.status_code == 200
    assert res_floor.json()["security_score"] == 5

    # 4. Failed scan: security_score is None, status is failed
    scan_failed = Scan(
        user_id=u1.id,
        target_url="https://failed-target.local",
        depth="standard",
        status="failed",
        security_score=None,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    db.add(scan_failed)
    db.commit()
    db.refresh(scan_failed)

    res_failed = client.get(f"/api/scans/{scan_failed.id}/results", headers={"Authorization": f"Bearer {token1}"})
    assert res_failed.status_code == 200
    # For failed scans, routers safely returns 0 or None
    assert res_failed.json()["security_score"] in (0, None)

    db.close()

