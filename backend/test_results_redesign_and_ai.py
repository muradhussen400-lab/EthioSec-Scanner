import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal, engine, Base
from models import User, Scan, Finding
from security import create_access_token, get_password_hash

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Clean up test users
    db.query(Finding).delete()
    db.query(Scan).delete()
    db.query(User).filter(User.email.in_(["tester_res@ethiosec.com", "other_res@ethiosec.com"])).delete()
    db.commit()

    # Create verified test users
    pw_hash = get_password_hash("ValidPass123!")
    user_a = User(
        email="tester_res@ethiosec.com",
        password_hash=pw_hash,
        is_verified=True,
        full_name="Tester Res"
    )
    user_b = User(
        email="other_res@ethiosec.com",
        password_hash=pw_hash,
        is_verified=True,
        full_name="Other User"
    )
    db.add_all([user_a, user_b])
    db.commit()
    db.refresh(user_a)
    db.refresh(user_b)

    yield {"user_a": user_a, "user_b": user_b}

    db = SessionLocal()
    db.query(Finding).delete()
    db.query(Scan).delete()
    db.query(User).filter(User.email.in_(["tester_res@ethiosec.com", "other_res@ethiosec.com"])).delete()
    db.commit()
    db.close()


def test_results_endpoint_returns_module_details_and_accurate_counts(setup_db):
    user_a = setup_db["user_a"]
    token = create_access_token(data={"sub": user_a.email, "is_verified": True})
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    scan = Scan(
        id="scan-redesign-test-1",
        user_id=user_a.id,
        target_url="http://example.com",
        depth="standard",
        status="completed",
        security_score=78,
        modules={
            "module_details": {
                "access_control": {
                    "id": "access_control",
                    "name": "Broken Access Control",
                    "selected": True,
                    "status": "inconclusive",
                    "message": "Inconclusive — dual authorization contexts required for IDOR testing."
                },
                "xss": {
                    "id": "xss",
                    "name": "Cross-Site Scripting",
                    "selected": True,
                    "status": "completed",
                    "findings": 1
                },
                "cookies": {
                    "id": "cookies",
                    "name": "Cookie Security",
                    "selected": True,
                    "status": "completed",
                    "findings": 0
                },
                "sqli": {
                    "id": "sqli",
                    "name": "SQL Injection",
                    "selected": False,
                    "status": "skipped",
                    "message": "Skipped — module was not selected."
                }
            }
        }
    )
    db.add(scan)
    db.commit()

    # Add 1 confirmed XSS finding, 1 clean Cookies check, 1 inconclusive Access Control finding
    f1 = Finding(
        id="f-xss-1",
        scan_id=scan.id,
        title="Reflected Cross-Site Scripting (XSS)",
        severity="high",
        status="CONFIRMED",
        type="xss",
        description="Reflected input without encoding.",
        url="http://example.com/search?q=test",
        parameter="q",
        evidence="<script>alert(1)</script> was reflected in response body",
        impact="Allows execution of arbitrary JavaScript in the user's browser context."
    )
    f2 = Finding(
        id="f-cookies-1",
        scan_id=scan.id,
        title="Cookie Security Flags Verified",
        severity="info",
        status="NOT_DETECTED",
        type="cookies",
        description="All session cookies include HttpOnly and Secure flags.",
        url="http://example.com",
        evidence="Observed Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Lax"
    )
    f3 = Finding(
        id="f-ac-inconc",
        scan_id="scan-redesign-test-1",
        title="Access Control Inconclusive (Configuration Required)",
        severity="info",
        status="INCONCLUSIVE",
        type="access_control",
        description="Dual authorization contexts were not provided.",
        url="http://example.com",
        evidence="Dual authorization contexts not configured."
    )
    db.add_all([f1, f2, f3])
    db.commit()
    db.close()

    res = client.get("/api/scans/scan-redesign-test-1/results", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["scan_id"] == "scan-redesign-test-1"
    assert data["target"] == "http://example.com"
    assert data["status"] == "completed"
    assert data["module_details"] is not None
    assert "access_control" in data["module_details"]
    assert data["module_details"]["access_control"]["status"] == "inconclusive"
    assert data["module_details"]["sqli"]["status"] == "skipped"

    counts = data["counts"]
    assert counts["high"] == 1
    assert counts["not_detected"] == 1
    assert counts["inconclusive"] == 1
    assert counts["total"] == 1  # Only confirmed vulnerabilities are counted in total


def test_ai_chat_finding_ownership_and_context(setup_db):
    user_a = setup_db["user_a"]
    user_b = setup_db["user_b"]
    token_a = create_access_token(data={"sub": user_a.email, "is_verified": True})
    token_b = create_access_token(data={"sub": user_b.email, "is_verified": True})

    db = SessionLocal()
    scan_a = Scan(
        id="scan-ai-test-1",
        user_id=user_a.id,
        target_url="http://example.com",
        depth="standard",
        status="completed"
    )
    db.add(scan_a)
    db.commit()

    f_a = Finding(
        id="f-ai-test-1",
        scan_id=scan_a.id,
        title="SQL Injection in Parameter id",
        severity="high",
        status="CONFIRMED",
        type="sqli",
        description="Boolean-based blind SQL injection detected.",
        url="http://example.com/api/items?id=1",
        parameter="id",
        evidence="Response timing discrepancy of 5.2s on benchmark query."
    )
    db.add(f_a)
    db.commit()
    db.close()

    # User B should be forbidden from accessing User A's finding
    res_b = client.post(
        "/api/ai/chat",
        json={"message": "Explain this vulnerability", "finding_id": "f-ai-test-1"},
        headers={"Authorization": f"Bearer {token_b}"}
    )
    assert res_b.status_code == 403

    # User A should succeed
    res_a = client.post(
        "/api/ai/chat",
        json={"message": "Explain this finding and provide remediation code", "finding_id": "f-ai-test-1"},
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert res_a.status_code == 200
    ai_data = res_a.json()
    assert "reply" in ai_data
    assert len(ai_data["reply"]) > 10


def test_results_headline_counting_contract_six_confirmed_two_not_detected(setup_db):
    """
    Direct regression test for observed issue #1:
    Database has 8 findings (0 Critical, 2 High, 1 Medium, 3 Low, 2 Not Detected).
    Confirmed vulnerabilities must strictly equal 6 (2 + 1 + 3 = 6), NOT 8.
    The 2 Not Detected records must not inflate confirmed vulnerability counts.
    """
    user_a = setup_db["user_a"]
    token = create_access_token(data={"sub": user_a.email, "is_verified": True})
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    scan = Scan(
        id="scan-contract-test-8",
        user_id=user_a.id,
        target_url="http://cafeteria.edu.et",
        depth="standard",
        status="completed",
        security_score=55
    )
    db.add(scan)
    db.commit()

    test_findings = [
        # 2 High
        Finding(id="f-h1", scan_id=scan.id, title="High Vuln 1", description="High vuln desc", severity="high", status="HIGH", type="sqli"),
        Finding(id="f-h2", scan_id=scan.id, title="High Vuln 2", description="High vuln desc", severity="high", status="HIGH", type="xss"),
        # 1 Medium
        Finding(id="f-m1", scan_id=scan.id, title="Medium Vuln 1", description="Medium vuln desc", severity="medium", status="MEDIUM", type="cors"),
        # 3 Low
        Finding(id="f-l1", scan_id=scan.id, title="Low Vuln 1", description="Low vuln desc", severity="low", status="LOW", type="headers"),
        Finding(id="f-l2", scan_id=scan.id, title="Low Vuln 2", description="Low vuln desc", severity="low", status="LOW", type="cookies"),
        Finding(id="f-l3", scan_id=scan.id, title="Low Vuln 3", description="Low vuln desc", severity="low", status="LOW", type="http_methods"),
        # 2 Not Detected
        Finding(id="f-nd1", scan_id=scan.id, title="TLS Check Clean", description="TLS clean desc", severity="info", status="NOT_DETECTED", type="https"),
        Finding(id="f-nd2", scan_id=scan.id, title="Files Check Clean", description="Files clean desc", severity="info", status="NOT_DETECTED", type="exposed_files"),
    ]
    db.add_all(test_findings)
    db.commit()
    db.close()

    res = client.get("/api/scans/scan-contract-test-8/results", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Total records in findings array is 8
    assert len(data["findings"]) == 8

    # Category counts must strictly partition confirmed vs clean
    c = data["counts"]
    assert c["critical"] == 0
    assert c["high"] == 2
    assert c["medium"] == 1
    assert c["low"] == 3
    assert c["not_detected"] == 2
    assert c["scanner_error"] == 0

    # Total confirmed vulnerabilities MUST equal 6, not 8
    assert c["total"] == 6
    assert c["critical"] + c["high"] + c["medium"] + c["low"] == c["total"]

