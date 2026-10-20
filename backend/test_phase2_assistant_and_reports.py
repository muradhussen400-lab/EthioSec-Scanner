"""
Phase 2 Comprehensive Test Suite — AI Assistant and Reports
Tests:
- AI Assistant authentication, scan context ownership, finding context, cross-user denial
- Report listing, 5-category posture verification, ownership isolation
- Real JSON export & CSV export endpoints with ownership enforcement & 409 running guard
- Unverified/unauthenticated access rejection
"""

import json
import csv
import io
import uuid
import pytest
from fastapi.testclient import TestClient

from main import app
from database import Base, engine, SessionLocal
from models import User, ScanTarget, Scan, Finding
from ai.service import set_mock_provider
from security import get_password_hash, create_access_token
from routers import request_counts

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_rate_limits():
    request_counts.clear()
    yield
    request_counts.clear()

@pytest.fixture(scope="module")
def phase2_data():
    db = SessionLocal()

    # Create User A
    uA = User(
        email=f"usera_p2_{uuid.uuid4().hex[:6]}@ethiosec.test",
        password_hash=get_password_hash("PassUserA123!"),
        full_name="Alice SecOps",
        is_verified=True
    )
    # Create User B
    uB = User(
        email=f"userb_p2_{uuid.uuid4().hex[:6]}@ethiosec.test",
        password_hash=get_password_hash("PassUserB123!"),
        full_name="Bob ThreatAnalyst",
        is_verified=True
    )
    db.add(uA)
    db.add(uB)
    db.commit()
    db.refresh(uA)
    db.refresh(uB)

    tokenA = create_access_token({"sub": uA.email, "is_verified": True})
    tokenB = create_access_token({"sub": uB.email, "is_verified": True})

    # Targets
    targetA = ScanTarget(user_id=uA.id, url="https://app-a.ethiosec.test", authorized=True)
    targetB = ScanTarget(user_id=uB.id, url="https://app-b.ethiosec.test", authorized=True)
    db.add(targetA)
    db.add(targetB)
    db.commit()
    db.refresh(targetA)
    db.refresh(targetB)

    # User A completed scan with 5-category mixed findings
    scanA_completed = Scan(
        user_id=uA.id,
        target_url=targetA.url,
        depth="standard",
        status="completed",
        security_score=72
    )
    # User A running scan (report export should return 409)
    scanA_running = Scan(
        user_id=uA.id,
        target_url=targetA.url,
        depth="deep",
        status="running",
        security_score=None
    )
    # User B completed scan
    scanB_completed = Scan(
        user_id=uB.id,
        target_url=targetB.url,
        depth="quick",
        status="completed",
        security_score=95
    )

    db.add(scanA_completed)
    db.add(scanA_running)
    db.add(scanB_completed)
    db.commit()
    db.refresh(scanA_completed)
    db.refresh(scanA_running)
    db.refresh(scanB_completed)

    # User A Findings
    f_high = Finding(
        scan_id=scanA_completed.id,
        target_id=targetA.id,
        type="sqli",
        severity="high",
        status="HIGH",
        title="SQL Injection in Order Search",
        description="Boolean differential injection allows arbitrary table queries.",
        evidence="order_id=5' OR '1'='1 returned 200 with record.",
        url="https://app-a.ethiosec.test/orders",
        parameter="order_id",
        http_method="GET",
        remediation=["Use parameterized SQL prepared statements."],
        owasp="A03:2021-Injection",
        cwe="CWE-89"
    )
    f_med = Finding(
        scan_id=scanA_completed.id,
        target_id=targetA.id,
        type="cors",
        severity="medium",
        status="MEDIUM",
        title="Arbitrary Origin CORS Reflection",
        description="Access-Control-Allow-Origin reflects unauthorized attacker origin.",
        evidence="Origin: https://attacker.com reflected in header.",
        url="https://app-a.ethiosec.test/api/profile",
        parameter=None,
        http_method="POST",
        remediation=["Configure strict origin whitelist."],
        owasp="A05:2021-Security Misconfiguration",
        cwe="CWE-346"
    )
    f_low = Finding(
        scan_id=scanA_completed.id,
        target_id=targetA.id,
        type="headers",
        severity="low",
        status="LOW",
        title="Missing X-Frame-Options Header",
        description="Clickjacking defense header not provided.",
        evidence="Response headers omit X-Frame-Options.",
        url="https://app-a.ethiosec.test/",
        parameter=None,
        http_method="GET",
        remediation=["Set X-Frame-Options to DENY or SAMEORIGIN."],
        owasp="A05:2021-Security Misconfiguration",
        cwe="CWE-1021"
    )
    f_not_detected = Finding(
        scan_id=scanA_completed.id,
        target_id=targetA.id,
        type="xss",
        severity="info",
        status="NOT_DETECTED",
        title="Cross-Site Scripting (XSS)",
        description="Automated injection probes did not detect reflected script execution.",
        evidence=None,
        url="https://app-a.ethiosec.test/search"
    )
    f_scanner_error = Finding(
        scan_id=scanA_completed.id,
        target_id=targetA.id,
        type="scanner_error",
        severity="info",
        status="SCANNER_ERROR",
        title="TLS Certificate Query Timeout",
        description="Socket timeout querying handshake ciphers.",
        evidence="ReadTimeout: port 443 timed out after 10s",
        url="https://app-a.ethiosec.test/"
    )
    f_inconclusive = Finding(
        scan_id=scanA_completed.id,
        target_id=targetA.id,
        type="access_control",
        severity="medium",
        status="INCONCLUSIVE",
        title="Ambiguous Access Control Boundary",
        description="Differential probe returned unexpected 500 status.",
        evidence="HTTP 500 for unauthorized token.",
        url="https://app-a.ethiosec.test/admin/dashboard"
    )

    db.add_all([f_high, f_med, f_low, f_not_detected, f_scanner_error, f_inconclusive])

    # User B Finding
    f_b = Finding(
        scan_id=scanB_completed.id,
        target_id=targetB.id,
        type="headers",
        severity="low",
        status="LOW",
        title="Missing Referrer-Policy",
        description="Header absent.",
        evidence="Missing Referrer-Policy",
        url="https://app-b.ethiosec.test/"
    )
    db.add(f_b)
    db.commit()
    db.refresh(f_high)

    yield {
        "uA": uA, "tokenA": tokenA, "scanA_completed": scanA_completed, "scanA_running": scanA_running, "f_high": f_high,
        "uB": uB, "tokenB": tokenB, "scanB_completed": scanB_completed
    }

    db.close()


# ==============================================================================
# 1. AI ASSISTANT ENDPOINT TESTS
# ==============================================================================

def test_ai_chat_general_question(phase2_data):
    """User can ask general security questions with no scan ID."""
    token = phase2_data["tokenA"]
    set_mock_provider(lambda ctx, msg: f"AI Answer to: {msg}")

    res = client.post(
        "/api/ai/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "What is CSRF?"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert "AI Answer to: What is CSRF?" in data["reply"]


def test_ai_chat_scan_context_ownership(phase2_data):
    """User A can chat within the context of their own scan."""
    token = phase2_data["tokenA"]
    scan_id = phase2_data["scanA_completed"].id
    set_mock_provider(lambda ctx, msg: f"Verified for scan: {msg}")

    res = client.post(
        "/api/ai/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Summarize this scan", "scan_id": scan_id}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["scan_id"] == scan_id
    assert "Verified for scan: Summarize this scan" in data["reply"]


def test_ai_chat_cross_user_scan_access_denied(phase2_data):
    """User B cannot access User A's scan in AI Assistant (returns 403 Forbidden)."""
    token = phase2_data["tokenB"]
    scan_id = phase2_data["scanA_completed"].id

    res = client.post(
        "/api/ai/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Show findings", "scan_id": scan_id}
    )
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower()


def test_ai_chat_cross_user_finding_access_denied(phase2_data):
    """User B cannot access User A's finding in AI Assistant (returns 403 Forbidden)."""
    token = phase2_data["tokenB"]
    finding_id = phase2_data["f_high"].id

    res = client.post(
        "/api/ai/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Explain finding", "finding_id": finding_id}
    )
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower()


def test_ai_chat_unauthenticated_denied():
    """Unauthenticated request to AI Assistant returns 401."""
    res = client.post("/api/ai/chat", json={"message": "Hello"})
    assert res.status_code == 401


# ==============================================================================
# 2. REPORTS ENDPOINTS & 5-CATEGORY POSTURE TESTS
# ==============================================================================

def test_reports_list_isolation(phase2_data):
    """User A only sees their completed reports; User B only sees theirs."""
    tokenA = phase2_data["tokenA"]
    tokenB = phase2_data["tokenB"]

    resA = client.get("/api/reports", headers={"Authorization": f"Bearer {tokenA}"})
    assert resA.status_code == 200
    reportsA = resA.json()["reports"]
    assert len(reportsA) == 1
    assert reportsA[0]["scan_id"] == phase2_data["scanA_completed"].id

    resB = client.get("/api/reports", headers={"Authorization": f"Bearer {tokenB}"})
    assert resB.status_code == 200
    reportsB = resB.json()["reports"]
    assert len(reportsB) == 1
    assert reportsB[0]["scan_id"] == phase2_data["scanB_completed"].id


def test_report_detail_5_category_verification(phase2_data):
    """Report detail computes exact 5 categories consistently."""
    tokenA = phase2_data["tokenA"]
    scan_id = phase2_data["scanA_completed"].id

    res = client.get(f"/api/reports/r{scan_id}", headers={"Authorization": f"Bearer {tokenA}"})
    assert res.status_code == 200
    data = res.json()

    c = data["counts"]
    assert c["high"] == 1
    assert c["medium"] == 1
    assert c["low"] == 1
    assert c["not_detected"] == 1
    assert c["scanner_error"] == 1
    assert c["inconclusive"] == 1
    assert c["total"] == 3  # high + medium + low confirmed


def test_report_cross_user_access_denied(phase2_data):
    """User B cannot fetch User A's report (returns 404)."""
    tokenB = phase2_data["tokenB"]
    scan_id = phase2_data["scanA_completed"].id

    res = client.get(f"/api/reports/r{scan_id}", headers={"Authorization": f"Bearer {tokenB}"})
    assert res.status_code == 404


# ==============================================================================
# 3. EXPORT ENDPOINTS (JSON & CSV) WITH AUTHORIZATION & RFC 4180 SAFETY
# ==============================================================================

def test_report_export_json_success(phase2_data):
    """User A downloads authorized report as machine-readable JSON."""
    tokenA = phase2_data["tokenA"]
    scan_id = phase2_data["scanA_completed"].id

    res = client.get(f"/api/reports/r{scan_id}/export/json", headers={"Authorization": f"Bearer {tokenA}"})
    assert res.status_code == 200
    assert "application/json" in res.headers["content-type"]
    assert f'filename="ethiosec_report_{scan_id}.json"' in res.headers["content-disposition"]

    data = res.json()
    assert data["scan_id"] == scan_id
    assert data["target_url"] == "https://app-a.ethiosec.test"
    assert data["counts"]["high"] == 1
    assert data["counts"]["scanner_error"] == 1
    assert len(data["findings"]) == 6

    # Verify finding fields in export
    finding_sqli = next(f for f in data["findings"] if f["type"] == "sqli")
    assert finding_sqli["title"] == "SQL Injection in Order Search"
    assert finding_sqli["severity"] == "high"
    assert finding_sqli["category"] == "HIGH"
    assert "order_id" in finding_sqli["evidence"]


def test_report_export_csv_success(phase2_data):
    """User A downloads authorized report as tabular CSV formatted with RFC 4180 safety."""
    tokenA = phase2_data["tokenA"]
    scan_id = phase2_data["scanA_completed"].id

    res = client.get(f"/api/reports/r{scan_id}/export/csv", headers={"Authorization": f"Bearer {tokenA}"})
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert f'filename="ethiosec_report_{scan_id}.csv"' in res.headers["content-disposition"]

    csv_text = res.text
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)

    # Header row
    header = rows[0]
    assert "Finding ID" in header
    assert "Type" in header
    assert "Title" in header
    assert "Severity" in header
    assert "Category" in header
    assert "Evidence" in header
    assert "Remediation" in header

    # Ensure all 6 findings exported
    assert len(rows) == 7 # 1 header + 6 findings


def test_report_export_cross_user_denied(phase2_data):
    """User B cannot export User A's report in JSON or CSV (returns 404)."""
    tokenB = phase2_data["tokenB"]
    scan_id = phase2_data["scanA_completed"].id

    res_json = client.get(f"/api/reports/r{scan_id}/export/json", headers={"Authorization": f"Bearer {tokenB}"})
    assert res_json.status_code == 404

    res_csv = client.get(f"/api/reports/r{scan_id}/export/csv", headers={"Authorization": f"Bearer {tokenB}"})
    assert res_csv.status_code == 404


def test_report_export_running_scan_rejected(phase2_data):
    """Attempting to export a report for a running scan returns HTTP 409 Conflict."""
    tokenA = phase2_data["tokenA"]
    running_id = phase2_data["scanA_running"].id

    res = client.get(f"/api/reports/r{running_id}/export/json", headers={"Authorization": f"Bearer {tokenA}"})
    assert res.status_code == 409
    assert "still running" in res.json()["detail"].lower()


def test_scan_export_aliases(phase2_data):
    """Scan ID aliases (/api/scans/{id}/export/...) return identical export data."""
    tokenA = phase2_data["tokenA"]
    scan_id = phase2_data["scanA_completed"].id

    res_json = client.get(f"/api/scans/{scan_id}/export/json", headers={"Authorization": f"Bearer {tokenA}"})
    assert res_json.status_code == 200
    assert res_json.json()["scan_id"] == scan_id

    res_csv = client.get(f"/api/scans/{scan_id}/export/csv", headers={"Authorization": f"Bearer {tokenA}"})
    assert res_csv.status_code == 200
    assert "Finding ID" in res_csv.text
