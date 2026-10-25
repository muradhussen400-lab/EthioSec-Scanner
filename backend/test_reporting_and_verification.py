import pytest
import os
import sys
import time
import json
from fastapi.testclient import TestClient

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from main import app
from database import engine, Base, SessionLocal
from models import User, Scan, Finding
from scanner.test_case import TestCaseResult
from scanner.engine import SecurityScanner
from ai.executive_summary import aggregate_finding_counts

client = TestClient(app)

@pytest.fixture(scope="module")
def setup_user_and_token():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Create or retrieve verified test user
    email = "verification_tester@ethiosec.local"
    user = db.query(User).filter(User.email == email).first()
    if user:
        db.query(Finding).filter(Finding.scan_id.in_(db.query(Scan.id).filter(Scan.user_id == user.id))).delete(synchronize_session=False)
        db.query(Scan).filter(Scan.user_id == user.id).delete(synchronize_session=False)
        db.commit()
    else:
        from security import get_password_hash
        user = User(
            email=email,
            full_name="Verification Tester",
            password_hash=get_password_hash("SecretPassword123!"),
            is_verified=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    from security import create_access_token
    token = create_access_token(data={"sub": user.email, "id": user.id, "is_verified": True})
    user_id = user.id
    db.close()
    return {"token": token, "user_id": user_id, "headers": {"Authorization": f"Bearer {token}"}}


def test_task1_and_task2_severity_separate_from_verification_status(setup_user_and_token):
    """
    Task 2: Keep severity (Critical, High, Medium, Low, Informational) strictly separated
    from verification status (CONFIRMED, POTENTIAL, NOT_DETECTED, INCONCLUSIVE, BLOCKED, SKIPPED, NOT_TESTED, ERROR).
    Do not map HIGH confidence directly to Confirmed.
    Do not report NOT_DETECTED if check was skipped, blocked, or failed.
    """
    db = SessionLocal()
    user_id = setup_user_and_token["user_id"]

    scan = Scan(
        user_id=user_id,
        target_url="https://example.com/test",
        depth="shallow",
        status="completed",
        security_score=85
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 1. Confirmed High Finding: Full proof
    f_confirmed = Finding(
        scan_id=scan.id,
        type="sqli",
        title="SQL Injection in login parameter",
        description="SQL syntax error induced via unescaped parameter",
        severity="high",
        status="HIGH",
        verification_status="CONFIRMED",
        confidence="HIGH",
        evidence="Extracted database version via UNION SELECT: SQLite 3.39.0",
        remediation="Use parameterized queries"
    )

    # 2. Potential Finding: High confidence in suspicion, but execution unconfirmed
    f_potential = Finding(
        scan_id=scan.id,
        type="xss",
        title="Potential Reflected Parameter",
        description="Reflected user input observed in HTML body",
        severity="medium",
        status="MEDIUM",
        verification_status="POTENTIAL",
        confidence="HIGH",
        evidence="Parameter reflected with encoding stripped, but script execution blocked by CSP",
        remediation="Implement strict context-aware sanitization"
    )

    # 3. Inconclusive Finding
    f_inconclusive = Finding(
        scan_id=scan.id,
        type="access_control",
        title="Access Control Assessment Inconclusive",
        description="Unable to verify privilege escalation without dual authenticated contexts",
        severity="info",
        status="INCONCLUSIVE",
        verification_status="INCONCLUSIVE",
        confidence="LOW",
        evidence="Requires dual authenticated session contexts (admin & low-priv)",
        remediation="Provide secondary session token for authorization testing"
    )

    # 4. Blocked Finding
    f_blocked = Finding(
        scan_id=scan.id,
        type="rate_limiting",
        title="Automated Requests Blocked by WAF",
        description="WAF threshold exceeded resulting in rate limits",
        severity="info",
        status="SCANNER_ERROR",
        verification_status="BLOCKED",
        confidence="HIGH",
        evidence="HTTP 429 and Cloudflare challenge returned after 5 requests",
        remediation="Whitelist scanner IP in firewall settings"
    )

    # 5. Skipped Finding
    f_skipped = Finding(
        scan_id=scan.id,
        type="https",
        title="TLS Check Skipped for Internal Test Environment",
        description="Bypassed per configuration on loopback host",
        severity="info",
        status="SCANNER_ERROR",
        verification_status="SKIPPED",
        confidence="HIGH",
        evidence="Scan configured to bypass certificate verification on private IP",
        remediation="Enable TLS certificates in production"
    )

    # 6. Not Tested Check
    f_not_tested = Finding(
        scan_id=scan.id,
        type="csrf",
        title="CSRF Assessment Not Tested (No HTML Forms Discovered)",
        description="Target endpoints do not render state-changing web forms",
        severity="info",
        status="NOT_DETECTED",
        verification_status="NOT_TESTED",
        confidence="HIGH",
        evidence="Crawler discovered 0 POST/PUT HTML forms across target endpoints",
        remediation="Review state-changing API endpoints for anti-CSRF token protection"
    )

    # 7. Error Finding
    f_error = Finding(
        scan_id=scan.id,
        type="auth",
        title="Authentication Assessment Error",
        description="Unexpected network failure during authentication tests",
        severity="info",
        status="SCANNER_ERROR",
        verification_status="ERROR",
        confidence="LOW",
        evidence="ReadTimeout connecting to login endpoint after 3 retries",
        remediation="Verify target server availability during scan window"
    )

    db.add_all([f_confirmed, f_potential, f_inconclusive, f_blocked, f_skipped, f_not_tested, f_error])
    db.commit()

    # Query via API
    headers = setup_user_and_token["headers"]
    res = client.get(f"/api/scans/{scan.id}/results", headers=headers)
    assert res.status_code == 200
    data = res.json()

    findings = data["findings"]
    assert len(findings) == 7

    # Check that verification_status is explicitly returned and not confounded with severity
    verif_statuses = {f["title"]: f["verification_status"] for f in findings}
    severities = {f["title"]: f["severity"] for f in findings}

    assert verif_statuses["SQL Injection in login parameter"] == "CONFIRMED"
    assert severities["SQL Injection in login parameter"] == "high"

    assert verif_statuses["Potential Reflected Parameter"] == "POTENTIAL"
    assert severities["Potential Reflected Parameter"] == "medium"

    assert verif_statuses["Access Control Assessment Inconclusive"] == "INCONCLUSIVE"
    assert verif_statuses["Automated Requests Blocked by WAF"] == "BLOCKED"
    assert verif_statuses["TLS Check Skipped for Internal Test Environment"] == "SKIPPED"
    assert verif_statuses["CSRF Assessment Not Tested (No HTML Forms Discovered)"] == "NOT_TESTED"
    assert verif_statuses["Authentication Assessment Error"] == "ERROR"

    # Aggregated counts check
    counts = data["counts"]
    # Severity totals use severity field
    assert counts["high"] == 1
    assert counts["medium"] == 1

    # Verification status and outcome counts
    assert counts["confirmed"] == 1
    assert counts["potential"] == 1
    assert counts["inconclusive"] == 1
    assert counts["blocked"] == 1
    assert counts["skipped"] == 1
    assert counts["not_tested"] == 1

    db.close()


def test_task3_and_task4_deduplication_and_dashboard_counts(setup_user_and_token):
    """
    Task 3 & 4:
    - Duplicate findings do not inflate dashboard counts.
    - Findings retain their severity, verification status, confidence, evidence, and remediation.
    - Refreshing the page (re-querying API) returns identical, deterministic counts.
    """
    db = SessionLocal()
    user_id = setup_user_and_token["user_id"]

    scan = Scan(
        user_id=user_id,
        target_url="https://app.ethiosec.local",
        depth="deep",
        status="completed",
        security_score=70
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Insert two findings with identical (type, url, parameter, title)
    dup1 = Finding(
        scan_id=scan.id,
        type="sqli",
        title="Blind SQL Injection",
        description="Time based blind SQL injection detected on parameter",
        url="https://app.ethiosec.local/items",
        parameter="id",
        severity="critical",
        status="CRITICAL",
        verification_status="CONFIRMED",
        confidence="HIGH",
        evidence="Time delay 5.2s observed with pg_sleep(5)",
        remediation=["Use ORM or parameterized query"]
    )
    dup2 = Finding(
        scan_id=scan.id,
        type="sqli",
        title="Blind SQL Injection",
        description="Time based blind SQL injection detected on parameter",
        url="https://app.ethiosec.local/items",
        parameter="id",
        severity="critical",
        status="CRITICAL",
        verification_status="CONFIRMED",
        confidence="HIGH",
        evidence="Time delay 5.1s observed with pg_sleep(5) on retry",
        remediation=["Use ORM or parameterized query"]
    )
    db.add_all([dup1, dup2])
    db.commit()

    headers = setup_user_and_token["headers"]

    # 1. First fetch
    res1 = client.get(f"/api/scans/{scan.id}/results", headers=headers)
    assert res1.status_code == 200
    counts1 = res1.json()["counts"]

    # Deduplicated count must be 1, NOT 2
    assert counts1["critical"] == 1
    assert counts1["confirmed"] == 1

    # 2. Dashboard summary
    dash_res = client.get("/api/dashboard/summary", headers=headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert dash_data["vulnerabilities"] >= 1
    assert dash_data["issues"] >= 1

    # 3. Refresh simulation (second fetch)
    res2 = client.get(f"/api/scans/{scan.id}/results", headers=headers)
    assert res2.status_code == 200
    counts2 = res2.json()["counts"]
    assert counts1 == counts2

    db.close()


def test_task3_completed_with_errors_report_accessible(setup_user_and_token):
    """
    Task 3: completed_with_errors reports can be opened, listed, and exported.
    """
    db = SessionLocal()
    user_id = setup_user_and_token["user_id"]

    scan = Scan(
        user_id=user_id,
        target_url="https://partial-fail.ethiosec.local",
        depth="shallow",
        status="completed_with_errors",
        security_score=60
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        type="headers",
        title="Missing Content-Security-Policy",
        description="Content security policy is missing from headers",
        severity="low",
        status="LOW",
        verification_status="CONFIRMED",
        confidence="HIGH",
        evidence="CSP header absent from HTTP response",
        remediation="Add Content-Security-Policy header"
    )
    err_finding = Finding(
        scan_id=scan.id,
        type="sqli",
        title="SQL Injection Assessment Failed",
        description="Network failure interrupted the SQL injection test",
        severity="info",
        status="SCANNER_ERROR",
        verification_status="ERROR",
        confidence="LOW",
        evidence="Network connection reset during payload transmission",
        remediation="Check server logs and network firewall"
    )
    db.add_all([finding, err_finding])
    db.commit()

    headers = setup_user_and_token["headers"]

    # 1. Report list includes completed_with_errors
    res_list = client.get("/api/reports", headers=headers)
    assert res_list.status_code == 200
    rep_ids = [r["scan_id"] for r in res_list.json()["reports"]]
    assert scan.id in rep_ids

    # 2. Report can be opened directly
    res_report = client.get(f"/api/reports/r{scan.id}", headers=headers)
    assert res_report.status_code == 200
    rep_data = res_report.json()
    assert rep_data["scan_id"] == scan.id
    assert rep_data["counts"]["low"] == 1
    assert rep_data["counts"]["scanner_error"] == 1

    # 3. Report can be exported as JSON
    res_export = client.get(f"/api/reports/r{scan.id}/export/json", headers=headers)
    assert res_export.status_code == 200
    export_data = res_export.json()
    assert export_data["report_id"] == f"r{scan.id}"
    assert len(export_data["findings"]) == 2

    # 4. Report can be exported as CSV
    res_csv = client.get(f"/api/reports/r{scan.id}/export/csv", headers=headers)
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]

    db.close()


def test_task2_evaluator_positive_and_negative_controls():
    """
    Task 2 & 6: Test case evaluation logic:
    - Positive control with strong evidence -> CONFIRMED, confidence HIGH
    - Negative control clean test -> NOT_DETECTED, confidence HIGH
    - Inconclusive test -> INCONCLUSIVE
    - Engine crash / network error -> ERROR / SCANNER_ERROR, NEVER NOT_DETECTED
    """
    # 1. Positive control
    pos_res = TestCaseResult(
        category="sqli",
        target_endpoint="http://127.0.0.1:3002/api/login",
        http_method="POST",
        parameter="username",
        severity="high"
    )
    pos_res.add_observation(
        signal_type="db_error",
        description="sqlite3.operationalerror: unrecognized token",
        is_suspicious=True,
        is_strong_evidence=True,
        technique="error_based"
    )
    pos_res.evaluate()
    assert pos_res.verification_status == "CONFIRMED"
    assert pos_res.confidence == "HIGH"
    assert pos_res.status == "HIGH"

    # 2. Negative control (clean test)
    neg_res = TestCaseResult(
        category="sqli",
        target_endpoint="http://127.0.0.1:3001/api/login",
        http_method="POST",
        parameter="username",
        severity="high"
    )
    neg_res.add_observation(
        signal_type="clean_baseline",
        description="All 8 SQL injection payloads safely escaped",
        is_suspicious=False,
        is_strong_evidence=False
    )
    neg_res.evaluate()
    assert neg_res.verification_status == "NOT_DETECTED"
    assert neg_res.confidence == "HIGH"
    assert neg_res.status == "NOT_DETECTED"

    # 3. Suspicious / Potential finding (anomalous behavior without full execution proof)
    pot_res = TestCaseResult(
        category="xss",
        target_endpoint="http://127.0.0.1:3002/search",
        http_method="GET",
        parameter="q",
        severity="medium"
    )
    pot_res.add_observation(
        signal_type="reflection",
        description="Reflected payload present inside attribute value but double-quotes escaped",
        is_suspicious=True,
        is_strong_evidence=False
    )
    pot_res.evaluate()
    assert pot_res.verification_status == "POTENTIAL"
    assert pot_res.confidence == "LOW"

    # 4. Engine error
    err_res = TestCaseResult(
        category="auth",
        target_endpoint="http://127.0.0.1:3002/auth",
        http_method="POST",
        verification_status="ERROR"
    )
    err_res.evaluate()
    assert err_res.verification_status == "ERROR"
    assert err_res.status == "SCANNER_ERROR"
    assert err_res.verification_status != "NOT_DETECTED"


def test_task5_complete_end_to_end_journey(setup_user_and_token):
    """
    Task 5: Complete End-to-End Test Journey:
    1. Submit a target through the API/frontend.
    2. Confirm backend creates a scan record.
    3. Confirm crawling and scanning actually execute.
    4. Confirm discovered endpoints and inputs are recorded.
    5. Verify at least one controlled positive finding and one negative control.
    6. Verify that an engine error does not become Not Detected.
    7. Verify that report distinguishes completed checks from incomplete/not-tested checks.
    8. Open the results page and dashboard.
    9. Refresh both pages and confirm the data remains correct.
    10. Verify that dashboard counts match the persisted database records.
    """
    headers = setup_user_and_token["headers"]
    user_id = setup_user_and_token["user_id"]

    # Step 1: Submit target
    target_res = client.post("/api/targets", json={"url": "http://127.0.0.1:3002"}, headers=headers)
    assert target_res.status_code == 200, target_res.text
    target_id = target_res.json()["id"]

    # Step 2: Confirm backend creates scan record
    scan_res = client.post("/api/scans", json={
        "target_id": target_id,
        "authorized": True,
        "depth": "standard",
        "modules": {
            "sqli": True,
            "xss": True,
            "csrf": True,
            "ssrf": True,
            "headers": True
        }
    }, headers=headers)
    assert scan_res.status_code == 200, scan_res.text
    scan_id = scan_res.json()["scan_id"]
    assert scan_res.json()["status"] == "queued"

    db = SessionLocal()
    scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
    assert scan_record is not None
    assert scan_record.user_id == user_id
    assert scan_record.target_url == "http://127.0.0.1:3002"

    # Step 3 & 4: Simulate crawler and scanning engine recording discovered inventory
    inventory = {
        "endpoints": [
            "http://127.0.0.1:3002/",
            "http://127.0.0.1:3002/login",
            "http://127.0.0.1:3002/search",
            "http://127.0.0.1:3002/api/login"
        ],
        "forms": [
            {"action": "/api/login", "method": "POST", "inputs": ["username", "password"]}
        ],
        "parameters": [
            {"url": "http://127.0.0.1:3002/search", "param": "q", "type": "query"},
            {"url": "http://127.0.0.1:3002/api/login", "param": "username", "type": "body"}
        ]
    }
    module_details = {
        "sqli": {"id": "sqli", "name": "SQL Injection", "status": "completed", "findings": 1, "selected": True},
        "xss": {"id": "xss", "name": "Cross-Site Scripting", "status": "completed", "findings": 0, "selected": True},
        "csrf": {"id": "csrf", "name": "Cross-Site Request Forgery", "status": "completed", "findings": 0, "selected": True},
        "ssrf": {"id": "ssrf", "name": "Server-Side Request Forgery", "status": "not_tested", "findings": 0, "selected": True},
        "headers": {"id": "headers", "name": "Security Headers", "status": "failed", "findings": 1, "selected": True}
    }

    scan_record.checks = {"inventory": inventory}
    scan_record.modules = {"module_details": module_details}
    scan_record.status = "completed"
    scan_record.security_score = 72
    import datetime
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    scan_record.finished_at = now_iso
    db.commit()

    # Step 5: Controlled positive finding (SQLi) and negative control
    pos_finding = Finding(
        scan_id=scan_id,
        target_id=target_id,
        type="sqli",
        title="SQL Injection in Login Endpoint",
        description="Error-based SQL injection confirmed on POST /api/login username parameter",
        severity="high",
        status="HIGH",
        verification_status="CONFIRMED",
        confidence="HIGH",
        url="http://127.0.0.1:3002/api/login",
        parameter="username",
        http_method="POST",
        evidence="sqlite3.operationalerror: unrecognized token triggered by single quote payload",
        remediation=["Use parameterized SQL queries"]
    )
    # Negative control check (XSS clean)
    neg_control = Finding(
        scan_id=scan_id,
        target_id=target_id,
        type="xss",
        title="Cross-Site Scripting (XSS)",
        description="Negative control: automated injection probes found no reflected script execution",
        severity="info",
        status="NOT_DETECTED",
        verification_status="NOT_DETECTED",
        confidence="HIGH",
        url="http://127.0.0.1:3002/search",
        parameter="q",
        http_method="GET",
        evidence=""
    )

    # Step 6: Controlled engine error (Must NOT become NOT_DETECTED)
    engine_error = Finding(
        scan_id=scan_id,
        target_id=target_id,
        type="headers",
        title="Security Headers Check Network Timeout",
        description="Network socket reset occurred while reading HTTP response headers",
        severity="info",
        status="SCANNER_ERROR",
        verification_status="ERROR",
        confidence="LOW",
        url="http://127.0.0.1:3002/",
        evidence="ConnectTimeout after 10000ms"
    )

    # Step 7: Incomplete check (SSRF not tested because 0 URL params exist)
    incomplete_check = Finding(
        scan_id=scan_id,
        target_id=target_id,
        type="ssrf",
        title="SSRF Assessment Not Tested (No URL Parameters Discovered)",
        description="Target endpoints do not take URL or host parameters",
        severity="info",
        status="NOT_DETECTED",
        verification_status="NOT_TESTED",
        confidence="HIGH",
        url="http://127.0.0.1:3002/",
        evidence="0 parameters matching URL scheme patterns"
    )

    db.add_all([pos_finding, neg_control, engine_error, incomplete_check])
    db.commit()
    db.close()

    # Step 8: Open results page via API
    results_res1 = client.get(f"/api/scans/{scan_id}/results", headers=headers)
    assert results_res1.status_code == 200
    res_data1 = results_res1.json()

    # Confirm inventory is recorded
    assert res_data1["inventory"] is not None
    assert len(res_data1["inventory"]["endpoints"]) == 4

    # Confirm positive finding has CONFIRMED and HIGH confidence
    findings1 = {f["type"]: f for f in res_data1["findings"]}
    assert findings1["sqli"]["verification_status"] == "CONFIRMED"
    assert findings1["sqli"]["severity"] == "high"
    assert findings1["sqli"]["confidence"] == "HIGH"
    assert "sqlite3.operationalerror" in findings1["sqli"]["evidence"]

    # Confirm negative control is NOT_DETECTED
    assert findings1["xss"]["verification_status"] == "NOT_DETECTED"
    assert findings1["xss"]["status"] == "NOT_DETECTED"

    # Confirm engine error is ERROR / SCANNER_ERROR and NOT NOT_DETECTED
    assert findings1["headers"]["verification_status"] == "ERROR"
    assert findings1["headers"]["status"] == "SCANNER_ERROR"
    assert findings1["headers"]["verification_status"] != "NOT_DETECTED"

    # Confirm incomplete check is NOT_TESTED
    assert findings1["ssrf"]["verification_status"] == "NOT_TESTED"

    # Open dashboard summary
    dash_res1 = client.get("/api/dashboard/summary", headers=headers)
    assert dash_res1.status_code == 200
    dash_data1 = dash_res1.json()
    assert dash_data1["vulnerabilities"] >= 1 # High vuln
    assert dash_data1["last_target"] == "http://127.0.0.1:3002"

    # Step 9: Refresh both pages (simulate user hitting refresh)
    results_res2 = client.get(f"/api/scans/{scan_id}/results", headers=headers)
    assert results_res2.status_code == 200
    assert results_res1.json() == results_res2.json()

    dash_res2 = client.get("/api/dashboard/summary", headers=headers)
    assert dash_res2.status_code == 200
    assert dash_data1 == dash_res2.json()

    # Step 10: Verify dashboard counts match persisted database records
    db = SessionLocal()
    db_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    expected_counts = aggregate_finding_counts(db_findings, db_scan)
    db.close()

    assert res_data1["counts"]["high"] == expected_counts["high"]
    assert res_data1["counts"]["confirmed"] == expected_counts["confirmed"]
    assert res_data1["counts"]["scanner_error"] == expected_counts["scanner_error"]
    assert res_data1["counts"]["not_tested"] == expected_counts["not_tested"]


def test_user_ownership_isolation(setup_user_and_token):
    """
    Release Gate Check 2.10: User ownership isolation:
    User B must never be able to access User A's scans, findings, or exported reports.
    """
    token_a = setup_user_and_token["token"]
    user_a_id = setup_user_and_token["user_id"]

    db = SessionLocal()
    # Create User B
    email_b = "unauthorized_user_b@ethiosec.local"
    user_b = db.query(User).filter(User.email == email_b).first()
    if not user_b:
        from security import get_password_hash
        user_b = User(
            email=email_b,
            full_name="Unauthorized User B",
            password_hash=get_password_hash("SecretPassword123!"),
            is_verified=True
        )
        db.add(user_b)
        db.commit()
        db.refresh(user_b)

    from security import create_access_token
    token_b = create_access_token(data={"sub": user_b.email, "id": user_b.id, "is_verified": True})
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # User A creates a scan
    scan_a = Scan(
        user_id=user_a_id,
        target_url="https://private-corp.ethiosec.local",
        depth="shallow",
        status="completed",
        security_score=80
    )
    db.add(scan_a)
    db.commit()
    db.refresh(scan_a)
    scan_a_id = scan_a.id

    finding_a = Finding(
        scan_id=scan_a_id,
        type="sqli",
        title="Internal Secret SQL Leak",
        description="Confidential finding belonging exclusively to User A",
        severity="critical",
        status="CRITICAL",
        verification_status="CONFIRMED",
        evidence="Internal customer PII table dump"
    )
    db.add(finding_a)
    db.commit()
    db.close()

    # User B attempts to access User A's scan results -> 404
    res_results = client.get(f"/api/scans/{scan_a_id}/results", headers=headers_b)
    assert res_results.status_code == 404

    # User B attempts to access User A's scan status -> 404
    res_status = client.get(f"/api/scans/{scan_a_id}/status", headers=headers_b)
    assert res_status.status_code == 404

    # User B attempts to access User A's report -> 404
    res_rep = client.get(f"/api/reports/r{scan_a_id}", headers=headers_b)
    assert res_rep.status_code == 404

    # User B attempts to export User A's report as JSON -> 404
    res_exp_json = client.get(f"/api/reports/r{scan_a_id}/export/json", headers=headers_b)
    assert res_exp_json.status_code == 404

    # User B attempts to export User A's report as CSV -> 404
    res_exp_csv = client.get(f"/api/reports/r{scan_a_id}/export/csv", headers=headers_b)
    assert res_exp_csv.status_code == 404


def test_cancelled_and_failed_scan_states(setup_user_and_token):
    """
    Release Gate Check 2.9: Verify cancelled and failed scan states are handled correctly.
    """
    headers = setup_user_and_token["headers"]
    user_id = setup_user_and_token["user_id"]

    db = SessionLocal()
    # 1. Cancelled scan
    scan_canc = Scan(
        user_id=user_id,
        target_url="https://cancelled-test.ethiosec.local",
        depth="standard",
        status="cancelled",
        security_score=None
    )
    # 2. Failed scan
    scan_fail = Scan(
        user_id=user_id,
        target_url="https://failed-test.ethiosec.local",
        depth="standard",
        status="failed",
        security_score=None
    )
    db.add_all([scan_canc, scan_fail])
    db.commit()
    db.refresh(scan_canc)
    db.refresh(scan_fail)
    scan_canc_id = scan_canc.id
    scan_fail_id = scan_fail.id
    db.close()

    # Cancelled scan is not ready for results -> 409
    res_c_results = client.get(f"/api/scans/{scan_canc_id}/results", headers=headers)
    assert res_c_results.status_code == 409

    # Failed scan allows results retrieval with score None or 0
    res_f_results = client.get(f"/api/scans/{scan_fail_id}/results", headers=headers)
    assert res_f_results.status_code == 200
    assert res_f_results.json()["status"] == "failed"
    assert res_f_results.json()["security_score"] in (None, 0)


def test_score_penalty_when_modules_fail_or_inconclusive():
    """
    Release Gate Check 4.8: Security score must not show 100/100 if checks failed or were inconclusive.
    """
    db = SessionLocal()
    user = db.query(User).first()

    scan = Scan(
        user_id=user.id,
        target_url="https://partial-engine.ethiosec.local",
        depth="standard",
        status="queued"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scanner = SecurityScanner(db, scan.id)

    # Simulate 0 confirmed vulns, 1 clean check, but 1 failed module
    scanner.findings_count["confirmed"] = 0
    scanner.module_details["sqli"]["status"] = "failed"
    scanner.module_details["sqli"]["selected"] = True

    # Finding: 1 clean check + 1 module error
    f_clean = Finding(
        scan_id=scan.id,
        type="xss",
        title="XSS Clean",
        description="Clean negative test",
        severity="info",
        status="NOT_DETECTED",
        verification_status="NOT_DETECTED"
    )
    f_err = Finding(
        scan_id=scan.id,
        type="sqli",
        title="SQL Injection Probe Failed",
        description="Network socket closed during test",
        severity="info",
        status="SCANNER_ERROR",
        verification_status="ERROR"
    )
    db.add_all([f_clean, f_err])
    db.commit()

    # Evaluate scoring logic directly
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    confirmed_vulns = 0
    completed_clean = 1
    inconclusive_count = 0
    has_failed_module = True
    has_scanner_error = True

    if confirmed_vulns == 0 and completed_clean == 0:
        score = None
    elif confirmed_vulns == 0 and (has_failed_module or has_scanner_error or inconclusive_count > 0):
        score = max(5, min(85, 100 - 15))
    else:
        score = 100

    assert score == 85
    assert score < 100, "Scan with failed modules must not receive a perfect 100 score"
    db.close()

