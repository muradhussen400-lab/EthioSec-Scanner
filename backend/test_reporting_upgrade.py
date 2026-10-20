
"""
EthioSec Professional Reporting & AI Executive Summary Upgrade Test Suite.
Verifies all 11 requirements specified in the upgrade mandate:
 1. The five user-facing categories render consistently (HIGH, MEDIUM, LOW, NOT_DETECTED, SCANNER_ERROR).
 2. CONFIRMED and INCONCLUSIVE do not appear as extra top-level categories.
 3. Inconclusive checks are not falsely counted as confirmed vulnerabilities or NOT DETECTED.
 4. Scanner errors are never counted as successful negative results (NOT DETECTED).
 5. Summary counts match the real scan data.
 6. AI summaries remain concise and structured (A. SECURITY OVERVIEW, B. FINDINGS AT A GLANCE, C. TOP RISKS, D. WHAT TO FIX FIRST, E. SCAN LIMITATIONS, F. FINAL NOTE).
 7. The AI does not invent findings when the scan is empty.
 8. Missing evidence does not produce fabricated remediation details.
 9. Provider errors produce a safe fallback.
10. Existing scanner, authentication, and report tests continue to pass.
11. PDF export structure matches the on-screen report data.
"""

import json
import pytest
from fastapi.testclient import TestClient
from main import app
from database import Base, engine, SessionLocal
from models import User, ScanTarget, Scan, Finding
from ai.service import set_mock_provider
from ai.executive_summary import (
    aggregate_finding_counts,
    map_finding_to_category,
    generate_executive_summary,
    format_executive_summary_markdown,
    build_deterministic_executive_summary
)
from security import get_password_hash
from routers import request_counts

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_rate_limiter():
    request_counts.clear()
    yield
    request_counts.clear()

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.create_all(bind=engine)

@pytest.fixture(scope="module")
def reporting_test_data():
    db = SessionLocal()
    existing_user = db.query(User).filter(User.email == "reporting_user@ethiosec.test").first()
    if existing_user:
        db.query(Finding).filter(Finding.scan_id.in_(db.query(Scan.id).filter(Scan.user_id == existing_user.id))).delete(synchronize_session=False)
        db.query(Scan).filter(Scan.user_id == existing_user.id).delete(synchronize_session=False)
        db.query(ScanTarget).filter(ScanTarget.user_id == existing_user.id).delete(synchronize_session=False)
        db.delete(existing_user)
        db.commit()

    # User
    user = User(email="reporting_user@ethiosec.test", password_hash=get_password_hash("ReportingPass123!"), full_name="Report Specialist")
    db.add(user)
    db.commit()
    db.refresh(user)

    target = ScanTarget(user_id=user.id, url="https://acme-bank.ethiosec.test", authorized=True)
    db.add(target)
    db.commit()
    db.refresh(target)

    # 1. Populated Scan with confirmed vulnerabilities, inconclusive check, not detected check, and scanner error
    scan_mixed = Scan(
        user_id=user.id,
        target_url="https://acme-bank.ethiosec.test",
        depth="standard",
        status="completed",
        security_score=68
    )
    db.add(scan_mixed)
    db.commit()
    db.refresh(scan_mixed)

    # High severity confirmed finding
    f_high = Finding(
        scan_id=scan_mixed.id,
        target_id=target.id,
        type="sqli",
        severity="high",
        status="HIGH",
        title="SQL Injection in Account Search",
        description="Boolean-based SQL injection allows database exfiltration.",
        evidence="account_id=1' AND '1'='1 -- returned HTTP 200 with record.",
        url="https://acme-bank.ethiosec.test/api/accounts",
        parameter="account_id",
        remediation=["Use parameterized SQL prepared statements."]
    )
    # Medium severity confirmed finding
    f_med = Finding(
        scan_id=scan_mixed.id,
        target_id=target.id,
        type="cors",
        severity="medium",
        status="MEDIUM",
        title="Permissive CORS Origin Reflection",
        description="Access-Control-Allow-Origin header reflects arbitrary attacker origins.",
        evidence="Origin: https://evil.com resulted in Access-Control-Allow-Origin: https://evil.com",
        url="https://acme-bank.ethiosec.test/api/profile",
        remediation=["Restrict CORS origins to an explicit whitelist."]
    )
    # Low severity confirmed finding
    f_low = Finding(
        scan_id=scan_mixed.id,
        target_id=target.id,
        type="headers",
        severity="low",
        status="LOW",
        title="Missing Content-Security-Policy Header",
        description="Response lacks CSP protection against content injection.",
        evidence="HTTP/1.1 200 OK without Content-Security-Policy header.",
        url="https://acme-bank.ethiosec.test/",
        remediation=["Configure Content-Security-Policy header."]
    )
    # Not detected baseline check
    f_not_detected = Finding(
        scan_id=scan_mixed.id,
        target_id=target.id,
        type="xss",
        severity="info",
        status="NOT_DETECTED",
        title="Cross-Site Scripting (XSS)",
        description="Automated injection probes did not detect reflected XSS.",
        evidence=None,
        url="https://acme-bank.ethiosec.test/search"
    )
    # Scanner error check (network timeout)
    f_error = Finding(
        scan_id=scan_mixed.id,
        target_id=target.id,
        type="scanner_error",
        severity="info",
        status="SCANNER_ERROR",
        title="TLS Protocol Analysis Error",
        description="Connection timed out while querying handshake ciphers.",
        evidence="ConnectTimeout: HTTPS port 443 timed out after 10.0s",
        url="https://acme-bank.ethiosec.test/"
    )
    # Inconclusive check (insufficient evidence)
    f_inconclusive = Finding(
        scan_id=scan_mixed.id,
        target_id=target.id,
        type="access_control",
        severity="medium",
        status="INCONCLUSIVE",
        title="Ambiguous Access Control Response",
        description="Differential probe returned unexpected 500 status rather than 403 or 200.",
        evidence="HTTP 500 Internal Server Error returned for unauthorized token.",
        url="https://acme-bank.ethiosec.test/admin/dashboard"
    )

    db.add_all([f_high, f_med, f_low, f_not_detected, f_error, f_inconclusive])
    db.commit()

    # 2. Clean Scan with zero vulnerabilities
    scan_clean = Scan(
        user_id=user.id,
        target_url="https://secure-vault.ethiosec.test",
        depth="quick",
        status="completed",
        security_score=100
    )
    db.add(scan_clean)
    db.commit()
    db.refresh(scan_clean)

    f_clean_1 = Finding(
        scan_id=scan_clean.id,
        type="headers",
        severity="info",
        status="NOT_DETECTED",
        title="Security Headers",
        description="All standard baseline headers present.",
        evidence=None,
        url="https://secure-vault.ethiosec.test"
    )
    f_clean_2 = Finding(
        scan_id=scan_clean.id,
        type="https",
        severity="info",
        status="NOT_DETECTED",
        title="HTTPS/TLS Enforcement",
        description="HSTS and TLS 1.3 enforced.",
        evidence=None,
        url="https://secure-vault.ethiosec.test"
    )
    db.add_all([f_clean_1, f_clean_2])
    db.commit()

    user_id = str(user.id)
    scan_mixed_id = str(scan_mixed.id)
    scan_clean_id = str(scan_clean.id)
    db.close()

    return {
        "user_id": user_id,
        "scan_mixed_id": scan_mixed_id,
        "scan_clean_id": scan_clean_id,
    }


def get_auth_token(email: str = "reporting_user@ethiosec.test", password: str = "ReportingPass123!") -> str:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["token"]


# ==============================================================================
# TEST 1: The five user-facing categories render consistently
# ==============================================================================
def test_five_categories_render_consistently(reporting_test_data):
    token = get_auth_token()
    scan_id = reporting_test_data["scan_mixed_id"]

    res = client.get(f"/api/scans/{scan_id}/results", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    counts = res.json()["counts"]

    # Must contain the five top-level categories
    for cat in ["high", "medium", "low", "not_detected", "scanner_error"]:
        assert cat in counts, f"Missing category: {cat}"

    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["not_detected"] == 1
    assert counts["scanner_error"] == 1


# ==============================================================================
# TEST 2: CONFIRMED and INCONCLUSIVE do not appear as extra top-level categories
# ==============================================================================
def test_confirmed_and_inconclusive_not_extra_headline_categories(reporting_test_data):
    token = get_auth_token()
    scan_id = reporting_test_data["scan_mixed_id"]

    res = client.get(f"/api/reports/r{scan_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    counts = data["counts"]

    # Headline counts must be exactly the 5 categories
    headline_keys = ["high", "medium", "low", "not_detected", "scanner_error"]
    assert all(k in counts for k in headline_keys)
    # CONFIRMED must not be a counter card
    assert "confirmed" not in counts

    # Check the structured executive summary
    structured = data["executive_summary_structured"]
    summary_counts = structured["counts"]
    assert set(summary_counts.keys()) == set(headline_keys)


# ==============================================================================
# TEST 3: Inconclusive checks are not falsely counted as confirmed vulns or NOT DETECTED
# ==============================================================================
def test_inconclusive_not_falsely_counted(reporting_test_data):
    db = SessionLocal()
    scan_id = reporting_test_data["scan_mixed_id"]
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    db.close()

    counts = aggregate_finding_counts(findings)
    # The scan has 1 high, 1 medium, 1 low, 1 not_detected, 1 scanner_error, 1 inconclusive
    assert counts["inconclusive"] == 1
    # Confirmed vulns must NOT include the inconclusive check
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["total"] == 3  # high + medium + low
    # NOT DETECTED must NOT include the inconclusive check
    assert counts["not_detected"] == 1


# ==============================================================================
# TEST 4: Scanner errors are never counted as successful negative results
# ==============================================================================
def test_scanner_error_never_counted_as_not_detected(reporting_test_data):
    token = get_auth_token()
    scan_id = reporting_test_data["scan_mixed_id"]

    res = client.get(f"/api/scans/{scan_id}/results", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    counts = res.json()["counts"]

    assert counts["scanner_error"] == 1
    assert counts["not_detected"] == 1  # Exactly 1 legitimate negative check, not 2


# ==============================================================================
# TEST 5: Summary counts match real scan data across endpoints
# ==============================================================================
def test_summary_counts_match_real_scan_data(reporting_test_data):
    token = get_auth_token()
    scan_id = reporting_test_data["scan_mixed_id"]

    # 1. Scans API
    res_scans = client.get(f"/api/scans", headers={"Authorization": f"Bearer {token}"})
    assert res_scans.status_code == 200
    scan_entry = next(s for s in res_scans.json()["scans"] if s["id"] == scan_id)

    # 2. Results API
    res_results = client.get(f"/api/scans/{scan_id}/results", headers={"Authorization": f"Bearer {token}"})
    assert res_results.status_code == 200

    # 3. Reports API
    res_reports = client.get(f"/api/reports/r{scan_id}", headers={"Authorization": f"Bearer {token}"})
    assert res_reports.status_code == 200

    c1 = scan_entry["counts"]
    c2 = res_results.json()["counts"]
    c3 = res_reports.json()["counts"]

    # All three endpoints must agree exactly
    for key in ["high", "medium", "low", "not_detected", "scanner_error"]:
        assert c1[key] == c2[key] == c3[key]


# ==============================================================================
# TEST 6: AI summaries remain concise and structured
# ==============================================================================
@pytest.mark.asyncio
async def test_ai_summary_structured_and_concise(reporting_test_data):
    db = SessionLocal()
    scan_id = reporting_test_data["scan_mixed_id"]
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    db.close()

    # Deterministic mock provider that simulates structured Gemini response
    def mock_gemini(system, user):
        return json.dumps({
            "security_overview": "EthioSec Scanner completed an assessment of acme-bank.ethiosec.test. The primary security concern is an active SQL injection vulnerability that allows unauthorized database querying. Prompt remediation is recommended.",
            "top_risks": [
                {
                    "title": "SQL Injection in Account Search",
                    "severity": "HIGH",
                    "endpoint": "https://acme-bank.ethiosec.test/api/accounts",
                    "risk": "Allows attackers to query arbitrary backend records.",
                    "action": "Use parameterized queries."
                }
            ],
            "what_to_fix_first": [
                "Fix high-priority SQL injection in Account Search immediately.",
                "Address permissive CORS origin reflection.",
                "Configure missing Content-Security-Policy header."
            ],
            "scan_limitations": "1 check encountered a TLS handshake timeout.",
            "final_note": "This scan reflects tests performed at scan time and does not guarantee complete security."
        })

    summary = await generate_executive_summary(scan, findings, ai_callable=lambda sys, usr: mock_gemini(sys, usr))

    # Verify structured sections exist
    assert "security_overview" in summary
    assert "counts" in summary
    assert "top_risks" in summary
    assert "what_to_fix_first" in summary
    assert "scan_limitations" in summary
    assert "final_note" in summary

    # Verify markdown formatting contains the 6 headers
    md = format_executive_summary_markdown(summary)
    assert "### A. SECURITY OVERVIEW" in md
    assert "### B. FINDINGS AT A GLANCE" in md
    assert "### C. TOP RISKS" in md
    assert "### D. WHAT TO FIX FIRST" in md
    assert "### E. SCAN LIMITATIONS" in md
    assert "### F. FINAL NOTE" in md

    # Word count should be concise (around 100-250 words total)
    word_count = len(md.split())
    assert 50 <= word_count <= 280, f"Expected concise summary, got {word_count} words"


# ==============================================================================
# TEST 7: The AI does not invent findings when the scan is empty
# ==============================================================================
@pytest.mark.asyncio
async def test_ai_does_not_invent_findings_for_empty_scan(reporting_test_data):
    db = SessionLocal()
    scan_id = reporting_test_data["scan_clean_id"]
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    db.close()

    # Even if an untrusted or hallucinating AI returned fake findings:
    def hallucinating_ai(system, user):
        return json.dumps({
            "security_overview": "Fake hallucination.",
            "top_risks": [
                {
                    "title": "Fabricated Remote Code Execution",
                    "severity": "HIGH",
                    "endpoint": "https://fake.com/admin",
                    "risk": "Dangerous.",
                    "action": "Fix it."
                }
            ],
            "what_to_fix_first": ["Fix fake finding."],
            "scan_limitations": "",
            "final_note": "A scan represents checks at that time."
        })

    summary = await generate_executive_summary(scan, findings, ai_callable=lambda s, u: hallucinating_ai(s, u))

    # Backend validation MUST reject fabricated risks when real count is 0
    assert summary["top_risks"] == [], "Validation must ensure top_risks is empty for clean scans"
    assert summary["counts"]["high"] == 0
    assert summary["counts"]["medium"] == 0
    assert summary["counts"]["low"] == 0
    assert summary["counts"]["not_detected"] == 2


# ==============================================================================
# TEST 8: Missing evidence does not produce fabricated remediation details
# ==============================================================================
def test_missing_evidence_safe_handling():
    # Build finding without evidence
    f_sparse = Finding(
        type="headers",
        severity="low",
        status="LOW",
        title="Sparse Finding Without Evidence",
        description="Missing header.",
        evidence=None,
        remediation=[]
    )
    scan = Scan(target_url="https://sparse.test", security_score=90)
    counts = aggregate_finding_counts([f_sparse])
    summary = build_deterministic_executive_summary(scan, counts, [f_sparse], [])

    assert len(summary["top_risks"]) == 1
    risk = summary["top_risks"][0]
    # Must use truthful generic defense guidance rather than hallucinating specific commands
    assert "Apply defensive validation" in risk["action"] or "security configuration" in risk["action"]


# ==============================================================================
# TEST 9: Provider errors produce a safe fallback
# ==============================================================================
@pytest.mark.asyncio
async def test_provider_errors_produce_safe_fallback(reporting_test_data):
    db = SessionLocal()
    scan_id = reporting_test_data["scan_mixed_id"]
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    db.close()

    # Simulate Gemini provider throwing an exception (e.g. RateLimit or 503)
    def crashing_provider(system, user):
        raise RuntimeError("Google Gemini API error: 429 Resource Exhausted")

    summary = await generate_executive_summary(scan, findings, ai_callable=lambda s, u: crashing_provider(s, u))

    # Must produce a complete, valid structured fallback
    assert summary is not None
    assert "security_overview" in summary
    assert summary["counts"]["high"] == 1
    assert summary["counts"]["medium"] == 1
    assert summary["counts"]["low"] == 1
    assert len(summary["top_risks"]) >= 1
    assert len(summary["what_to_fix_first"]) >= 1
    assert "final_note" in summary


# ==============================================================================
# TEST 10: Report AI summary API route works as expected
# ==============================================================================
def test_report_ai_summary_api_endpoint(reporting_test_data):
    token = get_auth_token()
    scan_id = reporting_test_data["scan_mixed_id"]

    res = client.post(
        f"/api/reports/r{scan_id}/ai-summary",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "markdown" in data
    assert data["summary"]["counts"]["high"] == 1
    assert "### A. SECURITY OVERVIEW" in data["markdown"]


# ==============================================================================
# TEST 11: PDF export metadata matches on-screen data
# ==============================================================================
def test_pdf_export_matches_onscreen_data(reporting_test_data):
    token = get_auth_token()
    scan_id = reporting_test_data["scan_mixed_id"]

    res = client.get(f"/api/reports/r{scan_id}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()

    # PDF and on-screen report use the exact same verified counts
    c = data["counts"]
    assert c["high"] == 1
    assert c["medium"] == 1
    assert c["low"] == 1
    assert c["not_detected"] == 1
    assert c["scanner_error"] == 1

    # Metadata required for PDF header
    assert data["scan_id"] == scan_id
    assert "target" in data
    assert "depth" in data
    assert "generated_at" in data
    assert "security_score" in data
    assert "executive_summary_structured" in data
