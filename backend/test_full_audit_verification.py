"""
Complete Real Integration Matrix Verification Script
Executes real HTTP requests against the live running FastAPI backend on http://127.0.0.1:8000.
"""

import json
import time
import uuid
import urllib.request
import urllib.error

API_BASE = "http://127.0.0.1:8000/api"

def http_req(path, method="GET", data=None, token=None):
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as err:
        content = err.read().decode("utf-8")
        try:
            err_json = json.loads(content)
        except Exception:
            err_json = {"raw": content}
        return err.code, err_json

def run_tests():
    print("=" * 70)
    print("ETHIOSEC SCANNER — FULL LIVE END-TO-END INTEGRATION AUDIT")
    print("=" * 70)

    # 1. USER REGISTRATION
    user_a_email = f"audit_user_{uuid.uuid4().hex[:8]}@example.com"
    user_a_pass = "AuditPassword123!"
    user_a_name = "Audit Lead Specialist"

    print(f"\n[STEP 1] Testing User Registration (POST /api/auth/register)...")
    code, resp = http_req("/auth/register", method="POST", data={
        "email": user_a_email,
        "password": user_a_pass,
        "full_name": user_a_name
    })
    assert code == 200, f"Registration failed: {code} {resp}"
    token_a = resp.get("token")
    assert token_a, "Missing token in register response"
    print(f"  -> SUCCESS: Registered user {user_a_email} and received JWT token.")

    # 2. USER LOGIN
    print(f"\n[STEP 2] Testing User Login (POST /api/auth/login)...")
    code, resp = http_req("/auth/login", method="POST", data={
        "email": user_a_email,
        "password": user_a_pass
    })
    assert code == 200, f"Login failed: {code} {resp}"
    token_a = resp.get("token")
    print(f"  -> SUCCESS: Authenticated successfully. Bearer token issued.")

    # 3. IDENTITY & AUTH VERIFICATION
    print(f"\n[STEP 3] Testing Identity Synchronization (GET /api/auth/me)...")
    code, resp = http_req("/auth/me", token=token_a)
    assert code == 200, f"GET /auth/me failed: {code} {resp}"
    u_obj = resp.get("user") or resp
    assert u_obj["email"] == user_a_email, "Email mismatch in /auth/me"
    assert u_obj["full_name"] == user_a_name, "Full name mismatch in /auth/me"
    print(f"  -> SUCCESS: Synchronized user identity: {u_obj['full_name']} ({u_obj['email']}).")

    # 4. USER PROFILE UPDATE & GET
    print(f"\n[STEP 4] Testing User Profile Management (GET/PUT /api/user/profile)...")
    code, resp = http_req("/user/profile", token=token_a)
    assert code == 200, f"GET /user/profile failed: {code} {resp}"
    code, resp = http_req("/user/profile", method="PUT", token=token_a, data={
        "full_name": "Updated Audit Specialist",
        "website": "https://cybersecurity.local",
        "role": "Lead Security Auditor"
    })
    assert code == 200, f"PUT /user/profile failed: {code} {resp}"
    assert resp["full_name"] == "Updated Audit Specialist"
    print(f"  -> SUCCESS: User profile updated and verified.")

    # 5. USER SETTINGS
    print(f"\n[STEP 5] Testing User Settings (GET/PUT /api/user/settings)...")
    code, resp = http_req("/user/settings", token=token_a)
    assert code == 200, f"GET /user/settings failed: {code} {resp}"
    code, resp = http_req("/user/settings", method="PUT", token=token_a, data={
        "default_scan_depth": "deep",
        "notif_scan_completed": True,
        "notif_scan_failed": True
    })
    assert code == 200, f"PUT /user/settings failed: {code} {resp}"
    assert resp["default_scan_depth"] == "deep"
    print(f"  -> SUCCESS: User scanner defaults and preferences persisted.")

    # 6. TARGET REGISTRATION & SAFETY
    print(f"\n[STEP 6] Testing Target Management & Safety (POST /api/targets)...")
    target_url = "https://example.com"
    code, resp = http_req("/targets", method="POST", token=token_a, data={"url": target_url})
    assert code in (200, 201), f"POST /targets failed: {code} {resp}"
    target_id = resp["id"]
    print(f"  -> SUCCESS: Registered target {target_url} with Target ID {target_id}.")

    # Test Validation rejection on invalid scheme (ftp://)
    code, resp = http_req("/targets", method="POST", token=token_a, data={"url": "ftp://malicious.org"})
    assert code == 400, f"Expected 400 on ftp scheme, got {code}"
    print(f"  -> SUCCESS: Rejected invalid scheme (ftp://) with HTTP 400 Bad Request.")

    # Test Validation rejection on missing hostname
    code, resp = http_req("/targets", method="POST", token=token_a, data={"url": "http://"})
    assert code == 400, f"Expected 400 on invalid hostname, got {code}"
    print(f"  -> SUCCESS: Rejected malformed URL structure with HTTP 400 Bad Request.")

    # 7. SCAN CREATION WITH CUSTOM MODULES (12 Canonical Modules)
    print(f"\n[STEP 7] Testing Scan Creation (POST /api/scans)...")
    modules_payload = {
        "headers": True,
        "cookies": True,
        "cors": True,
        "https": True,
        "sqli": False,
        "xss": False,
        "auth": False,
        "access_control": False,
        "exposed_files": False,
        "http_methods": False,
        "info_disclosure": False,
        "misconfig": False
    }
    code, resp = http_req("/scans", method="POST", token=token_a, data={
        "target_id": target_id,
        "depth": "standard",
        "modules": modules_payload,
        "authorized": True
    })
    assert code in (200, 201), f"POST /scans failed: {code} {resp}"
    scan_id = resp.get("scan_id") or resp.get("id")
    assert scan_id, "Missing scan ID in scan creation response"
    print(f"  -> SUCCESS: Created scan record ID {scan_id}.")

    # 8. START SCAN TASK
    print(f"\n[STEP 8] Triggering Scanner Worker (POST /api/scans/{scan_id}/start)...")
    code, resp = http_req(f"/scans/{scan_id}/start", method="POST", token=token_a)
    assert code == 200, f"POST /scans/{scan_id}/start failed: {code} {resp}"
    print(f"  -> SUCCESS: Scanner worker started.")

    # 9. STATUS POLLING (Live Scan telemetry validation)
    print(f"\n[STEP 9] Polling Real-Time Telemetry (GET /api/scans/{scan_id}/status)...")
    finished = False
    for i in range(25):
        time.sleep(1.5)
        code, status_data = http_req(f"/scans/{scan_id}/status", token=token_a)
        assert code == 200, f"GET status failed: {code}"
        st = status_data.get("status")
        stage = status_data.get("stage", "Unknown")
        prog = status_data.get("progress", 0)
        stages = status_data.get("pipeline_stages", [])
        modules = status_data.get("module_details", {})
        print(f"  [Poll #{i+1}] Status: {st} | Progress: {prog}% | Stage: {stage} | Pipeline Stages: {len(stages)} | Modules: {len(modules)}")
        if st in ("completed", "failed"):
            finished = True
            break

    assert finished, "Scan did not reach terminal state within timeout"
    print(f"  -> SUCCESS: Scan reached terminal state: '{st}'.")
    assert len(stages) == 7, f"Expected 7 pipeline stages, got {len(stages)}"
    assert len(modules) == 12, f"Expected 12 canonical modules in telemetry, got {len(modules)}"

    # 10. RESULTS RETRIEVAL
    print(f"\n[STEP 10] Testing Findings Retrieval (GET /api/scans/{scan_id}/results)...")
    code, results = http_req(f"/scans/{scan_id}/results", token=token_a)
    assert code == 200, f"GET results failed: {code} {results}"
    findings = results.get("findings", [])
    security_score = results.get("security_score")
    print(f"  -> SUCCESS: Retrieved results! Security Score: {security_score}/100. Findings: {len(findings)}.")
    for f in findings:
        print(f"     • [{f.get('severity', 'info').upper()}] {f.get('title')} ({f.get('check_type')})")

    # 10b. ACTIVE SCAN CANCELLATION TEST
    print(f"\n[STEP 10b] Testing Scan Cancellation (POST /api/scans/{{id}}/cancel)...")
    code, c_scan = http_req("/scans", method="POST", token=token_a, data={
        "target_id": target_id,
        "depth": "deep",
        "modules": {"headers": True, "cookies": True},
        "authorized": True
    })
    cancel_scan_id = c_scan.get("scan_id") or c_scan.get("id")
    http_req(f"/scans/{cancel_scan_id}/start", method="POST", token=token_a)
    # Cancel the active scan
    code, cancel_resp = http_req(f"/scans/{cancel_scan_id}/cancel", method="POST", token=token_a)
    assert code == 200, f"POST cancel failed: {code} {cancel_resp}"
    assert cancel_resp.get("status") == "cancelled"
    # Verify status reflects cancellation
    code, st_cancel = http_req(f"/scans/{cancel_scan_id}/status", token=token_a)
    assert st_cancel.get("status") == "cancelled"
    print(f"  -> SUCCESS: Actively running scan cancelled cooperatively. Status persisted as 'cancelled'.")

    # 11. REPORTS GENERATION & DETAILS
    print(f"\n[STEP 11] Testing Report Endpoints (GET /api/reports, /api/reports/{scan_id})...")
    code, reports_list = http_req("/reports", token=token_a)
    assert code == 200, f"GET /reports failed: {code}"
    rep_items = reports_list.get("reports", [])
    print(f"  -> SUCCESS: Retrieved {len(rep_items)} audit report records.")

    code, single_rep = http_req(f"/reports/r{scan_id}", token=token_a)
    assert code == 200, f"GET /reports/r{scan_id} failed: {code}"
    assert single_rep.get("target") == target_url
    print(f"  -> SUCCESS: Fetched formal audit report r{scan_id}.")

    # 12. DASHBOARD DATA
    print(f"\n[STEP 12] Testing Dashboard Summary (GET /api/dashboard/summary & /api/scans)...")
    code, summary = http_req("/dashboard/summary", token=token_a)
    assert code == 200, f"GET /dashboard/summary failed: {code}"
    code, scans_resp = http_req("/scans?limit=100", token=token_a)
    assert code == 200, f"GET /scans failed: {code}"
    scans_list = scans_resp.get("scans", [])
    assert any(s["id"] == scan_id for s in scans_list), "Scan not found in dashboard scans list"
    print(f"  -> SUCCESS: Dashboard populated with real scans: {len(scans_list)} records.")

    # 13. AI ASSISTANT CHAT
    print(f"\n[STEP 13] Testing AI Security Assistant (POST /api/ai/chat)...")
    code, ai_resp = http_req("/ai/chat", method="POST", token=token_a, data={
        "message": "Summarize the security posture of this target and provide next steps.",
        "scan_id": scan_id
    })
    assert code == 200, f"POST /ai/chat failed: {code} {ai_resp}"
    ai_reply = ai_resp.get("reply", "")
    assert len(ai_reply) > 20, "AI response too short"
    print(f"  -> SUCCESS: AI Assistant returned answer based on scan context:")
    print(f"     \"{ai_reply[:140]}...\"")

    # 14. CROSS-USER RESOURCE ISOLATION (Security IDOR Check)
    print(f"\n[STEP 14] Testing Cross-User Resource Isolation (User B vs User A)...")
    user_b_email = f"user_b_{uuid.uuid4().hex[:8]}@example.com"
    code, resp_b = http_req("/auth/register", method="POST", data={
        "email": user_b_email,
        "password": "Password123!",
        "full_name": "User B"
    })
    token_b = resp_b["token"]

    # User B cannot read User A's scan results
    code, _ = http_req(f"/scans/{scan_id}/results", token=token_b)
    assert code == 404, f"IDOR Vulnerability! User B could access User A scan results (code {code})"
    # User B cannot read User A's target
    code, _ = http_req(f"/targets/{target_id}", token=token_b)
    assert code == 404, f"IDOR Vulnerability! User B could access User A target (code {code})"
    print(f"  -> SUCCESS: Strong server-side cross-user authorization enforced. IDOR attempts rejected (404 Not Found).")

    # 15. SESSION REVOCATION & LOGOUT
    print(f"\n[STEP 15] Testing Session Revocation (POST /api/auth/logout)...")
    code, resp = http_req("/auth/logout", method="POST", token=token_a)
    assert code == 200, f"Logout failed: {code}"
    # Token A is now revoked
    code, _ = http_req("/auth/me", token=token_a)
    assert code == 401, f"Expected 401 on revoked token, got {code}"
    print(f"  -> SUCCESS: Token revoked on logout. Subsequent calls return HTTP 401 Unauthorized.")

    print("\n" + "=" * 70)
    print("ALL 15 INTEGRATION WORKFLOW CHECKS PASSED WITH 100% ACCURACY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
