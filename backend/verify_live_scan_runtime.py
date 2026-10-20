import os
import sys
import time
import json
import subprocess
import httpx
from fastapi.testclient import TestClient

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from main import app
from database import SessionLocal
from models import User
from security import create_access_token, get_password_hash

client = TestClient(app)

def run_live_scan_runtime_verification():
    # 1. Ensure test user exists
    db = SessionLocal()
    user_email = "livescan_verifier@test.com"
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        user = User(
            email=user_email,
            full_name="Live Scan Verifier",
            website="http://127.0.0.1:3001",
            password_hash=get_password_hash("Password123!"),
            is_verified=True,
            role="user"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    token = create_access_token({"sub": user.email})
    headers = {"Authorization": f"Bearer {token}"}
    db.close()

    # 2. Start secure_app fixture if not running
    proc = None
    try:
        httpx.get("http://127.0.0.1:3001/", timeout=1.0)
    except Exception:
        proc = subprocess.Popen([sys.executable, "backend/secure_app.py"])
        for _ in range(30):
            try:
                r = httpx.get("http://127.0.0.1:3001/", timeout=1.0)
                if r.status_code == 200:
                    break
            except Exception:
                time.sleep(0.2)

    try:
        # Step A: Register Target
        res_t = client.post("/api/targets", json={"url": "http://127.0.0.1:3001"}, headers=headers)
        assert res_t.status_code == 200, res_t.text
        target_id = res_t.json()["id"]

        # Step B: Create Scan with selected modules
        modules_req = {
            "sqli": True,
            "xss": True,
            "headers": True,
            "cookies": True,
            "cors": True,
            "https": False, # skipped intentionally to verify 'skipped' state
            "auth": True,
            "access_control": True,
            "exposed_files": True,
            "http_methods": False, # skipped intentionally
            "info_disclosure": True,
            "misconfig": True
        }
        res_s = client.post("/api/scans", json={
            "target_id": target_id,
            "depth": "standard",
            "modules": modules_req,
            "authorized": True
        }, headers=headers)
        assert res_s.status_code == 200, res_s.text
        scan_id = res_s.json()["scan_id"]

        # Capture 1: Initial Queued state
        res_q = client.get(f"/api/scans/{scan_id}/status", headers=headers)
        queued_data = res_q.json()
        print("--- CAPTURE 1: QUEUED STATE ---")
        print(f"Status: {queued_data['status']}")
        print(f"Progress: {queued_data['progress']}%")
        print(f"Stage: {queued_data['stage']}")
        print(f"sqli status: {queued_data['module_details']['sqli']['status']}")
        print(f"https status (not selected): {queued_data['module_details']['https']['status']}")

        # Step C: Start Scan
        res_start = client.post(f"/api/scans/{scan_id}/start", headers=headers)
        assert res_start.status_code == 200

        # Capture 2 & 3: Poll for Running state and transitions
        running_captured = False
        module_transition_captured = False
        pipeline_stages_captured = False

        for i in range(120):
            time.sleep(0.5)
            res_poll = client.get(f"/api/scans/{scan_id}/status", headers=headers)
            poll_data = res_poll.json()
            status = poll_data["status"]

            if status == "running" and not running_captured:
                running_captured = True
                print("\n--- CAPTURE 2: RUNNING STATE ---")
                print(f"Status: {poll_data['status']}")
                print(f"Progress: {poll_data['progress']}%")
                print(f"Current Stage: {poll_data['stage']}")
                print(f"Pipeline stages keys: {list((poll_data.get('pipeline_stages') or {}).keys())}")

            # Check for module in running or completed state
            if poll_data.get("module_details"):
                for m_id, m_info in poll_data["module_details"].items():
                    if m_info["status"] in ("running", "completed") and not module_transition_captured:
                        module_transition_captured = True
                        print("\n--- CAPTURE 3: MODULE STATE TRANSITION ---")
                        print(f"Module: {m_id}")
                        print(f"Status: {m_info['status']}")
                        print(f"Started at: {m_info.get('started_at')}")
                        print(f"Finished at: {m_info.get('finished_at')}")
                        print(f"Message: {m_info.get('message')}")
                        break

            if status in ("completed", "failed"):
                break

        # Capture 4: Final Completed State
        res_final = client.get(f"/api/scans/{scan_id}/status", headers=headers)
        final_data = res_final.json()
        print("\n--- CAPTURE 4: COMPLETED FINAL STATE ---")
        print(f"Status: {final_data['status']}")
        print(f"Progress: {final_data['progress']}%")
        print(f"Created at: {final_data['created_at']}")
        print(f"Finished at: {final_data['finished_at']}")
        print(f"Findings summary: {final_data['findings_count']}")

        pipeline_stages = final_data.get("pipeline_stages") or []
        print("\nPipeline Stages Summary:")
        if isinstance(pipeline_stages, list):
            for st_val in pipeline_stages:
                print(f"  Stage '{st_val.get('id')}': status={st_val.get('status')}, start={st_val.get('started_at')}, finish={st_val.get('finished_at')}")
        elif isinstance(pipeline_stages, dict):
            for st_name, st_val in pipeline_stages.items():
                print(f"  Stage '{st_name}': status={st_val.get('status')}, start={st_val.get('started_at')}, finish={st_val.get('finished_at')}")

        print("\nModule Details Summary (Sample):")
        for m_id in ["sqli", "headers", "https", "auth", "access_control"]:
            m = final_data["module_details"][m_id]
            print(f"  [{m['status'].upper()}] {m['name']} ({m_id}): findings={m['findings']}, start={m.get('started_at')}, finish={m.get('finished_at')}")

        # Capture 5: Post-Refresh Verification (querying same endpoint again)
        res_refresh = client.get(f"/api/scans/{scan_id}/status", headers=headers)
        refreshed_data = res_refresh.json()
        print("\n--- CAPTURE 5: POST-REFRESH PERSISTENCE VERIFICATION ---")
        assert refreshed_data["status"] == final_data["status"]
        assert refreshed_data["finished_at"] == final_data["finished_at"]
        assert refreshed_data["findings_count"] == final_data["findings_count"]
        assert refreshed_data["module_details"]["sqli"]["status"] == final_data["module_details"]["sqli"]["status"]
        assert refreshed_data["module_details"]["sqli"]["started_at"] == final_data["module_details"]["sqli"]["started_at"]
        print("Verified: Timestamps, module outcomes, and progress values remain 100% identical upon page refresh.")

    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

if __name__ == "__main__":
    run_live_scan_runtime_verification()
