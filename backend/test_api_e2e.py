import asyncio
import os
import sys
import time
import httpx
from fastapi.testclient import TestClient

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from main import app
from database import engine, Base, SessionLocal
from models import User

client = TestClient(app)

def test_api_workflow():
    print("Resetting database...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    print("Registering user...")
    resp = client.post("/api/auth/register", json={
        "email": "api_test@example.com",
        "full_name": "API Tester",
        "website": "http://127.0.0.1:3000",
        "password": "password123"
    })
    assert resp.status_code == 200, resp.text
    
    # Verify email
    from email_service import email_service
    code = email_service.get_last_sent_code("api_test@example.com")
    if code:
        ver_resp = client.post("/api/auth/verify-email", json={"email": "api_test@example.com", "code": code})
        assert ver_resp.status_code == 200
        token = ver_resp.json()["token"]
    else:
        token = resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    print("Creating target...")
    resp = client.post("/api/targets", json={"url": "http://127.0.0.1:3000"}, headers=headers)
    assert resp.status_code == 200, resp.text
    target_id = resp.json()["id"]

    print("Creating scan...")
    scan_req = {
        "target_id": target_id,
        "authorized": True,
        "depth": "deep",
        "modules": {
            "sqli": True,
            "xss": True,
            "access_control": True,
            "headers": True,
            "misconfig": True
        }
    }
    resp = client.post("/api/scans", json=scan_req, headers=headers)
    assert resp.status_code == 200, resp.text
    scan_id = resp.json()["scan_id"]

    print(f"Scan {scan_id} created. Starting it...")
    
    resp = client.post(f"/api/scans/{scan_id}/start", headers=headers)
    assert resp.status_code == 200, resp.text

    print(f"Waiting for completion...")
    
    status = "running"
    for _ in range(60): # wait up to 60 seconds
        time.sleep(1)
        resp = client.get(f"/api/scans/{scan_id}/status", headers=headers)
        assert resp.status_code == 200, resp.text
        status = resp.json()["status"]
        print(f"Status: {status} (Progress: {resp.json()['progress']}%)")
        if status in ["completed", "failed", "completed_with_errors"]:
            break
            
    assert status in ["completed", "completed_with_errors"], f"Scan did not complete, status is {status}"

    print("Fetching findings...")
    resp = client.get(f"/api/scans/{scan_id}/results", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    
    print(f"Score: {data['security_score']}")
    print(f"Found {len(data['findings'])} findings")
    
    valid_statuses = ["HIGH", "MEDIUM", "LOW", "NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE", "CONFIRMED"]
    for f in data['findings']:
        print(f"- [{f['status']}] {f['type']}: {f['title']}")
        assert f['status'] in valid_statuses, f"Invalid status: {f['status']}"
        assert f['evidence'] is not None, "Evidence is missing!"
        
    print("API E2E test passed successfully!")

if __name__ == "__main__":
    import subprocess
    print("Starting vulnerable_app...")
    vuln_process = subprocess.Popen([sys.executable, "vulnerable_app.py"])
    time.sleep(2)
    try:
        test_api_workflow()
    finally:
        vuln_process.terminate()
        vuln_process.wait()
