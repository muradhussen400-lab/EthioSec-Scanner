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

import pytest
import subprocess

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def run_secure_app():
    proc = None
    try:
        httpx.get("http://127.0.0.1:3001/", timeout=1.0)
    except Exception:
        proc = subprocess.Popen([sys.executable, "secure_app.py"])
        for _ in range(30):
            try:
                r = httpx.get("http://127.0.0.1:3001/", timeout=1.0)
                if r.status_code == 200:
                    break
            except Exception:
                time.sleep(0.2)
    yield
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

def test_secure_workflow():
    print("Resetting database...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    print("Registering user...")
    resp = client.post("/api/auth/register", json={
        "email": "secure_tester@example.com",
        "full_name": "API Tester",
        "website": "http://127.0.0.1:3001",
        "password": "password123"
    })
    assert resp.status_code == 200, resp.text
    
    # Verify email
    from email_service import email_service
    code = email_service.get_last_sent_code("secure_tester@example.com")
    if code:
        ver_resp = client.post("/api/auth/verify-email", json={"email": "secure_tester@example.com", "code": code})
        assert ver_resp.status_code == 200
        token = ver_resp.json()["token"]
    else:
        token = resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    print("Creating target...")
    resp = client.post("/api/targets", json={"url": "http://127.0.0.1:3001"}, headers=headers)
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
            "misconfig": True,
            "https": True,
            "auth": True,
            "info_disclosure": True,
            "exposed_files": True
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
    for _ in range(120): # wait up to 120 seconds
        time.sleep(1)
        resp = client.get(f"/api/scans/{scan_id}/status", headers=headers)
        assert resp.status_code == 200, resp.text
        s_data = resp.json()
        status = s_data["status"]
        if _ % 5 == 0:
            print(f"Status: {status} ({s_data.get('progress')}%) - {s_data.get('stage')}")
        if status in ["completed", "failed"]:
            break
            
    assert status == "completed", f"Scan did not complete, status is {status}"

    print("Fetching findings...")
    resp = client.get(f"/api/scans/{scan_id}/results", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    
    print(f"Score: {data['security_score']}")
    print(f"Found {len(data['findings'])} findings")
    
    valid_statuses = ["HIGH", "MEDIUM", "LOW", "NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE", "CONFIRMED"]
    vulns_found = 0
    for f in data['findings']:
        print(f"- [{f['status']}] {f['type']}: {f['title']}")
        assert f['status'] in valid_statuses, f"Invalid status: {f['status']}"
        assert f['evidence'] is not None, "Evidence is missing!"
        if f['status'] in ["HIGH", "MEDIUM", "LOW"]:
            # Note: The secure app uses HTTP locally (no TLS config in uvicorn script).
            if f['type'] == 'https':
                continue
            # The test app submits a login form locally over HTTP.
            if f['title'] == 'Insecure Authentication Form':
                continue
            # Uvicorn exposes 'Server: uvicorn'. This is an info disclosure, but not a false positive logic error.
            if f['type'] == 'info_disclosure' and 'uvicorn' in f['evidence']:
                continue
            # The secure app intentionally doesn't set all possible security headers, just some. We can ignore missing LOW impact headers.
            if f['type'] == 'headers' and f['status'] == 'LOW':
                continue
            # If we don't pass an auth context, it's a Low Confidence issue, which is a warning, not a FP vulnerability.
            if f['title'] == 'Authentication Check Low Confidence':
                continue
                
            vulns_found += 1
                
    assert vulns_found == 0, f"False positives detected! {vulns_found} vulnerabilities found."
    print("API E2E Negative Test passed successfully! No false positives detected.")

if __name__ == "__main__":
    import subprocess
    print("Starting secure_app...")
    secure_process = subprocess.Popen([sys.executable, "secure_app.py"])
    time.sleep(2)
    try:
        test_secure_workflow()
    finally:
        secure_process.terminate()
        secure_process.wait()
