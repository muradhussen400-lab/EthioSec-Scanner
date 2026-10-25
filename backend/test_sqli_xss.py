import asyncio
import os
import sys
import httpx

# Allow local targets
os.environ["ALLOW_LOCAL_TARGETS"] = "true"
os.environ["DATABASE_URL"] = "sqlite:///./ethiosec_test.db"

# Add backend to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import engine, Base, SessionLocal
from models import User, ScanTarget, Scan, Finding
import pytest
from scanner.engine import SecurityScanner

import subprocess
import time

@pytest.fixture(scope="module", autouse=True)
def run_vulnerable_app():
    proc = None
    try:
        httpx.get("http://127.0.0.1:3000/", timeout=1.0)
    except Exception:
        proc = subprocess.Popen([sys.executable, "vulnerable_app.py"])
        for _ in range(30):
            try:
                r = httpx.get("http://127.0.0.1:3000/", timeout=1.0)
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

@pytest.mark.asyncio
async def test_scan():
    # Setup DB
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    # Create test data
    user = User(email="test@example.com", password_hash="hash")
    db.add(user)
    db.commit()
    
    target = ScanTarget(user_id=user.id, url="http://127.0.0.1:3000", authorized=True)
    db.add(target)
    db.commit()
    
    scan = Scan(
        user_id=user.id, 
        target_url=target.url, 
        status="queued",
        auth_context_1={"headers": {"Authorization": "Bearer token1"}},
        auth_context_2={"headers": {"Authorization": "Bearer token2"}}
    )
    scan.target_id = target.id
    db.add(scan)
    db.commit()
    
    scan_id = scan.id
    db.close()
    
    print(f"Starting scan {scan_id}")
    
    # Help the crawler find the endpoints by adding a quick link injection or just let's see if the crawler can find it.
    # The crawler won't find /api/users/1 unless it's linked. Let's dynamically add it via a request or just patch the crawler target
    # For testing, we'll patch the vulnerable app to link it on the homepage.
    
    # Run Scanner
    db_scan = SessionLocal()
    scanner = SecurityScanner(db_scan, scan_id)
    await scanner.run_scan()
    db_scan.close()
    
    print("Scan finished.")
    
    # Print Findings
    db_results = SessionLocal()
    findings = db_results.query(Finding).filter(Finding.scan_id == scan_id).all()
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f"[{f.severity.upper()}] {f.type}: {f.title} (Param: {f.parameter})")
    
    db_results.close()

if __name__ == "__main__":
    asyncio.run(test_scan())
