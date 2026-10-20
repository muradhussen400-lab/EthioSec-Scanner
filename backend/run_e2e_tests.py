import asyncio
import os
import sys
import httpx
import time
import subprocess

# Allow local targets
os.environ["ALLOW_LOCAL_TARGETS"] = "true"
os.environ["DATABASE_URL"] = "sqlite:///./ethiosec_test.db"

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import engine, Base, SessionLocal
from models import User, ScanTarget, Scan, Finding
from scanner.engine import SecurityScanner

async def run_scan_on_target(url: str, app_name: str):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    user = User(email=f"test_{app_name}@example.com", password_hash="hash")
    db.add(user)
    db.commit()
    
    target = ScanTarget(user_id=user.id, url=url, authorized=True)
    db.add(target)
    db.commit()
    
    scan = Scan(
        user_id=user.id, 
        target_url=target.url, 
        status="queued",
        depth="deep",
        modules={
            "sqli": True,
            "xss": True,
            "access_control": True,
            "auth": True,
            "headers": True,
            "misconfig": True,
            "exposed_files": True,
            "https": True
        },
        auth_context_1={"headers": {"Authorization": "Bearer token1"}},
        auth_context_2={"headers": {"Authorization": "Bearer token2"}}
    )
    scan.target_id = target.id
    db.add(scan)
    db.commit()
    
    scan_id = scan.id
    db.close()
    
    print(f"\n--- Starting Scan on {app_name} ({url}) ---")
    
    db_scan = SessionLocal()
    scanner = SecurityScanner(db_scan, scan_id)
    await scanner.run_scan()
    db_scan.close()
    
    db_results = SessionLocal()
    findings = db_results.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    print(f"Results for {app_name}:")
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NOT_DETECTED": 0, "SCANNER_ERROR": 0}
    for f in findings:
        print(f"[{f.status}] {f.type} - {f.title}")
        if f.status in counts:
            counts[f.status] += 1
            
    print(f"Summary: {counts}")
    db_results.close()
    return counts

async def main():
    # Start vulnerable app
    print("Starting vulnerable_app...")
    vuln_process = subprocess.Popen([sys.executable, "vulnerable_app.py"])
    time.sleep(2) # wait for startup
    
    try:
        await run_scan_on_target("http://127.0.0.1:3000", "Vulnerable App")
    finally:
        vuln_process.terminate()
        vuln_process.wait()
        
    # Start secure app
    print("\nStarting secure_app...")
    secure_process = subprocess.Popen([sys.executable, "secure_app.py"])
    time.sleep(2) # wait for startup
    
    try:
        await run_scan_on_target("http://127.0.0.1:3001", "Secure App")
    finally:
        secure_process.terminate()
        secure_process.wait()

if __name__ == "__main__":
    asyncio.run(main())
