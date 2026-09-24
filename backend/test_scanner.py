import asyncio
import os
import sqlite3
from database import SessionLocal, Base, engine
from scanner.engine import SecurityScanner
from scanner.safety import UnsafeTargetError
import pytest
from models import Scan, User, ScanTarget

# Allow local targets for this test
os.environ["ALLOW_LOCAL_TARGETS"] = "true"

@pytest.mark.asyncio
async def test():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    # Create dummy user and target to satisfy foreign key constraints
    user = User(email="scanner_test@example.com", password_hash="hash")
    db.add(user)
    db.commit()
    
    target = ScanTarget(user_id=user.id, url="http://127.0.0.1:3000", authorized=True)
    db.add(target)
    db.commit()
    
    # Create a dummy scan entry
    scan = Scan(target_url=target.url, depth="standard", user_id=user.id)
    scan.target_id = target.id  # Dynamically assign for the engine if it needs it
    db.add(scan)
    db.commit()
    
    print(f"Created scan ID: {scan.id}")
    
    scanner = SecurityScanner(db, scan.id)
    await scanner.run_scan()
    
    print(f"Scan finished. Score: {scan.security_score}")
    print("Findings:")
    for finding in scan.findings:
        print(f"- [{finding.severity.upper()}] {finding.title} ({finding.type})")
        print(f"  URL: {finding.url} | Param: {finding.parameter}")
        print(f"  Evidence: {finding.evidence}")
        print("  ---")
        
    db.close()

if __name__ == "__main__":
    asyncio.run(test())
