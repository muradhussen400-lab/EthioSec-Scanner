import os
import uuid
import pytest
from unittest.mock import patch
from database import Base, engine, SessionLocal
from models import User, ScanTarget, Scan, Finding
from scanner.safety import is_safe_url, UnsafeTargetError
from scanner.engine import SecurityScanner

def test_ssrf_safety_unspecified_and_carrier_grade_nat():
    os.environ["ALLOW_LOCAL_TARGETS"] = "false"
    
    # 0.0.0.0
    with pytest.raises(UnsafeTargetError):
        is_safe_url("http://0.0.0.0")
        
    # Carrier-grade NAT (100.64.0.0/10)
    with pytest.raises(UnsafeTargetError):
        is_safe_url("http://100.64.0.1")
        
    # Cloud metadata link-local
    with pytest.raises(UnsafeTargetError):
        is_safe_url("http://169.254.169.254")
        
    # Standard loopback
    with pytest.raises(UnsafeTargetError):
        is_safe_url("http://127.0.0.1")

def test_inconclusive_status_preserved():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    user = User(email=f"inconclusive_{uuid.uuid4().hex[:8]}@example.com", password_hash="hash")
    db.add(user)
    db.commit()
    
    scan = Scan(user_id=user.id, target_url="http://example.com", status="running")
    db.add(scan)
    db.commit()
    
    scanner = SecurityScanner(db, scan.id)
    scanner._add_finding(
        f_type="access_control",
        severity="medium",
        status="INCONCLUSIVE",
        title="Inconclusive Access Control Test",
        description="Behavior was ambiguous; evidence was insufficient.",
        url="http://example.com/test"
    )
    
    finding = db.query(Finding).filter(Finding.scan_id == scan.id).first()
    assert finding is not None
    assert finding.status == "INCONCLUSIVE", f"Expected INCONCLUSIVE but got {finding.status}"
    
    db.close()

@pytest.mark.asyncio
async def test_scan_failure_does_not_produce_clean_score():
    os.environ["ALLOW_LOCAL_TARGETS"] = "true"
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    user = User(email=f"failure_score_{uuid.uuid4().hex[:8]}@example.com", password_hash="hash")
    db.add(user)
    db.commit()
    
    scan = Scan(user_id=user.id, target_url="http://127.0.0.1:9999", status="queued")
    db.add(scan)
    db.commit()
    
    scanner = SecurityScanner(db, scan.id)
    
    # Simulate an unexpected critical crash during scanner execution
    with patch.object(scanner, "_update_progress", side_effect=RuntimeError("Simulated pipeline crash")):
        await scanner.run_scan()
        
    db.refresh(scan)
    assert scan.status == "failed", f"Expected status 'failed' after crash, got {scan.status}"
    assert scan.security_score is None, f"Expected security_score None after crash, got {scan.security_score}"
    
    db.close()
