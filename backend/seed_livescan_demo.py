import uuid
import datetime
from database import SessionLocal, engine, Base
from models import User, Scan, Finding
from security import create_access_token, get_password_hash

Base.metadata.create_all(bind=engine)
db = SessionLocal()

try:
    user = db.query(User).filter_by(email="miftah@example.com").first()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            email="miftah@example.com",
            full_name="Mekdes Abebe",
            role="Administrator",
            password_hash=get_password_hash("Password123!"),
            is_verified=True,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.full_name = "Mekdes Abebe"
        user.role = "Administrator"
        user.is_verified = True
        db.commit()

    token = create_access_token({"sub": user.email})
    print(f"USER_EMAIL: {user.email}")
    print(f"USER_TOKEN: {token}")

    now = datetime.datetime.now(datetime.timezone.utc)
    t_start = (now - datetime.timedelta(seconds=154)).isoformat()

    # 1. LIVE RUNNING SCAN MATCHING REFERENCE IMAGE (42% RUNNING)
    scan_id = "7ed07927-accd-4abe-adc6-95932ee09f08"
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        scan = Scan(id=scan_id, user_id=user.id, target_url="https://cafeteria.aau.edu.et")
        db.add(scan)

    scan.user_id = user.id
    scan.target_url = "https://cafeteria.aau.edu.et"
    scan.depth = "deep"
    scan.status = "running"
    scan.progress = 42
    scan.stage = "Running security checks..."
    scan.created_at = t_start
    scan.finished_at = None

    pipeline_stages = [
        {"id": "target_validation", "name": "Target Validation", "status": "completed", "duration_seconds": 12, "started_at": t_start, "finished_at": t_start, "message": "Target validated."},
        {"id": "dns_reachability", "name": "DNS & Reachability", "status": "completed", "duration_seconds": 8, "started_at": t_start, "finished_at": t_start, "message": "Host reachable (200 OK)."},
        {"id": "security_headers", "name": "Security Headers", "status": "running", "duration_seconds": 32, "started_at": t_start, "finished_at": None, "message": "Analyzing HTTP response headers..."},
        {"id": "auth", "name": "Authentication", "status": "pending", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Awaiting authentication checks"},
        {"id": "access_control", "name": "Access Control", "status": "pending", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Awaiting access control testing"},
        {"id": "vuln_checks", "name": "Vulnerability Checks", "status": "pending", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Awaiting active payload scanning"},
        {"id": "report_generation", "name": "Report Generation", "status": "pending", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Awaiting report compilation"}
    ]

    module_details = {
        "sqli": {"status": "completed", "selected": True, "duration_seconds": 18, "findings_count": 0, "message": "No vulnerabilities found."},
        "xss": {"status": "running", "selected": True, "duration_seconds": 32, "findings_count": 0, "message": "Testing reflected and stored XSS..."},
        "headers": {"status": "running", "selected": True, "duration_seconds": 32, "findings_count": 0, "message": "Checking security headers..."},
        "cookies": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"},
        "cors": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"},
        "https": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"},
        "auth": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"},
        "access_control": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"},
        "exposed_files": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"},
        "http_methods": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"},
        "info_disclosure": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"},
        "misconfig": {"status": "pending", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Queued"}
    }

    timeline = [
        {"timestamp": "2026-10-18T10:24:12Z", "event": "Scan started", "details": "Initializing security assessment pipeline...", "status": "completed"},
        {"timestamp": "2026-10-18T10:24:14Z", "event": "Target validation", "details": "Target is reachable and valid.", "status": "completed"},
        {"timestamp": "2026-10-18T10:24:22Z", "event": "DNS & reachability", "details": "DNS resolution successful. 200 OK.", "status": "completed"},
        {"timestamp": "2026-10-18T10:24:54Z", "event": "Security headers", "details": "Checking security headers...", "status": "running"},
        {"timestamp": "2026-10-18T10:25:20Z", "event": "XSS module", "details": "Testing reflected and stored XSS...", "status": "running"},
        {"timestamp": "2026-10-18T10:25:41Z", "event": "SQL injection", "details": "Module completed. No vulnerabilities found.", "status": "completed"},
        {"timestamp": "2026-10-18T10:25:52Z", "event": "Scan progress", "details": "42% complete. 3 of 12 modules finished.", "status": "running"}
    ]

    scan.checks = {
        "pipeline_stages": pipeline_stages,
        "module_details": module_details,
        "timeline": timeline,
        "completed_checks": {"sqli": True, "xss": False, "headers": False}
    }
    scan.modules = {k: True for k in module_details}
    db.commit()
    print("SUCCESS: Seeded reference running scan 7ed07927-accd-4abe-adc6-95932ee09f08")

    # 2. SEED DNS FAILURE SCAN
    fail_id = "fail-dns-demo-scan"
    fail_scan = db.query(Scan).filter_by(id=fail_id).first()
    if not fail_scan:
        fail_scan = Scan(id=fail_id, user_id=user.id, target_url="https://test.local")
        db.add(fail_scan)

    fail_scan.user_id = user.id
    fail_scan.target_url = "https://test.local"
    fail_scan.depth = "standard"
    fail_scan.status = "failed"
    fail_scan.progress = 15
    fail_scan.stage = "Target Validation Failed: Could not resolve hostname: test.local"
    fail_scan.created_at = t_start
    fail_scan.finished_at = now.isoformat()

    fail_pipeline_stages = [
        {"id": "target_validation", "name": "Target Validation", "status": "failed", "duration_seconds": 4, "started_at": t_start, "finished_at": now.isoformat(), "message": "Could not resolve hostname: test.local"},
        {"id": "dns_reachability", "name": "DNS & Reachability", "status": "skipped", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Skipped due to validation failure"},
        {"id": "security_headers", "name": "Security Headers", "status": "skipped", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Skipped"},
        {"id": "auth", "name": "Authentication", "status": "skipped", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Skipped"},
        {"id": "access_control", "name": "Access Control", "status": "skipped", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Skipped"},
        {"id": "vuln_checks", "name": "Vulnerability Checks", "status": "skipped", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Skipped"},
        {"id": "report_generation", "name": "Report Generation", "status": "skipped", "duration_seconds": None, "started_at": None, "finished_at": None, "message": "Skipped"}
    ]

    fail_module_details = {k: {"status": "skipped", "selected": True, "duration_seconds": None, "findings_count": 0, "message": "Check was skipped because target validation failed"} for k in module_details}
    fail_timeline = [
        {"timestamp": "2026-10-18T10:24:12Z", "event": "Scan started", "details": "Initializing security assessment pipeline...", "status": "completed"},
        {"timestamp": "2026-10-18T10:24:14Z", "event": "Target validation", "details": "Validating hostname resolution for test.local...", "status": "running"},
        {"timestamp": "2026-10-18T10:24:18Z", "event": "Target validation failed", "details": "Could not resolve hostname: test.local. Target host unreachable.", "status": "failed"}
    ]

    fail_scan.checks = {
        "pipeline_stages": fail_pipeline_stages,
        "module_details": fail_module_details,
        "timeline": fail_timeline,
        "completed_checks": {}
    }
    fail_scan.modules = {k: True for k in module_details}
    db.commit()
    print("SUCCESS: Seeded failure scan fail-dns-demo-scan")

finally:
    db.close()
