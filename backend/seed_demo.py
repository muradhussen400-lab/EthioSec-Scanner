import uuid
import json
from datetime import datetime, timezone
from security import create_access_token, get_password_hash
from database import SessionLocal
from models import User, Scan, Finding

db = SessionLocal()
try:
    user = db.query(User).filter_by(email="admin@test.com").first()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            email="admin@test.com",
            password_hash=get_password_hash("AdminPassword123!"),
            role="Security Administrator",
            is_verified=True,
        )
        db.add(user)
        db.commit()

    scan = db.query(Scan).filter_by(user_id=user.id).first()
    if not scan:
        scan = Scan(
            id=str(uuid.uuid4()),
            user_id=user.id,
            target_url="https://ethiopian-banking-portal.et",
            depth="deep",
            status="completed",
            progress=100,
            stage="Finished",
            security_score=72,
            created_at=datetime.now(timezone.utc).isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        db.add(scan)
        db.flush()
        f1 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            type="sql_injection",
            title="SQL Injection in Account Search",
            description="The 'acc_no' input parameter is vulnerable to SQL injection flaw.",
            severity="high",
            status="CONFIRMED",
            evidence=json.dumps({"parameter": "acc_no", "payload": "' OR 1=1--", "response_snippet": "syntax error at line 1"}),
            remediation=json.dumps(["Use parameterized queries and bind variables."]),
            url="https://ethiopian-banking-portal.et/api/v1/accounts/search",
        )
        f2 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            type="xss",
            title="Cross-Site Scripting (Reflected)",
            description="User input is reflected in HTML output without proper sanitization.",
            severity="medium",
            status="CONFIRMED",
            evidence=json.dumps({"vector": "q=alert_test"}),
            remediation=json.dumps(["Encode untrusted HTML output and apply Content Security Policy."]),
            url="https://ethiopian-banking-portal.et/search",
        )
        f3 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            type="missing_headers",
            title="Missing Strict-Transport-Security Header",
            description="The HTTP response lacks the Strict-Transport-Security header.",
            severity="low",
            status="CONFIRMED",
            evidence=json.dumps({"header": "Strict-Transport-Security missing"}),
            remediation=json.dumps(["Configure HSTS response header with max-age of at least 31536000."]),
            url="https://ethiopian-banking-portal.et",
        )
        f4 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            type="cors",
            title="CORS Wildcard Origin Check",
            description="Origin validation check completed successfully.",
            severity="low",
            status="NOT_DETECTED",
            evidence="{}",
            remediation=json.dumps(["None required; origin validation passed."]),
            url="https://ethiopian-banking-portal.et",
        )
        f5 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            type="ssl_tls",
            title="SSL/TLS Handshake Check",
            description="Could not complete SSL check due to remote host reset.",
            severity="medium",
            status="ERROR",
            evidence=json.dumps({"error": "Remote host reset TLS handshake on port 443"}),
            remediation=json.dumps(["Verify target host network availability and retry the test."]),
            url="https://ethiopian-banking-portal.et",
        )
        db.add_all([f1, f2, f3, f4, f5])
        db.commit()

    token = create_access_token({"sub": user.email, "id": user.id, "role": user.role})
    print(f"TOKEN_KEY:{token}")
    print(f"SCAN_KEY:{scan.id}")
finally:
    db.close()
