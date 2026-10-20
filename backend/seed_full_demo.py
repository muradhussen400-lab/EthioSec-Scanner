import uuid
import json
import datetime
from security import create_access_token, get_password_hash
from database import SessionLocal, engine, Base
from models import User, Scan, Finding, ScanTarget

Base.metadata.create_all(bind=engine)
db = SessionLocal()

try:
    # 1. User: miftah@example.com
    user = db.query(User).filter_by(email="miftah@example.com").first()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            email="miftah@example.com",
            full_name="Miftah Hussen",
            password_hash=get_password_hash("Password123!"),
            role="Security Analyst",
            is_verified=True,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.is_verified = True
        user.password_hash = get_password_hash("Password123!")
        db.commit()

    # 2. Add Scan 1: Completed with Findings
    now = datetime.datetime.now(datetime.timezone.utc)
    t1 = now - datetime.timedelta(minutes=45)
    t1_end = t1 + datetime.timedelta(seconds=42)

    scan1 = db.query(Scan).filter_by(user_id=user.id, target_url="https://ethio-ecommerce.local").first()
    if not scan1:
        scan1 = Scan(
            id=str(uuid.uuid4()),
            user_id=user.id,
            target_url="https://ethio-ecommerce.local",
            depth="standard",
            status="completed",
            progress=100,
            stage="Finished",
            security_score=68,
            created_at=t1.isoformat(),
            finished_at=t1_end.isoformat()
        )
        db.add(scan1)
        db.commit()
        db.refresh(scan1)

        f1 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan1.id,
            type="sqli",
            severity="high",
            confidence="HIGH",
            status="CONFIRMED",
            title="SQL Injection in Product Search",
            description="The 'category_id' parameter in /api/v1/products is vulnerable to boolean-based SQL injection.",
            url="https://ethio-ecommerce.local/api/v1/products?category_id=1",
            parameter="category_id",
            http_method="GET",
            evidence="Parameter: category_id\nPayload: 1' OR 1=1--\nResponse: Returned unescaped catalog rows with HTTP 200",
            request="GET /api/v1/products?category_id=1'%20OR%201=1-- HTTP/1.1\nHost: ethio-ecommerce.local\nUser-Agent: EthioSecScan/2.0",
            response_summary="HTTP/1.1 200 OK\nContent-Type: application/json\n[{\"id\": 1, \"title\": \"Product A\"}, {\"id\": 2, \"title\": \"Product B\"}]",
            impact="Unauthorized database disclosure, potential authentication bypass, and unauthorized data modification.",
            remediation=json.dumps([
                "Use parameterized SQL queries or ORM prepared statements for all dynamic inputs.",
                "Implement strict server-side integer casting on category_id parameter.",
                "Enforce database principle of least privilege."
            ]),
            owasp="A03:2021-Injection",
            cwe="CWE-89",
            ai_explanation="The application concatenates untrusted user input directly into SQL queries without proper sanitization. Replacing string interpolation with parameterized queries immediately mitigates this vulnerability.",
            created_at=t1_end.isoformat()
        )

        f2 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan1.id,
            type="cors",
            severity="medium",
            confidence="HIGH",
            status="CONFIRMED",
            title="Overly Permissive CORS Origin Configuration",
            description="The Access-Control-Allow-Origin header reflects untrusted request origins with Access-Control-Allow-Credentials enabled.",
            url="https://ethio-ecommerce.local/api/v1/auth/user",
            parameter="Origin header",
            http_method="OPTIONS",
            evidence="Request: Origin: https://attacker.example\nResponse: Access-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true",
            remediation=json.dumps([
                "Specify an explicit whitelist of trusted frontend domains in CORS headers.",
                "Never reflect arbitrary request origins when credentials flag is set to true."
            ]),
            owasp="A01:2021-Broken Access Control",
            cwe="CWE-942",
            ai_explanation="Reflecting arbitrary origins while allowing credentials enables malicious third-party websites to extract sensitive authenticated data via browser fetch calls.",
            created_at=t1_end.isoformat()
        )

        f3 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan1.id,
            type="cookies",
            severity="low",
            confidence="HIGH",
            status="CONFIRMED",
            title="Missing SameSite Attribute on Session Cookie",
            description="The session_id cookie lacks the SameSite=Lax or SameSite=Strict attribute, increasing CSRF exposure.",
            url="https://ethio-ecommerce.local/login",
            parameter="session_id cookie",
            evidence="Set-Cookie: session_id=abc12345; Path=/; Secure; HttpOnly",
            remediation=json.dumps([
                "Append SameSite=Lax or SameSite=Strict to all authenticated cookies."
            ]),
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-1275",
            created_at=t1_end.isoformat()
        )

        f4 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan1.id,
            type="access_control",
            severity="high",
            confidence="LOW",
            status="INCONCLUSIVE",
            title="Cross-User Object Access (IDOR) Inconclusive",
            description="Dual authenticated test contexts were not provided. Automated comparison between distinct tenants could not be executed.",
            url="https://ethio-ecommerce.local/api/v1/orders/1042",
            parameter="order_id",
            remediation=json.dumps([
                "Supply Context 1 (primary identity) and Context 2 (secondary identity) in New Scan configuration to retest IDOR boundaries.",
                "Ensure server-side authorization validates that requesting user owns target resource."
            ]),
            owasp="A01:2021-Broken Access Control",
            cwe="CWE-639",
            created_at=t1_end.isoformat()
        )

        f5 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan1.id,
            type="xss",
            severity="low",
            confidence="HIGH",
            status="NOT_DETECTED",
            title="Reflected XSS Filter Test Passed",
            description="Input forms and parameters safely encode characters (< > \" ') before HTML output.",
            url="https://ethio-ecommerce.local/search",
            created_at=t1_end.isoformat()
        )

        f6 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan1.id,
            type="headers",
            severity="low",
            confidence="HIGH",
            status="NOT_DETECTED",
            title="Core Response Headers Present",
            description="Essential defense-in-depth headers (X-Frame-Options, X-Content-Type-Options) are active.",
            url="https://ethio-ecommerce.local",
            created_at=t1_end.isoformat()
        )

        db.add_all([f1, f2, f3, f4, f5, f6])
        db.commit()

    # 3. Add Scan 2: Clean Target
    t2 = now - datetime.timedelta(hours=3)
    t2_end = t2 + datetime.timedelta(seconds=98)
    scan2 = db.query(Scan).filter_by(user_id=user.id, target_url="https://api.banking-secure.et").first()
    if not scan2:
        scan2 = Scan(
            id=str(uuid.uuid4()),
            user_id=user.id,
            target_url="https://api.banking-secure.et",
            depth="deep",
            status="completed",
            progress=100,
            stage="Finished",
            security_score=94,
            created_at=t2.isoformat(),
            finished_at=t2_end.isoformat()
        )
        db.add(scan2)
        db.commit()
        db.refresh(scan2)

        f_clean1 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan2.id,
            type="sqli",
            severity="high",
            confidence="HIGH",
            status="NOT_DETECTED",
            title="SQL Injection Not Detected",
            description="Parameterized queries verified on all audited REST endpoints.",
            url="https://api.banking-secure.et",
            created_at=t2_end.isoformat()
        )
        f_clean2 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan2.id,
            type="info_disclosure",
            severity="low",
            confidence="MEDIUM",
            status="CONFIRMED",
            title="Server Banner Header Discloses Nginx Version",
            description="The 'Server: nginx/1.24.0' response header discloses precise web server version.",
            url="https://api.banking-secure.et",
            evidence="Server: nginx/1.24.0",
            remediation=json.dumps(["Disable server_tokens directive in nginx.conf configuration."]),
            owasp="A05:2021-Security Misconfiguration",
            cwe="CWE-200",
            created_at=t2_end.isoformat()
        )
        db.add_all([f_clean1, f_clean2])
        db.commit()

    # Generate permanent verified token for miftah@example.com (expires in 1 year)
    expires = datetime.timedelta(days=365)
    token = create_access_token(
        data={"sub": user.email, "is_verified": True},
        expires_delta=expires
    )
    print("=== SEEDING COMPLETED ===")
    print(f"User: {user.email}")
    print(f"Token: {token}")
    print(f"Scan 1 ID: {scan1.id}")
    print(f"Scan 2 ID: {scan2.id}")

finally:
    db.close()
