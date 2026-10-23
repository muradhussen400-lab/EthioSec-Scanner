#!/usr/bin/env python3
"""
EthioSec Scanner Database Seed Script

Inserts a demo dataset (admin user, normal user, scan targets, scans, findings, user settings)
using the backend's own SQLAlchemy models and password hashing function (Argon2id).

Rules:
- Password read from SEED_PASSWORD or DEMO_PASSWORD environment variable (fails if unset).
- Uses only allowed values as validated by backend schemas and security checks.
- Completely idempotent: running multiple times does not produce duplicates or errors.
"""

import os
import sys
import logging
from datetime import datetime, timezone
from dotenv import load_dotenv

# Ensure backend directory is in sys.path dynamically without modifying backend files
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
backend_dir = os.path.join(project_root, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Load environment variables
load_dotenv(os.path.join(current_dir, ".env"))
load_dotenv(os.path.join(backend_dir, ".env"))

# Import backend models and security hashing
from models import User, ScanTarget, Scan, Finding, UserSettings, generate_uuid  # noqa: E402
from security import get_password_hash, validate_password_strength  # noqa: E402
from database import SessionLocal, engine  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ethiosec.seed")


def get_seed_password() -> str:
    """Retrieve demo password from environment variables and validate strength."""
    password = os.getenv("SEED_PASSWORD") or os.getenv("DEMO_PASSWORD")
    if not password:
        logger.error(
            "FATAL: Demo seed password is not set. "
            "Please set the SEED_PASSWORD environment variable before running seed.py.\n"
            "Example: export SEED_PASSWORD='DemoSecurePassword123!'"
        )
        sys.exit(1)

    is_valid, error_msg = validate_password_strength(password)
    if not is_valid:
        logger.error(f"FATAL: SEED_PASSWORD does not meet backend security policy: {error_msg}")
        sys.exit(1)

    return password


def seed_database():
    seed_pwd = get_seed_password()
    pwd_hash = get_password_hash(seed_pwd)
    now_iso = datetime.now(timezone.utc).isoformat()

    db = SessionLocal()
    try:
        logger.info("Starting idempotent database seeding...")

        # -------------------------------------------------------------
        # 1. Seed Users (1 Admin, 1 Standard Analyst)
        # -------------------------------------------------------------
        admin_email = "admin@ethiosec.local"
        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            admin = User(
                id=generate_uuid(),
                full_name="EthioSec Administrator",
                email=admin_email,
                password_hash=pwd_hash,
                role="admin",
                website="https://ethiosec.local",
                is_verified=True,
                created_at=now_iso,
            )
            db.add(admin)
            db.flush()
            logger.info(f"Created admin user: {admin_email} (ID: {admin.id})")
        else:
            logger.info(f"Admin user already exists: {admin_email} (ID: {admin.id})")

        analyst_email = "analyst@ethiosec.local"
        analyst = db.query(User).filter(User.email == analyst_email).first()
        if not analyst:
            analyst = User(
                id=generate_uuid(),
                full_name="Security Analyst",
                email=analyst_email,
                password_hash=pwd_hash,
                role="user",
                website="https://analyst.ethiosec.local",
                is_verified=True,
                created_at=now_iso,
            )
            db.add(analyst)
            db.flush()
            logger.info(f"Created standard user: {analyst_email} (ID: {analyst.id})")
        else:
            logger.info(f"Standard user already exists: {analyst_email} (ID: {analyst.id})")

        # -------------------------------------------------------------
        # 2. Seed User Settings
        # -------------------------------------------------------------
        for u in [admin, analyst]:
            settings = db.query(UserSettings).filter(UserSettings.user_id == u.id).first()
            if not settings:
                settings = UserSettings(
                    user_id=u.id,
                    default_scan_depth="standard",
                    notif_scan_completed=True,
                    notif_scan_failed=True,
                    notif_security_findings=True,
                    updated_at=now_iso,
                )
                db.add(settings)
                logger.info(f"Created user settings for user: {u.email}")

        # -------------------------------------------------------------
        # 3. Seed Scan Targets
        # -------------------------------------------------------------
        target_urls = [
            ("https://demo-app.ethiosec.local", True),
            ("https://staging-api.ethiosec.local", True),
            ("https://unverified.ethiosec.local", False),
        ]
        targets = []
        for url, auth in target_urls:
            target = db.query(ScanTarget).filter(
                ScanTarget.user_id == analyst.id,
                ScanTarget.url == url
            ).first()
            if not target:
                target = ScanTarget(
                    id=generate_uuid(),
                    user_id=analyst.id,
                    url=url,
                    authorized=auth,
                    created_at=now_iso,
                )
                db.add(target)
                db.flush()
                logger.info(f"Created scan target: {url} (ID: {target.id})")
            else:
                logger.info(f"Scan target already exists: {url} (ID: {target.id})")
            targets.append(target)

        primary_target = targets[0]

        # -------------------------------------------------------------
        # 4. Seed Scans
        # -------------------------------------------------------------
        scans_data = [
            {
                "target_url": primary_target.url,
                "depth": "standard",
                "status": "completed",
                "progress": 100,
                "stage": "Completed",
                "checks": {
                    "headers": True,
                    "ssl": True,
                    "dns": True,
                    "meta": True,
                    "owasp": True,
                    "ai": True,
                },
                "modules": {"sqli": True, "xss": True, "headers": True, "https": True},
                "security_score": 78,
                "created_at": now_iso,
                "finished_at": now_iso,
            },
            {
                "target_url": targets[1].url,
                "depth": "deep",
                "status": "running",
                "progress": 45,
                "stage": "Vulnerability Analysis",
                "checks": {
                    "headers": True,
                    "ssl": True,
                    "dns": True,
                    "meta": False,
                    "owasp": False,
                    "ai": False,
                },
                "modules": {"sqli": True, "xss": True, "auth": True, "cors": True},
                "security_score": None,
                "created_at": now_iso,
                "finished_at": None,
            },
            {
                "target_url": targets[2].url,
                "depth": "quick",
                "status": "queued",
                "progress": 0,
                "stage": "Queued",
                "checks": {},
                "modules": {"headers": True},
                "security_score": None,
                "created_at": now_iso,
                "finished_at": None,
            },
        ]

        seeded_scans = []
        for s_data in scans_data:
            scan = db.query(Scan).filter(
                Scan.user_id == analyst.id,
                Scan.target_url == s_data["target_url"],
                Scan.depth == s_data["depth"]
            ).first()
            if not scan:
                scan = Scan(
                    id=generate_uuid(),
                    user_id=analyst.id,
                    target_url=s_data["target_url"],
                    depth=s_data["depth"],
                    status=s_data["status"],
                    progress=s_data["progress"],
                    stage=s_data["stage"],
                    checks=s_data["checks"],
                    modules=s_data["modules"],
                    security_score=s_data["security_score"],
                    created_at=s_data["created_at"],
                    finished_at=s_data["finished_at"],
                )
                db.add(scan)
                db.flush()
                logger.info(f"Created scan for {scan.target_url} [{scan.depth}] (ID: {scan.id})")
            else:
                logger.info(f"Scan already exists for {scan.target_url} [{scan.depth}] (ID: {scan.id})")
            seeded_scans.append(scan)

        completed_scan = seeded_scans[0]

        # -------------------------------------------------------------
        # 5. Seed Findings
        # -------------------------------------------------------------
        findings_data = [
            {
                "type": "headers",
                "severity": "medium",
                "confidence": "HIGH",
                "status": "HIGH",
                "url": f"{primary_target.url}/",
                "parameter": "Content-Security-Policy",
                "title": "Missing Content-Security-Policy Header",
                "description": "The Content-Security-Policy HTTP response header is not implemented, increasing susceptibility to Cross-Site Scripting (XSS) attacks.",
                "evidence": "HTTP response headers inspected; 'Content-Security-Policy' header was absent.",
                "http_method": "GET",
                "request": "GET / HTTP/1.1\nHost: demo-app.ethiosec.local",
                "response_summary": "HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html",
                "impact": "Browsers cannot restrict which dynamic resources are allowed to load and execute.",
                "remediation": [
                    "Configure a robust Content-Security-Policy header.",
                    "Disallow unsafe-inline scripts and evaluate directives against OWASP guidelines."
                ],
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-693",
                "ai_explanation": "A Content-Security-Policy (CSP) instructs the browser which origins are trusted for executing scripts and rendering assets.",
            },
            {
                "type": "xss",
                "severity": "high",
                "confidence": "HIGH",
                "status": "HIGH",
                "url": f"{primary_target.url}/search",
                "parameter": "q",
                "title": "Reflected Cross-Site Scripting (XSS)",
                "description": "The 'q' parameter reflects user input into the HTML body without contextual sanitization or HTML entity encoding.",
                "evidence": "<script>alert(1)</script> was reflected unaltered in the HTTP response body.",
                "http_method": "GET",
                "request": "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\nHost: demo-app.ethiosec.local",
                "response_summary": "HTTP/1.1 200 OK\n... <div>Results for <script>alert(1)</script></div> ...",
                "impact": "Attackers can execute arbitrary JavaScript in the victim's browser session, potentially stealing authentication tokens.",
                "remediation": [
                    "Apply context-aware output encoding on all user reflection points.",
                    "Use template engines that auto-escape by default.",
                    "Deploy a restrictive Content-Security-Policy."
                ],
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-79",
                "ai_explanation": "Reflected XSS occurs when an application receives untrusted data in an HTTP request and echoes it immediately without verification.",
            },
            {
                "type": "https",
                "severity": "low",
                "confidence": "HIGH",
                "status": "HIGH",
                "url": f"{primary_target.url}/",
                "parameter": "Strict-Transport-Security",
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "description": "The HSTS header is missing, allowing downgrade attacks from HTTPS to HTTP on insecure network paths.",
                "evidence": "'Strict-Transport-Security' header not detected in TLS response.",
                "http_method": "GET",
                "request": "GET / HTTP/1.1\nHost: demo-app.ethiosec.local",
                "response_summary": "HTTP/1.1 200 OK",
                "impact": "Network adversaries can perform SSL-stripping and intercept cleartext communication.",
                "remediation": [
                    "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses."
                ],
                "owasp": "A05:2021-Security Misconfiguration",
                "cwe": "CWE-319",
                "ai_explanation": "HSTS instructs modern web browsers to only ever connect to the site via HTTPS, blocking unencrypted HTTP attempts.",
            },
            {
                "type": "sqli",
                "severity": "info",
                "confidence": "HIGH",
                "status": "NOT_DETECTED",
                "url": f"{primary_target.url}/api/v1/items",
                "parameter": "id",
                "title": "SQL Injection Assessment - No Vulnerability Detected",
                "description": "All SQL injection heuristics (error-based, boolean-based, and time-based blind vectors) were tested and returned negative.",
                "evidence": "Tested 14 SQL injection payloads; database syntax errors were not triggered.",
                "http_method": "GET",
                "request": "GET /api/v1/items?id=1'%20OR%20'1'='1 HTTP/1.1",
                "response_summary": "HTTP/1.1 400 Bad Request",
                "impact": "None observed.",
                "remediation": [
                    "Continue utilizing parameterized queries and ORM abstractions."
                ],
                "owasp": "A03:2021-Injection",
                "cwe": "CWE-89",
                "ai_explanation": "The endpoint correctly parses parameters as strongly typed integers or utilizes prepared statements.",
            },
        ]

        for f_data in findings_data:
            finding = db.query(Finding).filter(
                Finding.scan_id == completed_scan.id,
                Finding.title == f_data["title"]
            ).first()
            if not finding:
                finding = Finding(
                    id=generate_uuid(),
                    scan_id=completed_scan.id,
                    target_id=primary_target.id,
                    type=f_data["type"],
                    severity=f_data["severity"],
                    confidence=f_data["confidence"],
                    status=f_data["status"],
                    url=f_data["url"],
                    parameter=f_data["parameter"],
                    title=f_data["title"],
                    description=f_data["description"],
                    evidence=f_data["evidence"],
                    http_method=f_data["http_method"],
                    request=f_data["request"],
                    response_summary=f_data["response_summary"],
                    impact=f_data["impact"],
                    remediation=f_data["remediation"],
                    owasp=f_data["owasp"],
                    cwe=f_data["cwe"],
                    ai_explanation=f_data["ai_explanation"],
                    created_at=now_iso,
                )
                db.add(finding)
                logger.info(f"Created finding: '{finding.title}' [{finding.severity}] (ID: {finding.id})")
            else:
                logger.info(f"Finding already exists: '{finding.title}' (ID: {finding.id})")

        db.commit()
        logger.info("Database seeding successfully committed.")

    except Exception as e:
        db.rollback()
        logger.error(f"Error during seeding: {e}", exc_info=True)
        raise
    finally:
        db.close()


def print_table_counts():
    """Print the count of records in each table."""
    db = SessionLocal()
    try:
        tables = [
            ("users", User),
            ("scan_targets", ScanTarget),
            ("scans", Scan),
            ("findings", Finding),
            ("user_settings", UserSettings),
        ]
        print("\n--- Current Database Table Row Counts ---")
        for name, model in tables:
            count = db.query(model).count()
            print(f"  {name:15}: {count} row(s)")
        print("-----------------------------------------\n")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
    print_table_counts()
