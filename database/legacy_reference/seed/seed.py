"""
Database Seed Script for EthioSec Scanner.

Populates a demonstration user, user settings, verified target, completed scan,
and findings spanning all five severities (Critical, High, Medium, Low, Info).
Safe to run repeatedly without producing duplicate records.
"""

import datetime
import os
import sys

# Ensure backend directory is in sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models import Finding, Report, Scan, Target, User, UserSettings
from app.utils.vocabulary import SCANNER_MODULE_KEYS


def run_seed():
    db = SessionLocal()
    try:
        demo_email = "demo@ethiosec.local"
        existing_user = db.query(User).filter(User.email == demo_email).first()

        if existing_user:
            print(f"[+] Existing demo user '{demo_email}' found. Removing to ensure clean idempotent seed...")
            db.delete(existing_user)
            db.commit()

        print("[+] Creating demo user and profile...")
        demo_user = User(
            email=demo_email,
            password_hash=hash_password("EthioSec2026!"),
            full_name="EthioSec Security Analyst",
            role="user",
            is_active=True,
        )
        db.add(demo_user)
        db.flush()

        print("[+] Creating default user settings...")
        demo_settings = UserSettings(
            user_id=demo_user.id,
            default_scan_depth="standard",
            notify_scan_completed=True,
            notify_scan_failed=True,
            notify_critical_finding=True,
        )
        db.add(demo_settings)

        print("[+] Creating verified demonstration target...")
        now = datetime.datetime.now(datetime.timezone.utc)
        demo_target = Target(
            user_id=demo_user.id,
            url="http://127.0.0.1:5000",
            normalized_url="http://127.0.0.1:5000",
            verification_method="meta_tag",
            verification_token="ethiosec-verify-4f7b2c9a1d8e5f03",
            is_verified=True,
            verified_at=now,
            last_checked_at=now,
        )
        db.add(demo_target)
        db.flush()

        print("[+] Creating completed demo scan with full module_progress...")
        module_progress = {
            "sqli": {
                "status": "done",
                "checks_run": 5,
                "checks_passed": 4,
                "findings_count": 1,
                "error": "",
            },
            "access_control": {
                "status": "done",
                "checks_run": 3,
                "checks_passed": 2,
                "findings_count": 1,
                "error": "",
            },
            "xss": {
                "status": "done",
                "checks_run": 4,
                "checks_passed": 3,
                "findings_count": 1,
                "error": "",
            },
            "headers": {
                "status": "done",
                "checks_run": 6,
                "checks_passed": 5,
                "findings_count": 1,
                "error": "",
            },
            "info_disclosure": {
                "status": "done",
                "checks_run": 4,
                "checks_passed": 3,
                "findings_count": 1,
                "error": "",
            },
            "cookies": {
                "status": "done",
                "checks_run": 3,
                "checks_passed": 3,
                "findings_count": 0,
                "error": "",
            },
            "cors": {
                "status": "done",
                "checks_run": 3,
                "checks_passed": 3,
                "findings_count": 0,
                "error": "",
            },
            "http_methods": {
                "status": "done",
                "checks_run": 4,
                "checks_passed": 4,
                "findings_count": 0,
                "error": "",
            },
            "https": {
                "status": "done",
                "checks_run": 3,
                "checks_passed": 3,
                "findings_count": 0,
                "error": "",
            },
            "exposed_files": {
                "status": "done",
                "checks_run": 5,
                "checks_passed": 5,
                "findings_count": 0,
                "error": "",
            },
            "auth_checks": {
                "status": "done",
                "checks_run": 4,
                "checks_passed": 4,
                "findings_count": 0,
                "error": "",
            },
        }

        demo_scan = Scan(
            user_id=demo_user.id,
            target_id=demo_target.id,
            target_url=demo_target.url,
            depth="standard",
            selected_modules=list(SCANNER_MODULE_KEYS),
            module_progress=module_progress,
            status="completed",
            progress=100,
            current_module="completed",
            security_score=56,
            started_at=now - datetime.timedelta(minutes=4, seconds=20),
            finished_at=now,
        )
        db.add(demo_scan)
        db.flush()

        print("[+] Creating sample findings covering every severity level...")
        findings_data = [
            Finding(
                scan_id=demo_scan.id,
                target_id=demo_target.id,
                module="sqli",
                severity="critical",
                status="open",
                title="SQL Injection Vulnerability in Authentication Endpoint",
                description="The username parameter on the /api/login endpoint is vulnerable to SQL injection via unescaped string concatenation.",
                evidence="Payload: ' OR 1=1-- resulted in unexpected HTTP 200 with admin profile data.",
                remediation="Use parameterized queries or ORM models with bound parameters. Never concatenate user input directly into SQL strings.",
                affected_url="http://127.0.0.1:5000/api/login",
                parameter="username",
                owasp_category="A03:2021-Injection",
                cwe_id="CWE-89",
                confidence="certain",
                http_method="POST",
            ),
            Finding(
                scan_id=demo_scan.id,
                target_id=demo_target.id,
                module="access_control",
                severity="high",
                status="open",
                title="Broken Access Control: Unprotected Administrative Portal",
                description="The administrative dashboard route /admin/users does not enforce authentication checks, exposing confidential user details.",
                evidence="GET /admin/users returned HTTP 200 with sensitive records without any Authorization header.",
                remediation="Enforce mandatory authentication and role-based authorization dependencies on all administrative routes.",
                affected_url="http://127.0.0.1:5000/admin/users",
                parameter=None,
                owasp_category="A01:2021-Broken Access Control",
                cwe_id="CWE-284",
                confidence="high",
                http_method="GET",
            ),
            Finding(
                scan_id=demo_scan.id,
                target_id=demo_target.id,
                module="xss",
                severity="medium",
                status="open",
                title="Reflected Cross-Site Scripting (XSS) in Query Parameter",
                description="The 'q' search parameter reflects user-supplied content directly into the DOM without HTML entity encoding.",
                evidence="Payload: <script>alert(1)</script> reflected verbatim inside <div> search results.",
                remediation="Properly context-encode all dynamic values before rendering them into the HTML document, and implement a strict Content Security Policy.",
                affected_url="http://127.0.0.1:5000/search?q=test",
                parameter="q",
                owasp_category="A03:2021-Injection",
                cwe_id="CWE-79",
                confidence="high",
                http_method="GET",
            ),
            Finding(
                scan_id=demo_scan.id,
                target_id=demo_target.id,
                module="headers",
                severity="low",
                status="open",
                title="Missing Content-Security-Policy (CSP) Header",
                description="The target web server does not return a Content-Security-Policy HTTP header, increasing susceptibility to cross-site script injection.",
                evidence="HTTP response headers omitted Content-Security-Policy.",
                remediation="Configure a restrictive Content-Security-Policy header specifying authorized script and style origins.",
                affected_url="http://127.0.0.1:5000/",
                parameter=None,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-16",
                confidence="certain",
                http_method="GET",
            ),
            Finding(
                scan_id=demo_scan.id,
                target_id=demo_target.id,
                module="info_disclosure",
                severity="info",
                status="confirmed",
                title="Server and Technology Banner Disclosure",
                description="The target web server explicitly discloses its underlying framework and server version in the Server and X-Powered-By response headers.",
                evidence="Server: Werkzeug/3.0.1 Python/3.14 disclosed in response headers.",
                remediation="Disable banner headers in web server configuration to minimize reconnaissance information available to attackers.",
                affected_url="http://127.0.0.1:5000/",
                parameter=None,
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                confidence="certain",
                http_method="GET",
            ),
        ]
        db.add_all(findings_data)

        print("[+] Creating sample report record...")
        demo_report = Report(
            scan_id=demo_scan.id,
            user_id=demo_user.id,
            report_format="pdf",
            summary={
                "target_url": demo_target.url,
                "scan_id": str(demo_scan.id),
                "security_score": 56,
                "counts": {
                    "critical": 1,
                    "high": 1,
                    "medium": 1,
                    "low": 1,
                    "info": 1,
                    "passed": 38,
                    "scanner_errors": 0,
                },
            },
            file_path=None,
            file_size_bytes=None,
        )
        db.add(demo_report)

        db.commit()
        print("[✓] Database seeding completed successfully!")
    except Exception as e:
        db.rollback()
        print(f"[!] Error seeding database: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
