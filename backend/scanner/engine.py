import asyncio
import datetime
from sqlalchemy.orm import Session
from models import Scan, Finding
from database import SessionLocal
from urllib.parse import urlparse
from .safety import is_safe_url, UnsafeTargetError
from .http_client import SafeHTTPClient
from .crawler import Crawler

class SecurityScanner:
    def __init__(self, db: Session, scan_id: str):
        self.db = db
        self.scan_id = scan_id
        
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        self.target_id = scan.target_id if hasattr(scan, 'target_id') else None
        
        self.checks_progress = {"headers": False, "ssl": False, "dns": False, "meta": False, "owasp": False, "ai": False}
        self.findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "passed": 0}

    def _update_progress(self, progress: int, stage: str):
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if scan:
            scan.progress = progress
            scan.stage = stage
            scan.checks = self.checks_progress
            self.db.commit()

    def _add_finding(self, f_type: str, severity: str, status: str, title: str, description: str, evidence: str = None, impact: str = None, remediation: list = None, owasp: str = None, cwe: str = None, ai_explanation: str = None, url: str = None, parameter: str = None, http_method: str = None, request: str = None, response_summary: str = None):
        # Deduplication check
        existing = self.db.query(Finding).filter(
            Finding.scan_id == self.scan_id,
            Finding.type == f_type,
            Finding.url == url,
            Finding.parameter == parameter
        ).first()
        if existing:
            return

        finding = Finding(
            scan_id=self.scan_id,
            target_id=self.target_id,
            type=f_type,
            severity=severity,
            status=status,
            title=title,
            description=description,
            evidence=evidence,
            impact=impact,
            remediation=remediation or [],
            owasp=owasp,
            cwe=cwe,
            ai_explanation=ai_explanation,
            url=url,
            parameter=parameter,
            http_method=http_method,
            request=request,
            response_summary=response_summary
        )
        self.db.add(finding)
        self.db.commit()
        
        if status == "passed":
            self.findings_count["passed"] += 1
        elif severity in self.findings_count:
            self.findings_count[severity] += 1

    async def run_scan(self):
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            return

        scan.status = "running"
        self.db.commit()
        
        target_url = scan.target_url
        if not target_url.startswith("http"):
            target_url = "http://" + target_url

        try:
            # 1. Target Validation
            self._update_progress(5, "Validating target")
            is_safe_url(target_url)
            
            async with SafeHTTPClient() as client:
                # 2. Endpoint Discovery (Crawling)
                self._update_progress(15, "Discovering endpoints")
                crawler = Crawler(target_url, client, max_pages=15, max_depth=2)
                crawl_results = await crawler.run()
                discovered_urls = crawl_results["urls"]
                discovered_endpoints = crawl_results.get("endpoints", [])
                discovered_forms = crawl_results.get("forms", [])
                if not discovered_urls:
                    discovered_urls = [target_url]
                
                # 3. Passive Checks (Phase 3)
                self._update_progress(40, "Running passive security checks")
                
                from .checks.headers import check_security_headers
                from .checks.cookies import check_cookies
                from .checks.info_disclosure import check_info_disclosure
                from .checks.exposed_files import check_exposed_files
                from .checks.auth import check_auth
                from .checks.access_control import check_access_control
                from .checks.https import check_https
                from .checks.http_methods import check_http_methods
                from .checks.cors import check_cors
                
                # Check root URL response for general headers/cookies/info
                try:
                    root_response = await client.get(target_url)
                    await check_security_headers(self, target_url, root_response)
                    await check_cookies(self, target_url, root_response)
                    await check_info_disclosure(self, target_url, root_response)
                    await check_https(self, target_url, root_response)
                    await check_cors(self, target_url, root_response)
                except Exception as e:
                    self._add_finding("error", "info", "error", "Root URL Check Error", f"Failed to check root URL: {e}", evidence=str(e))

                await check_exposed_files(self, target_url, client)
                await check_http_methods(self, target_url, client)
                
                # Auth & Session Security (Stage 8)
                auth_context_1 = scan.auth_context_1 or {}
                auth_context_2 = scan.auth_context_2 or {}
                
                await check_auth(self, discovered_urls, discovered_forms, client, auth_context_1)
                
                # Access Control (Stage 7)
                await check_access_control(self, discovered_endpoints, client, auth_context_1, auth_context_2)
                
                # 4. Active Checks (Phase 4)
                self._update_progress(70, "Running active vulnerability checks")
                
                from .checks.sqli import check_sqli
                from .checks.xss import check_xss
                
                await check_sqli(self, discovered_endpoints, discovered_forms, client)
                await check_xss(self, discovered_endpoints, discovered_forms, client)
                
                self.checks_progress["headers"] = True
                self.checks_progress["ssl"] = True
                self.checks_progress["owasp"] = True
                self.checks_progress["ai"] = True
                
        except UnsafeTargetError as e:
            self._add_finding("error", "high", "open", "Target Validation Failed", str(e), evidence=str(e))
            scan.status = "failed"
            scan.finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.db.commit()
            return
        except Exception as e:
            self._add_finding("error", "high", "open", "Scan Error", f"Critical error during scan: {str(e)}", evidence=str(e))
            scan.status = "failed"
            scan.finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.db.commit()
            return

        self._update_progress(100, "Scoring and building the report")
        
        # Calculate score (100 - penalties)
        score = 100 - (self.findings_count["critical"] * 25) - (self.findings_count["high"] * 14) - (self.findings_count["medium"] * 7) - (self.findings_count["low"] * 3)
        score = max(5, min(100, score))
        
        scan.status = "completed"
        scan.security_score = score
        scan.finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.db.commit()

async def run_scan_task(scan_id: str):
    db = SessionLocal()
    try:
        scanner = SecurityScanner(db, scan_id)
        await scanner.run_scan()
    finally:
        db.close()
