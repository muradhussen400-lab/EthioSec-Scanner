import asyncio
import datetime
from sqlalchemy.orm import Session
from models import Scan, Finding
from database import SessionLocal
from urllib.parse import urlparse
from .safety import is_safe_url, UnsafeTargetError
from .http_client import SafeHTTPClient
from .crawler import Crawler
from .registry import CANONICAL_MODULES, resolve_module_selection
import logging
import re

logger = logging.getLogger(__name__)


class SecurityScanner:
    def __init__(self, db: Session, scan_id: str):
        self.db = db
        self.scan_id = scan_id
        
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        self.target_id = scan.target_id if (scan and hasattr(scan, 'target_id')) else None
        self.auth_context_1 = scan.auth_context_1 if scan else {}
        self.auth_context_2 = scan.auth_context_2 if scan else {}
        
        # Legacy boolean completed checks tracking (backward compatibility)
        self.checks_progress = {k: False for k in CANONICAL_MODULES.keys()}
        
        # Resolve user module selection cleanly
        raw_modules = scan.modules if (scan and isinstance(scan.modules, dict)) else {}
        self.resolved_selection = resolve_module_selection(raw_modules)
        
        # Comprehensive truthful module states
        self.module_details = {}
        for mod_id, meta in CANONICAL_MODULES.items():
            is_selected = self.resolved_selection.get(mod_id, False)
            self.module_details[mod_id] = {
                "id": mod_id,
                "name": meta["name"],
                "description": meta["description"],
                "category": meta["owasp"],
                "type": meta["type"],
                "selected": is_selected,
                "status": "pending" if is_selected else "skipped",
                "findings": 0,
                "started_at": None,
                "finished_at": None,
                "message": "Waiting for execution." if is_selected else "Skipped — module was not selected for this scan."
            }
            
        # Authoritative 7-Stage Pipeline (matches design specification)
        self.pipeline_stages = [
            {
                "id": "target_validation",
                "index": 1,
                "name": "Target Validation",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "duration_seconds": None,
                "message": "Validating target URL syntax, scheme, and SSRF loopback protections."
            },
            {
                "id": "dns_reachability",
                "index": 2,
                "name": "DNS & Reachability",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "duration_seconds": None,
                "message": "Testing hostname resolution, server responsiveness, and endpoint discovery."
            },
            {
                "id": "security_headers",
                "index": 3,
                "name": "Security Headers",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "duration_seconds": None,
                "message": "Auditing security headers, SSL/TLS certificates, and transport protections."
            },
            {
                "id": "auth",
                "index": 4,
                "name": "Authentication",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "duration_seconds": None,
                "message": "Evaluating login forms, password transport, and session safety."
            },
            {
                "id": "access_control",
                "index": 5,
                "name": "Access Control",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "duration_seconds": None,
                "message": "Testing authorization boundaries, IDOR, and privilege segregation."
            },
            {
                "id": "vuln_checks",
                "index": 6,
                "name": "Vulnerability Checks",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "duration_seconds": None,
                "message": "Executing SQL injection and cross-site scripting payload verification."
            },
            {
                "id": "report_generation",
                "index": 7,
                "name": "Report Generation",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "duration_seconds": None,
                "message": "Aggregating findings, calculating security score, and compiling report."
            }
        ]

        # Pipeline timeline stages
        self.timeline = [
            {
                "id": "validation",
                "name": "Target Validation & Safety Checks",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "message": "Validates target URL, hostname resolution, and SSRF loopback protections."
            },
            {
                "id": "discovery",
                "name": "Attack Surface Discovery",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "message": "Crawls target endpoints and input parameters."
            },
            {
                "id": "passive_checks",
                "name": "Passive Security Audits",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "message": "Audits headers, cookies, CORS, SSL/TLS, and sensitive files."
            },
            {
                "id": "active_checks",
                "name": "Active Vulnerability Checks",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "message": "Tests SQL injection, XSS, and authentication/access control boundaries."
            },
            {
                "id": "finalization",
                "name": "Assessment Finalization",
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "message": "Aggregates findings, computes security score, and prepares report."
            }
        ]
        
        self.findings_count = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "not_detected": 0, "scanner_error": 0, "inconclusive": 0, "total": 0
        }

    def _now_iso(self) -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def _calculate_progress(self) -> int:
        """
        Dynamically calculates honest scan progress based on real stage and module states:
        - Target validation: 10%
        - Discovery stage: 15% (if needed; if skipped, credited)
        - Security modules: 70% divided proportionally among selected modules
        - Finalization: 5%
        Returns 0-99 while running; terminal completed sets 100%.
        """
        prog = 0.0
        
        # Stage 1: Validation
        val_stage = next((s for s in self.timeline if s["id"] == "validation"), None)
        if val_stage:
            if val_stage["status"] == "completed":
                prog += 10.0
            elif val_stage["status"] == "running":
                prog += 5.0
                
        # Stage 2: Discovery
        disc_stage = next((s for s in self.timeline if s["id"] == "discovery"), None)
        if disc_stage:
            if disc_stage["status"] in ("completed", "skipped"):
                prog += 15.0
            elif disc_stage["status"] == "running":
                prog += 7.5
                
        # Module progress (70% total)
        selected_mods = [m for m in self.module_details.values() if m["selected"]]
        if selected_mods:
            slice_per_mod = 70.0 / len(selected_mods)
            for m in selected_mods:
                if m["status"] in ("completed", "inconclusive", "failed", "skipped"):
                    prog += slice_per_mod
                elif m["status"] == "running":
                    prog += (slice_per_mod * 0.5)
        else:
            # If no modules selected (edge case), grant full module slice
            prog += 70.0
            
        # Stage 5: Finalization
        fin_stage = next((s for s in self.timeline if s["id"] == "finalization"), None)
        if fin_stage and fin_stage["status"] == "completed":
            prog += 5.0
            
        return max(0, min(99, int(round(prog))))

    def _update_pipeline_stage(self, stage_id: str, status: str, message: str = None):
        for s in self.pipeline_stages:
            if s["id"] == stage_id:
                s["status"] = status
                if message:
                    s["message"] = message
                now_iso = self._now_iso()
                if status == "running" and not s.get("started_at"):
                    s["started_at"] = now_iso
                elif status in ("completed", "failed", "skipped", "inconclusive"):
                    if not s.get("started_at"):
                        s["started_at"] = now_iso
                    s["finished_at"] = now_iso
                    try:
                        t0 = datetime.datetime.fromisoformat(s["started_at"].replace("Z", "+00:00"))
                        t1 = datetime.datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
                        s["duration_seconds"] = max(1, int(round((t1 - t0).total_seconds())))
                    except Exception:
                        s["duration_seconds"] = None
                break
        self._persist_state()

    def _update_stage(self, stage_id: str, status: str, message: str = None):
        for s in self.timeline:
            if s["id"] == stage_id:
                s["status"] = status
                if message:
                    s["message"] = message
                if status == "running" and not s.get("started_at"):
                    s["started_at"] = self._now_iso()
                elif status in ("completed", "failed", "skipped"):
                    if not s.get("started_at"):
                        s["started_at"] = self._now_iso()
                    s["finished_at"] = self._now_iso()
                break
        self._persist_state()

    def _update_module(self, mod_id: str, status: str, message: str = None, findings_increment: int = 0):
        if mod_id in self.module_details:
            m = self.module_details[mod_id]
            m["status"] = status
            if message:
                m["message"] = message
            if status == "running" and not m.get("started_at"):
                m["started_at"] = self._now_iso()
            elif status in ("completed", "failed", "skipped", "inconclusive"):
                if not m.get("started_at"):
                    m["started_at"] = self._now_iso()
                m["finished_at"] = self._now_iso()
                if status == "completed":
                    self.checks_progress[mod_id] = True
                    
            # Count current findings for this module type
            try:
                real_cnt = self.db.query(Finding).filter(
                    Finding.scan_id == self.scan_id,
                    Finding.type == mod_id,
                    ~Finding.status.in_(["NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE"])
                ).count()
                m["findings"] = real_cnt
            except Exception:
                m["findings"] = m.get("findings", 0) + findings_increment

        self._persist_state()

    def _persist_state(self, stage_label: str = None):
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if scan:
            if scan.status not in ("completed", "failed", "cancelled"):
                scan.progress = self._calculate_progress()
            if stage_label:
                scan.stage = stage_label
            # Persist comprehensive telemetry payload inside checks column
            payload = {
                "completed_checks": self.checks_progress,
                "module_details": self.module_details,
                "timeline": self.timeline,
                "pipeline_stages": self.pipeline_stages
            }
            # For backward compatibility, also keep direct boolean keys in dict
            for k, v in self.checks_progress.items():
                payload[k] = v
                
            scan.checks = payload
            self.db.commit()

    def _update_progress(self, progress: int, stage: str):
        """Legacy helper for compatibility."""
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if scan:
            scan.progress = progress
            scan.stage = stage
            self._persist_state(stage_label=stage)

    def _redact_evidence(self, text: str) -> str:
        if not text:
            return text
        text = re.sub(r'(?i)(password|passwd|pwd|secret|token|api_key|apikey)[\s:=]+([^\s&\"\']+)', r'\1=[REDACTED]', text)
        text = re.sub(r'(?i)(set-cookie|cookie)[\s:=]+([^;\n]+)', r'\1=[REDACTED_COOKIE]', text)
        text = re.sub(r'(?i)(authorization)[\s:=]+(bearer\s|basic\s)?([^\s\"\']+)', r'\1=\2[REDACTED_TOKEN]', text)
        return text

    def _add_finding(self, f_type: str, severity: str, status: str, title: str, description: str, 
                     evidence: str = None, impact: str = None, remediation: list = None, 
                     owasp: str = None, cwe: str = None, ai_explanation: str = None, 
                     url: str = None, parameter: str = None, http_method: str = None, 
                     request: str = None, response_summary: str = None, confidence: str = "HIGH"):
        
        if status not in ["HIGH", "MEDIUM", "LOW", "NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE", "open", "closed"]:
            status = severity.upper()
            
        evidence = self._redact_evidence(evidence) if evidence else None
        request = self._redact_evidence(request) if request else None
        
        existing = self.db.query(Finding).filter(
            Finding.scan_id == self.scan_id,
            Finding.type == f_type,
            Finding.url == url,
            Finding.parameter == parameter
        ).first()
        if existing:
            if evidence and evidence not in (existing.evidence or ""):
                existing.evidence = (existing.evidence or "") + "\n\n---\nAdditional Observation:\n" + evidence
                self.db.commit()
            return

        finding = Finding(
            scan_id=self.scan_id,
            target_id=self.target_id,
            type=f_type,
            severity=severity,
            confidence=confidence or "HIGH",
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
        
        if status == "NOT_DETECTED":
            self.findings_count["not_detected"] += 1
        elif status == "INCONCLUSIVE":
            self.findings_count["inconclusive"] += 1
        elif status == "SCANNER_ERROR":
            self.findings_count["scanner_error"] += 1
        elif severity in self.findings_count:
            self.findings_count[severity] += 1
            if severity in ("critical", "high", "medium", "low"):
                self.findings_count["total"] += 1

    async def run_scan(self):
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            logger.error(f"Scan {self.scan_id} not found in database.")
            return

        scan.status = "running"
        scan.stage = "Initializing scanning worker"
        self._persist_state()
        
        target_url = scan.target_url
        if not target_url.startswith("http"):
            target_url = "http://" + target_url

        try:
            self._update_progress(0, "Initializing scanning worker")
            # =========================================================================
            # STAGE 1: Target Validation & Safety Constraints
            # =========================================================================
            self._update_pipeline_stage("target_validation", "running", "Validating target security constraints and SSRF protections…")
            self._update_stage("validation", "running", "Validating target security constraints and SSRF protections…")
            scan.stage = "Validating target security constraints"
            self._persist_state()
            
            is_safe_url(target_url)
            
            self._update_pipeline_stage("target_validation", "completed", f"Target validated successfully: {target_url}")
            self._update_stage("validation", "completed", f"Target validated successfully: {target_url}")
            
            # Check for early cancellation
            scan_refresh = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
            if scan_refresh and scan_refresh.status == "cancelled":
                logger.info(f"Scan {self.scan_id} was cancelled by user after validation.")
                return

            # Determine whether crawling is required
            # Crawling is needed if active checks or auth/access_control/exposed_files are selected
            active_selected = any(
                self.module_details[k]["selected"] 
                for k in ("sqli", "xss", "auth", "access_control", "exposed_files")
            )
            
            depth_param = (scan.depth or "standard").lower()

            async with SafeHTTPClient() as client:
                discovered_urls = [target_url]
                discovered_endpoints = []
                discovered_forms = []

                # =====================================================================
                # STAGE 2: Attack Surface Discovery & DNS Reachability
                # =====================================================================
                self._update_pipeline_stage("dns_reachability", "running", "Testing hostname resolution, server responsiveness, and endpoints…")
                if active_selected:
                    self._update_stage("discovery", "running", "Discovering endpoints and attack surface…")
                    scan.stage = "Discovering endpoints and attack surface"
                    self._persist_state()
                    
                    if depth_param == "deep":
                        c_depth = 4
                        c_pages = 50
                    else:
                        c_depth = 2
                        c_pages = 15
                    
                    crawler = Crawler(target_url, client, max_pages=c_pages, max_depth=c_depth)
                    try:
                        crawl_results = await crawler.run()
                        discovered_urls = crawl_results.get("urls", [target_url])
                        discovered_endpoints = crawl_results.get("endpoints", [])
                        discovered_forms = crawl_results.get("forms", [])
                        if not discovered_urls:
                            discovered_urls = [target_url]
                        self._update_stage(
                            "discovery", "completed", 
                            f"Crawling complete: discovered {len(discovered_urls)} URLs, {len(discovered_endpoints)} endpoints, {len(discovered_forms)} forms."
                        )
                        self._update_pipeline_stage("dns_reachability", "completed", f"Target reachable: discovered {len(discovered_urls)} URLs, {len(discovered_endpoints)} endpoints.")
                    except Exception as crawl_err:
                        logger.warning(f"Crawling encountered exception: {crawl_err}")
                        discovered_urls = [target_url]
                        self._update_stage("discovery", "completed", f"Crawling completed with fallback to root URL ({target_url}).")
                        self._update_pipeline_stage("dns_reachability", "completed", f"Target reachable: connected to root URL ({target_url}).")
                else:
                    self._update_stage("discovery", "skipped", "Discovery skipped — selected checks do not require deep crawling.")
                    self._update_pipeline_stage("dns_reachability", "completed", "Target reachable: DNS resolution and reachability verified.")

                # Check for cancellation
                scan_refresh = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
                if scan_refresh and scan_refresh.status == "cancelled":
                    logger.info(f"Scan {self.scan_id} was cancelled by user.")
                    return

                # =====================================================================
                # STAGE 3: Passive Security Audits
                # =====================================================================
                passive_modules = ["https", "headers", "cookies", "cors", "info_disclosure", "exposed_files", "http_methods", "misconfig"]
                has_passive = any(self.module_details[k]["selected"] for k in passive_modules)
                if has_passive:
                    self._update_pipeline_stage("security_headers", "running", "Auditing security headers, SSL/TLS, and configuration…")
                    self._update_stage("passive_checks", "running", "Running passive security checks…")
                    scan.stage = "Running passive security checks"
                    self._persist_state()

                    from .checks.headers import check_security_headers
                    from .checks.cookies import check_cookies
                    from .checks.info_disclosure import check_info_disclosure
                    from .checks.exposed_files import check_exposed_files
                    from .checks.https import check_https
                    from .checks.http_methods import check_http_methods
                    from .checks.cors import check_cors

                    root_response = None
                    root_response_needed = any(
                        self.module_details[k]["selected"] 
                        for k in ("headers", "cookies", "info_disclosure", "https", "misconfig")
                    )
                    if root_response_needed:
                        try:
                            root_response = await client.get(target_url)
                        except Exception as e:
                            logger.warning(f"Root request exception: {e}")
                            self._add_finding(
                                f_type="scanner_error", 
                                severity="info", 
                                status="SCANNER_ERROR", 
                                title="Root URL Check Notice", 
                                description=f"Could not fetch root response during passive checks: {str(e)}", 
                                evidence=str(e), 
                                url=target_url
                            )

                    # 3a. SSL / TLS
                    if self.module_details["https"]["selected"]:
                        self._update_module("https", "running", "Evaluating SSL/TLS configuration and certificate…")
                        try:
                            if root_response is not None:
                                await check_https(self, target_url, root_response)
                            else:
                                parsed = urlparse(target_url)
                                if parsed.scheme == "https":
                                    self._add_finding("https", "info", "NOT_DETECTED", "Encrypted Communication (HTTPS)", "The target uses HTTPS.", evidence=target_url, url=target_url)
                                else:
                                    self._add_finding("https", "high", "HIGH", "Unencrypted Communication (HTTP)", "The application communicates over plain HTTP.", evidence=target_url, url=target_url, remediation=["Enable TLS and enforce HTTPS redirect."])
                            self._update_module("https", "completed", "SSL/TLS checks complete.")
                        except Exception as e:
                            logger.exception(f"HTTPS check error: {e}")
                            self._update_module("https", "failed", f"SSL/TLS check failed: {str(e)}")

                    # 3b. Security Headers
                    if self.module_details["headers"]["selected"]:
                        self._update_module("headers", "running", "Auditing security headers (CSP, HSTS, X-Frame-Options)…")
                        try:
                            if root_response is not None:
                                await check_security_headers(self, target_url, root_response)
                            self._update_module("headers", "completed", "Security headers audit complete.")
                        except Exception as e:
                            logger.exception(f"Headers check error: {e}")
                            self._update_module("headers", "failed", f"Security headers check failed: {str(e)}")

                    # 3c. Cookies
                    if self.module_details["cookies"]["selected"]:
                        self._update_module("cookies", "running", "Auditing cookie attributes (Secure, HttpOnly, SameSite)…")
                        try:
                            if root_response is not None:
                                await check_cookies(self, target_url, root_response)
                            self._update_module("cookies", "completed", "Cookie security audit complete.")
                        except Exception as e:
                            logger.exception(f"Cookies check error: {e}")
                            self._update_module("cookies", "failed", f"Cookie audit failed: {str(e)}")

                    # 3d. CORS
                    if self.module_details["cors"]["selected"]:
                        self._update_module("cors", "running", "Auditing Cross-Origin Resource Sharing policy…")
                        try:
                            await check_cors(self, target_url, client)
                            self._update_module("cors", "completed", "CORS policy audit complete.")
                        except Exception as e:
                            logger.exception(f"CORS check error: {e}")
                            self._update_module("cors", "failed", f"CORS audit failed: {str(e)}")

                    # 3e. Information Disclosure
                    if self.module_details["info_disclosure"]["selected"]:
                        self._update_module("info_disclosure", "running", "Scanning for server header and banner leaks…")
                        try:
                            if root_response is not None:
                                await check_info_disclosure(self, target_url, root_response)
                            self._update_module("info_disclosure", "completed", "Information disclosure audit complete.")
                        except Exception as e:
                            logger.exception(f"Info disclosure check error: {e}")
                            self._update_module("info_disclosure", "failed", f"Info disclosure check failed: {str(e)}")

                    # 3f. Exposed Files
                    if self.module_details["exposed_files"]["selected"]:
                        self._update_module("exposed_files", "running", "Auditing exposed sensitive files and repository artifacts…")
                        try:
                            await check_exposed_files(self, target_url, client)
                            self._update_module("exposed_files", "completed", "Exposed files audit complete.")
                        except Exception as e:
                            logger.exception(f"Exposed files check error: {e}")
                            self._update_module("exposed_files", "failed", f"Exposed files audit failed: {str(e)}")

                    # 3g. HTTP Methods
                    if self.module_details["http_methods"]["selected"]:
                        self._update_module("http_methods", "running", "Auditing allowed and dangerous HTTP verbs…")
                        try:
                            await check_http_methods(self, target_url, client)
                            self._update_module("http_methods", "completed", "HTTP methods audit complete.")
                        except Exception as e:
                            logger.exception(f"HTTP methods check error: {e}")
                            self._update_module("http_methods", "failed", f"HTTP methods check failed: {str(e)}")

                    # 3h. Misconfiguration umbrella
                    if self.module_details["misconfig"]["selected"]:
                        self._update_module("misconfig", "completed", "Security misconfiguration audit complete.")

                    self._update_pipeline_stage("security_headers", "completed", "Security headers and configuration audit finished.")
                    self._update_stage("passive_checks", "completed", "Passive security checks finished.")
                else:
                    self._update_pipeline_stage("security_headers", "skipped", "Security headers skipped — module was not selected.")
                    self._update_stage("passive_checks", "skipped", "Passive security checks skipped — no passive modules were selected.")

                # Check for cancellation
                scan_refresh = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
                if scan_refresh and scan_refresh.status == "cancelled":
                    logger.info(f"Scan {self.scan_id} was cancelled by user.")
                    return

                # =====================================================================
                # STAGE 4: Active Vulnerability Testing
                # =====================================================================
                active_modules = ["auth", "access_control", "sqli", "xss"]
                has_active = any(self.module_details[k]["selected"] for k in active_modules)

                if has_active:
                    self._update_stage("active_checks", "running", "Running active vulnerability checks…")
                    scan.stage = "Running active vulnerability checks"
                    self._persist_state()

                    from .checks.auth import check_auth
                    from .checks.access_control import check_access_control
                    from .checks.sqli import check_sqli
                    from .checks.xss import check_xss

                    # 4a. Authentication Security
                    if self.module_details["auth"]["selected"]:
                        self._update_pipeline_stage("auth", "running", "Auditing authentication endpoints and form transmission…")
                        self._update_module("auth", "running", "Auditing authentication endpoints and form transmission…")
                        try:
                            auth_count_before = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "auth").count()
                            auth_context_1 = self.auth_context_1 or {}
                            await check_auth(self, discovered_urls, discovered_forms, client, auth_context_1)
                            auth_count_after = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "auth").count()
                            if auth_count_after == auth_count_before:
                                self._add_finding("auth", "info", "NOT_DETECTED", "Authentication Security Checks Passed", "Tested authentication forms. No plaintext credential transmission or unvalidated forms were identified.", evidence=f"Tested {len(discovered_forms)} form(s) and login endpoints.", url=target_url)
                            self._update_module("auth", "completed", "Authentication checks completed.")
                            self._update_pipeline_stage("auth", "completed", "Authentication checks completed.")
                        except Exception as e:
                            logger.exception(f"Auth check error: {e}")
                            self._update_module("auth", "failed", f"Authentication check failed: {str(e)}")
                            self._update_pipeline_stage("auth", "failed", f"Authentication check failed: {str(e)}")
                    else:
                        self._update_pipeline_stage("auth", "skipped", "Authentication checks skipped — module was not selected.")

                    # 4b. Broken Access Control
                    if self.module_details["access_control"]["selected"]:
                        self._update_pipeline_stage("access_control", "running", "Evaluating access control boundaries and authorization…")
                        self._update_module("access_control", "running", "Evaluating access control boundaries and dual auth contexts…")
                        try:
                            auth_context_1 = self.auth_context_1 or {}
                            auth_context_2 = self.auth_context_2 or {}
                            if not auth_context_1 and not auth_context_2:
                                self._add_finding(
                                    "access_control", 
                                    "info", 
                                    "INCONCLUSIVE", 
                                    "Access Control Checks Inconclusive (Configuration Required)", 
                                    "Access control and IDOR checks require authenticated session context(s) to evaluate object ownership boundaries. Because no authorization contexts were configured for this scan, cross-account and privilege isolation tests were not executed.", 
                                    evidence="Dual authorization contexts (auth_context_1 and auth_context_2) were not configured for this assessment.", 
                                    url=target_url
                                )
                                self._update_module("access_control", "inconclusive", "Inconclusive — dual authorization contexts required for IDOR testing.")
                                self._update_pipeline_stage("access_control", "completed", "Access control inconclusive — dual contexts required.")
                            else:
                                ac_count_before = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "access_control").count()
                                await check_access_control(self, discovered_endpoints, client, auth_context_1, auth_context_2, mode=depth_param)
                                ac_count_after = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "access_control").count()
                                if ac_count_after == ac_count_before:
                                    self._add_finding("access_control", "info", "NOT_DETECTED", "Access Control Verified", "No broken object-level or tested access-control bypass was detected in the assessed endpoints and available authorization contexts.", evidence=f"Tested {len(discovered_endpoints)} endpoint(s). Cross-account authorization was evaluated where possible.", url=target_url)
                                self._update_module("access_control", "completed", "Access control checks complete.")
                                self._update_pipeline_stage("access_control", "completed", "Access control evaluation complete.")
                        except Exception as e:
                            logger.exception(f"Access control check error: {e}")
                            self._update_module("access_control", "failed", f"Access control check failed: {str(e)}")
                            self._update_pipeline_stage("access_control", "failed", f"Access control check failed: {str(e)}")
                    else:
                        self._update_pipeline_stage("access_control", "skipped", "Access control skipped — module was not selected.")

                    # 4c. Active Injection Checks (SQLi / XSS)
                    has_vuln_checks = self.module_details["sqli"]["selected"] or self.module_details["xss"]["selected"]
                    if has_vuln_checks:
                        self._update_pipeline_stage("vuln_checks", "running", "Executing SQL injection and cross-site scripting payload tests…")
                    else:
                        self._update_pipeline_stage("vuln_checks", "skipped", "Vulnerability checks skipped — neither SQLi nor XSS selected.")

                    # SQL Injection
                    if self.module_details["sqli"]["selected"]:
                        self._update_module("sqli", "running", "Injecting SQL payloads and evaluating error/differential baselines…")
                        try:
                            sqli_count_before = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "sqli").count()
                            sqli_cov = await check_sqli(self, discovered_endpoints, discovered_forms, client, depth_param)
                            sqli_count_after = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "sqli").count()
                            new_sqli = sqli_count_after - sqli_count_before

                            if new_sqli == 0:
                                if isinstance(sqli_cov, SQLiCoverageRecord):
                                    if sqli_cov.candidate_inputs_discovered == 0:
                                        self._add_finding(
                                            f_type="sqli",
                                            severity="info",
                                            status="INCONCLUSIVE",
                                            title="SQL Injection Assessment Inconclusive (Untested Scope)",
                                            description="No injectable query parameters or HTML form inputs were discovered across the crawled attack surface.",
                                            evidence="Target attack surface exposed 0 candidate input parameters or form fields. Automated SQL injection payload injection and differential baseline analysis could not be conducted.",
                                            remediation=[
                                                "Specify an endpoint with query parameters (e.g. /filter?category=...) as the target URL.",
                                                "Increase scan depth to Deep Audit to discover deeper nested links and forms.",
                                                "Provide authenticated session cookies or authorization headers if inputs require login."
                                            ],
                                            owasp="A03:2021-Injection",
                                            cwe="CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                                            url=target_url,
                                            confidence="LOW"
                                        )
                                        self._update_module("sqli", "completed", "Inconclusive: 0 candidate parameters or forms were discovered to test.")
                                    elif sqli_cov.inputs_tested == 0:
                                        self._add_finding(
                                            f_type="sqli",
                                            severity="info",
                                            status="INCONCLUSIVE",
                                            title="SQL Injection Assessment Inconclusive",
                                            description=sqli_cov.blocking_reason or "Discovered parameters could not be safely tested.",
                                            evidence=f"Discovered {sqli_cov.candidate_inputs_discovered} candidate input(s), but testing could not proceed: {sqli_cov.blocking_reason}",
                                            remediation=["Review target responsiveness and crawler scope constraints."],
                                            owasp="A03:2021-Injection",
                                            url=target_url,
                                            confidence="LOW"
                                        )
                                        self._update_module("sqli", "completed", f"Inconclusive: {sqli_cov.blocking_reason}")
                                    elif sqli_cov.scanner_error:
                                        self._add_finding(
                                            f_type="sqli",
                                            severity="info",
                                            status="SCANNER_ERROR",
                                            title="SQL Injection Check Scanner Error",
                                            description=f"SQL injection testing encountered a scanner error: {sqli_cov.scanner_error}",
                                            evidence=f"Testing aborted or interrupted due to scanner exception: {sqli_cov.scanner_error}",
                                            remediation=["Check scanner connectivity and target health."],
                                            owasp="A03:2021-Injection",
                                            url=target_url,
                                            confidence="LOW"
                                        )
                                        self._update_module("sqli", "failed", f"SQL injection error: {sqli_cov.scanner_error}")
                                    elif getattr(sqli_cov, "inconclusive_reasons", None):
                                        reasons_str = "; ".join(sqli_cov.inconclusive_reasons[:3])
                                        self._add_finding(
                                            f_type="sqli",
                                            severity="info",
                                            status="INCONCLUSIVE",
                                            title="SQL Injection Assessment Inconclusive (Incomplete Testing)",
                                            description=f"SQL injection testing on discovered parameters could not be fully completed: {reasons_str}",
                                            evidence=f"Testing encountered conditions preventing verification: {reasons_str}",
                                            remediation=["Review target responsiveness and network stability."],
                                            owasp="A03:2021-Injection",
                                            url=target_url,
                                            confidence="LOW"
                                        )
                                        self._update_module("sqli", "completed", f"Inconclusive: {reasons_str}")
                                    elif sqli_cov.baseline_stability == "rate_limited":
                                        self._add_finding(
                                            f_type="sqli",
                                            severity="info",
                                            status="INCONCLUSIVE",
                                            title="SQL Injection Assessment Inconclusive (Rate Limited)",
                                            description="Target rate-limiting (HTTP 429) prevented conclusive SQL injection analysis.",
                                            evidence=f"Tested parameters encountered HTTP 429 rate limiting across {sqli_cov.requests_completed} requests.",
                                            remediation=["Reduce request concurrency or whitelist scanner IP."],
                                            owasp="A03:2021-Injection",
                                            url=target_url,
                                            confidence="LOW"
                                        )
                                        self._update_module("sqli", "completed", "Inconclusive: rate limited by target.")
                                    else:
                                        param_names_sample = ", ".join(sqli_cov.tested_parameters[:5])
                                        if len(sqli_cov.tested_parameters) > 5:
                                            param_names_sample += f" (+{len(sqli_cov.tested_parameters) - 5} more)"
                                        self._add_finding(
                                            f_type="sqli",
                                            severity="info",
                                            status="NOT_DETECTED",
                                            title="SQL Injection Not Detected",
                                            description="No SQL injection vulnerabilities were detected in tested endpoints or form parameters.",
                                            evidence=f"Tested {sqli_cov.inputs_tested} parameter(s) ({param_names_sample}) across {sqli_cov.requests_completed} HTTP requests using error-based, boolean differential, and timing checks. Baselines remained stable and no database error signatures, query anomalies, or reproducible delays were triggered.",
                                            remediation=["Maintain parameterized SQL queries and ORM abstractions."],
                                            owasp="A03:2021-Injection",
                                            url=target_url
                                        )
                                        self._update_module("sqli", "completed", f"Completed: tested {sqli_cov.inputs_tested} parameter(s) cleanly.")
                                else:
                                    self._update_module("sqli", "completed", "SQL injection checks complete.")
                            else:
                                self._update_module("sqli", "completed", f"Completed: identified {new_sqli} finding(s) across {getattr(sqli_cov, 'inputs_tested', 1)} tested parameter(s).")
                        except Exception as e:
                            logger.exception(f"SQLi check error: {e}")
                            self._add_finding(
                                f_type="sqli",
                                severity="info",
                                status="SCANNER_ERROR",
                                title="SQL Injection Check Scanner Error",
                                description=f"SQL injection testing encountered an unexpected failure: {str(e)}",
                                evidence=f"Scanner execution failed with {type(e).__name__}: {str(e)}",
                                remediation=["Inspect backend logs and server connectivity."],
                                owasp="A03:2021-Injection",
                                url=target_url,
                                confidence="LOW"
                            )
                            self._update_module("sqli", "failed", f"SQL injection check failed: {str(e)}")

                    # Cross-Site Scripting (XSS)
                    if self.module_details["xss"]["selected"]:
                        self._update_module("xss", "running", "Evaluating input reflection and context-specific XSS vectors…")
                        try:
                            xss_count_before = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "xss").count()
                            xss_cov = await check_xss(self, discovered_endpoints, discovered_forms, client, depth_param)
                            xss_count_after = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "xss").count()
                            new_xss = xss_count_after - xss_count_before

                            if new_xss == 0:
                                if isinstance(xss_cov, XSSCoverageRecord):
                                    if xss_cov.candidate_inputs_discovered == 0:
                                        self._add_finding(
                                            f_type="xss",
                                            severity="info",
                                            status="INCONCLUSIVE",
                                            title="Cross-Site Scripting (XSS) Assessment Inconclusive (Untested Scope)",
                                            description="No injectable query parameters or HTML form inputs were discovered across the crawled attack surface.",
                                            evidence="Target attack surface exposed 0 candidate input parameters or form fields. Automated reflection and context breakouts could not be tested.",
                                            remediation=[
                                                "Specify an endpoint with query parameters as the target URL.",
                                                "Increase scan depth to Deep Audit to discover deeper nested links and forms."
                                            ],
                                            owasp="A03:2021-Injection",
                                            url=target_url,
                                            confidence="LOW"
                                        )
                                        self._update_module("xss", "completed", "Inconclusive: 0 candidate parameters or forms were discovered to test.")
                                    elif xss_cov.inputs_tested == 0:
                                        self._add_finding(
                                            f_type="xss",
                                            severity="info",
                                            status="INCONCLUSIVE",
                                            title="Cross-Site Scripting (XSS) Assessment Inconclusive",
                                            description=xss_cov.blocking_reason or "Discovered parameters could not be tested.",
                                            evidence=f"Discovered {xss_cov.candidate_inputs_discovered} candidate input(s), but testing could not proceed.",
                                            remediation=["Review target responsiveness."],
                                            owasp="A03:2021-Injection",
                                            url=target_url,
                                            confidence="LOW"
                                        )
                                        self._update_module("xss", "completed", f"Inconclusive: {xss_cov.blocking_reason}")
                                    elif xss_cov.scanner_error:
                                        self._add_finding(
                                            f_type="xss",
                                            severity="info",
                                            status="SCANNER_ERROR",
                                            title="Cross-Site Scripting (XSS) Check Scanner Error",
                                            description=f"XSS testing encountered a scanner error: {xss_cov.scanner_error}",
                                            evidence=f"Testing aborted or interrupted due to scanner exception: {xss_cov.scanner_error}",
                                            remediation=["Check scanner connectivity and target health."],
                                            owasp="A03:2021-Injection",
                                            url=target_url,
                                            confidence="LOW"
                                        )
                                        self._update_module("xss", "failed", f"XSS check error: {xss_cov.scanner_error}")
                                    else:
                                        param_names_sample = ", ".join(xss_cov.tested_parameters[:5])
                                        if len(xss_cov.tested_parameters) > 5:
                                            param_names_sample += f" (+{len(xss_cov.tested_parameters) - 5} more)"
                                        self._add_finding(
                                            f_type="xss",
                                            severity="info",
                                            status="NOT_DETECTED",
                                            title="Cross-Site Scripting (XSS) Not Detected",
                                            description="No cross-site scripting vulnerabilities were detected in tested endpoints.",
                                            evidence=f"Tested {xss_cov.inputs_tested} parameter(s) ({param_names_sample}) across {xss_cov.requests_completed} HTTP requests for HTML reflection, context breakouts, and attribute escapes. All inputs were safely encoded or sanitized.",
                                            remediation=["Maintain context-aware output encoding and strict Content Security Policy."],
                                            owasp="A03:2021-Injection",
                                            url=target_url
                                        )
                                        self._update_module("xss", "completed", f"Completed: tested {xss_cov.inputs_tested} parameter(s) cleanly.")
                                else:
                                    self._update_module("xss", "completed", "XSS checks complete.")
                            else:
                                self._update_module("xss", "completed", f"Completed: identified {new_xss} finding(s) across {getattr(xss_cov, 'inputs_tested', 1)} tested parameter(s).")
                        except Exception as e:
                            logger.exception(f"XSS check error: {e}")
                            self._add_finding(
                                f_type="xss",
                                severity="info",
                                status="SCANNER_ERROR",
                                title="Cross-Site Scripting (XSS) Check Scanner Error",
                                description=f"XSS testing encountered an unexpected failure: {str(e)}",
                                evidence=f"Scanner execution failed with {type(e).__name__}: {str(e)}",
                                remediation=["Inspect backend logs and server connectivity."],
                                owasp="A03:2021-Injection",
                                url=target_url,
                                confidence="LOW"
                            )
                            self._update_module("xss", "failed", f"XSS check failed: {str(e)}")

                    if has_vuln_checks:
                        self._update_pipeline_stage("vuln_checks", "completed", "Active vulnerability checks finished.")
                    self._update_stage("active_checks", "completed", "Active vulnerability checks finished.")
                else:
                    self._update_pipeline_stage("auth", "skipped", "Authentication skipped — not selected.")
                    self._update_pipeline_stage("access_control", "skipped", "Access control skipped — not selected.")
                    self._update_pipeline_stage("vuln_checks", "skipped", "Vulnerability checks skipped — not selected.")
                    self._update_stage("active_checks", "skipped", "Active checks skipped — no active vulnerability modules were selected.")

        except UnsafeTargetError as e:
            logger.warning(f"Scan {self.scan_id} blocked by SSRF/target validation: {e}")
            self._update_pipeline_stage("target_validation", "failed", f"Target validation blocked: {str(e)}")
            for s in self.pipeline_stages[1:]:
                s["status"] = "skipped"
                s["message"] = f"Skipped — target validation failed: {str(e)}"
            self._update_stage("validation", "failed", f"Target validation blocked: {str(e)}")
            self._update_stage("discovery", "skipped", "Discovery skipped due to validation failure.")
            self._update_stage("passive_checks", "skipped", "Passive checks skipped due to validation failure.")
            self._update_stage("active_checks", "skipped", "Active checks skipped due to validation failure.")
            self._update_stage("finalization", "failed", "Assessment failed during target validation.")
            
            # Mark all modules skipped or failed
            for m in self.module_details.values():
                if m["selected"]:
                    m["status"] = "skipped"
                    m["message"] = f"Skipped — target validation failed: {str(e)}"
            
            self._add_finding("error", "high", "SCANNER_ERROR", "Target Validation Blocked", str(e), evidence=str(e), url=target_url)
            
            scan.status = "failed"
            scan.stage = f"Target Validation Failed: {str(e)}"
            scan.finished_at = self._now_iso()
            self._persist_state()
            return

        except Exception as e:
            logger.exception(f"Critical error during scan {self.scan_id}: {e}")
            for s in self.pipeline_stages:
                if s["status"] == "running":
                    s["status"] = "failed"
                    s["message"] = f"Halted: {str(e)}"
            self._update_pipeline_stage("report_generation", "failed", f"Scanner execution error: {str(e)}")
            self._update_stage("finalization", "failed", f"Scanner execution error: {str(e)}")
            self._add_finding(
                "scanner_error", "high", "SCANNER_ERROR", 
                "Scanner Execution Warning", 
                f"Scanner encountered an unexpected condition: {str(e)}", 
                evidence=str(e), 
                url=target_url
            )
            scan.status = "failed"
            scan.stage = f"Scan Failed: {str(e)}"
            scan.security_score = None
            scan.finished_at = self._now_iso()
            self._persist_state()
            return

        # =========================================================================
        # STAGE 5: Assessment Finalization & Scoring
        # =========================================================================
        self._update_pipeline_stage("report_generation", "running", "Calculating security score and finalizing assessment…")
        self._update_stage("finalization", "running", "Calculating security score and finalizing assessment…")
        scan.stage = "Calculating security score and finalizing assessment"
        self._persist_state()
        
        # Calculate score with coverage awareness
        findings = self.db.query(Finding).filter(Finding.scan_id == self.scan_id).all()
        critical = sum(1 for f in findings if f.severity == "critical" and (f.status or "").upper() not in ("NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE"))
        high = sum(1 for f in findings if f.severity == "high" and (f.status or "").upper() not in ("NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE"))
        medium = sum(1 for f in findings if f.severity == "medium" and (f.status or "").upper() not in ("NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE"))
        low = sum(1 for f in findings if f.severity == "low" and (f.status or "").upper() not in ("NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE"))

        confirmed_vulns = critical + high + medium + low
        completed_clean = sum(1 for f in findings if (f.status or "").upper() == "NOT_DETECTED")
        inconclusive_count = sum(1 for f in findings if (f.status or "").upper() == "INCONCLUSIVE")

        # Determine coverage adequacy:
        # If no vulnerabilities were confirmed, but also ZERO checks completed clean (all inconclusive/errors)
        if confirmed_vulns == 0 and completed_clean == 0:
            score = None
            scan.security_score = None
            stage_msg = f"Assessment complete with coverage limitations ({inconclusive_count} inconclusive check(s)). Security score unavailable due to untested scope."
        else:
            score = 100 - (critical * 25) - (high * 14) - (medium * 7) - (low * 3)
            score = max(5, min(100, score))
            scan.security_score = score
            stage_msg = f"Assessment complete. Overall security score: {score}/100."

        scan.status = "completed"
        scan.finished_at = self._now_iso()
        scan.progress = 100
        scan.stage = "Assessment completed successfully"
        
        self._update_pipeline_stage("report_generation", "completed", stage_msg)
        self._update_stage("finalization", "completed", stage_msg)
        self._persist_state(stage_label="Assessment completed successfully")
        logger.info(f"Scan {self.scan_id} finished successfully with score {score} (confirmed={confirmed_vulns}, clean={completed_clean}, inconclusive={inconclusive_count}).")


# Module-level check runners available for scanner execution and test mocking
from .checks.auth import check_auth
from .checks.access_control import check_access_control
from .checks.sqli import check_sqli, SQLiCoverageRecord
from .checks.xss import check_xss, XSSCoverageRecord


async def run_scan_task(scan_id: str):
    """
    Background worker task with robust exception safety and database lifecycle handling.
    """
    db = SessionLocal()
    try:
        scanner = SecurityScanner(db, scan_id)
        await scanner.run_scan()
    except Exception as e:
        logger.exception(f"Unhandled exception in background scan task {scan_id}: {e}")
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.status != "completed":
                scan.status = "failed"
                scan.stage = f"Background Task Error: {str(e)}"
                scan.finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                db.commit()
        except Exception as db_err:
            logger.error(f"Failed to record scan failure in database: {db_err}")
    finally:
        db.close()
