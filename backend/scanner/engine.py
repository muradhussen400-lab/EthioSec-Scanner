import asyncio
import datetime
import httpx
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
        self.inventory = {}
        
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

    def _is_cancelled(self) -> bool:
        scan_refresh = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        return bool(scan_refresh and scan_refresh.status == "cancelled")

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
            if scan.status not in ("completed", "failed", "cancelled", "completed_with_errors"):
                scan.progress = self._calculate_progress()
            if stage_label:
                scan.stage = stage_label
            # Persist comprehensive telemetry payload inside checks column
            payload = {
                "completed_checks": self.checks_progress,
                "module_details": self.module_details,
                "timeline": self.timeline,
                "pipeline_stages": self.pipeline_stages,
                "inventory": self.inventory
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
        text = re.sub(r'(?i)(password|passwd|pwd|secret|token|api_key|apikey)\s*[:=]\s*([^\s&\"\']+)', r'\1=[REDACTED]', text)
        text = re.sub(r'(?i)(set-cookie|cookie)\s*[:=]\s*([^;\n]+)', r'\1=[REDACTED]', text)
        text = re.sub(r'(?i)(authorization)\s*[:=]\s*(bearer\s|basic\s)?([^\s\"\']+)', r'\1=\2[REDACTED]', text)
        return text

    def _add_finding(self, f_type: str, severity: str, status: str, title: str, description: str, 
                     evidence: str = None, impact: str = None, remediation: list = None, 
                     owasp: str = None, cwe: str = None, ai_explanation: str = None, 
                     url: str = None, parameter: str = None, http_method: str = None, 
                     request: str = None, response_summary: str = None, confidence: str = "HIGH",
                     verification_status: str = None):
        
        # Standardize verification status and legacy status
        if verification_status:
            verification_status = verification_status.upper()
            if verification_status == "SCANNER_ERROR":
                verification_status = "ERROR"
        else:
            st = (status or "").upper()
            if st in ("SCANNER_ERROR", "ERROR"):
                verification_status = "ERROR"
            elif st == "NOT_DETECTED":
                verification_status = "NOT_DETECTED"
            elif st == "INCONCLUSIVE":
                verification_status = "INCONCLUSIVE"
            elif st in ("BLOCKED", "SKIPPED", "NOT_TESTED", "POTENTIAL", "CONFIRMED"):
                verification_status = st
            elif st in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                # Rule: Never derive confirmation solely from severity.
                # Only explicit verification keywords in title establish CONFIRMED without explicit verification_status.
                if any(w in (title or "").lower() for w in ("confirmed", "verified", "bypass:", "injection confirmed")):
                    verification_status = "CONFIRMED"
                else:
                    verification_status = "POTENTIAL"
            else:
                verification_status = "POTENTIAL" if severity in ("critical", "high", "medium", "low") else "INCONCLUSIVE"

        if status not in ["HIGH", "MEDIUM", "LOW", "NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE", "CONFIRMED", "POTENTIAL", "BLOCKED", "SKIPPED", "NOT_TESTED", "open", "closed"]:
            status = severity.upper()
            
        evidence = self._redact_evidence(evidence) if evidence else None
        request = self._redact_evidence(request) if request else None
        
        # Deduplication preserving separate endpoints, methods, parameters, and verification status
        existing = self.db.query(Finding).filter(
            Finding.scan_id == self.scan_id,
            Finding.type == f_type,
            Finding.url == url,
            Finding.parameter == parameter,
            Finding.http_method == http_method,
            Finding.title == title,
            Finding.verification_status == verification_status
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
            verification_status=verification_status,
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
        
        # Truthful coverage and status telemetry
        if verification_status == "CONFIRMED":
            self.findings_count["confirmed"] = self.findings_count.get("confirmed", 0) + 1
        elif verification_status == "POTENTIAL":
            self.findings_count["potential"] = self.findings_count.get("potential", 0) + 1
        elif verification_status == "BLOCKED":
            self.findings_count["blocked"] = self.findings_count.get("blocked", 0) + 1
        elif verification_status == "SKIPPED":
            self.findings_count["skipped"] = self.findings_count.get("skipped", 0) + 1
        elif verification_status == "NOT_TESTED":
            self.findings_count["not_tested"] = self.findings_count.get("not_tested", 0) + 1
        elif verification_status == "NOT_DETECTED" or status == "NOT_DETECTED":
            self.findings_count["not_detected"] = self.findings_count.get("not_detected", 0) + 1
        elif verification_status == "INCONCLUSIVE" or status == "INCONCLUSIVE":
            self.findings_count["inconclusive"] = self.findings_count.get("inconclusive", 0) + 1
        elif verification_status in ("ERROR", "SCANNER_ERROR") or status in ("SCANNER_ERROR", "ERROR"):
            self.findings_count["scanner_error"] = self.findings_count.get("scanner_error", 0) + 1

        if severity in ("critical", "high", "medium", "low"):
            self.findings_count[severity] = self.findings_count.get(severity, 0) + 1
            if verification_status == "CONFIRMED":
                self.findings_count["total"] = self.findings_count.get("total", 0) + 1

    async def run_scan(self):
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            logger.error(f"Scan {self.scan_id} not found in database.")
            return

        scan.status = "validating"
        scan.stage = "Validating target security constraints"
        self._persist_state()
        
        target_url = scan.target_url or ""
        parsed_target = urlparse(target_url)
        if parsed_target.scheme.lower() not in ("http", "https"):
            if "://" not in target_url:
                target_url = "http://" + target_url
                parsed_target = urlparse(target_url)
            else:
                raise UnsafeTargetError(f"Unsupported or malformed URL scheme: '{parsed_target.scheme}'. Only HTTP and HTTPS are permitted.")
        if parsed_target.username or parsed_target.password:
            raise UnsafeTargetError("Target URL contains embedded credentials which are not permitted.")

        try:
            self._update_progress(0, "Validating target security constraints")
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
                self.module_details.get(k, {}).get("selected", False) 
                for k in ("sqli", "xss", "auth", "access_control", "exposed_files", "csrf", "ssrf")
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
                    scan.status = "crawling"
                    scan.stage = "Crawling target endpoints and attack surface"
                    self._persist_state()
                    self._update_stage("discovery", "running", "Discovering endpoints and attack surface…")
                    
                    if depth_param == "deep":
                        c_depth = 4
                        c_pages = 50
                    else:
                        c_depth = 2
                        c_pages = 15
                    
                    crawler = Crawler(target_url, client, max_pages=c_pages, max_depth=c_depth)
                    try:
                        crawl_results = await crawler.run()
                        self.inventory = crawl_results.get("inventory", {})
                        discovered_urls = crawl_results.get("urls", [target_url])
                        discovered_endpoints = crawl_results.get("endpoints", [])
                        discovered_forms = crawl_results.get("forms", [])
                        discovered_cookies = crawl_results.get("cookies", []) or crawl_results.get("inventory", {}).get("cookies", [])
                        self.discovered_cookies = discovered_cookies
                        if not discovered_urls:
                            discovered_urls = [target_url]
                        scan.status = "discovering"
                        scan.stage = f"Attack surface mapped: {len(discovered_urls)} URLs, {len(discovered_endpoints)} endpoints, {len(discovered_forms)} forms"
                        self._persist_state()
                        self._update_stage(
                            "discovery", "completed", 
                            f"Crawling complete: discovered {len(discovered_urls)} URLs, {len(discovered_endpoints)} endpoints, {len(discovered_forms)} forms."
                        )
                        self._update_pipeline_stage("dns_reachability", "completed", f"Target reachable: discovered {len(discovered_urls)} URLs, {len(discovered_endpoints)} endpoints.")
                    except Exception as crawl_err:
                        logger.warning(f"Crawling encountered exception: {crawl_err}")
                        discovered_urls = [target_url]
                        self.inventory["crawl_error"] = str(crawl_err)
                        self.inventory["partial_discovery"] = True
                        scan.stage = f"Crawling encountered error ({crawl_err}); proceeding with partial discovery at root URL."
                        self._persist_state()
                        self._update_stage("discovery", "inconclusive", f"Discovery incomplete due to crawl error ({crawl_err}). Falling back to root URL.")
                        self._update_pipeline_stage("dns_reachability", "inconclusive", f"Target partially reachable: crawl error ({crawl_err}); using root URL.")
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
                has_passive = any(self.module_details.get(k, {}).get("selected", False) for k in passive_modules)
                if has_passive:
                    scan.status = "scanning"
                    scan.stage = "Running passive security checks"
                    self._persist_state()
                    self._update_pipeline_stage("security_headers", "running", "Auditing security headers, SSL/TLS, and configuration…")
                    self._update_stage("passive_checks", "running", "Running passive security checks…")

                    from .checks.headers import check_security_headers
                    from .checks.cookies import check_cookies
                    from .checks.info_disclosure import check_info_disclosure
                    from .checks.exposed_files import check_exposed_files
                    from .checks.https import check_https
                    from .checks.http_methods import check_http_methods
                    from .checks.cors import check_cors
                    from .checks.misconfig import check_misconfig

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
                                await check_https(self, target_url, root_response, client=client)
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
                            else:
                                self._update_module("headers", "failed", "Headers check could not execute: root response unavailable.")
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
                            else:
                                self._update_module("cookies", "failed", "Cookie audit could not execute: root response unavailable.")
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
                            else:
                                self._update_module("info_disclosure", "failed", "Info disclosure check could not execute: root response unavailable.")
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

                    # 3h. Misconfiguration audit
                    if self.module_details["misconfig"]["selected"]:
                        self._update_module("misconfig", "running", "Auditing directory indexing, diagnostic endpoints, and debug traces…")
                        try:
                            await check_misconfig(self, target_url, client, root_response)
                            self._update_module("misconfig", "completed", "Security misconfiguration audit complete.")
                        except Exception as e:
                            logger.exception(f"Misconfiguration check error: {e}")
                            self._update_module("misconfig", "failed", f"Misconfiguration check failed: {str(e)}")

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
                active_modules = ["auth", "access_control", "sqli", "xss", "csrf", "ssrf"]
                has_active = any(self.module_details.get(k, {}).get("selected", False) for k in active_modules)

                if has_active:
                    scan.status = "verifying"
                    scan.stage = "Running active vulnerability checks"
                    self._persist_state()
                    self._update_stage("active_checks", "running", "Running active vulnerability checks…")

                    from .checks.auth import check_auth, AuthCoverageRecord
                    from .checks.access_control import check_access_control
                    from .checks.sqli import check_sqli, SQLiCoverageRecord
                    from .checks.xss import check_xss, XSSCoverageRecord

                    # 4a. Authentication Security
                    if self.module_details["auth"]["selected"]:
                        self._update_pipeline_stage("auth", "running", "Auditing authentication endpoints and form transmission…")
                        self._update_module("auth", "running", "Auditing authentication endpoints and form transmission…")
                        try:
                            auth_count_before = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "auth").count()
                            auth_context_1 = self.auth_context_1 or {}
                            auth_coverage = await check_auth(
                                self, 
                                discovered_urls, 
                                discovered_forms, 
                                client, 
                                auth_context_1,
                                endpoints=discovered_endpoints,
                                cookies=self.discovered_cookies,
                                mode=depth_param
                            )
                            auth_count_after = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "auth").count()
                            if auth_count_after == auth_count_before:
                                if hasattr(auth_coverage, "forms_tested") and (auth_coverage.forms_tested > 0 or (auth_coverage.endpoints_tested > 0 and auth_context_1)) and getattr(auth_coverage, "requests_completed", 0) > 0:
                                    self._add_finding("auth", "info", "NOT_DETECTED", "Authentication Security Checks Passed", "Audited authentication endpoints. No plaintext credential transmission or unvalidated forms were identified.", evidence=f"Tested attack surface on {getattr(auth_coverage, 'forms_tested', 0)} form(s) and {getattr(auth_coverage, 'endpoints_tested', 0)} endpoint(s).", url=target_url)
                                else:
                                    self._add_finding("auth", "info", "SKIPPED", "Authentication Checks Skipped", "No candidate authentication endpoints or login forms were available for active evaluation.", evidence="Zero candidate authentication attack surface evaluated.", url=target_url)
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
                                    if len(discovered_endpoints) > 0:
                                        self._add_finding("access_control", "info", "NOT_DETECTED", "Access Control Verified", "No broken object-level or tested access-control bypass was detected in the assessed endpoints and available authorization contexts.", evidence=f"Tested {len(discovered_endpoints)} endpoint(s). Cross-account authorization was evaluated where possible.", url=target_url)
                                    else:
                                        self._add_finding("access_control", "info", "NOT_TESTED", "Access Control Not Tested (No Endpoints Discovered)", "No API endpoints or parameterized routes were discovered across the crawled attack surface to evaluate object-level authorization.", evidence="Discovered candidate endpoints count is zero.", url=target_url)
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
                            
                            # Harvest discovered cookies for injection testing
                            active_cookies = list(getattr(self, "discovered_cookies", []))
                            if hasattr(self, "inventory") and isinstance(self.inventory, dict):
                                for c in self.inventory.get("cookies", []):
                                    c_n = c.get("name") if isinstance(c, dict) else getattr(c, "name", None)
                                    if c_n and not any((x.get("name") if isinstance(x, dict) else getattr(x, "name", None)) == c_n for x in active_cookies):
                                        active_cookies.append(c)
                            client_inner = getattr(client, "client", None)
                            if client_inner is not None:
                                cookies_obj = getattr(client_inner, "cookies", None)
                                if isinstance(cookies_obj, (dict, httpx.Cookies)):
                                    for c_name, c_val in cookies_obj.items():
                                        if not any((x.get("name") if isinstance(x, dict) else getattr(x, "name", None)) == c_name for x in active_cookies):
                                            active_cookies.append({"name": c_name, "value": c_val, "url": target_url})

                            sqli_cov = await check_sqli(
                                self, 
                                discovered_endpoints, 
                                discovered_forms, 
                                client, 
                                depth_param, 
                                cookies=active_cookies
                            )
                            sqli_count_after = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "sqli").count()
                            new_sqli = sqli_count_after - sqli_count_before

                            if new_sqli == 0:
                                if isinstance(sqli_cov, SQLiCoverageRecord):
                                    if sqli_cov.candidate_inputs_discovered == 0:
                                        ev_msg = "Target attack surface exposed 0 candidate input parameters or form fields. Automated SQL injection payload injection and differential baseline analysis could not be conducted."
                                        if getattr(sqli_cov, "cookies_excluded_policy", None):
                                            ev_msg += f" Discovered {sqli_cov.candidate_cookies_discovered} cookie(s) ({', '.join(sqli_cov.cookies_excluded_policy)}), all excluded by authentication preservation policy."
                                        self._add_finding(
                                            f_type="sqli",
                                            severity="info",
                                            status="INCONCLUSIVE",
                                            title="SQL Injection Assessment Inconclusive (Untested Scope)",
                                            description=sqli_cov.blocking_reason or "No injectable query parameters or HTML form inputs were discovered across the crawled attack surface.",
                                            evidence=ev_msg,
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

                                        cookie_notes = []
                                        if getattr(sqli_cov, "cookies_tested", 0) > 0:
                                            cookie_notes.append(f"{sqli_cov.cookies_tested} cookie(s)")
                                        if getattr(sqli_cov, "cookies_excluded_policy", None):
                                            cookie_notes.append(f"excluded session cookies: {', '.join(sqli_cov.cookies_excluded_policy)}")
                                        cookie_suffix = f" [including {'; '.join(cookie_notes)}]" if cookie_notes else ""

                                        self._add_finding(
                                            f_type="sqli",
                                            severity="info",
                                            status="NOT_DETECTED",
                                            title="SQL Injection Not Detected",
                                            description="No SQL injection vulnerabilities were detected in tested endpoints, form parameters, or cookies.",
                                            evidence=f"Tested {sqli_cov.inputs_tested} parameter(s) ({param_names_sample}){cookie_suffix} across {sqli_cov.requests_completed} HTTP requests using error-based, boolean differential, and timing checks. Baselines remained stable and no database error signatures, query anomalies, or reproducible delays were triggered.",
                                            remediation=["Maintain parameterized SQL queries and ORM abstractions."],
                                            owasp="A03:2021-Injection",
                                            url=target_url
                                        )
                                        self._update_module("sqli", "completed", f"Completed: tested {sqli_cov.inputs_tested} parameter(s) cleanly.")
                                else:
                                    self._update_module("sqli", "completed", "SQL injection checks complete.")
                            else:
                                self._update_module("sqli", "completed", f"Completed: identified {new_sqli} finding(s) across {getattr(sqli_cov, 'inputs_tested', 1)} tested input(s).")
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

                    # 4d. Cross-Site Request Forgery (CSRF)
                    if self.module_details.get("csrf", {}).get("selected", False):
                        self._update_module("csrf", "running", "Auditing forms and state changes for anti-CSRF protections…")
                        try:
                            from .checks.csrf import check_csrf
                            csrf_count_before = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "csrf").count()
                            await check_csrf(self, discovered_forms, client)
                            csrf_count_after = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "csrf").count()
                            if csrf_count_after == csrf_count_before:
                                if discovered_forms:
                                    self._add_finding(
                                        f_type="csrf",
                                        severity="info",
                                        status="NOT_DETECTED",
                                        verification_status="NOT_DETECTED",
                                        title="Anti-CSRF Controls Verified",
                                        description="Assessed forms and state-changing endpoints implement anti-CSRF tokens or SameSite cookie protection.",
                                        evidence=f"Audited {len(discovered_forms)} form(s) and endpoints. State-changing requests are protected.",
                                        remediation=["Maintain anti-CSRF token verification and SameSite cookie attributes."],
                                        owasp="A01:2021-Broken Access Control",
                                        url=target_url
                                    )
                                else:
                                    self._add_finding(
                                        f_type="csrf",
                                        severity="info",
                                        status="NOT_TESTED",
                                        verification_status="NOT_TESTED",
                                        title="CSRF Assessment Not Tested (No Forms Discovered)",
                                        description="The crawler identified 0 state-changing forms across the crawled attack surface.",
                                        evidence="Target exposed 0 forms across crawled scope. Automated anti-CSRF testing was not applicable.",
                                        owasp="A01:2021-Broken Access Control",
                                        url=target_url
                                    )
                            self._update_module("csrf", "completed", "CSRF checks completed.")
                        except Exception as e:
                            logger.exception(f"CSRF check error: {e}")
                            self._update_module("csrf", "failed", f"CSRF check failed: {str(e)}")

                    # 4e. Server-Side Request Forgery (SSRF)
                    if self.module_details.get("ssrf", {}).get("selected", False):
                        self._update_module("ssrf", "running", "Auditing URL/webhook parameters for safe scheme validation and SSRF defenses…")
                        try:
                            from .checks.ssrf import check_ssrf
                            ssrf_count_before = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "ssrf").count()
                            await check_ssrf(self, discovered_endpoints, client)
                            ssrf_count_after = self.db.query(Finding).filter(Finding.scan_id == self.scan_id, Finding.type == "ssrf").count()
                            if ssrf_count_after == ssrf_count_before:
                                has_candidate = any(
                                    any(cand in str(p).lower() for cand in ("url", "uri", "dest", "target", "link", "webhook", "callback"))
                                    for ep in (discovered_endpoints or [])
                                    for p in ep.get("params", [])
                                )
                                if has_candidate:
                                    self._add_finding(
                                        f_type="ssrf",
                                        severity="info",
                                        status="NOT_DETECTED",
                                        verification_status="NOT_DETECTED",
                                        title="SSRF Parameter Defenses Verified",
                                        description="Discovered URL/callback parameters enforce safe scheme validations and reject non-HTTP schemes.",
                                        evidence="Tested URL parameter inputs with non-HTTP URI schemes. Unsafe schemes were rejected.",
                                        remediation=["Enforce strict protocol allowlists (https only) and private IP/cloud metadata blacklists."],
                                        owasp="A10:2021-Server-Side Request Forgery (SSRF)",
                                        cwe="CWE-918: Server-Side Request Forgery (SSRF)",
                                        url=target_url
                                    )
                                else:
                                    self._add_finding(
                                        f_type="ssrf",
                                        severity="info",
                                        status="NOT_TESTED",
                                        verification_status="NOT_TESTED",
                                        title="Safe SSRF Assessment Not Tested (No URL Parameters Discovered)",
                                        description="The crawler identified 0 URL or callback parameters across discovered endpoints.",
                                        evidence="Target exposed 0 candidate URL-fetch inputs across crawled application scope.",
                                        owasp="A10:2021-Server-Side Request Forgery (SSRF)",
                                        url=target_url
                                    )
                            self._update_module("ssrf", "completed", "SSRF checks completed.")
                        except Exception as e:
                            logger.exception(f"SSRF check error: {e}")
                            self._update_module("ssrf", "failed", f"SSRF check failed: {str(e)}")

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
        scan.status = "reporting"
        scan.stage = "Calculating security score and compiling assessment report"
        self._persist_state()
        self._update_pipeline_stage("report_generation", "running", "Calculating security score and finalizing assessment…")
        self._update_stage("finalization", "running", "Calculating security score and finalizing assessment…")
        
        # Calculate score strictly penalizing eligible confirmed vulnerabilities
        if self._is_cancelled():
            logger.info(f"Scan {self.scan_id} was cancelled; skipping final score calculation.")
            return

        def _is_confirmed_vuln(f) -> bool:
            v_stat = (getattr(f, "verification_status", None) or "").upper()
            stat = (getattr(f, "status", None) or "").upper()
            if stat in ("NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE", "NOT_TESTED", "SKIPPED", "BLOCKED", "ERROR", "POTENTIAL"):
                return False
            if v_stat in ("NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE", "NOT_TESTED", "SKIPPED", "BLOCKED", "ERROR", "POTENTIAL"):
                return False
            return v_stat == "CONFIRMED" or stat == "CONFIRMED"

        findings = self.db.query(Finding).filter(Finding.scan_id == self.scan_id).all()
        critical = sum(1 for f in findings if f.severity == "critical" and _is_confirmed_vuln(f))
        high = sum(1 for f in findings if f.severity == "high" and _is_confirmed_vuln(f))
        medium = sum(1 for f in findings if f.severity == "medium" and _is_confirmed_vuln(f))
        low = sum(1 for f in findings if f.severity == "low" and _is_confirmed_vuln(f))

        confirmed_vulns = critical + high + medium + low
        completed_clean = sum(1 for f in findings if (f.status or "").upper() == "NOT_DETECTED")
        inconclusive_count = sum(1 for f in findings if (f.status or "").upper() == "INCONCLUSIVE")

        has_failed_module = any(
            m.get("status") == "failed"
            for m in self.module_details.values()
            if m.get("selected")
        )
        has_scanner_error = self.findings_count.get("scanner_error", 0) > 0

        # Determine coverage adequacy:
        # If no vulnerabilities were confirmed, but also ZERO checks completed clean (all inconclusive/errors)
        if confirmed_vulns == 0 and completed_clean == 0:
            score = None
            scan.security_score = None
            stage_msg = f"Assessment complete with coverage limitations ({inconclusive_count} inconclusive check(s)). Security score unavailable due to untested scope."
        else:
            base_score = 100 - (critical * 25) - (high * 14) - (medium * 7) - (low * 3)
            # If any checks failed or were inconclusive, do not award a perfect 100 score
            if confirmed_vulns == 0 and (has_failed_module or has_scanner_error or inconclusive_count > 0):
                score = max(5, min(85, base_score - (15 if (has_failed_module or has_scanner_error) else 5)))
                stage_msg = f"Assessment completed with coverage limitations. Security score: {score}/100."
            else:
                score = max(5, min(100, base_score))
                stage_msg = f"Assessment complete. Overall security score: {score}/100."
            scan.security_score = score

        if has_failed_module or has_scanner_error:
            scan.status = "completed_with_errors"
            scan.stage = "Assessment completed with module or probe errors"
        else:
            scan.status = "completed"
            scan.stage = "Assessment completed successfully"

        scan.finished_at = self._now_iso()
        scan.progress = 100
        
        self._update_pipeline_stage("report_generation", "completed", stage_msg)
        self._update_stage("finalization", "completed", stage_msg)
        self._persist_state(stage_label=scan.stage)
        logger.info(f"Scan {self.scan_id} finished successfully with score {score} (status={scan.status}, confirmed={confirmed_vulns}, clean={completed_clean}, inconclusive={inconclusive_count}).")


# Module-level check runners available for scanner execution and test mocking
from .checks.auth import check_auth, AuthCoverageRecord
from .checks.access_control import check_access_control
from .checks.sqli import check_sqli, SQLiCoverageRecord
from .checks.xss import check_xss, XSSCoverageRecord
from .checks.csrf import check_csrf
from .checks.ssrf import check_ssrf


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
            if scan and scan.status not in ("completed", "completed_with_errors", "cancelled"):
                scan.status = "failed"
                scan.stage = f"Background Task Error: {str(e)}"
                scan.finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                db.commit()
        except Exception as db_err:
            logger.error(f"Failed to record scan failure in database: {db_err}")
    finally:
        db.close()
