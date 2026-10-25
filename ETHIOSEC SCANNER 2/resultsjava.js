/* ==========================================================================
   ETHIOSECSCAN — SCAN RESULTS CONTROLLER (resultsjava.js)
   Strict Real Backend API Integration (/api/scans/{id}/results, /api/scans)
   ========================================================================== */

async function initResultsController() {
    const API_BASE = "http://127.0.0.1:8000/api";
    function getAuthToken() {
        const token = localStorage.getItem("token");
        if (!token) {
            window.location.href = "login.html";
            return "";
        }
        return token;
    }

    // UI Helpers
    const UI = {
        escapeHTML: (str) => {
            if (!str) return "";
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        },
        timeAgo: (dateString) => {
            if (!dateString) return "—";
            try {
                const date = new Date(dateString);
                if (isNaN(date.getTime())) return "—";
                const diff = Date.now() - date.getTime();
                const mins = Math.floor(diff / 60000);
                if (mins < 1) return "Just now";
                if (mins < 60) return `${mins}m ago`;
                const hours = Math.floor(mins / 60);
                if (hours < 24) return `${hours}h ago`;
                const days = Math.floor(hours / 24);
                return `${days}d ago`;
            } catch {
                return "—";
            }
        },
        formatDate: (dateString) => {
            if (!dateString) return "—";
            try {
                const date = new Date(dateString);
                if (isNaN(date.getTime())) return "—";
                return date.toLocaleDateString("en-US", {
                    month: "short",
                    day: "numeric",
                    year: "numeric",
                    hour: "2-digit",
                    minute: "2-digit"
                });
            } catch {
                return "—";
            }
        },
        calculateDuration: (startStr, finishStr) => {
            if (!startStr || !finishStr) return null;
            try {
                const start = new Date(startStr).getTime();
                const finish = new Date(finishStr).getTime();
                if (isNaN(start) || isNaN(finish) || finish < start) return null;
                const totalSeconds = Math.max(0, Math.round((finish - start) / 1000));
                if (totalSeconds < 60) return `${totalSeconds}s`;
                const mins = Math.floor(totalSeconds / 60);
                const secs = totalSeconds % 60;
                return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
            } catch {
                return null;
            }
        },
        toast: (msg, type = "info") => {
            const toastEl = document.getElementById("toast");
            if (toastEl) {
                toastEl.textContent = msg;
                toastEl.className = `toast show ${type === "error" ? "error" : ""}`;
                setTimeout(() => toastEl.classList.remove("show"), 3500);
            }
        },
        getQueryParam: (name) => {
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get(name);
        }
    };

    // DOM Elements
    const targetBreadcrumb = document.getElementById("targetBreadcrumb");
    const scanIdBadge = document.getElementById("scanIdBadge");
    const btnExportJson = document.getElementById("btnExportJson");
    const inProgressBanner = document.getElementById("inProgressBanner");
    const linkLiveMonitor = document.getElementById("linkLiveMonitor");

    const ringProgress = document.getElementById("ringProgress");
    const scoreValue = document.getElementById("scoreValue");
    const verdictTitle = document.getElementById("verdictTitle");
    const verdictDesc = document.getElementById("verdictDesc");
    const metaStatusPill = document.getElementById("metaStatusPill");
    const metaStatusText = document.getElementById("metaStatusText");
    const metaScanId = document.getElementById("metaScanId");
    const metaProfile = document.getElementById("metaProfile");
    const metaScannedAt = document.getElementById("metaScannedAt");
    const metaDurationItem = document.getElementById("metaDurationItem");
    const metaDuration = document.getElementById("metaDuration");

    // Summary counts (6 Distinct Primary Categories)
    const countCritical = document.getElementById("countCritical");
    const countHigh = document.getElementById("countHigh");
    const countMedium = document.getElementById("countMedium");
    const countLow = document.getElementById("countLow");
    const countPassed = document.getElementById("countPassed");
    const countError = document.getElementById("countError");

    // Assessment Coverage Section
    const coverageSection = document.getElementById("coverageSection");
    const coverageList = document.getElementById("coverageList");
    const coverageCountPill = document.getElementById("coverageCountPill");

    // Modal AI Explain Action
    const btnModalAiExplain = document.getElementById("btnModalAiExplain");
    let activeModalFinding = null;

    // Filter controls
    const findingSearchInput = document.getElementById("findingSearchInput");
    const btnFindingSearchClear = document.getElementById("btnFindingSearchClear");
    const filterSeverity = document.getElementById("filterSeverity");
    const filterModule = document.getElementById("filterModule");
    const filterStatus = document.getElementById("filterStatus");
    const btnResetFilters = document.getElementById("btnResetFilters");
    const summaryPillsRow = document.getElementById("summaryPillsRow");

    // Findings List
    const findingsList = document.getElementById("findingsList");
    const findingsCountBadge = document.getElementById("findingsCountBadge");

    // Details Modal
    const detailModalOverlay = document.getElementById("detailModalOverlay");
    const modalCloseBtn = document.getElementById("modalCloseBtn");
    const btnModalClose = document.getElementById("btnModalClose");
    const dSeverityBadge = document.getElementById("dSeverityBadge");
    const dStatusBadge = document.getElementById("dStatusBadge");
    const dConfidence = document.getElementById("dConfidence");
    const dModuleTag = document.getElementById("dModuleTag");
    const dTitle = document.getElementById("dTitle");
    const dEndpoint = document.getElementById("dEndpoint");
    const dDescription = document.getElementById("dDescription");
    const dParamBlock = document.getElementById("dParamBlock");
    const dParameterMethod = document.getElementById("dParameterMethod");
    const dEvidenceBlock = document.getElementById("dEvidenceBlock");
    const dEvidence = document.getElementById("dEvidence");
    const dImpactBlock = document.getElementById("dImpactBlock");
    const dImpact = document.getElementById("dImpact");
    const dAiBlock = document.getElementById("dAiBlock");
    const dAiText = document.getElementById("dAiText");
    const dRemediationBlock = document.getElementById("dRemediationBlock");
    const dRemediationList = document.getElementById("dRemediationList");
    const dOwaspTag = document.getElementById("dOwaspTag");
    const dCweTag = document.getElementById("dCweTag");

    // State Variables
    let currentScanId = UI.getQueryParam("id") || UI.getQueryParam("scan_id");
    let scanResultData = null;
    let allFindings = [];
    let filteredFindings = [];
    const CIRCUMFERENCE = 2 * Math.PI * 58; // 364.42px

    renderLoading();

    // Step 1: Resolve Scan ID if not supplied
    if (!currentScanId) {
        try {
            const token = getAuthToken();
            const res = await fetch(`${API_BASE}/scans?limit=1`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                if (data.scans && data.scans.length > 0) {
                    currentScanId = data.scans[0].id;
                    history.replaceState(null, "", `results.html?id=${encodeURIComponent(currentScanId)}`);
                }
            }
        } catch (e) {
            console.error("Could not auto-resolve latest scan ID:", e);
        }
    }

    if (!currentScanId) {
        renderNoScanState();
        return;
    }

    currentScanId = String(currentScanId).trim();
    if (!/^[a-zA-Z0-9_\-]{1,64}$/.test(currentScanId)) {
        renderNotFoundError("Invalid scan identifier format. Please select a valid assessment from Scan History.");
        return;
    }

    // Step 2: Load Scan Results
    async function loadScanResults() {
        renderLoading();
        const token = getAuthToken();

        try {
            // Concurrent fetch: results + scan record metadata (to get exact timestamps)
            const [resultsRes, scanListRes] = await Promise.all([
                fetch(`${API_BASE}/scans/${encodeURIComponent(currentScanId)}/results`, {
                    headers: { "Authorization": `Bearer ${token}` }
                }),
                fetch(`${API_BASE}/scans?limit=50`, {
                    headers: { "Authorization": `Bearer ${token}` }
                }).catch(() => null)
            ]);

            // Handle HTTP 409: Scan Still Running
            if (resultsRes.status === 409) {
                renderInProgressState();
                return;
            }

            // Handle HTTP 404: Scan Not Found
            if (resultsRes.status === 404) {
                renderNotFoundError("Scan record was not found or has been deleted.");
                return;
            }

            // Handle HTTP 401 / 403: Auth Expired
            if (resultsRes.status === 401 || resultsRes.status === 403) {
                renderAuthExpiredError();
                return;
            }

            if (!resultsRes.ok) {
                throw new Error(`Server returned HTTP ${resultsRes.status}`);
            }

            scanResultData = await resultsRes.json();
            allFindings = scanResultData.findings || [];

            // Extract additional duration metadata if available
            let scanMetaRecord = null;
            if (scanListRes && scanListRes.ok) {
                try {
                    const listData = await scanListRes.json();
                    scanMetaRecord = (listData.scans || []).find(s => s.id === currentScanId);
                } catch (_) { }
            }

            paintOverview(scanResultData, scanMetaRecord);
            renderAssessmentCoverage(scanResultData);
            populateModuleFilter(allFindings);
            applyFindingsFilters();

        } catch (err) {
            console.error("Error loading scan results:", err);
            renderGeneralError(err.message || "Unable to retrieve scan results from backend.");
        }
    }

    // Paint Overview Banner and Score Ring
    function paintOverview(result, metaRecord) {
        const target = result.target || "Target Web Application";
        const depth = (result.depth || "standard").toUpperCase();
        const isScoreAvailable = result.security_score !== undefined && result.security_score !== null;
        const score = isScoreAvailable ? Number(result.security_score) : null;
        const counts = result.counts || {};

        // Breadcrumb and IDs
        if (targetBreadcrumb) {
            targetBreadcrumb.textContent = target;
            targetBreadcrumb.href = target.startsWith("http") ? target : `https://${target}`;
        }
        const scanId = String(result.scan_id || result.id || currentScanId || "");
        if (scanIdBadge) {
            scanIdBadge.textContent = `#${scanId}`;
        }
        if (metaScanId) metaScanId.textContent = scanId.slice(0, 12);
        if (metaProfile) metaProfile.textContent = depth;
        if (metaScannedAt) metaScannedAt.textContent = UI.formatDate(result.scanned_at || metaRecord?.created_at);

        // Calculate Duration if timestamps exist
        const duration = UI.calculateDuration(metaRecord?.created_at, metaRecord?.finished_at || result.scanned_at);
        if (duration && metaDurationItem && metaDuration) {
            metaDurationItem.style.display = "flex";
            metaDuration.textContent = duration;
        }

        // Animate Circular Score Ring
        if (ringProgress) {
            ringProgress.style.strokeDasharray = CIRCUMFERENCE;
            if (score === null) {
                ringProgress.style.strokeDashoffset = CIRCUMFERENCE;
                ringProgress.style.stroke = "var(--sev-inconclusive)";
            } else {
                const offset = Math.max(0, CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE);
                requestAnimationFrame(() => {
                    ringProgress.style.strokeDashoffset = offset;
                    // Color interpolation
                    if (score >= 80) {
                        ringProgress.style.stroke = "var(--sev-passed)";
                    } else if (score >= 60) {
                        ringProgress.style.stroke = "var(--sev-medium)";
                    } else {
                        ringProgress.style.stroke = "var(--brand-red)";
                    }
                });
            }
        }

        // Animate Numeric Score
        if (scoreValue) {
            if (score === null) {
                scoreValue.textContent = "—";
            } else {
                animateNumber(scoreValue, score);
            }
        }

        // Calculate Exact 6 Primary Categories from findings & backend counts
        let cCrit = 0, cHigh = 0, cMed = 0, cLow = 0, cPass = 0, cErr = 0, cInconc = 0;

        if (allFindings.length > 0) {
            allFindings.forEach(f => {
                const sev = (f.severity || "low").toLowerCase();
                const stat = (f.status || "NOT_DETECTED").toUpperCase();

                if (stat === "SCANNER_ERROR" || f.type === "scanner_error") {
                    cErr++;
                } else if (stat === "NOT_DETECTED") {
                    cPass++;
                } else if (stat === "INCONCLUSIVE") {
                    cInconc++;
                } else if (stat === "NOT_TESTED" || stat === "SKIPPED" || stat === "BLOCKED" || (f.verification_status || "").toUpperCase() === "NOT_TESTED") {
                    // Informational coverage notices, skipped checks, and uninspected telemetry do not inflate vulnerability counts
                } else {
                    // Confirmed or potential vulnerability finding
                    if (sev === "critical") cCrit++;
                    else if (sev === "high") cHigh++;
                    else if (sev === "medium") cMed++;
                    else cLow++; // low or info
                }
            });
        } else if (counts) {
            cCrit = Number(counts.critical || 0);
            const rawHigh = Number(counts.high || 0);
            cHigh = Math.max(0, rawHigh - cCrit);
            cMed = Number(counts.medium || 0);
            cLow = Number(counts.low || 0);
            cPass = Number(counts.not_detected || 0);
            cErr = Number(counts.scanner_error || 0);
            cInconc = Number(counts.inconclusive || 0);
        }

        if (countCritical) animateNumber(countCritical, cCrit);
        if (countHigh) animateNumber(countHigh, cHigh);
        if (countMedium) animateNumber(countMedium, cMed);
        if (countLow) animateNumber(countLow, cLow);
        if (countPassed) animateNumber(countPassed, cPass);
        if (countError) animateNumber(countError, cErr);

        // Contextual Evidence-Based Verdict Header
        if (verdictTitle && verdictDesc) {
            const totalConfirmed = cCrit + cHigh + cMed + cLow;

            if (cCrit > 0) {
                verdictTitle.textContent = `Critical Security Vulnerabilities Confirmed (${totalConfirmed} Total)`;
                verdictTitle.style.color = "var(--sev-critical)";
                verdictDesc.textContent = `Audit confirmed ${cCrit} critical risk issue(s) supported by direct probe evidence (${totalConfirmed} total confirmed vulnerabilities). Immediate remediation is required to protect the application.`;
            } else if (cHigh > 0) {
                verdictTitle.textContent = `High-Severity Vulnerabilities Confirmed (${totalConfirmed} Total)`;
                verdictTitle.style.color = "var(--brand-red)";
                verdictDesc.textContent = `Audit confirmed ${cHigh} high-severity issue(s) (${totalConfirmed} total confirmed vulnerabilities across all severities). ${cPass} executed check(s) completed clean with no vulnerabilities detected.`;
            } else if (totalConfirmed > 0) {
                verdictTitle.textContent = `Security Hardening Findings Identified (${totalConfirmed} Total)`;
                verdictTitle.style.color = "var(--sev-medium)";
                verdictDesc.textContent = `Audit confirmed ${totalConfirmed} moderate/low security misconfiguration(s) (${cMed} Medium, ${cLow} Low). ${cPass} executed check(s) completed clean. Review headers, cookies, and CORS controls to strengthen defense-in-depth.`;
            } else if (cInconc > 0) {
                verdictTitle.textContent = `No Confirmed Vulnerabilities in Tested Scope (${cInconc} Inconclusive Check${cInconc === 1 ? '' : 's'})`;
                verdictTitle.style.color = "var(--sev-inconclusive)";
                verdictDesc.textContent = `${cPass} executed check(s) completed clean with no vulnerabilities detected. However, ${cInconc} check(s) had coverage limitations (such as missing dual-account credentials for access control) and require authenticated follow-up testing.`;
            } else if (cErr > 0) {
                verdictTitle.textContent = `Scan Completed with Probe Notices (${cErr} Scanner Error${cErr === 1 ? '' : 's'})`;
                verdictTitle.style.color = "var(--text-primary)";
                verdictDesc.textContent = `Executed checks completed. ${cErr} probe warning(s) were recorded due to target response timeouts. Security status for failed probes remains unknown.`;
            } else {
                verdictTitle.textContent = `No Vulnerabilities Detected in Executed Scope (${cPass} Passed)`;
                verdictTitle.style.color = "var(--sev-passed)";
                verdictDesc.textContent = `All ${cPass} executed automated security checks completed without detecting vulnerabilities on assessed endpoints. Note: This assessment covers executed checks only and does not establish that the application is completely invulnerable.`;
            }
        }
    }

    // Render Assessment Coverage & Scope Limitations Section
    function renderAssessmentCoverage(result) {
        if (!coverageSection || !coverageList) return;

        const moduleDetails = result.module_details || {};
        const coverageItems = [];

        // 1. Inconclusive findings from engine (e.g. Broken Access Control without dual auth tokens)
        const inconclusiveFindings = allFindings.filter(f => (f.status || "").toUpperCase() === "INCONCLUSIVE");
        inconclusiveFindings.forEach(f => {
            const modKey = (f.type || "").toLowerCase();
            let name = f.title || "Inconclusive Assessment";
            let reason = f.evidence || "Assessment required credentials or dual authentication contexts that were not supplied.";
            let tested = f.url || "Target web endpoints (baseline reachability)";
            let unverified = "Object-level authorization boundaries, cross-tenant isolation, or advanced exploitability.";
            let nextSteps = "Provide dual authenticated user tokens or run an authorized multi-account security verification.";

            if (modKey === "access_control" || f.title.toLowerCase().includes("access control")) {
                name = "Broken Access Control & IDOR (OWASP A01)";
                reason = "Dual authorization contexts were not provided. Automated access control and IDOR testing requires two independent session tokens to verify object ownership boundaries.";
                tested = "Passive response inspection and public endpoint reachability.";
                unverified = "Horizontal privilege escalation, IDOR, and tenant boundary enforcement.";
                nextSteps = "Configure user credentials (auth_context_1 and auth_context_2) in New Scan > Scan Configuration, or perform authorized manual multi-role testing.";
            }

            coverageItems.push({
                type: "inconclusive",
                badge: "INCONCLUSIVE ASSESSMENT",
                name,
                reason,
                tested,
                unverified,
                nextSteps
            });
        });

        // 2. Telemetry modules from module_details
        Object.entries(moduleDetails).forEach(([modKey, mod]) => {
            const st = (mod.status || "").toLowerCase();
            const isAlreadyCaptured = inconclusiveFindings.some(f => (f.type || "").toLowerCase() === modKey);

            if (st === "inconclusive" && !isAlreadyCaptured) {
                coverageItems.push({
                    type: "inconclusive",
                    badge: "INCONCLUSIVE ASSESSMENT",
                    name: mod.name || modKey.toUpperCase(),
                    reason: mod.message || "Required authentication or environmental conditions were not available.",
                    tested: "Public perimeter and basic route reachability.",
                    unverified: "Authenticated application logic and sensitive privilege boundaries.",
                    nextSteps: "Provide required test credentials and re-execute assessment."
                });
            } else if (st === "failed") {
                coverageItems.push({
                    type: "error",
                    badge: "SCANNER ERROR",
                    name: mod.name || modKey.toUpperCase(),
                    reason: mod.message || "Scanner engine encountered probe timeout or connection reset.",
                    tested: "Initial connection handshake.",
                    unverified: "Module could not complete execution; security outcome is unknown.",
                    nextSteps: "Verify network firewall permissions and re-run probe."
                });
            } else if (mod.selected === false || st === "skipped") {
                coverageItems.push({
                    type: "skipped",
                    badge: "SKIPPED CHECK",
                    name: mod.name || modKey.toUpperCase(),
                    reason: "This module was intentionally not selected for this assessment.",
                    tested: "None (excluded from scan profile).",
                    unverified: `Vulnerabilities in this category (${mod.category || 'Module scope'}) were not assessed.`,
                    nextSteps: "To evaluate this attack vector, enable this module in New Scan."
                });
            }
        });

        if (coverageItems.length === 0) {
            coverageSection.style.display = "none";
            return;
        }

        coverageSection.style.display = "block";
        if (coverageCountPill) {
            coverageCountPill.textContent = `${coverageItems.length} Scope Limitation${coverageItems.length === 1 ? "" : "s"}`;
        }

        coverageList.innerHTML = coverageItems.map(item => `
            <div class="coverage-item-card ${item.type}">
                <div class="coverage-item-header">
                    <span class="coverage-item-badge ${item.type}">${item.badge}</span>
                    <h4 class="coverage-item-name">${UI.escapeHTML(item.name)}</h4>
                </div>
                <div class="coverage-item-grid">
                    <div class="coverage-metric-col">
                        <span class="cov-label">Why Incomplete</span>
                        <p class="cov-text">${UI.escapeHTML(item.reason)}</p>
                    </div>
                    <div class="coverage-metric-col">
                        <span class="cov-label">Tested Scope</span>
                        <p class="cov-text">${UI.escapeHTML(item.tested)}</p>
                    </div>
                    <div class="coverage-metric-col">
                        <span class="cov-label">Remains Unverified</span>
                        <p class="cov-text highlight">${UI.escapeHTML(item.unverified)}</p>
                    </div>
                    <div class="coverage-metric-col">
                        <span class="cov-label">Recommended Next Step</span>
                        <p class="cov-text action">${UI.escapeHTML(item.nextSteps)}</p>
                    </div>
                </div>
            </div>
        `).join("");
    }

    // Populate Dynamic Module Filter
    function populateModuleFilter(findings) {
        if (!filterModule) return;
        const currentSelected = filterModule.value;
        filterModule.innerHTML = '<option value="all">All Modules</option>';

        const uniqueModules = [...new Set(findings.map(f => f.type).filter(Boolean))].sort();
        uniqueModules.forEach(mod => {
            const opt = document.createElement("option");
            opt.value = mod;
            opt.textContent = mod.replace(/_/g, " ").toUpperCase();
            if (mod === currentSelected) opt.selected = true;
            filterModule.appendChild(opt);
        });
    }

    // Apply Client-Side Filters & Render Findings
    function applyFindingsFilters() {
        const query = (findingSearchInput?.value || "").trim().toLowerCase();
        const selSev = filterSeverity?.value || "all";
        const selMod = filterModule?.value || "all";
        const selStat = filterStatus?.value || "all";

        if (btnFindingSearchClear) {
            btnFindingSearchClear.style.display = query ? "block" : "none";
        }

        filteredFindings = allFindings.filter(f => {
            const sev = (f.severity || "info").toLowerCase();
            const stat = (f.status || "NOT_DETECTED").toUpperCase();
            const mod = (f.type || "").toLowerCase();
            const verifStat = (f.verification_status || f.status || "").toUpperCase();

            // Severity filter (CRITICAL, HIGH, MEDIUM, LOW, NOT DETECTED, SCANNER ERROR)
            if (selSev === "confirmed") {
                if (verifStat !== "CONFIRMED") return false;
            } else if (selSev === "critical") {
                if (sev !== "critical" || stat === "NOT_DETECTED" || stat === "SCANNER_ERROR") return false;
            } else if (selSev === "high") {
                if (sev !== "high" || stat === "NOT_DETECTED" || stat === "SCANNER_ERROR") return false;
            } else if (selSev === "medium") {
                if (sev !== "medium" || stat === "NOT_DETECTED" || stat === "SCANNER_ERROR") return false;
            } else if (selSev === "low") {
                if ((sev !== "low" && sev !== "info") || stat === "NOT_DETECTED" || stat === "SCANNER_ERROR") return false;
            } else if (selSev === "not_detected") {
                if (stat !== "NOT_DETECTED") return false;
            } else if (selSev === "scanner_error") {
                if (stat !== "SCANNER_ERROR" && mod !== "scanner_error") return false;
            } else if (selSev !== "all") {
                if (sev !== selSev) return false;
            }

            // Module filter
            if (selMod !== "all" && mod !== selMod.toLowerCase()) {
                return false;
            }

            // Verification status filter
            if (selStat !== "all" && verifStat !== selStat) {
                return false;
            }

            // Search query match across title, description, parameter, url, evidence, owasp, cwe
            if (query) {
                const hay = `${f.title} ${f.description} ${f.parameter || ""} ${f.url || ""} ${f.evidence || ""} ${f.owasp || ""} ${f.cwe || ""}`.toLowerCase();
                if (!hay.includes(query)) return false;
            }

            return true;
        });

        // Sort findings: Critical -> High -> Medium -> Low -> Info -> Not Detected -> Error
        const SEV_WEIGHT = {
            critical: 0,
            high: 1,
            medium: 2,
            low: 3,
            info: 4
        };

        filteredFindings.sort((a, b) => {
            const aPassed = a.status === "NOT_DETECTED";
            const bPassed = b.status === "NOT_DETECTED";
            if (aPassed !== bPassed) return aPassed ? 1 : -1;

            const aErr = a.status === "SCANNER_ERROR";
            const bErr = b.status === "SCANNER_ERROR";
            if (aErr !== bErr) return aErr ? 1 : -1;

            const wA = SEV_WEIGHT[(a.severity || "info").toLowerCase()] ?? 9;
            const wB = SEV_WEIGHT[(b.severity || "info").toLowerCase()] ?? 9;
            return wA - wB;
        });

        renderFindingsList();
    }

    // Render Findings List
    function renderFindingsList() {
        if (!findingsList) return;

        if (filteredFindings.length === 0) {
            if (allFindings.length === 0) {
                findingsList.innerHTML = `
                    <div class="state-container">
                        <div class="state-icon-wrap" style="color:var(--sev-passed); border-color:rgba(16,185,129,0.3); background:rgba(16,185,129,0.06);">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
                        </div>
                        <h4 class="state-title">No Security Findings Detected</h4>
                        <p class="state-desc">The executed security checks completed with clean responses across all probed endpoints. Note: This assessment covers tested scope only and does not imply absolute invulnerability.</p>
                    </div>`;
            } else {
                findingsList.innerHTML = `
                    <div class="state-container">
                        <div class="state-icon-wrap">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                        </div>
                        <h4 class="state-title">No Findings Match Filter</h4>
                        <p class="state-desc">No findings matched your current severity, module, or keyword filters.</p>
                        <button type="button" class="btn-secondary" onclick="document.getElementById('btnResetFilters').click()">
                            <span>Reset Filters</span>
                        </button>
                    </div>`;
            }

            if (findingsCountBadge) findingsCountBadge.textContent = "0 findings";
            return;
        }

        if (findingsCountBadge) {
            findingsCountBadge.textContent = `${filteredFindings.length} of ${allFindings.length} finding${allFindings.length === 1 ? "" : "s"}`;
        }

        findingsList.innerHTML = filteredFindings.map((f, idx) => {
            const rawSev = (f.severity || "info").toLowerCase();
            const status = (f.status || "NOT_DETECTED").toUpperCase();
            let verif = (f.verification_status || f.status || "NOT_DETECTED").toUpperCase();
            if (verif === "SCANNER_ERROR") verif = "ERROR";
            const isPassed = status === "NOT_DETECTED";
            const isError = status === "SCANNER_ERROR" || f.type === "scanner_error";

            let cardClass = rawSev;
            let badgeClass = rawSev;
            let badgeLabel = rawSev.toUpperCase();

            if (isError) {
                cardClass = "error";
                badgeClass = "error";
                badgeLabel = "SCANNER ERROR";
            } else if (isPassed) {
                cardClass = "passed";
                badgeClass = "passed";
                badgeLabel = "NOT DETECTED";
            } else if (status === "INCONCLUSIVE" || verif === "INCONCLUSIVE") {
                cardClass = "inconclusive";
                badgeClass = "inconclusive";
                badgeLabel = "INCONCLUSIVE";
            }

            // Evidence preview (safe excerpt)
            let evidencePreviewHtml = "";
            if (f.evidence && String(f.evidence).trim()) {
                const cleanEv = String(f.evidence).trim().slice(0, 180);
                evidencePreviewHtml = `<pre class="finding-evidence-preview" title="Verified scanner probe evidence">${UI.escapeHTML(cleanEv)}${f.evidence.length > 180 ? "…" : ""}</pre>`;
            }

            // Real-world Impact summary
            let impactPreviewHtml = "";
            if (f.impact && String(f.impact).trim()) {
                impactPreviewHtml = `<div class="finding-impact-preview"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg><span><strong>Impact:</strong> ${UI.escapeHTML(f.impact)}</span></div>`;
            }

            return `
                <div class="finding-card ${cardClass}" data-finding-id="${UI.escapeHTML(f.id)}" data-index="${idx}">
                    <div class="finding-main">
                        <div class="finding-header-row">
                            <span class="sev-badge ${badgeClass}">${badgeLabel}</span>
                            <span class="status-badge-outline ${verif.toLowerCase().replace(/_/g, "-")}">${UI.escapeHTML(verif.replace(/_/g, " "))}</span>
                            <span class="finding-title-text">${UI.escapeHTML(f.title)}</span>
                        </div>
                        <p class="finding-desc-snippet">${UI.escapeHTML(f.description)}</p>
                        
                        ${evidencePreviewHtml}
                        ${impactPreviewHtml}

                        <div class="finding-footer-meta">
                            <div class="finding-tags-row">
                                <span class="chip-tag">${UI.escapeHTML((f.type || "MODULE").toUpperCase())}</span>
                                ${f.parameter ? `<span class="chip-tag">param: <strong>${UI.escapeHTML(f.parameter)}</strong></span>` : ""}
                                ${f.url ? `<span class="chip-tag endpoint" title="${UI.escapeHTML(f.url)}">${UI.escapeHTML(f.url)}</span>` : ""}
                                ${f.owasp ? `<span class="chip-tag">${UI.escapeHTML(f.owasp)}</span>` : ""}
                                ${f.cwe ? `<span class="chip-tag">${UI.escapeHTML(f.cwe)}</span>` : ""}
                            </div>
                            <div class="finding-actions-row">
                                <button type="button" class="btn-card-ai" data-finding-id="${UI.escapeHTML(f.id)}" title="Explain finding and get remediation guidance with EthioSec AI">
                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                                    <span>Explain with AI</span>
                                </button>
                                <button type="button" class="btn-card-details" data-finding-id="${UI.escapeHTML(f.id)}">
                                    <span>Inspect Details →</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join("");

        // Attach Click to open Detail Modal and Explain with AI
        findingsList.querySelectorAll(".finding-card").forEach(card => {
            const fId = card.getAttribute("data-finding-id");
            const found = allFindings.find(item => item.id === fId);

            // Card click opens modal
            card.addEventListener("click", () => {
                if (found) openDetailModal(found);
            });

            // Card "Explain with AI" button click
            const btnAi = card.querySelector(".btn-card-ai");
            if (btnAi) {
                btnAi.addEventListener("click", (e) => {
                    e.stopPropagation();
                    window.location.href = `assistant.html?scan_id=${encodeURIComponent(currentScanId)}&finding_id=${encodeURIComponent(fId)}`;
                });
            }

            // Card "Inspect Details" button click
            const btnDetails = card.querySelector(".btn-card-details");
            if (btnDetails) {
                btnDetails.addEventListener("click", (e) => {
                    e.stopPropagation();
                    if (found) openDetailModal(found);
                });
            }
        });
    }

    // Open Technical Details Modal
    function openDetailModal(finding) {
        if (!detailModalOverlay) return;
        activeModalFinding = finding;

        const sev = (finding.severity || "info").toLowerCase();
        const stat = (finding.status || "NOT_DETECTED").toUpperCase();
        let verif = (finding.verification_status || stat).toUpperCase();
        if (verif === "SCANNER_ERROR") verif = "ERROR";

        if (dSeverityBadge) {
            dSeverityBadge.textContent = sev.toUpperCase();
            dSeverityBadge.className = `sev-badge ${sev}`;
        }
        if (dStatusBadge) {
            dStatusBadge.textContent = verif.replace(/_/g, " ");
            dStatusBadge.className = `status-badge-outline ${verif.toLowerCase().replace(/_/g, "-")}`;
        }
        if (dConfidence) {
            dConfidence.textContent = `Confidence: ${finding.confidence || "HIGH"}`;
        }
        if (dModuleTag) {
            dModuleTag.textContent = `MODULE: ${(finding.type || "CHECK").toUpperCase()}`;
        }
        if (dTitle) {
            dTitle.textContent = finding.title;
        }
        if (dEndpoint) {
            dEndpoint.textContent = finding.url || "Target Webroot";
        }
        if (dDescription) {
            dDescription.textContent = finding.description;
        }

        // Parameter & HTTP Method
        if (finding.parameter || finding.http_method) {
            if (dParamBlock) dParamBlock.style.display = "block";
            const parts = [];
            if (finding.http_method) parts.push(`Method: ${finding.http_method}`);
            if (finding.parameter) parts.push(`Parameter: ${finding.parameter}`);
            if (dParameterMethod) dParameterMethod.textContent = parts.join(" · ");
        } else {
            if (dParamBlock) dParamBlock.style.display = "none";
        }

        // Evidence code box
        if (dEvidence) {
            if (finding.evidence) {
                dEvidence.textContent = finding.evidence;
                if (dEvidenceBlock) dEvidenceBlock.style.display = "block";
            } else if (finding.response_summary || finding.request) {
                const combined = [
                    finding.request ? `--- REQUEST ---\n${finding.request}` : "",
                    finding.response_summary ? `--- RESPONSE ---\n${finding.response_summary}` : ""
                ].filter(Boolean).join("\n\n");
                dEvidence.textContent = combined;
                if (dEvidenceBlock) dEvidenceBlock.style.display = "block";
            } else {
                dEvidence.textContent = "No raw payload evidence was required or logged for this check.";
                if (dEvidenceBlock) dEvidenceBlock.style.display = "block";
            }
        }

        // Real-World Impact
        if (finding.impact) {
            if (dImpactBlock) dImpactBlock.style.display = "block";
            if (dImpact) dImpact.textContent = finding.impact;
        } else {
            if (dImpactBlock) dImpactBlock.style.display = "none";
        }

        // AI Explanation (if present)
        if (finding.ai_explanation) {
            if (dAiBlock) dAiBlock.style.display = "block";
            if (dAiText) dAiText.textContent = finding.ai_explanation;
        } else {
            if (dAiBlock) dAiBlock.style.display = "none";
        }

        // Remediation list
        if (dRemediationList) {
            dRemediationList.innerHTML = "";
            let items = finding.remediation;
            if (typeof items === "string") {
                try { items = JSON.parse(items); } catch { items = [items]; }
            }
            if (Array.isArray(items) && items.length > 0) {
                items.forEach(step => {
                    const li = document.createElement("li");
                    li.textContent = step;
                    dRemediationList.appendChild(li);
                });
                if (dRemediationBlock) dRemediationBlock.style.display = "block";
            } else {
                const li = document.createElement("li");
                li.textContent = "Review secure coding standards and consult relevant OWASP / CWE guidelines.";
                dRemediationList.appendChild(li);
                if (dRemediationBlock) dRemediationBlock.style.display = "block";
            }
        }

        // OWASP & CWE tags
        if (dOwaspTag) {
            if (finding.owasp) {
                dOwaspTag.textContent = `OWASP: ${finding.owasp}`;
                dOwaspTag.style.display = "inline-block";
            } else {
                dOwaspTag.style.display = "none";
            }
        }
        if (dCweTag) {
            if (finding.cwe) {
                dCweTag.textContent = `CWE: ${finding.cwe}`;
                dCweTag.style.display = "inline-block";
            } else {
                dCweTag.style.display = "none";
            }
        }

        // Wire Modal "Explain with AI" Button
        if (btnModalAiExplain) {
            btnModalAiExplain.onclick = () => {
                if (activeModalFinding) {
                    window.location.href = `assistant.html?scan_id=${encodeURIComponent(currentScanId)}&finding_id=${encodeURIComponent(activeModalFinding.id)}`;
                }
            };
        }

        detailModalOverlay.classList.add("open");
    }

    function closeDetailModal() {
        if (detailModalOverlay) {
            detailModalOverlay.classList.remove("open");
        }
    }

    // Export Scan Data as Clean JSON
    function exportFindingsAsJson() {
        if (!scanResultData) {
            UI.toast("No scan data available to export.", "error");
            return;
        }

        const exportPayload = {
            scan_id: scanResultData.scan_id,
            target: scanResultData.target,
            depth: scanResultData.depth,
            scanned_at: scanResultData.scanned_at,
            security_score: scanResultData.security_score,
            counts: scanResultData.counts,
            findings: allFindings
        };

        const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportPayload, null, 2));
        const downloadAnchor = document.createElement("a");
        downloadAnchor.setAttribute("href", jsonStr);
        downloadAnchor.setAttribute("download", `EthioSecScan-${scanResultData.scan_id}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        UI.toast("Scan report JSON downloaded.", "info");
    }

    // Number Counting Animation
    function animateNumber(element, target) {
        const duration = 750;
        const start = performance.now();
        function update(now) {
            const progress = Math.min((now - start) / duration, 1);
            const easeOut = 1 - Math.pow(1 - progress, 3);
            element.textContent = Math.round(target * easeOut);
            if (progress < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
    }

    // Loading State
    function renderLoading() {
        if (findingsList) {
            findingsList.innerHTML = `
                <div class="state-container">
                    <div class="spinner"></div>
                    <h3 class="state-title">Loading Scan Results</h3>
                    <p class="state-desc">Retrieving vulnerability records and engine telemetry from the backend…</p>
                </div>`;
        }
    }

    // In-Progress State (HTTP 409)
    function renderInProgressState() {
        if (inProgressBanner) {
            inProgressBanner.style.display = "flex";
            if (linkLiveMonitor) {
                linkLiveMonitor.href = `livescan.html?id=${encodeURIComponent(currentScanId)}`;
            }
        }
        if (findingsList) {
            findingsList.innerHTML = `
                <div class="state-container">
                    <div class="spinner" style="border-top-color:#3B82F6;"></div>
                    <h3 class="state-title">Scan in Progress</h3>
                    <p class="state-desc">The security scanner is currently assessing this target. Results will be published once all selected check modules complete execution.</p>
                    <a href="livescan.html?id=${encodeURIComponent(currentScanId)}" class="btn-primary" style="background:#2563EB;">
                        <span>View Live Engine Telemetry →</span>
                    </a>
                </div>`;
        }
        if (verdictTitle) verdictTitle.textContent = "Scan in Progress…";
        if (verdictDesc) verdictDesc.textContent = "The background crawler and module dispatchers are actively executing security checks.";
        if (metaStatusText) metaStatusText.textContent = "Running";
        if (metaStatusPill) metaStatusPill.className = "status-pill running";
    }

    // Not Found State (HTTP 404)
    function renderNotFoundError(message) {
        if (targetBreadcrumb) targetBreadcrumb.textContent = "Scan Not Found";
        if (verdictTitle) verdictTitle.textContent = "Assessment Record Not Found";
        if (verdictDesc) verdictDesc.textContent = UI.escapeHTML(message);
        if (metaScanId) metaScanId.textContent = "—";
        if (metaStatusText) metaStatusText.textContent = "Not Found";
        if (metaStatusPill) metaStatusPill.className = "status-pill failed";
        if (findingsCountBadge) findingsCountBadge.textContent = "0 findings";
        if (findingsList) {
            findingsList.innerHTML = `
                <div class="state-container">
                    <div class="state-icon-wrap" style="color:var(--brand-red); border-color:rgba(232,59,37,0.3); background:rgba(232,59,37,0.06);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    </div>
                    <h3 class="state-title">Scan Not Found</h3>
                    <p class="state-desc">${UI.escapeHTML(message)}</p>
                    <a href="scan_history.html" class="btn-primary">
                        <span>← Back to Scan History</span>
                    </a>
                </div>`;
        }
    }

    // Auth Expired State (HTTP 401/403)
    function renderAuthExpiredError() {
        if (targetBreadcrumb) targetBreadcrumb.textContent = "Authentication Required";
        if (verdictTitle) verdictTitle.textContent = "Session Expired";
        if (verdictDesc) verdictDesc.textContent = "Your session has expired. Please sign in again to access this scan result.";
        if (metaScanId) metaScanId.textContent = "—";
        if (metaStatusText) metaStatusText.textContent = "Unauthorized";
        if (metaStatusPill) metaStatusPill.className = "status-pill failed";
        if (findingsCountBadge) findingsCountBadge.textContent = "0 findings";
        if (findingsList) {
            findingsList.innerHTML = `
                <div class="state-container">
                    <div class="state-icon-wrap" style="color:var(--brand-red); border-color:rgba(232,59,37,0.3); background:rgba(232,59,37,0.06);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                    </div>
                    <h3 class="state-title">Authentication Expired</h3>
                    <p class="state-desc">Your session has expired. Please sign in again to access this scan result.</p>
                    <a href="login.html" class="btn-primary">
                        <span>Log In Again →</span>
                    </a>
                </div>`;
        }
    }

    // No Scan State (no ID and no history)
    function renderNoScanState() {
        if (targetBreadcrumb) targetBreadcrumb.textContent = "No Target Selected";
        if (verdictTitle) verdictTitle.textContent = "No Scan Assessment Selected";
        if (verdictDesc) verdictDesc.textContent = "No prior scans were found on record. Start an automated assessment on an authorized target to view results.";
        if (metaScanId) metaScanId.textContent = "—";
        if (metaStatusText) metaStatusText.textContent = "Idle";
        if (metaStatusPill) metaStatusPill.className = "status-pill completed";
        if (findingsCountBadge) findingsCountBadge.textContent = "0 findings";
        if (findingsList) {
            findingsList.innerHTML = `
                <div class="state-container">
                    <div class="state-icon-wrap">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    </div>
                    <h3 class="state-title">No Scan Selected</h3>
                    <p class="state-desc">No previous scans were found on record. Start an automated assessment on an authorized target to view results.</p>
                    <a href="scanfinal.html" class="btn-primary">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>
                        <span>Start New Scan</span>
                    </a>
                </div>`;
        }
    }

    // General Error State
    function renderGeneralError(message) {
        if (targetBreadcrumb) targetBreadcrumb.textContent = "Assessment Unavailable";
        if (verdictTitle) verdictTitle.textContent = "Unable to Retrieve Results";
        if (verdictDesc) verdictDesc.textContent = UI.escapeHTML(message);
        if (metaScanId) metaScanId.textContent = "—";
        if (metaStatusText) metaStatusText.textContent = "Error";
        if (metaStatusPill) metaStatusPill.className = "status-pill failed";
        if (findingsCountBadge) findingsCountBadge.textContent = "0 findings";
        if (findingsList) {
            findingsList.innerHTML = `
                <div class="state-container">
                    <div class="state-icon-wrap" style="color:var(--brand-red); border-color:rgba(232,59,37,0.3); background:rgba(232,59,37,0.06);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    </div>
                    <h3 class="state-title">Failed to Load Scan Results</h3>
                    <p class="state-desc">${UI.escapeHTML(message)}</p>
                    <button type="button" class="btn-secondary" onclick="window.location.reload()">
                        <span>Retry Loading</span>
                    </button>
                </div>`;
        }
    }

    // Summary Pill Click Filter Handler
    if (summaryPillsRow) {
        summaryPillsRow.querySelectorAll(".summary-pill-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                const targetSev = btn.getAttribute("data-severity");
                const isCurrentlyActive = btn.classList.contains("active");

                summaryPillsRow.querySelectorAll(".summary-pill-btn").forEach(b => b.classList.remove("active"));

                if (isCurrentlyActive) {
                    if (filterSeverity) filterSeverity.value = "all";
                } else {
                    btn.classList.add("active");
                    if (filterSeverity) filterSeverity.value = targetSev;
                }
                applyFindingsFilters();
            });
        });
    }

    // Event Listeners
    if (findingSearchInput) {
        findingSearchInput.addEventListener("input", applyFindingsFilters);
    }
    if (btnFindingSearchClear) {
        btnFindingSearchClear.addEventListener("click", () => {
            findingSearchInput.value = "";
            applyFindingsFilters();
            findingSearchInput.focus();
        });
    }
    if (filterSeverity) {
        filterSeverity.addEventListener("change", () => {
            // Synchronize active class on summary pills
            if (summaryPillsRow) {
                summaryPillsRow.querySelectorAll(".summary-pill-btn").forEach(b => {
                    b.classList.toggle("active", b.getAttribute("data-severity") === filterSeverity.value);
                });
            }
            applyFindingsFilters();
        });
    }
    if (filterModule) {
        filterModule.addEventListener("change", applyFindingsFilters);
    }
    if (filterStatus) {
        filterStatus.addEventListener("change", applyFindingsFilters);
    }
    if (btnResetFilters) {
        btnResetFilters.addEventListener("click", () => {
            if (findingSearchInput) findingSearchInput.value = "";
            if (filterSeverity) filterSeverity.value = "all";
            if (filterModule) filterModule.value = "all";
            if (filterStatus) filterStatus.value = "all";
            if (summaryPillsRow) {
                summaryPillsRow.querySelectorAll(".summary-pill-btn").forEach(b => b.classList.remove("active"));
            }
            applyFindingsFilters();
        });
    }

    if (btnExportJson) {
        btnExportJson.addEventListener("click", exportFindingsAsJson);
    }

    // Modal Close Listeners
    if (modalCloseBtn) modalCloseBtn.addEventListener("click", closeDetailModal);
    if (btnModalClose) btnModalClose.addEventListener("click", closeDetailModal);
    if (detailModalOverlay) {
        detailModalOverlay.addEventListener("click", (e) => {
            if (e.target === detailModalOverlay) closeDetailModal();
        });
    }
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && detailModalOverlay?.classList.contains("open")) {
            closeDetailModal();
        }
    });

    // Initial Load Execution
    await loadScanResults();
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initResultsController);
} else {
    initResultsController();
}
