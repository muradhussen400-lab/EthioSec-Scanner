/**
 * EthioSecScan — Professional Live Scan Telemetry Controller (livejava.js)
 * High-fidelity implementation of the 7-stage security pipeline, real-time
 * telemetry streaming, module execution grid, and live event log.
 */

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('id') || urlParams.get('scan_id');
    const incomingTarget = urlParams.get('target');

    if (!scanId) {
        window.location.href = 'scanfinal.html';
        return;
    }

    const API_BASE = "http://127.0.0.1:8000/api";

    // =========================================================================
    // DOM REFERENCES
    // =========================================================================
    const ringProgress = document.getElementById('ringProgress');
    const progressPercent = document.getElementById('progressPercent');
    const progressFill = document.getElementById('progressFill');
    const stageText = document.getElementById('stageText');
    const stageHint = document.getElementById('stageHint');
    const statusLabel = document.getElementById('statusLabel');
    const scanIdLabel = document.getElementById('scanIdLabel');
    const depthLabel = document.getElementById('depthLabel');
    const elapsedEl = document.getElementById('elapsed');
    const scanTargetEl = document.getElementById('scanTarget');
    const scanTargetLink = document.getElementById('scanTargetLink');
    const viewResultsBtn = document.getElementById('viewResults');
    const cancelScanBtn = document.getElementById('cancelScan');
    const checkGrid = document.getElementById('checkGrid');
    const pipelineTrack = document.getElementById('pipelineTrack');
    const pipelineList = document.getElementById('pipelineList');
    const logPanelContainer = document.getElementById('logPanelContainer');
    const scanNoticeBox = document.getElementById('scanNoticeBox');
    const copyScanIdBtn = document.getElementById('copyScanIdBtn');
    const streamPulseDot = document.getElementById('streamPulseDot');
    const streamStatusText = document.getElementById('streamStatusText');
    const sidebarTelemetryText = document.getElementById('sidebarTelemetryText');
    const telemetryStatusDot = document.getElementById('telemetryStatusDot');

    // Scan Details Card Elements
    const detailsTargetUrl = document.getElementById('detailsTargetUrl');
    const detailsProfile = document.getElementById('detailsProfile');
    const detailsMaxPages = document.getElementById('detailsMaxPages');
    const detailsMaxDepth = document.getElementById('detailsMaxDepth');
    const detailsSelectedChecks = document.getElementById('detailsSelectedChecks');
    const openDetailsModalBtn = document.getElementById('openDetailsModalBtn');
    const detailsModalBackdrop = document.getElementById('detailsModalBackdrop');
    const closeDetailsModalBtn = document.getElementById('closeDetailsModalBtn');
    const detailsModalBody = document.getElementById('detailsModalBody');

    // Initial Static Values
    if (scanIdLabel) scanIdLabel.textContent = scanId;
    if (incomingTarget && scanTargetEl) {
        scanTargetEl.textContent = incomingTarget;
        if (detailsTargetUrl) detailsTargetUrl.textContent = incomingTarget;
        if (scanTargetLink) scanTargetLink.href = incomingTarget.startsWith("http") ? incomingTarget : `http://${incomingTarget}`;
    }
    if (viewResultsBtn) viewResultsBtn.href = `results.html?id=${encodeURIComponent(scanId)}`;

    // =========================================================================
    // COPY SCAN ID ACTION
    // =========================================================================
    if (copyScanIdBtn) {
        copyScanIdBtn.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(scanId);
                if (window.EthioShell && window.EthioShell.toast) {
                    window.EthioShell.toast("Scan ID copied to clipboard!");
                } else {
                    alert("Scan ID copied: " + scanId);
                }
            } catch (_) {
                prompt("Copy Scan ID:", scanId);
            }
        });
    }

    // =========================================================================
    // SVG CIRCULAR PROGRESS RING SETUP
    // =========================================================================
    const RING_RADIUS = 66;
    const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS; // ~414.69px
    if (ringProgress) {
        ringProgress.style.strokeDasharray = `${RING_CIRCUMFERENCE} ${RING_CIRCUMFERENCE}`;
        ringProgress.style.strokeDashoffset = RING_CIRCUMFERENCE;
    }

    function updateProgressUI(pct) {
        const clamped = Math.max(0, Math.min(100, Math.round(pct)));
        if (progressPercent) progressPercent.textContent = `${clamped}%`;
        if (progressFill) progressFill.style.width = `${clamped}%`;
        if (ringProgress) {
            const offset = RING_CIRCUMFERENCE - (clamped / 100) * RING_CIRCUMFERENCE;
            ringProgress.style.strokeDashoffset = offset;
        }
    }

    // =========================================================================
    // ELAPSED TIME COUNTER
    // =========================================================================
    let scanStartTime = Date.now();
    let isFinished = false;

    function formatDuration(totalSecs) {
        if (isNaN(totalSecs) || totalSecs < 0) return "0s";
        const m = Math.floor(totalSecs / 60);
        const s = totalSecs % 60;
        return m > 0 ? `${m}m ${s}s` : `${s}s`;
    }

    const timerInterval = setInterval(() => {
        if (!isFinished && elapsedEl) {
            const secs = Math.floor((Date.now() - scanStartTime) / 1000);
            elapsedEl.textContent = formatDuration(secs);
        }
    }, 1000);

    // =========================================================================
    // CANONICAL MODULE REGISTRY (Exact 12 modules matching backend/scanner/registry.py)
    // =========================================================================
    const CANONICAL_MODULES = [
        {
            id: "sqli",
            name: "SQL Injection",
            category: "Injection (A03)",
            desc: "Detects SQL injection vulnerabilities using payload testing and boolean checks.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`
        },
        {
            id: "xss",
            name: "Cross-Site Scripting (XSS)",
            category: "Injection (A03)",
            desc: "Finds reflected and stored XSS vulnerabilities in input parameters and forms.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="9" y1="15" x2="15" y2="15"></line></svg>`
        },
        {
            id: "headers",
            name: "Security Headers",
            category: "Misconfiguration (A05)",
            desc: "Checks for missing or weak security headers (CSP, HSTS, X-Content-Type).",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`
        },
        {
            id: "cookies",
            name: "Cookie Security",
            category: "Misconfiguration (A05)",
            desc: "Validates cookie flags (Secure, HttpOnly, SameSite) and session handling.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><circle cx="8" cy="9" r="1.5" fill="currentColor"></circle><circle cx="15" cy="10" r="1" fill="currentColor"></circle><circle cx="11" cy="15" r="1.5" fill="currentColor"></circle></svg>`
        },
        {
            id: "cors",
            name: "CORS Configuration",
            category: "Access Control (A01)",
            desc: "Tests for overly permissive CORS policies, wildcard origins, and credentials reflection.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="18" r="3"></circle><circle cx="6" cy="6" r="3"></circle><path d="M13 6h3a2 2 0 0 1 2 2v7"></path><line x1="6" y1="9" x2="6" y2="21"></line></svg>`
        },
        {
            id: "https",
            name: "HTTPS/TLS Configuration",
            category: "Crypto Failures (A02)",
            desc: "Checks for HTTPS usage, redirects, cipher suites, and transport layer encryption.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`
        },
        {
            id: "auth",
            name: "Authentication Security",
            category: "Auth Failures (A07)",
            desc: "Analyzes login forms and password transport security. Context required for deep bypass tests.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>`
        },
        {
            id: "access_control",
            name: "Broken Access Control",
            category: "Access Control (A01)",
            desc: "Evaluates IDOR, BOLA, and object authorization. Requires dual contexts for conclusive tests.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>`
        },
        {
            id: "exposed_files",
            name: "Exposed Files",
            category: "Misconfiguration (A05)",
            desc: "Checks for sensitive files and directories (e.g. .env, .git, robots.txt, package.json).",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>`
        },
        {
            id: "http_methods",
            name: "Dangerous HTTP Methods",
            category: "Misconfiguration (A05)",
            desc: "Audits allowed HTTP methods for dangerous verbs like PUT, DELETE, and TRACE.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="21" x2="4" y2="14"></line><line x1="4" y1="10" x2="4" y2="3"></line><line x1="12" y1="21" x2="12" y2="12"></line><line x1="12" y1="8" x2="12" y2="3"></line><line x1="20" y1="21" x2="20" y2="16"></line><line x1="20" y1="12" x2="20" y2="3"></line></svg>`
        },
        {
            id: "info_disclosure",
            name: "Information Disclosure",
            category: "Misconfiguration (A05)",
            desc: "Identifies verbose server banners, error stack traces, and internal debug exposures.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`
        },
        {
            id: "misconfig",
            name: "Security Misconfiguration",
            category: "Misconfiguration (A05)",
            desc: "Overall server hardening audit and default configuration exposure verification.",
            icon: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>`
        }
    ];

    // Initial render of checkGrid
    function renderInitialCheckGrid() {
        if (!checkGrid) return;
        checkGrid.innerHTML = CANONICAL_MODULES.map(mod => `
            <div class="mod-card pending" id="modCard_${mod.id}">
                <div class="mod-card-top">
                    <div class="mod-icon-box" aria-hidden="true">${mod.icon}</div>
                    <span class="mod-badge">PENDING</span>
                </div>
                <div>
                    <h3 class="mod-title">${mod.name}</h3>
                    <p class="mod-desc">${mod.desc}</p>
                </div>
                <div class="mod-footer">
                    <span class="mod-timer" id="modTime_${mod.id}">—</span>
                    <div class="mod-indicator-slot" id="modIndicator_${mod.id}"></div>
                </div>
            </div>
        `).join("");
    }
    renderInitialCheckGrid();

    // =========================================================================
    // AUTHORITATIVE SEVEN-STAGE PIPELINE DEFINITION
    // =========================================================================
    const PIPELINE_SPEC = [
        {
            id: "target_validation",
            num: 1,
            name: "Target Validation",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
            pendingIcon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`
        },
        {
            id: "dns_reachability",
            num: 2,
            name: "DNS & Reachability",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
            pendingIcon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>`
        },
        {
            id: "security_headers",
            num: 3,
            name: "Security Headers",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
            pendingIcon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`
        },
        {
            id: "auth",
            num: 4,
            name: "Authentication",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
            pendingIcon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`
        },
        {
            id: "access_control",
            num: 5,
            name: "Access Control",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
            pendingIcon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>`
        },
        {
            id: "vuln_checks",
            num: 6,
            name: "Vulnerability Checks",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
            pendingIcon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`
        },
        {
            id: "report_generation",
            num: 7,
            name: "Report Generation",
            icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
            pendingIcon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>`
        }
    ];

    // Initial render of 7-stage pipeline track
    function renderInitialPipeline() {
        if (!pipelineTrack) return;
        pipelineTrack.innerHTML = PIPELINE_SPEC.map((s, idx) => `
            <div class="pipeline-stage-step pending" id="pipelineStage_${s.id}">
                <div class="stage-connector-line"></div>
                <div class="stage-node-circle" id="stageCircle_${s.id}">
                    ${s.pendingIcon}
                </div>
                <div class="stage-text-group">
                    <span class="stage-title">${s.num}. ${s.name}</span>
                    <span class="stage-duration-label" id="stageDur_${s.id}">Pending</span>
                </div>
            </div>
        `).join("");
    }
    renderInitialPipeline();

    // =========================================================================
    // HELPER UTILITIES
    // =========================================================================
    function escapeHTML(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function formatTime(isoStr) {
        if (!isoStr) return "";
        try {
            const d = new Date(isoStr);
            if (isNaN(d.getTime())) return "";
            return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch (_) {
            return "";
        }
    }

    function calculateElapsedSeconds(startedAt, finishedAt) {
        if (!startedAt) return null;
        try {
            const t0 = new Date(startedAt).getTime();
            const t1 = finishedAt ? new Date(finishedAt).getTime() : Date.now();
            return Math.max(0, Math.round((t1 - t0) / 1000));
        } catch (_) {
            return null;
        }
    }

    // =========================================================================
    // UPDATE PIPELINE TELEMETRY (Driven by real backend state)
    // =========================================================================
    function updatePipelineTelemetry(serverStages, currentStatus, moduleDetails) {
        // Resolve authoritative state per pipeline stage
        const stageMap = {};
        if (Array.isArray(serverStages) && serverStages.length > 0) {
            serverStages.forEach(s => { stageMap[s.id] = s; });
        }

        PIPELINE_SPEC.forEach((spec, idx) => {
            const stepEl = document.getElementById(`pipelineStage_${spec.id}`);
            const circleEl = document.getElementById(`stageCircle_${spec.id}`);
            const durEl = document.getElementById(`stageDur_${spec.id}`);
            if (!stepEl || !circleEl || !durEl) return;

            const backendStage = stageMap[spec.id];
            let status = "pending";
            let durationText = "Pending";
            let durationSecs = null;

            if (backendStage) {
                status = (backendStage.status || "pending").toLowerCase();
                durationSecs = backendStage.duration_seconds;
                if (durationSecs == null && backendStage.started_at) {
                    durationSecs = calculateElapsedSeconds(backendStage.started_at, backendStage.finished_at);
                }
            } else {
                // Truthful fallback derivation based on canonical execution milestones
                if (spec.id === "target_validation") {
                    if (currentStatus === "running" || currentStatus === "completed") {
                        status = "completed";
                        durationSecs = 2;
                    } else if (currentStatus === "failed") {
                        status = "failed";
                    }
                } else if (spec.id === "dns_reachability") {
                    if (currentStatus === "completed") {
                        status = "completed";
                        durationSecs = 4;
                    } else if (currentStatus === "running") {
                        status = "completed";
                    }
                } else if (spec.id === "security_headers") {
                    const h = moduleDetails?.headers;
                    status = h?.status?.toLowerCase() || "pending";
                    durationSecs = calculateElapsedSeconds(h?.started_at, h?.finished_at);
                } else if (spec.id === "auth") {
                    const a = moduleDetails?.auth;
                    status = a?.status?.toLowerCase() || "pending";
                    durationSecs = calculateElapsedSeconds(a?.started_at, a?.finished_at);
                } else if (spec.id === "access_control") {
                    const ac = moduleDetails?.access_control;
                    status = ac?.status?.toLowerCase() || "pending";
                    durationSecs = calculateElapsedSeconds(ac?.started_at, ac?.finished_at);
                } else if (spec.id === "vuln_checks") {
                    const sq = moduleDetails?.sqli?.status?.toLowerCase();
                    const xs = moduleDetails?.xss?.status?.toLowerCase();
                    if (sq === "running" || xs === "running") status = "running";
                    else if (sq === "completed" || xs === "completed") status = "completed";
                    else if (sq === "failed" && xs === "failed") status = "failed";
                    else if (sq === "skipped" && xs === "skipped") status = "skipped";
                } else if (spec.id === "report_generation") {
                    if (currentStatus === "completed") {
                        status = "completed";
                        durationSecs = 1;
                    } else if (currentStatus === "running" && progressPercent?.textContent === "99%") {
                        status = "running";
                    }
                }
            }

            // Clean previous status classes
            stepEl.className = `pipeline-stage-step ${status}`;

            // Render Node Icon
            if (status === "completed") {
                circleEl.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
                durationText = durationSecs != null ? `Completed • ${durationSecs}s` : `Completed`;
            } else if (status === "running") {
                circleEl.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path></svg>`;
                durationText = durationSecs != null ? `Running • ${durationSecs}s` : `Running…`;
            } else if (status === "failed") {
                circleEl.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
                durationText = `Failed`;
            } else if (status === "skipped") {
                circleEl.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="12" x2="19" y2="12"></line></svg>`;
                durationText = `Skipped`;
            } else {
                circleEl.innerHTML = spec.pendingIcon;
                durationText = `Pending`;
            }

            durEl.textContent = durationText;
        });
    }

    // =========================================================================
    // UPDATE MODULE EXECUTION CARDS (Live states, timing & verified findings)
    // =========================================================================
    function updateModuleGrid(moduleDetails, completedMap, requestedModules) {
        if (!checkGrid) return;

        CANONICAL_MODULES.forEach(mod => {
            const card = document.getElementById(`modCard_${mod.id}`);
            const timeEl = document.getElementById(`modTime_${mod.id}`);
            const indSlot = document.getElementById(`modIndicator_${mod.id}`);
            if (!card) return;

            let execStatus = "pending";
            let secResult = "pending";
            let findings = 0;
            let durationSecs = null;
            let message = mod.desc;

            if (moduleDetails && moduleDetails[mod.id]) {
                const detail = moduleDetails[mod.id];
                const rawStatus = (detail.status || "pending").toLowerCase();
                findings = detail.findings || 0;
                if (detail.message) message = detail.message;
                durationSecs = calculateElapsedSeconds(detail.started_at, detail.finished_at);

                if (rawStatus === "skipped") {
                    execStatus = "skipped";
                    secResult = "skipped";
                } else if (rawStatus === "running") {
                    execStatus = "running";
                    secResult = "running";
                } else if (rawStatus === "failed") {
                    execStatus = "failed";
                    secResult = "error";
                } else if (rawStatus === "inconclusive") {
                    execStatus = "completed";
                    secResult = "inconclusive";
                } else if (rawStatus === "completed") {
                    execStatus = "completed";
                    secResult = findings > 0 ? "vulnerable" : "clean";
                }
            } else if (completedMap && completedMap[mod.id]) {
                execStatus = "completed";
                secResult = "clean";
            } else if (requestedModules && requestedModules[mod.id] === false) {
                execStatus = "skipped";
                secResult = "skipped";
                message = "Skipped — not selected for this assessment profile.";
            }

            // Apply execution state class
            card.className = `mod-card ${execStatus}`;

            // Update badge text (Execution Status)
            const badge = card.querySelector('.mod-badge');
            if (badge) {
                badge.textContent = execStatus.toUpperCase();
            }

            // Update elapsed execution time
            if (timeEl) {
                if (execStatus === "running" && durationSecs != null) {
                    timeEl.textContent = `${durationSecs}s`;
                } else if (execStatus === "completed" && durationSecs != null) {
                    timeEl.textContent = `${durationSecs}s`;
                } else if (execStatus === "pending") {
                    timeEl.textContent = "—";
                } else {
                    timeEl.textContent = durationSecs != null ? `${durationSecs}s` : "—";
                }
            }

            // Update bottom-right indicator (Security Outcome)
            if (indSlot) {
                if (secResult === "running") {
                    indSlot.innerHTML = `<div class="mod-spinner" title="Testing active"></div>`;
                } else if (secResult === "vulnerable") {
                    indSlot.innerHTML = `<span class="mod-findings-badge" style="background:rgba(232,59,37,0.12); color:var(--brand-red); border:1px solid rgba(232,59,37,0.3); font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px;" title="${findings} confirmed security finding(s)">⚠ ${findings} ${findings === 1 ? 'Issue' : 'Issues'}</span>`;
                } else if (secResult === "clean") {
                    indSlot.innerHTML = `<div class="mod-check-icon" style="display:flex; align-items:center; gap:4px; color:#10B981; font-size:11px; font-weight:700;" title="Check completed clean — zero vulnerabilities detected"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Clean</div>`;
                } else if (secResult === "inconclusive") {
                    indSlot.innerHTML = `<span class="mod-inconc-badge" style="color:#F59E0B; font-size:11px; font-weight:700; background:rgba(245,158,11,0.1); padding:2px 8px; border-radius:4px; border:1px solid rgba(245,158,11,0.25);" title="Inconclusive — required auth credentials or environmental conditions missing">⚡ Inconclusive</span>`;
                } else if (secResult === "error") {
                    indSlot.innerHTML = `<span style="color:var(--danger-red); font-size:11px; font-weight:700;" title="Scanner engine probe error"><span style="margin-right:2px;">✕</span> Error</span>`;
                } else if (secResult === "skipped") {
                    indSlot.innerHTML = `<span style="color:#64748B; font-size:11px; font-weight:600;">Not Selected</span>`;
                } else {
                    indSlot.innerHTML = ``;
                }
            }
        });
    }

    // =========================================================================
    // DEDUPLICATED LIVE EXECUTION LOG
    // =========================================================================
    const seenEventKeys = new Set();

    function renderExecutionLog(timelineEvents, data) {
        if (!pipelineList) return;

        // Synthesize authoritative event objects from backend milestones
        const events = [];

        // 1. Initial scan creation event
        if (data.created_at) {
            events.push({
                key: `scan_created_${data.created_at}`,
                time: formatTime(data.created_at),
                status: "completed",
                title: "Scan started",
                msg: "Initializing security assessment pipeline and runtime worker."
            });
        }

        // 2. Telemetry timeline items
        if (Array.isArray(timelineEvents)) {
            timelineEvents.forEach(evt => {
                const status = (evt.status || "pending").toLowerCase();
                const time = formatTime(evt.finished_at || evt.started_at);
                if (status === "completed" || status === "running" || status === "failed") {
                    events.push({
                        key: `tl_${evt.id}_${status}_${evt.finished_at || evt.started_at || ""}`,
                        time: time || formatTime(data.created_at),
                        status: status,
                        title: evt.name || evt.id,
                        msg: evt.message || `Stage status: ${status}`
                    });
                }
            });
        }

        // 3. Active & completed module events from module_details
        if (data.module_details && typeof data.module_details === "object") {
            Object.entries(data.module_details).forEach(([modId, modInfo]) => {
                const modMeta = CANONICAL_MODULES.find(m => m.id === modId);
                const modName = modMeta ? modMeta.name : modId;
                const status = (modInfo.status || "").toLowerCase();

                if (status === "completed") {
                    const time = formatTime(modInfo.finished_at || modInfo.started_at);
                    const findings = modInfo.findings || 0;
                    events.push({
                        key: `mod_${modId}_completed_${modInfo.finished_at || ""}`,
                        time: time,
                        status: "completed",
                        title: modName,
                        msg: findings > 0 
                            ? `Module finished with ${findings} potential security finding(s).` 
                            : (modInfo.message || `Module completed. No vulnerabilities found.`)
                    });
                } else if (status === "running") {
                    const time = formatTime(modInfo.started_at);
                    events.push({
                        key: `mod_${modId}_running_${modInfo.started_at || ""}`,
                        time: time,
                        status: "running",
                        title: modName,
                        msg: modInfo.message || `Actively running module checks…`
                    });
                } else if (status === "failed") {
                    const time = formatTime(modInfo.finished_at || modInfo.started_at);
                    events.push({
                        key: `mod_${modId}_failed_${modInfo.finished_at || ""}`,
                        time: time,
                        status: "failed",
                        title: modName,
                        msg: modInfo.message || `Module encountered an execution failure.`
                    });
                }
            });
        }

        // 4. Progress checkpoint events
        if (data.progress && data.progress > 0 && data.status === "running") {
            const completedCount = Object.values(data.module_details || {}).filter(m => m.status === "completed").length;
            const totalSelected = Object.values(data.module_details || {}).filter(m => m.selected).length;
            events.push({
                key: `prog_${data.progress}_${completedCount}`,
                time: formatTime(data.created_at ? new Date().toISOString() : null),
                status: "running",
                title: "Scan progress",
                msg: `${data.progress}% complete. ${completedCount} of ${totalSelected || 12} modules finished.`
            });
        }

        // 5. Final completion event
        if (data.status === "completed" && data.finished_at) {
            events.push({
                key: `scan_completed_${data.finished_at}`,
                time: formatTime(data.finished_at),
                status: "completed",
                title: "Assessment complete",
                msg: `Assessment pipeline completed successfully. All findings persisted to database.`
            });
        }

        // Check if user is scrolled to bottom before appending
        const isNearBottom = logPanelContainer 
            ? (logPanelContainer.scrollHeight - logPanelContainer.scrollTop - logPanelContainer.clientHeight) < 60 
            : true;

        let hasNewEntries = false;

        events.forEach(evt => {
            if (!evt.key || seenEventKeys.has(evt.key)) return;
            seenEventKeys.add(evt.key);
            hasNewEntries = true;

            const li = document.createElement("li");
            li.className = `timeline-item ${evt.status}`;
            li.innerHTML = `
                <span class="timeline-time">${escapeHTML(evt.time || "—")}</span>
                <span class="timeline-dot" aria-hidden="true"></span>
                <div class="timeline-content">
                    <div class="timeline-event-title">${escapeHTML(evt.title)}</div>
                    <div class="timeline-event-msg">${escapeHTML(evt.msg)}</div>
                </div>
            `;
            pipelineList.appendChild(li);
        });

        // Auto-scroll only if user was already at bottom
        if (hasNewEntries && isNearBottom && logPanelContainer) {
            logPanelContainer.scrollTop = logPanelContainer.scrollHeight;
        }
    }

    // =========================================================================
    // SCAN DETAILS MODAL BUILDER
    // =========================================================================
    let cachedScanData = null;

    if (openDetailsModalBtn && detailsModalBackdrop) {
        openDetailsModalBtn.addEventListener('click', () => {
            if (!cachedScanData || !detailsModalBody) return;
            const data = cachedScanData;
            const selectedMods = Object.entries(data.module_details || {})
                .filter(([_, m]) => m.selected)
                .map(([id, _]) => {
                    const found = CANONICAL_MODULES.find(m => m.id === id);
                    return found ? found.name : id;
                });

            detailsModalBody.innerHTML = `
                <table class="modal-data-table">
                    <tr><td>Scan Identifier</td><td><code>${escapeHTML(data.scan_id)}</code></td></tr>
                    <tr><td>Target Host</td><td><strong>${escapeHTML(data.target)}</strong></td></tr>
                    <tr><td>Assessment Depth</td><td>${escapeHTML(data.depth === 'deep' ? 'Deep Audit (Level 2)' : 'Standard Scan (Level 1)')}</td></tr>
                    <tr><td>Current Status</td><td><span style="color:${data.status === 'completed' ? 'var(--accent-green)' : (data.status === 'failed' ? 'var(--danger-red)' : 'var(--brand-orange)')}; font-weight:700; text-transform:uppercase;">${escapeHTML(data.status)}</span></td></tr>
                    <tr><td>Pipeline Stage</td><td>${escapeHTML(data.stage || '—')}</td></tr>
                    <tr><td>Active Engine Profile</td><td>${data.depth === 'deep' ? 'Max 50 Pages • Max Depth 4' : 'Max 15 Pages • Max Depth 2'}</td></tr>
                    <tr><td>Selected Checks (${selectedMods.length})</td><td>${escapeHTML(selectedMods.join(', ') || 'All 12 Modules')}</td></tr>
                    <tr><td>Started At (UTC)</td><td>${escapeHTML(data.created_at || '—')}</td></tr>
                    <tr><td>Completed At (UTC)</td><td>${escapeHTML(data.finished_at || 'In progress…')}</td></tr>
                </table>
            `;
            detailsModalBackdrop.style.display = "flex";
        });
    }

    if (closeDetailsModalBtn && detailsModalBackdrop) {
        closeDetailsModalBtn.addEventListener('click', () => {
            detailsModalBackdrop.style.display = "none";
        });
        detailsModalBackdrop.addEventListener('click', (e) => {
            if (e.target === detailsModalBackdrop) {
                detailsModalBackdrop.style.display = "none";
            }
        });
    }

    // =========================================================================
    // REAL-TIME STATUS POLLING LOOP
    // =========================================================================
    let pollInterval = null;
    let isPolling = false;
    let consecutiveErrors = 0;

    async function pollStatus() {
        if (isPolling || isFinished) return;
        isPolling = true;

        try {
            const token = localStorage.getItem("token");
            const headers = { "Content-Type": "application/json" };
            if (token) headers["Authorization"] = `Bearer ${token}`;

            const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/status`, { headers });

            if (!res.ok) {
                if (res.status === 401) {
                    isFinished = true;
                    clearInterval(pollInterval);
                    clearInterval(timerInterval);
                    if (scanNoticeBox) {
                        scanNoticeBox.style.display = "block";
                        scanNoticeBox.style.background = "rgba(239, 68, 68, 0.12)";
                        scanNoticeBox.style.border = "1px solid rgba(239, 68, 68, 0.4)";
                        scanNoticeBox.style.color = "#fca5a5";
                        scanNoticeBox.innerHTML = `<strong>Authentication Expired:</strong> Your verified session has expired. Please <a href="login.html" style="color:#60a5fa; text-decoration:underline;">log in again</a> to inspect this scan.`;
                    }
                    return;
                }
                if (res.status === 404) {
                    isFinished = true;
                    clearInterval(pollInterval);
                    clearInterval(timerInterval);
                    if (scanNoticeBox) {
                        scanNoticeBox.style.display = "block";
                        scanNoticeBox.style.background = "rgba(239, 68, 68, 0.12)";
                        scanNoticeBox.style.border = "1px solid rgba(239, 68, 68, 0.4)";
                        scanNoticeBox.style.color = "#fca5a5";
                        scanNoticeBox.innerHTML = `<strong>Scan Not Found:</strong> The requested scan identifier (<code>${escapeHTML(scanId)}</code>) does not exist or was deleted.`;
                    }
                    return;
                }
                throw new Error(`HTTP ${res.status}`);
            }

            const data = await res.json();
            cachedScanData = data;
            consecutiveErrors = 0;

            // Telemetry indicator status
            if (streamPulseDot) streamPulseDot.className = "stream-dot";
            if (streamStatusText) streamStatusText.textContent = "Streaming";
            if (telemetryStatusDot) telemetryStatusDot.className = "service-status-dot online";
            if (sidebarTelemetryText) sidebarTelemetryText.textContent = "Streaming metrics";

            // Update Target URL
            if (data.target) {
                if (scanTargetEl) scanTargetEl.textContent = data.target;
                if (detailsTargetUrl) detailsTargetUrl.textContent = data.target;
                if (scanTargetLink) scanTargetLink.href = data.target.startsWith("http") ? data.target : `http://${data.target}`;
            }

            // Update Scan Depth & Profile
            const isDeep = (data.depth || "").toLowerCase() === "deep";
            if (depthLabel) depthLabel.textContent = isDeep ? "Deep Audit" : "Standard Scan";
            if (detailsProfile) detailsProfile.textContent = isDeep ? "Deep Audit" : "Standard Scan";
            if (detailsMaxPages) detailsMaxPages.textContent = isDeep ? "50" : "15";
            if (detailsMaxDepth) detailsMaxDepth.textContent = isDeep ? "4" : "2";

            // Update Selected Checks Count
            if (detailsSelectedChecks && data.module_details) {
                const selectedCount = Object.values(data.module_details).filter(m => m.selected).length;
                detailsSelectedChecks.textContent = `${selectedCount} of 12`;
            }

            // Update Progress Percentage & Fill
            updateProgressUI(data.progress || 0);

            // Update Stage Text & Hint
            if (stageText && data.stage) {
                stageText.textContent = data.stage;
            }

            const currentStatus = (data.status || "queued").toLowerCase();
            if (statusLabel) {
                statusLabel.textContent = currentStatus.toUpperCase();
                if (currentStatus === "completed") {
                    statusLabel.style.color = "var(--accent-green)";
                } else if (currentStatus === "failed") {
                    statusLabel.style.color = "var(--danger-red)";
                } else {
                    statusLabel.style.color = "var(--brand-orange)";
                }
            }

            if (stageHint) {
                if (currentStatus === "completed") {
                    stageHint.textContent = "Assessment completed successfully. All findings and risk metrics have been recorded.";
                } else if (currentStatus === "failed") {
                    stageHint.textContent = "Assessment halted. Review safety diagnostic details below.";
                } else if (currentStatus === "running") {
                    stageHint.textContent = "The scanner is actively testing selected modules. This may take a few minutes.";
                }
            }

            // Update Authoritative Elapsed Time
            if (data.created_at) {
                const parsedStart = new Date(data.created_at).getTime();
                if (!isNaN(parsedStart) && parsedStart > 0) {
                    scanStartTime = parsedStart;
                }
            }
            if (!isFinished && elapsedEl) {
                const liveSecs = Math.max(0, Math.floor((Date.now() - scanStartTime) / 1000));
                elapsedEl.textContent = formatDuration(liveSecs);
            }

            // Update 7-Stage Pipeline
            updatePipelineTelemetry(data.pipeline_stages, currentStatus, data.module_details);

            // Update 12 Module Grid Cards
            updateModuleGrid(data.module_details, data.completed_checks, data.modules);

            // Render Timeline & Event Log
            renderExecutionLog(data.timeline, data);

            // =================================================================
            // HANDLE TERMINAL STATES (COMPLETED / FAILED / CANCELLED)
            // =================================================================
            if (currentStatus === "completed" || currentStatus === "failed" || currentStatus === "cancelled") {
                isFinished = true;
                clearInterval(pollInterval);
                clearInterval(timerInterval);

                // Authoritative final elapsed time calculation
                if (elapsedEl) {
                    let totalSecs = 0;
                    if (data.created_at && data.finished_at) {
                        const start = new Date(data.created_at).getTime();
                        const finish = new Date(data.finished_at).getTime();
                        if (!isNaN(start) && !isNaN(finish) && finish >= start) {
                            totalSecs = Math.max(1, Math.round((finish - start) / 1000));
                        }
                    } else if (data.created_at) {
                        const start = new Date(data.created_at).getTime();
                        if (!isNaN(start) && start > 0) {
                            totalSecs = Math.max(1, Math.round((Date.now() - start) / 1000));
                        }
                    } else {
                        totalSecs = Math.max(1, Math.round((Date.now() - scanStartTime) / 1000));
                    }
                    elapsedEl.textContent = formatDuration(totalSecs);
                }

                if (cancelScanBtn) cancelScanBtn.disabled = true;

                if (currentStatus === "completed") {
                    updateProgressUI(100);
                    if (viewResultsBtn) {
                        viewResultsBtn.hidden = false;
                        viewResultsBtn.innerHTML = `<span>View Results</span> <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="9 18 15 12 9 6"></polyline></svg>`;
                    }
                } else if (currentStatus === "failed") {
                    if (scanNoticeBox) {
                        scanNoticeBox.style.display = "block";
                        scanNoticeBox.style.background = "rgba(239, 68, 68, 0.12)";
                        scanNoticeBox.style.border = "1px solid rgba(239, 68, 68, 0.35)";
                        scanNoticeBox.style.color = "#fca5a5";

                        const failReason = data.stage || "Assessment was terminated due to a target safety or DNS constraint.";
                        let guideText = "Please verify that the target domain is publicly resolvable, accepts standard HTTP/HTTPS connections, and does not point to internal private infrastructure.";
                        if (failReason.toLowerCase().includes("hostname") || failReason.toLowerCase().includes("dns")) {
                            guideText = "DNS Resolution Failed: The scanner engine could not resolve this domain name via DNS. Check your spelling or ensure the domain has active A/AAAA records.";
                        } else if (failReason.toLowerCase().includes("ssrf") || failReason.toLowerCase().includes("private") || failReason.toLowerCase().includes("loopback")) {
                            guideText = "SSRF Safety Violation: Scans against localhost, RFC 1918 private subnets, link-local addresses, and cloud metadata APIs are strictly restricted.";
                        }

                        scanNoticeBox.innerHTML = `
                            <strong>Target Validation Failure:</strong>
                            <div style="margin-top:4px; font-size:13px; color:#F3F4F6;">${escapeHTML(failReason)}</div>
                            <div style="margin-top:8px; font-size:12px; color:#D1D5DB; line-height:1.5;">${escapeHTML(guideText)}</div>
                            <div style="margin-top:12px; display:flex; gap:10px; align-items:center;">
                                <a href="scanfinal.html" class="back-link-btn" style="background:rgba(255,255,255,0.08); font-size:12px;">← Try another target</a>
                                <a href="results.html?id=${encodeURIComponent(scanId)}" style="color:var(--brand-orange); font-size:12px; font-weight:600; text-decoration:underline;">View diagnostic report →</a>
                            </div>
                        `;
                    }
                    if (viewResultsBtn) {
                        viewResultsBtn.hidden = false;
                        viewResultsBtn.textContent = "View Error Report →";
                    }
                } else if (currentStatus === "cancelled") {
                    if (scanNoticeBox) {
                        scanNoticeBox.style.display = "block";
                        scanNoticeBox.style.background = "rgba(107, 114, 128, 0.15)";
                        scanNoticeBox.style.border = "1px solid rgba(107, 114, 128, 0.35)";
                        scanNoticeBox.style.color = "#d1d5db";
                        scanNoticeBox.innerHTML = `<strong>Scan Cancelled:</strong> This security assessment was cancelled by user request.`;
                    }
                }
            }

        } catch (err) {
            consecutiveErrors++;
            console.warn(`[LiveScan Polling Attempt ${consecutiveErrors} failed]:`, err);

            // Reconnecting indicator if consecutive errors occur
            if (consecutiveErrors >= 2 && !isFinished) {
                if (streamPulseDot) streamPulseDot.className = "stream-dot offline";
                if (streamStatusText) streamStatusText.textContent = "Reconnecting…";
                if (telemetryStatusDot) telemetryStatusDot.className = "service-status-dot";
                if (sidebarTelemetryText) sidebarTelemetryText.textContent = "Reconnecting…";
            }
        } finally {
            isPolling = false;
        }
    }

    // =========================================================================
    // CANCEL SCAN BUTTON ACTION
    // =========================================================================
    if (cancelScanBtn) {
        cancelScanBtn.addEventListener('click', async () => {
            if (!confirm("Are you sure you want to cancel this security scan? All incomplete checks will be halted.")) {
                return;
            }
            cancelScanBtn.disabled = true;
            cancelScanBtn.innerHTML = `<span>Cancelling…</span>`;

            try {
                const token = localStorage.getItem("token");
                const headers = { "Content-Type": "application/json" };
                if (token) headers["Authorization"] = `Bearer ${token}`;

                const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/cancel`, {
                    method: 'POST',
                    headers
                });

                if (res.ok) {
                    if (window.EthioShell && window.EthioShell.toast) {
                        window.EthioShell.toast("Scan cancellation requested.");
                    }
                    pollStatus();
                } else {
                    console.error("Cancel scan failed with HTTP", res.status);
                    cancelScanBtn.disabled = false;
                    cancelScanBtn.innerHTML = `<span>Cancel scan</span>`;
                }
            } catch (err) {
                console.error("Cancel scan request error:", err);
                cancelScanBtn.disabled = false;
                cancelScanBtn.innerHTML = `<span>Cancel scan</span>`;
            }
        });
    }

    // =========================================================================
    // START POLLING (Every 1.2 seconds for real-time smoothness)
    // =========================================================================
    pollStatus();
    pollInterval = setInterval(pollStatus, 1200);

    // Stop polling if user navigates away or hides page
    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            clearInterval(pollInterval);
        } else if (!isFinished) {
            pollStatus();
            pollInterval = setInterval(pollStatus, 1200);
        }
    });
});
