/* ==========================================================================
   ETHIOSECSCAN — REPORTS CONTROLLER (reportjava.js)
   Real Backend Synchronization via FastAPI (/api/reports, /api/reports/{id})
   5-Category Posture Breakdown · Real JSON/CSV Exports · AI Executive Summary
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    const API_BASE = "http://127.0.0.1:8000/api";

    function getAuthToken() {
        const token = localStorage.getItem("token");
        if (!token) {
            window.location.href = "login.html";
            return "";
        }
        return token;
    }

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
        hostOf: (url) => {
            try {
                const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
                return parsed.hostname;
            } catch {
                return url || "Target Host";
            }
        },
        timeAgo: (dateString) => {
            if (!dateString) return "Recently";
            try {
                const date = new Date(dateString);
                if (isNaN(date.getTime())) return "Recently";
                const diff = Date.now() - date.getTime();
                const mins = Math.floor(diff / 60000);
                if (mins < 1) return "Just now";
                if (mins < 60) return `${mins}m ago`;
                const hours = Math.floor(mins / 60);
                if (hours < 24) return `${hours}h ago`;
                const days = Math.floor(hours / 24);
                return `${days}d ago`;
            } catch {
                return "Recently";
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
        severityClass: (sev) => {
            const map = {
                critical: "sev-critical",
                high: "sev-high",
                medium: "sev-medium",
                low: "sev-low",
                info: "sev-low"
            };
            return map[sev?.toLowerCase()] || "sev-low";
        },
        getQueryParam: (param) => new URLSearchParams(window.location.search).get(param),
        toast: (msg, type = "info") => {
            const t = document.getElementById("toast");
            if (t) {
                t.textContent = msg;
                t.className = "toast show " + (type === "error" ? "error" : "");
                setTimeout(() => t.classList.remove("show"), 3500);
            }
        }
    };

    // DOM Elements
    const listEl = document.getElementById("reportList");
    const docEl = document.getElementById("reportDoc");
    const countEl = document.getElementById("reportCount");
    const reportSearchInput = document.getElementById("reportSearchInput");
    const reportDepthFilter = document.getElementById("reportDepthFilter");

    // Overview Metric Counter Elements
    const mTotalReports = document.getElementById("mTotalReports");
    const mTargetsAudited = document.getElementById("mTargetsAudited");
    const mHighFindings = document.getElementById("mHighFindings");
    const mCleanAudits = document.getElementById("mCleanAudits");

    // State Variables
    let allReports = [];
    let filteredReports = [];
    let activeReportId = null;

    function scoreClass(score) {
        if (score === null || score === undefined) return "score-bad";
        const n = Number(score);
        return n >= 80 ? "score-good" : n >= 60 ? "score-mid" : "score-bad";
    }

    /* =====================================================
       1. LOAD REPORTS LIST & OVERVIEW METRICS
       ===================================================== */
    async function loadReports() {
        if (!listEl || !docEl) return;

        const token = getAuthToken();
        if (!token) return;

        listEl.innerHTML = '<p class="loading-state">Loading authorized reports…</p>';

        try {
            const res = await fetch(`${API_BASE}/reports`, {
                headers: { "Authorization": `Bearer ${token}` }
            });

            if (res.status === 401 || res.status === 403) {
                window.location.href = "login.html";
                return;
            }

            if (!res.ok) {
                throw new Error(`Failed to retrieve reports (HTTP ${res.status})`);
            }

            const data = await res.json();
            allReports = data.reports || [];

            // Calculate Overview Metrics from real records
            updateOverviewMetrics(allReports);

            applyFilters();

            // Handle deep link via URL query param (?id=...)
            const deepId = UI.getQueryParam("id") || UI.getQueryParam("report_id") || UI.getQueryParam("scan_id");
            if (deepId && allReports.length > 0) {
                const targetId = deepId.startsWith("r") ? deepId : "r" + deepId;
                const match = allReports.find(r => r.id === deepId || r.id === targetId || r.scan_id === deepId);
                if (match) {
                    openReport(match.id);
                    return;
                }
            }

            if (allReports.length > 0) {
                openReport(allReports[0].id);
            } else {
                docEl.innerHTML = `
                    <div class="empty-state">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" style="color:var(--text-muted); margin-bottom:12px;">
                            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
                            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
                        </svg>
                        <h3 style="color:#FFFFFF; font-size:16px; margin-bottom:6px;">No Completed Audit Reports</h3>
                        <p style="color:var(--text-secondary); max-width:380px; margin:0 auto 16px auto;">Formal reports are generated automatically once a vulnerability assessment reaches completion.</p>
                        <a href="scanfinal.html" class="primary-btn">Start a New Scan →</a>
                    </div>
                `;
            }

        } catch (err) {
            console.error("Reports loading error:", err);
            listEl.innerHTML = '<p class="empty-state" style="color:#F87171;">Could not connect to the Reports API service.</p>';
            docEl.innerHTML = '<p class="empty-state">Please ensure the backend is running and reachable.</p>';
        }
    }

    function updateOverviewMetrics(reports) {
        if (mTotalReports) mTotalReports.textContent = reports.length;

        // Distinct target domains audited
        const uniqueTargets = new Set();
        let totalHighFindings = 0;
        let cleanAuditsCount = 0;

        reports.forEach(r => {
            if (r.target) uniqueTargets.add(UI.hostOf(r.target));
            const c = r.counts || {};
            const high = Number(c.high || 0) + Number(c.critical || 0);
            const med = Number(c.medium || 0);
            totalHighFindings += high;

            if (Number(r.security_score || 0) >= 80 || (high === 0 && med === 0)) {
                cleanAuditsCount++;
            }
        });

        if (mTargetsAudited) mTargetsAudited.textContent = uniqueTargets.size;
        if (mHighFindings) mHighFindings.textContent = totalHighFindings;
        if (mCleanAudits) mCleanAudits.textContent = cleanAuditsCount;
    }

    /* =====================================================
       2. FILTERING AND SEARCH
       ===================================================== */
    function applyFilters() {
        const query = (reportSearchInput?.value || "").trim().toLowerCase();
        const depth = (reportDepthFilter?.value || "all").toLowerCase();

        filteredReports = allReports.filter(r => {
            const matchesQuery = !query ||
                (r.target && r.target.toLowerCase().includes(query)) ||
                (r.id && r.id.toLowerCase().includes(query)) ||
                (r.scan_id && r.scan_id.toLowerCase().includes(query));

            const matchesDepth = depth === "all" || (r.depth || "standard").toLowerCase() === depth;

            return matchesQuery && matchesDepth;
        });

        if (countEl) {
            countEl.textContent = `${filteredReports.length} of ${allReports.length}`;
        }

        renderReportList();
    }

    function renderReportList() {
        if (!listEl) return;

        if (!filteredReports.length) {
            listEl.innerHTML = `
                <div class="empty-state" style="padding:24px 12px;">
                    <p style="color:var(--text-muted); margin-bottom:10px;">No matching reports found.</p>
                    <button type="button" class="btn-secondary" id="btnResetFilters" style="padding:4px 10px; font-size:11.5px;">Reset Filters</button>
                </div>
            `;
            const resetBtn = document.getElementById("btnResetFilters");
            if (resetBtn) {
                resetBtn.addEventListener("click", () => {
                    if (reportSearchInput) reportSearchInput.value = "";
                    if (reportDepthFilter) reportDepthFilter.value = "all";
                    applyFilters();
                });
            }
            return;
        }

        listEl.innerHTML = filteredReports.map(r => {
            const isActive = r.id === activeReportId;
            const scoreVal = r.security_score !== null && r.security_score !== undefined ? r.security_score : "—";
            const c = r.counts || {};
            const cHigh = Number(c.high || 0) + Number(c.critical || 0);

            return `
                <div class="report-item ${isActive ? 'active' : ''}" data-id="${UI.escapeHTML(r.id)}">
                    <div class="report-item-main">
                        <div class="report-host">${UI.escapeHTML(UI.hostOf(r.target))}</div>
                        <div class="report-when">
                            <span>${UI.timeAgo(r.generated_at)}</span>
                            <span>·</span>
                            <span style="text-transform:uppercase;">${UI.escapeHTML(r.depth || 'standard')}</span>
                            ${cHigh > 0 ? `<span style="color:var(--brand-red); font-weight:700;">· ${cHigh} High</span>` : ''}
                        </div>
                    </div>
                    <div class="report-score ${scoreClass(r.security_score)}">${scoreVal}</div>
                </div>
            `;
        }).join("");

        listEl.querySelectorAll(".report-item").forEach(item => {
            item.addEventListener("click", () => {
                const id = item.dataset.id;
                if (id) openReport(id);
            });
        });
    }

    if (reportSearchInput) {
        reportSearchInput.addEventListener("input", applyFilters);
    }
    if (reportDepthFilter) {
        reportDepthFilter.addEventListener("change", applyFilters);
    }

    /* =====================================================
       3. LOAD AND RENDER REPORT DOCUMENT
       ===================================================== */
    async function openReport(id) {
        if (!docEl || !id) return;
        activeReportId = id;

        // Update active class in list items
        if (listEl) {
            listEl.querySelectorAll(".report-item").forEach(item => {
                item.classList.toggle("active", item.dataset.id === id);
            });
        }

        docEl.innerHTML = '<p class="loading-state">Loading formal security report…</p>';

        try {
            const token = getAuthToken();
            const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(id)}`, {
                headers: { "Authorization": `Bearer ${token}` }
            });

            if (res.status === 401 || res.status === 403) {
                window.location.href = "login.html";
                return;
            }

            if (res.status === 404) {
                docEl.innerHTML = '<p class="empty-state" style="color:#F87171;">Report record not found or access denied.</p>';
                return;
            }

            if (!res.ok) {
                throw new Error(`Report detail fetch returned HTTP ${res.status}`);
            }

            const report = await res.json();
            docEl.innerHTML = renderReportDocument(report);
            wireDocumentActions(report);

        } catch (err) {
            console.error("Report detail fetch error:", err);
            docEl.innerHTML = '<p class="empty-state" style="color:#F87171;">Failed to load report contents.</p>';
        }
    }

    function renderReportDocument(r) {
        const c = r.counts || {};
        const allFindings = r.findings || [];

        // Exact 5-Category Posture Counts
        const cHigh = Number(c.high || 0) + Number(c.critical || 0);
        const cMed = Number(c.medium || 0);
        const cLow = Number(c.low || 0);
        const cPassed = Number(c.not_detected || 0);
        const cError = Number(c.scanner_error || 0);
        const cInconclusive = Number(c.inconclusive || 0);

        // Filter active findings for detailed remediation display (confirmed vulnerabilities only)
        const activeFindings = allFindings.filter(f => {
            const st = (f.status || "").toUpperCase();
            return st !== "NOT_DETECTED" && st !== "SCANNER_ERROR" && st !== "INCONCLUSIVE";
        });

        // Inconclusive findings representing scope limitations
        const inconclusiveFindings = allFindings.filter(f => (f.status || "").toUpperCase() === "INCONCLUSIVE");

        // Category breakdown progress bars
        const categories = (r.categories || []).map(cat => `
            <div class="cat-row">
                <span class="cat-name">${UI.escapeHTML(cat.name)}</span>
                <div class="cat-bar"><div class="cat-fill" style="width:${cat.score}%"></div></div>
                <span class="cat-value">${cat.score}%</span>
            </div>
        `).join("");

        // Finding Cards with full evidence and remediation
        const findingCards = activeFindings.length ? activeFindings.map(f => {
            const sevClass = (f.severity || "low").toLowerCase();
            const remediationList = Array.isArray(f.remediation) ? f.remediation : (f.remediation ? [String(f.remediation)] : []);

            return `
                <div class="fix-item ${sevClass}">
                    <div class="fix-head">
                        <div style="flex:1;">
                            <strong>${UI.escapeHTML(f.title)}</strong>
                            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">
                                ${f.url ? `<span>Location: <code style="color:#F3F4F6;">${UI.escapeHTML(f.url)}</code></span>` : ''}
                                ${f.parameter ? ` · <span>Parameter: <code style="color:#FBBF24;">${UI.escapeHTML(f.parameter)}</code></span>` : ''}
                                ${f.http_method ? ` · <span>Method: ${UI.escapeHTML(f.http_method)}</span>` : ''}
                            </div>
                        </div>
                        <span class="sev-badge ${UI.severityClass(f.severity)}">${UI.escapeHTML((f.severity || 'low').toUpperCase())}</span>
                    </div>

                    <div style="margin-top:10px;">
                        <span style="font-size:11.5px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-muted);">Impact Description</span>
                        <p style="margin:4px 0 8px 0;">${UI.escapeHTML(f.description || f.impact || 'Vulnerability verified on target.')}</p>
                    </div>

                    ${f.evidence ? `
                    <div style="margin-top:8px;">
                        <span style="font-size:11.5px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-muted);">Detection Methodology & Evidence</span>
                        <pre style="background:#0B0C0E; border:1px solid var(--border-color); padding:10px 14px; border-radius:6px; font-size:12px; font-family:'Consolas',monospace; color:#E2E8F0; margin-top:4px; overflow-x:auto; white-space:pre-wrap;">${UI.escapeHTML(f.evidence)}</pre>
                    </div>` : ''}

                    <div style="margin-top:10px;">
                        <span style="font-size:11.5px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; color:#10B981;">Remediation Guidance</span>
                        <ul style="margin:6px 0 0 16px;">
                            ${remediationList.length 
                                ? remediationList.map(s => `<li>${UI.escapeHTML(s)}</li>`).join("") 
                                : '<li>Apply strict input validation, parameterized queries, and defense-in-depth controls.</li>'}
                        </ul>
                    </div>

                    <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap;">
                        ${f.owasp ? `<span class="tag" style="background:rgba(255,255,255,0.04); border:1px solid var(--border-color); padding:3px 8px; border-radius:4px; font-size:11px; color:var(--text-secondary);">${UI.escapeHTML(f.owasp)}</span>` : ''}
                        ${f.cwe ? `<span class="tag" style="background:rgba(255,255,255,0.04); border:1px solid var(--border-color); padding:3px 8px; border-radius:4px; font-size:11px; color:var(--text-secondary);">${UI.escapeHTML(f.cwe)}</span>` : ''}
                        <span class="tag" style="background:rgba(255,255,255,0.04); border:1px solid var(--border-color); padding:3px 8px; border-radius:4px; font-size:11px; color:var(--text-muted);">Status: ${UI.escapeHTML(f.status || 'CONFIRMED')}</span>
                    </div>
                </div>
            `;
        }).join("") : `
            <div style="padding:24px; text-align:center; background:rgba(16, 185, 129, 0.05); border:1px solid rgba(16, 185, 129, 0.2); border-radius:var(--radius-sm);">
                <div style="font-size:18px; margin-bottom:4px;">🛡️</div>
                <strong style="color:#10B981; font-size:14px;">No Active Vulnerabilities Detected</strong>
                <p style="color:var(--text-secondary); font-size:12.5px; margin:4px 0 0 0;">Automated blackbox checks did not identify confirmed security flaws during this assessment.</p>
            </div>
        `;

        // Format executive summary (renders markdown or clean text)
        const summaryText = r.executive_summary || "Automated security posture evaluation completed.";
        let formattedSummary = UI.escapeHTML(summaryText);
        formattedSummary = formattedSummary.replace(/^### (.*$)/gim, '<h4 style="margin:10px 0 4px 0; color:#FFFFFF; font-size:13.5px;">$1</h4>');
        formattedSummary = formattedSummary.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:#FFFFFF;">$1</strong>');
        formattedSummary = formattedSummary.replace(/\n\n+/g, '<br><br>');
        formattedSummary = formattedSummary.replace(/([^\n])\n([^\n])/g, '$1<br>$2');

        return `
            <!-- Document Header -->
            <div class="doc-head">
                <div>
                    <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                        <span style="font-size:1.1rem; color:var(--brand-red);">🛡️</span>
                        <span style="font-weight:800; letter-spacing:0.8px; color:var(--brand-red); text-transform:uppercase; font-size:11.5px;">EthioSec Security Assessment Report</span>
                    </div>
                    <h2>${UI.escapeHTML(UI.hostOf(r.target))}</h2>
                    <p>${UI.escapeHTML(r.target)} · Generated ${UI.formatDate(r.generated_at)}</p>
                </div>

                <div class="doc-actions">
                    <a class="ghost-btn" href="results.html?id=${encodeURIComponent(r.scan_id)}" title="Inspect in Results Explorer">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                        <span>Open Results</span>
                    </a>
                    <button class="ghost-btn" id="btnAiSummary" type="button" title="Regenerate Executive Summary with Gemini AI">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path></svg>
                        <span>AI Summary</span>
                    </button>
                    <button class="ghost-btn" id="btnExportJson" type="button" title="Download machine-readable JSON report">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                        <span>Export JSON</span>
                    </button>
                    <button class="ghost-btn" id="btnExportCsv" type="button" title="Download tabular CSV report">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="8" y1="13" x2="16" y2="13"></line><line x1="8" y1="17" x2="16" y2="17"></line></svg>
                        <span>Export CSV</span>
                    </button>
                    <button class="primary-btn" id="btnExportPdf" type="button" title="Print or save as PDF">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                        <span>Export PDF</span>
                    </button>
                </div>
            </div>

            <!-- Executive Summary Section -->
            <div class="doc-section">
                <h3>Executive Summary</h3>
                <div class="exec-summary" id="execSummaryBox">${formattedSummary}</div>
            </div>

            <!-- 5-Category Security Posture Strip (Exact match to Results page) -->
            <div class="doc-section">
                <h3>Verified Posture & 5-Category Breakdown</h3>
                <div class="score-strip">
                    <div class="score-tile">
                        <b style="color:${r.security_score >= 80 ? 'var(--sev-passed)' : r.security_score >= 60 ? 'var(--sev-medium)' : 'var(--brand-red)'};">${r.security_score !== null ? r.security_score : '—'}</b>
                        <span>Score</span>
                    </div>
                    <div class="score-tile">
                        <b style="color:var(--sev-high);">${cHigh}</b>
                        <span>High</span>
                    </div>
                    <div class="score-tile">
                        <b style="color:var(--sev-medium);">${cMed}</b>
                        <span>Medium</span>
                    </div>
                    <div class="score-tile">
                        <b style="color:var(--sev-low);">${cLow}</b>
                        <span>Low</span>
                    </div>
                    <div class="score-tile">
                        <b style="color:var(--sev-passed);">${cPassed}</b>
                        <span>Not Detected</span>
                    </div>
                    <div class="score-tile">
                        <b style="color:var(--sev-error);">${cError}</b>
                        <span>Scanner Error</span>
                    </div>
                    ${cInconclusive > 0 ? `
                    <div class="score-tile" style="border-color:rgba(245, 158, 11, 0.4); background:rgba(245, 158, 11, 0.05);">
                        <b style="color:#F59E0B;">${cInconclusive}</b>
                        <span>Inconclusive</span>
                    </div>` : ''}
                </div>
                ${cInconclusive > 0 ? `
                <p style="font-size:11.5px; color:var(--text-muted); margin-top:8px;">
                    * <strong>Notice on Inconclusive Checks:</strong> ${cInconclusive} check(s) returned ambiguous responses (such as unexpected 500s or unstable DOM baselines). Inconclusive checks are never counted as confirmed vulnerabilities or as Not Detected.
                </p>` : ''}
            </div>

            <!-- Category Breakdown Section -->
            <div class="doc-section">
                <h3>Category Coverage & Health</h3>
                ${categories || '<p class="empty-state">No category breakdown available.</p>'}
            </div>

            <!-- Vulnerabilities & Detailed Technical Remediation -->
            <div class="doc-section">
                <h3>Verified Findings & Technical Remediation</h3>
                ${findingCards}
            </div>

            ${(inconclusiveFindings.length > 0 || cInconclusive > 0) ? `
            <!-- Assessment Coverage & Scope Limitations -->
            <div class="doc-section">
                <h3 style="color:#F59E0B; display:flex; align-items:center; gap:8px;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    Assessment Coverage & Scope Limitations (${inconclusiveFindings.length || cInconclusive})
                </h3>
                <div style="background:rgba(245, 158, 11, 0.05); border:1px solid rgba(245, 158, 11, 0.25); border-radius:var(--radius-sm); padding:16px;">
                    <p style="margin:0 0 10px 0; font-size:12.5px; color:var(--text-secondary); line-height:1.5;">
                        <strong>Incomplete / Inconclusive Assessment Notice:</strong>
                        The scanner encountered boundary conditions where conclusive security testing was not possible due to missing credentials, authorization contexts, or unverified server states. Inconclusive outcomes are <strong>not confirmed vulnerabilities</strong>, but they also <strong>do not indicate that the application is secure</strong>.
                    </p>
                    ${inconclusiveFindings.map(inc => `
                        <div style="background:rgba(0,0,0,0.3); border-left:3px solid #F59E0B; padding:10px 14px; margin-top:8px; border-radius:0 4px 4px 0;">
                            <strong style="color:#F59E0B; font-size:13px;">${UI.escapeHTML(inc.title)}</strong>
                            <p style="margin:4px 0 6px 0; font-size:12px; color:var(--text-secondary);">${UI.escapeHTML(inc.description)}</p>
                            ${inc.evidence ? `<div style="font-size:11.5px; color:var(--text-muted); font-family:monospace; background:rgba(255,255,255,0.03); padding:4px 8px; border-radius:3px;">${UI.escapeHTML(inc.evidence)}</div>` : ''}
                        </div>
                    `).join("")}
                </div>
            </div>` : ''}

            <!-- Assessment Scope & Methodology -->
            <div class="doc-section">
                <h3>Assessment Scope & Methodology</h3>
                <div style="font-size:12.5px; color:var(--text-secondary); line-height:1.65; background:rgba(255,255,255,0.015); border:1px solid var(--border-color); padding:16px 18px; border-radius:var(--radius-sm);">
                    <p style="margin-bottom:8px;"><strong>Methodology:</strong> EthioSec Scanner performed automated web vulnerability analysis including asynchronous URL crawling, passive security header evaluations, cookie flag inspections, TLS protocol validation, and differential fuzzing for Reflected XSS, SQL Injection, and Broken Access Control (IDOR).</p>
                    <p style="margin-bottom:0;"><strong>Limitations:</strong> Automated blackbox assessments audit the observable attack surface. They do not substitute for manual source-code audits, architecture threat modeling, or deep business logic reviews. Scanner errors and inconclusive outcomes must not be interpreted as proof of security.</p>
                </div>
            </div>

            <!-- Technical Metadata Section -->
            <div class="doc-section">
                <h3>Technical Metadata</h3>
                <table class="tech-table">
                    <tr><td>Report Identifier</td><td>${UI.escapeHTML(r.id)}</td></tr>
                    <tr><td>Scan Identifier</td><td>${UI.escapeHTML(r.scan_id)}</td></tr>
                    <tr><td>Target URL</td><td>${UI.escapeHTML(r.target)}</td></tr>
                    <tr><td>Assessment Profile</td><td>${UI.escapeHTML((r.depth || 'standard').toUpperCase())}</td></tr>
                    <tr><td>Total Evaluated Checks</td><td>${allFindings.length}</td></tr>
                    <tr><td>Open Confirmed Findings</td><td>${activeFindings.length}</td></tr>
                    <tr><td>Generated Timestamp</td><td>${UI.formatDate(r.generated_at)}</td></tr>
                </table>
            </div>
        `;
    }

    /* =====================================================
       4. WIRE DOCUMENT ACTIONS & EXPORTS
       ===================================================== */
    function wireDocumentActions(r) {
        const token = getAuthToken();

        // 1. Export PDF / Print
        const btnExportPdf = document.getElementById("btnExportPdf");
        if (btnExportPdf) {
            btnExportPdf.addEventListener("click", () => {
                UI.toast("Opening print dialog for PDF export…");
                setTimeout(() => window.print(), 300);
            });
        }

        // 2. Export JSON (Direct authenticated backend endpoint)
        const btnExportJson = document.getElementById("btnExportJson");
        if (btnExportJson) {
            btnExportJson.addEventListener("click", async () => {
                UI.toast("Generating JSON export…");
                try {
                    const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(r.id)}/export/json`, {
                        headers: { "Authorization": `Bearer ${token}` }
                    });
                    if (!res.ok) throw new Error(`HTTP ${res.status}`);
                    const blob = await res.blob();
                    const downloadUrl = window.URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = downloadUrl;
                    a.download = `ethiosec_report_${r.scan_id}.json`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    window.URL.revokeObjectURL(downloadUrl);
                    UI.toast("JSON report downloaded successfully.");
                } catch (e) {
                    console.error("JSON export error:", e);
                    UI.toast("Failed to download JSON export from server.", "error");
                }
            });
        }

        // 3. Export CSV (Direct authenticated backend endpoint)
        const btnExportCsv = document.getElementById("btnExportCsv");
        if (btnExportCsv) {
            btnExportCsv.addEventListener("click", async () => {
                UI.toast("Generating CSV export…");
                try {
                    const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(r.id)}/export/csv`, {
                        headers: { "Authorization": `Bearer ${token}` }
                    });
                    if (!res.ok) throw new Error(`HTTP ${res.status}`);
                    const blob = await res.blob();
                    const downloadUrl = window.URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = downloadUrl;
                    a.download = `ethiosec_report_${r.scan_id}.csv`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    window.URL.revokeObjectURL(downloadUrl);
                    UI.toast("CSV report downloaded successfully.");
                } catch (e) {
                    console.error("CSV export error:", e);
                    UI.toast("Failed to download CSV export from server.", "error");
                }
            });
        }

        // 4. Regenerate AI Summary
        const btnAiSummary = document.getElementById("btnAiSummary");
        if (btnAiSummary) {
            btnAiSummary.addEventListener("click", async () => {
                const summaryBox = document.getElementById("execSummaryBox");
                if (!summaryBox) return;

                btnAiSummary.disabled = true;
                const origText = btnAiSummary.innerHTML;
                btnAiSummary.innerHTML = `<span>⏳ Synthesizing…</span>`;
                summaryBox.innerHTML = '<span style="color:#F59E0B;">Synthesizing evidence-grounded executive summary with Gemini AI…</span>';

                try {
                    const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(r.id)}/ai-summary`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "Authorization": `Bearer ${token}`
                        }
                    });

                    if (!res.ok) throw new Error(`HTTP ${res.status}`);
                    const data = await res.json();
                    const md = data.markdown || "Summary regenerated.";
                    let formatted = UI.escapeHTML(md);
                    formatted = formatted.replace(/^### (.*$)/gim, '<h4 style="margin:10px 0 4px 0; color:#FFFFFF; font-size:13.5px;">$1</h4>');
                    formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:#FFFFFF;">$1</strong>');
                    formatted = formatted.replace(/\n\n+/g, '<br><br>');
                    formatted = formatted.replace(/([^\n])\n([^\n])/g, '$1<br>$2');

                    summaryBox.innerHTML = `<div style="border-left:3px solid #10B981; padding-left:14px;">${formatted}</div>`;
                    UI.toast("AI Executive Summary updated.");
                } catch (e) {
                    console.error("AI summary generation error:", e);
                    summaryBox.innerHTML = `<span style="color:#F87171;">Could not refresh AI summary. Standard executive summary retained:</span><br><br>${UI.escapeHTML(r.executive_summary || "")}`;
                    UI.toast("AI summary synthesis failed.", "error");
                } finally {
                    btnAiSummary.disabled = false;
                    btnAiSummary.innerHTML = origText;
                }
            });
        }
    }

    // Startup Execution
    loadReports();
});