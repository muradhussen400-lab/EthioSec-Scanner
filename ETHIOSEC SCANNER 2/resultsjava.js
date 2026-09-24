/* =====================================================
   VULNERABILITY RESULTS (resultsjava.js) - Pure Frontend
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ---------- FRONTEND UTILITIES ---------- */
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
            if (!dateString) return "Recently";
            return "Today";
        },
        severityClass: (sev) => {
            const map = { critical: "sev-critical", high: "sev-high", medium: "sev-medium", low: "sev-low", info: "sev-info" };
            return map[sev?.toLowerCase()] || "sev-info";
        },
        toast: (msg) => {
            const t = document.getElementById("toast");
            if (t) {
                t.textContent = msg;
                t.classList.add("show");
                setTimeout(() => t.classList.remove("show"), 3000);
            }
        },
        getQueryParam: (param) => new URLSearchParams(window.location.search).get(param)
    };

    /* ---------- URL & IDENTIFIERS ---------- */
    const scanId = UI.getQueryParam("id") || "scan_demo_01";
    const RING_LENGTH = 2 * Math.PI * 60;

    let findings = [];
    let filterSeverity = "all";
    let filterModule = "all";
    let search = "";

    const list = document.getElementById("findingList");
    const scanIdLabel = document.getElementById("scanIdLabel");
    const openReport = document.getElementById("openReport");

    if (scanIdLabel) scanIdLabel.textContent = scanId;
    if (openReport) openReport.href = `reports.html?id=r${encodeURIComponent(scanId)}`;

    /* =====================================================
       DATA RESOLVER (LocalStorage -> EthioAPI -> Fallback)
       ===================================================== */
    async function fetchScanData(id) {
        // 1. Check if mock database has this scan in localStorage
        try {
            const rawDb = localStorage.getItem("ethio_mock_db");
            if (rawDb) {
                const db = JSON.parse(rawDb);
                const match = (db.scans || []).find(s => s.id === id);
                if (match && match.findings && match.findings.length) {
                    return match;
                }
            }
        } catch (e) {
            console.warn("Could not read from mock db:", e);
        }

        // 2. Check if window.EthioAPI is defined (e.g. from inline shim)
        if (window.EthioAPI && typeof window.EthioAPI.scanResults === "function") {
            try {
                const res = await window.EthioAPI.scanResults(id);
                if (res && res.findings) return res;
            } catch (err) {
                console.warn("EthioAPI fallback error:", err);
            }
        }

        // 3. Complete standalone fallback dataset
        return {
            target: "https://demo.ethio-security.org",
            depth: "Deep Audit",
            scanned_at: new Date().toISOString(),
            security_score: 72,
            counts: { critical: 1, high: 2, medium: 2, low: 3, passed: 14 },
            findings: [
                {
                    id: "f-01",
                    type: "injection",
                    severity: "critical",
                    confidence: "high",
                    url: "https://demo.ethio-security.org/login.php",
                    parameter: "username",
                    evidence: "SQL syntax error: ' OR 1=1 --",
                    title: "SQL Injection in Authentication Route",
                    description: "User parameter 'username' is concatenated directly into SQL query without parameterization.",
                    impact: "Attacker can bypass login and extract confidential database records.",
                    remediation: [
                        "Use parameterized PDO or prepared statements.",
                        "Enforce strict input validation."
                    ],
                    owasp: "A03:2021-Injection",
                    cwe: "CWE-89",
                    ai_explanation: "The query treats user input as executable SQL logic.",
                    status: "open"
                },
                {
                    id: "f-02",
                    type: "headers",
                    severity: "high",
                    confidence: "high",
                    url: "https://demo.ethio-security.org/",
                    parameter: "",
                    evidence: "Header 'Content-Security-Policy' missing",
                    title: "Missing Content-Security-Policy (CSP)",
                    description: "No CSP configured on the web server response headers.",
                    impact: "Leaves application vulnerable to persistent and reflected XSS execution.",
                    remediation: [
                        "Configure Content-Security-Policy: default-src 'self'."
                    ],
                    owasp: "A05:2021-Security Misconfiguration",
                    cwe: "CWE-693",
                    ai_explanation: "Browsers rely on CSP headers to restrict untrusted scripts.",
                    status: "open"
                },
                {
                    id: "f-03",
                    type: "misconfig",
                    severity: "medium",
                    confidence: "medium",
                    url: "https://demo.ethio-security.org/.git/",
                    parameter: "",
                    evidence: "Status 200 on /.git/config",
                    title: "Exposed Git Repository",
                    description: "Source code repository metadata is accessible over public HTTP.",
                    impact: "Full source code exposure and secret token leaks.",
                    remediation: [
                        "Deny web server access to hidden dotfiles starting with '.' in Nginx/Apache."
                    ],
                    owasp: "A01:2021-Broken Access Control",
                    cwe: "CWE-538",
                    ai_explanation: "Dot directories contain internal VCS revisions and metadata.",
                    status: "open"
                }
            ]
        };
    }

    /* =====================================================
       LOAD CONTROLLER
       ===================================================== */
    async function load() {
        const data = await fetchScanData(scanId);
        findings = data.findings || [];

        const targetEl = document.getElementById("resultTarget");
        const depthEl = document.getElementById("depthLabel");
        const finishedEl = document.getElementById("finishedLabel");

        if (targetEl) targetEl.textContent = data.target;
        if (depthEl) depthEl.textContent = data.depth || "Deep Audit";
        if (finishedEl) finishedEl.textContent = UI.timeAgo(data.scanned_at || data.finished_at);

        paintScore(data.security_score ?? 72, data.counts || {});
        buildModuleFilter();
        render();
    }

    function paintScore(score, counts) {
        const ring = document.getElementById("ringProgress");
        if (ring) {
            ring.style.strokeDasharray = RING_LENGTH;
            requestAnimationFrame(() => {
                ring.style.strokeDashoffset = RING_LENGTH - (score / 100) * RING_LENGTH;
            });
        }

        const scoreValEl = document.getElementById("scoreValue");
        if (scoreValEl) countUp(scoreValEl, score);

        const setSafeText = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };

        setSafeText("cCritical", counts.critical || 0);
        setSafeText("cHigh", counts.high || 0);
        setSafeText("cMedium", counts.medium || 0);
        setSafeText("cLow", counts.low || 0);
        setSafeText("cPassed", counts.passed || 0);

        const verdict = document.getElementById("verdict");
        const note = document.getElementById("verdictNote");

        if (verdict && note) {
            if (counts.critical) {
                verdict.textContent = "Critical issues found";
                note.textContent = "Fix the critical findings before anything else — they are directly exploitable.";
            } else if (counts.high) {
                verdict.textContent = "High-risk issues found";
                note.textContent = "No direct breach path, but an attacker only needs one extra step.";
            } else if (score >= 85) {
                verdict.textContent = "Looking healthy";
                note.textContent = "Only minor hardening remaining. Re-scan after each change.";
            } else {
                verdict.textContent = "Some hardening needed";
                note.textContent = "Review medium and low findings to strengthen defense-in-depth.";
            }
        }
    }

    function countUp(el, target) {
        const duration = 800;
        const start = performance.now();

        function frame(now) {
            const p = Math.min((now - start) / duration, 1);
            el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
            if (p < 1) requestAnimationFrame(frame);
        }

        requestAnimationFrame(frame);
    }

    /* =====================================================
       FILTERS + RENDER
       ===================================================== */
    function buildModuleFilter() {
        const select = document.getElementById("moduleFilter");
        if (!select) return;

        // Reset to initial state
        select.innerHTML = '<option value="all">All modules</option>';

        [...new Set(findings.map(f => f.type).filter(Boolean))].sort().forEach(type => {
            const opt = document.createElement("option");
            opt.value = type;
            opt.textContent = type.replace(/-/g, " ");
            select.appendChild(opt);
        });
    }

    function visible() {
        return findings.filter(f => {
            const open = f.status !== "passed";

            if (filterSeverity === "open" && !open) return false;
            if (filterSeverity === "passed" && open) return false;
            if (!["all", "open", "passed"].includes(filterSeverity) && f.severity !== filterSeverity) return false;

            if (filterModule !== "all" && f.type !== filterModule) return false;

            if (search) {
                const hay = `${f.title} ${f.description} ${f.type} ${f.owasp || ""} ${f.cwe || ""}`.toLowerCase();
                if (!hay.includes(search)) return false;
            }

            return true;
        });
    }

    const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

    function render() {
        if (!list) return;

        const rows = visible().sort((a, b) =>
            (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

        if (!rows.length) {
            list.innerHTML = '<p class="empty-state">No findings match these filters.</p>';
            return;
        }

        list.innerHTML = rows.map(f => `
            <div class="finding ${f.severity}" data-id="${UI.escapeHTML(f.id)}">
                <div class="finding-main">
                    <div class="finding-title">
                        <strong>${UI.escapeHTML(f.title)}</strong>
                        <span class="sev-badge ${UI.severityClass(f.severity)}">${f.status === "passed" ? "passed" : UI.escapeHTML(f.severity)}</span>
                    </div>
                    <div class="finding-desc">${UI.escapeHTML(f.description)}</div>
                    <div class="finding-tags">
                        <span class="tag">${UI.escapeHTML(f.type)}</span>
                        ${f.owasp ? `<span class="tag">${UI.escapeHTML(f.owasp)}</span>` : ""}
                        ${f.cwe ? `<span class="tag">${UI.escapeHTML(f.cwe)}</span>` : ""}
                        ${f.parameter ? `<span class="tag">param: ${UI.escapeHTML(f.parameter)}</span>` : ""}
                    </div>
                </div>
                <span class="finding-arrow">›</span>
            </div>`).join("");

        list.querySelectorAll(".finding").forEach(row => {
            row.addEventListener("click", () => openDetail(row.dataset.id));
        });
    }

    const sevFilterEl = document.getElementById("severityFilter");
    if (sevFilterEl) {
        sevFilterEl.addEventListener("change", e => {
            filterSeverity = e.target.value;
            syncCountButtons();
            render();
        });
    }

    const modFilterEl = document.getElementById("moduleFilter");
    if (modFilterEl) {
        modFilterEl.addEventListener("change", e => {
            filterModule = e.target.value;
            render();
        });
    }

    const searchEl = document.getElementById("findingSearch");
    if (searchEl) {
        searchEl.addEventListener("input", e => {
            search = e.target.value.trim().toLowerCase();
            render();
        });
    }

    document.querySelectorAll(".count").forEach(btn => {
        btn.addEventListener("click", () => {
            const value = btn.dataset.filter;
            filterSeverity = filterSeverity === value ? "all" : value;
            if (sevFilterEl) sevFilterEl.value = filterSeverity;
            syncCountButtons();
            render();
        });
    });

    function syncCountButtons() {
        document.querySelectorAll(".count").forEach(b => {
            b.classList.toggle("active", b.dataset.filter === filterSeverity);
        });
    }

    /* =====================================================
       DETAILS MODAL
       ===================================================== */
    const modal = document.getElementById("detailModal");

    function openDetail(id) {
        const f = findings.find(x => x.id === id);
        if (!f || !modal) return;

        document.getElementById("dTitle").textContent = f.title;
        document.getElementById("dUrl").textContent = f.url;

        const sev = document.getElementById("dSeverity");
        if (sev) {
            sev.textContent = f.status === "passed" ? "passed" : f.severity;
            sev.className = "sev-badge " + UI.severityClass(f.status === "passed" ? "info" : f.severity);
        }

        document.getElementById("dConfidence").textContent = (f.confidence || "high") + " confidence";
        document.getElementById("dDescription").textContent = f.description || "—";
        document.getElementById("dEvidence").textContent = f.evidence || "No raw evidence captured for this check.";
        document.getElementById("dImpact").textContent = f.impact || "—";
        document.getElementById("dAi").textContent = f.ai_explanation || "The AI module has generated proactive remediation guidance for this finding.";

        const steps = document.getElementById("dRemediation");
        if (steps) {
            steps.innerHTML = (f.remediation && f.remediation.length)
                ? f.remediation.map(s => `<li>${UI.escapeHTML(s)}</li>`).join("")
                : "<li>No action required — check verified as passed.</li>";
        }

        document.getElementById("dOwasp").textContent = f.owasp || "OWASP —";
        document.getElementById("dCwe").textContent = f.cwe || "CWE —";

        const param = document.getElementById("dParam");
        if (param) {
            param.hidden = !f.parameter;
            if (f.parameter) param.textContent = "Parameter: " + f.parameter;
        }

        const askAi = document.getElementById("askAi");
        if (askAi) {
            askAi.href = `assistance.html?scan=${encodeURIComponent(scanId)}&finding=${encodeURIComponent(f.id)}`;
        }

        modal.hidden = false;
        document.body.style.overflow = "hidden";
    }

    function closeDetail() {
        if (!modal) return;
        modal.hidden = true;
        document.body.style.overflow = "";
    }

    document.getElementById("modalClose")?.addEventListener("click", closeDetail);
    document.getElementById("modalDone")?.addEventListener("click", closeDetail);
    if (modal) modal.addEventListener("click", e => { if (e.target === modal) closeDetail(); });
    document.addEventListener("keydown", e => { if (e.key === "Escape" && modal && !modal.hidden) closeDetail(); });

    load();
});