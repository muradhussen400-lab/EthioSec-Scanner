/* =====================================================
   REPORTS PAGE (reports.html) - Pure Frontend Standalone
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ---------- INTERNAL FRONTEND HELPERS ---------- */
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
            return "Today";
        },
        severityClass: (sev) => {
            const map = { critical: "sev-critical", high: "sev-high", medium: "sev-medium", low: "sev-low", info: "sev-info" };
            return map[sev?.toLowerCase()] || "sev-info";
        },
        getQueryParam: (param) => new URLSearchParams(window.location.search).get(param),
        toast: (msg) => {
            const t = document.getElementById("toast");
            if (t) {
                t.textContent = msg;
                t.classList.add("show");
                setTimeout(() => t.classList.remove("show"), 3000);
            } else {
                console.log("[Toast]", msg);
            }
        }
    };

    const listEl = document.getElementById("reportList");
    const docEl = document.getElementById("reportDoc");
    const countEl = document.getElementById("reportCount");

    /* ---------- MOCK REPORTS DATABASE ---------- */
    const mockReports = [
        {
            id: "r-demo-01",
            scan_id: "scan_001",
            target: "https://demo.ethio-security.org",
            security_score: 72,
            generated_at: new Date().toISOString(),
            counts: { critical: 1, high: 2, medium: 2, low: 3, passed: 14, total: 8 },
            executive_summary: "The automated audit of demo.ethio-security.org finished with a security score of 72/100. 8 issues were detected across web endpoints, including 1 critical vulnerability requiring immediate patching before production deployment.",
            categories: [
                { name: "Injection Security", score: 40 },
                { name: "Cryptographic Controls", score: 85 },
                { name: "Security Configuration", score: 70 },
                { name: "Authentication & Session", score: 90 }
            ],
            findings: [
                {
                    id: "f-01",
                    severity: "critical",
                    title: "SQL Injection in Authentication Route",
                    owasp: "A03:2021-Injection",
                    impact: "Direct unauthorized access to database contents and credential theft.",
                    remediation: [
                        "Use parameterized prepared statements.",
                        "Enforce strict input sanitization and schema typing."
                    ],
                    status: "open"
                },
                {
                    id: "f-02",
                    severity: "high",
                    title: "Missing Content-Security-Policy (CSP)",
                    owasp: "A05:2021-Security Misconfiguration",
                    impact: "Allows arbitrary inline script execution in the context of the user's active session.",
                    remediation: [
                        "Add a Content-Security-Policy HTTP response header to restrict external asset sources."
                    ],
                    status: "open"
                },
                {
                    id: "f-03",
                    severity: "medium",
                    title: "Exposed .git Directory Metadata",
                    owasp: "A01:2021-Broken Access Control",
                    impact: "Enables attackers to reconstruct internal repository files and uncover hardcoded keys.",
                    remediation: [
                        "Configure web server rules to deny access to hidden files and dot directories."
                    ],
                    status: "open"
                }
            ]
        },
        {
            id: "r-demo-02",
            scan_id: "scan_002",
            target: "https://ecommerce.api.local",
            security_score: 94,
            generated_at: new Date(Date.now() - 86400000).toISOString(),
            counts: { critical: 0, high: 0, medium: 1, low: 2, passed: 22, total: 3 },
            executive_summary: "Security posture for ecommerce.api.local is strong with a score of 94/100. Only minor configuration hardening adjustments remain.",
            categories: [
                { name: "Injection Security", score: 100 },
                { name: "Cryptographic Controls", score: 95 },
                { name: "Security Configuration", score: 88 },
                { name: "Authentication & Session", score: 92 }
            ],
            findings: [
                {
                    id: "f-11",
                    severity: "medium",
                    title: "Server Software Version Banner Leaked",
                    owasp: "A05:2021-Security Misconfiguration",
                    impact: "Reveals exact software versions in use, aiding targeted version exploit identification.",
                    remediation: ["Disable server version tokens in web server configuration files."],
                    status: "open"
                }
            ]
        }
    ];

    function scoreClass(score) {
        return score >= 80 ? "score-good" : score >= 60 ? "score-mid" : "score-bad";
    }

    /* =====================================================
       LIST
       ===================================================== */
    function loadList() {
        if (!listEl || !docEl) return;

        if (countEl) {
            countEl.textContent = `${mockReports.length} report${mockReports.length === 1 ? "" : "s"}`;
        }

        if (!mockReports.length) {
            listEl.innerHTML = '<p class="empty-state">No completed scans yet.</p>';
            docEl.innerHTML = '<p class="empty-state">Run a scan and its report will appear here.</p>';
            return;
        }

        listEl.innerHTML = mockReports.map(r => `
            <div class="report-item" data-id="${UI.escapeHTML(r.id)}">
                <div class="report-item-main">
                    <div class="report-host">${UI.escapeHTML(UI.hostOf(r.target))}</div>
                    <div class="report-when">${UI.timeAgo(r.generated_at)}</div>
                </div>
                <div class="report-score ${scoreClass(r.security_score)}">${r.security_score}</div>
            </div>`).join("");

        listEl.querySelectorAll(".report-item").forEach(item => {
            item.addEventListener("click", () => openReport(item.dataset.id));
        });

        // Deep link verification (?id=...)
        const wanted = UI.getQueryParam("id");
        const found = wanted && mockReports.find(r => r.id === wanted || r.scan_id === wanted.replace(/^r/, ""));
        openReport(found ? found.id : mockReports[0].id);
    }

    /* =====================================================
       DOCUMENT
       ===================================================== */
    function openReport(id) {
        if (!listEl || !docEl) return;

        listEl.querySelectorAll(".report-item").forEach(i => {
            i.classList.toggle("active", i.dataset.id === id);
        });

        const r = mockReports.find(x => x.id === id);
        if (!r) {
            docEl.innerHTML = '<p class="empty-state">Report not found.</p>';
            return;
        }

        docEl.innerHTML = renderDoc(r);
        wireDoc(r);
    }

    function renderDoc(r) {
        const c = r.counts || {};
        const open = (r.findings || []).filter(f => f.status !== "passed");

        const categories = (r.categories || []).map(cat => `
            <div class="cat-row">
                <span class="cat-name">${UI.escapeHTML(cat.name)}</span>
                <div class="cat-bar"><div class="cat-fill" style="width:${cat.score}%"></div></div>
                <span class="cat-value">${cat.score}%</span>
            </div>`).join("");

        const fixes = open.length ? open.map(f => `
            <div class="fix-item ${f.severity}">
                <div class="fix-head">
                    <strong>${UI.escapeHTML(f.title)}</strong>
                    <span class="sev-badge ${UI.severityClass(f.severity)}">${UI.escapeHTML(f.severity)}</span>
                    <span class="tag">${UI.escapeHTML(f.owasp || "")}</span>
                </div>
                <p>${UI.escapeHTML(f.impact || "")}</p>
                <ul>${(f.remediation || []).map(s => `<li>${UI.escapeHTML(s)}</li>`).join("")}</ul>
            </div>`).join("")
            : '<p class="empty-state">No open issues in this scan.</p>';

        return `
            <div class="doc-head">
                <div>
                    <h2>${UI.escapeHTML(UI.hostOf(r.target))}</h2>
                    <p>${UI.escapeHTML(r.target)} · generated ${UI.timeAgo(r.generated_at)}</p>
                </div>
                <div class="doc-actions">
                    <a class="ghost-btn" href="results.html?id=${encodeURIComponent(r.scan_id)}">Open results</a>
                    <button class="primary-btn" id="downloadPdf" type="button">⤓ Download PDF</button>
                </div>
            </div>

            <div class="doc-section">
                <h3>Executive summary</h3>
                <div class="exec-summary">${UI.escapeHTML(r.executive_summary || "")}</div>
            </div>

            <div class="doc-section">
                <h3>Security score</h3>
                <div class="score-strip">
                    <div class="score-tile"><b>${r.security_score}</b><span>Score</span></div>
                    <div class="score-tile"><b style="color:#ff5b5b">${c.critical || 0}</b><span>Critical</span></div>
                    <div class="score-tile"><b style="color:#ff8a3d">${c.high || 0}</b><span>High</span></div>
                    <div class="score-tile"><b style="color:#ffa500">${c.medium || 0}</b><span>Medium</span></div>
                    <div class="score-tile"><b style="color:#5aa9ff">${c.low || 0}</b><span>Low</span></div>
                    <div class="score-tile"><b style="color:#1bb369">${c.passed || 0}</b><span>Passed</span></div>
                </div>
            </div>

            <div class="doc-section">
                <h3>Category breakdown</h3>
                ${categories || '<p class="empty-state">No category data.</p>'}
            </div>

            <div class="doc-section">
                <h3>Issues and recommended fixes</h3>
                ${fixes}
            </div>

            <div class="doc-section">
                <h3>Technical details</h3>
                <table class="tech-table">
                    <tr><td>Report ID</td><td>${UI.escapeHTML(r.id)}</td></tr>
                    <tr><td>Scan ID</td><td>${UI.escapeHTML(r.scan_id)}</td></tr>
                    <tr><td>Target</td><td>${UI.escapeHTML(r.target)}</td></tr>
                    <tr><td>Total checks</td><td>${(r.findings || []).length + (c.passed || 0)}</td></tr>
                    <tr><td>Open issues</td><td>${open.length}</td></tr>
                    <tr><td>Generated</td><td>${new Date(r.generated_at).toLocaleString()}</td></tr>
                </table>
            </div>`;
    }

    function wireDoc(r) {
        const btn = document.getElementById("downloadPdf");
        if (!btn) return;

        btn.addEventListener("click", () => {
            // Trigger native print dialogue to save as PDF in pure frontend mode
            UI.toast("Generating print preview / PDF export...");
            setTimeout(() => {
                window.print();
            }, 300);
        });
    }

    loadList();
});