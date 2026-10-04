if (!localStorage.getItem('token')) {
    window.location.href = 'login.html';
}
/* =====================================================
   REPORTS PAGE (reportjava.js) - Real Backend Sync
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

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
            const diff = Date.now() - new Date(dateString).getTime();
            const mins = Math.floor(diff / 60000);
            if (mins < 1) return "Just now";
            if (mins < 60) return `${mins}m ago`;
            const hours = Math.floor(mins / 60);
            if (hours < 24) return `${hours}h ago`;
            const days = Math.floor(hours / 24);
            return `${days}d ago`;
        },
        severityClass: (sev) => {
            const map = { critical: "sev-critical", high: "sev-high", medium: "sev-medium", low: "sev-low", info: "sev-info" };
            return map[sev?.toLowerCase()] || "sev-info";
        },
        getQueryParam: (param) => new URLSearchParams(window.location.search).get(param),
        toast: (msg, type = "info") => {
            const t = document.getElementById("toast");
            if (t) {
                t.textContent = msg;
                t.className = "toast show " + type;
                setTimeout(() => t.classList.remove("show"), 3000);
            }
        }
    };

    const listEl = document.getElementById("reportList");
    const docEl = document.getElementById("reportDoc");
    const countEl = document.getElementById("reportCount");

    let reportsList = [];
    let activeReportId = null;

    function scoreClass(score) {
        return score >= 80 ? "score-good" : score >= 60 ? "score-mid" : "score-bad";
    }

    /* =====================================================
       LOAD REPORTS LIST (From Backend)
       ===================================================== */
    async function loadList() {
        if (!listEl || !docEl) return;

        const token = localStorage.getItem("token");
        if (!token) {
            listEl.innerHTML = '<p class="empty-state">Please log in to view reports.</p>';
            return;
        }

        try {
            const res = await fetch("http://127.0.0.1:8000/api/reports", {
                headers: { "Authorization": `Bearer ${token}` }
            });

            if (!res.ok) {
                throw new Error(`Failed to load reports (HTTP ${res.status})`);
            }

            const data = await res.json();
            reportsList = data.reports || [];

            if (countEl) {
                countEl.textContent = `${reportsList.length} report${reportsList.length === 1 ? "" : "s"}`;
            }

            if (!reportsList.length) {
                listEl.innerHTML = '<p class="empty-state">No completed scans yet.<br><br><a href="scanfinal.html" style="color:#ff4b20">Start a scan to generate a report →</a></p>';
                docEl.innerHTML = '<p class="empty-state">Completed scans will automatically generate a formal security assessment report here.</p>';
                return;
            }

            listEl.innerHTML = reportsList.map(r => `
                <div class="report-item" data-id="${UI.escapeHTML(r.id)}">
                    <div class="report-item-main">
                        <div class="report-host">${UI.escapeHTML(UI.hostOf(r.target))}</div>
                        <div class="report-when">${UI.timeAgo(r.generated_at)} · ${(r.depth || 'standard').toUpperCase()}</div>
                    </div>
                    <div class="report-score ${scoreClass(r.security_score)}">${r.security_score !== null ? r.security_score : '—'}</div>
                </div>`).join("");

            listEl.querySelectorAll(".report-item").forEach(item => {
                item.addEventListener("click", () => openReport(item.dataset.id));
            });

            // Deep link verification (?id=...)
            const wanted = UI.getQueryParam("id");
            const found = wanted && reportsList.find(r => r.id === wanted || r.scan_id === wanted || r.scan_id === wanted.replace(/^r/, ""));
            openReport(found ? found.id : reportsList[0].id);

        } catch (err) {
            console.error("Reports list error:", err);
            listEl.innerHTML = '<p class="empty-state" style="color:#cc2f0c">Failed to connect to reports API.</p>';
            docEl.innerHTML = '<p class="empty-state">Ensure the backend service is reachable.</p>';
        }
    }

    /* =====================================================
       LOAD AND RENDER DOCUMENT
       ===================================================== */
    async function openReport(id) {
        if (!listEl || !docEl || !id) return;

        activeReportId = id;

        listEl.querySelectorAll(".report-item").forEach(i => {
            i.classList.toggle("active", i.dataset.id === id);
        });

        docEl.innerHTML = '<p class="loading-state">Loading formal security report…</p>';

        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`http://127.0.0.1:8000/api/reports/${encodeURIComponent(id)}`, {
                headers: { "Authorization": `Bearer ${token}` }
            });

            if (!res.ok) {
                throw new Error(`Failed to load report details (HTTP ${res.status})`);
            }

            const report = await res.json();
            docEl.innerHTML = renderDoc(report);
            wireDoc(report);

        } catch (err) {
            console.error("Report detail fetch error:", err);
            docEl.innerHTML = '<p class="empty-state" style="color:#cc2f0c">Failed to load report contents.</p>';
        }
    }

    function renderDoc(r) {
        const c = r.counts || {};
        const openFindings = (r.findings || []).filter(f => f.status !== "NOT_DETECTED" && f.status !== "not_detected" && f.status !== "SCANNER_ERROR");
        const passedFindings = (r.findings || []).filter(f => f.status === "NOT_DETECTED" || f.status === "not_detected");

        const categories = (r.categories || []).map(cat => `
            <div class="cat-row">
                <span class="cat-name">${UI.escapeHTML(cat.name)}</span>
                <div class="cat-bar"><div class="cat-fill" style="width:${cat.score}%"></div></div>
                <span class="cat-value">${cat.score}%</span>
            </div>`).join("");

        const findingCards = openFindings.length ? openFindings.map(f => `
            <div class="fix-item ${f.severity}">
                <div class="fix-head">
                    <div>
                        <strong style="font-size:1.05rem;">${UI.escapeHTML(f.title)}</strong>
                        <div style="font-size:0.8rem; color:var(--text-muted); margin-top:3px;">
                            ${f.url ? `<span>Location: <code>${UI.escapeHTML(f.url)}</code></span>` : ''}
                            ${f.parameter ? ` · <span>Param: <code>${UI.escapeHTML(f.parameter)}</code></span>` : ''}
                        </div>
                    </div>
                    <span class="sev-badge ${UI.severityClass(f.severity)}">${UI.escapeHTML(f.severity.toUpperCase())}</span>
                </div>
                
                <div style="margin-top:10px;">
                    <strong style="font-size:0.85rem; color:#eaeaea;">Description & Impact:</strong>
                    <p style="margin:4px 0 8px 0;">${UI.escapeHTML(f.description || f.impact || 'Vulnerability verified on target.')}</p>
                </div>

                ${f.evidence ? `
                <div style="margin-top:8px;">
                    <strong style="font-size:0.82rem; color:#eaeaea;">Detection Methodology & Evidence:</strong>
                    <pre style="background:rgba(0,0,0,0.4); padding:8px; border-radius:6px; font-size:0.8rem; margin-top:4px; overflow-x:auto; white-space:pre-wrap;">${UI.escapeHTML(f.evidence)}</pre>
                </div>` : ''}

                <div style="margin-top:8px;">
                    <strong style="font-size:0.85rem; color:#1bb369;">Remediation Recommendation:</strong>
                    <ul style="margin:4px 0 0 16px;">
                        ${(f.remediation && f.remediation.length) 
                            ? f.remediation.map(s => `<li>${UI.escapeHTML(s)}</li>`).join("") 
                            : '<li>Apply input validation and defense-in-depth controls.</li>'}
                    </ul>
                </div>

                <div style="margin-top:10px; display:flex; gap:8px;">
                    ${f.owasp ? `<span class="tag">${UI.escapeHTML(f.owasp)}</span>` : ''}
                    ${f.cwe ? `<span class="tag">${UI.escapeHTML(f.cwe)}</span>` : ''}
                </div>
            </div>`).join("")
            : '<p class="empty-state" style="color:#1bb369;">✓ No active vulnerabilities were detected in this assessment.</p>';

        return `
            <div class="doc-head">
                <div>
                    <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                        <span style="font-size:1.2rem;">🛡️</span>
                        <span style="font-weight:700; letter-spacing:0.5px; color:#cc2f0c; text-transform:uppercase; font-size:0.85rem;">EthioSec Security Assessment Report</span>
                    </div>
                    <h2>${UI.escapeHTML(UI.hostOf(r.target))}</h2>
                    <p>${UI.escapeHTML(r.target)} · Generated ${new Date(r.generated_at).toLocaleString()}</p>
                </div>
                <div class="doc-actions">
                    <a class="ghost-btn" href="results.html?id=${encodeURIComponent(r.scan_id)}">Open Results</a>
                    <button class="ghost-btn" id="generateAiSummary" type="button">🤖 AI Summary</button>
                    <button class="primary-btn" id="downloadPdf" type="button">⤓ Export PDF</button>
                </div>
            </div>

            <div class="doc-section">
                <h3>Executive Summary</h3>
                <div class="exec-summary" id="execSummaryContent">${UI.escapeHTML(r.executive_summary || "")}</div>
            </div>

            <div class="doc-section">
                <h3>Security Score & Posture</h3>
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
                <h3>Category Breakdown</h3>
                ${categories || '<p class="empty-state">No category breakdown available.</p>'}
            </div>

            <div class="doc-section">
                <h3>Vulnerabilities & Detailed Remediation</h3>
                ${findingCards}
            </div>

            <div class="doc-section">
                <h3>Assessment Scope & Methodology</h3>
                <div style="font-size:0.85rem; color:var(--text-muted); line-height:1.6;">
                    <p><strong>Methodology:</strong> EthioSec Scanner performed automated blackbox vulnerability scanning including crawler-based endpoint discovery, passive security header inspections, TLS protocol analysis, and targeted active fuzzing for SQL injection and Cross-Site Scripting (XSS).</p>
                    <p><strong>Limitations:</strong> Automated testing evaluates external web surface interfaces. It does not replace manual penetration testing, source code analysis, or comprehensive business logic audits.</p>
                </div>
            </div>

            <div class="doc-section">
                <h3>Technical Metadata</h3>
                <table class="tech-table">
                    <tr><td>Report ID</td><td>${UI.escapeHTML(r.id)}</td></tr>
                    <tr><td>Scan ID</td><td>${UI.escapeHTML(r.scan_id)}</td></tr>
                    <tr><td>Target URL</td><td>${UI.escapeHTML(r.target)}</td></tr>
                    <tr><td>Scan Depth</td><td>${UI.escapeHTML((r.depth || 'standard').toUpperCase())}</td></tr>
                    <tr><td>Total Checks Evaluated</td><td>${(r.findings || []).length}</td></tr>
                    <tr><td>Open Vulnerabilities</td><td>${openFindings.length}</td></tr>
                    <tr><td>Assessment Timestamp</td><td>${new Date(r.generated_at).toLocaleString()}</td></tr>
                </table>
            </div>`;
    }

    function wireDoc(r) {
        const printBtn = document.getElementById("downloadPdf");
        if (printBtn) {
            printBtn.addEventListener("click", () => {
                UI.toast("Opening print dialog for PDF export…");
                setTimeout(() => window.print(), 300);
            });
        }

        const aiBtn = document.getElementById("generateAiSummary");
        if (aiBtn) {
            aiBtn.addEventListener("click", async () => {
                const summaryEl = document.getElementById("execSummaryContent");
                if (!summaryEl) return;
                
                aiBtn.disabled = true;
                aiBtn.textContent = "⏳ Generating…";
                summaryEl.innerHTML = '<span style="color:#ffa500;">Synthesizing AI executive summary from real scan findings…</span>';

                try {
                    const token = localStorage.getItem("token");
                    const res = await fetch("http://127.0.0.1:8000/api/ai/chat", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "Authorization": `Bearer ${token}`
                        },
                        body: JSON.stringify({
                            message: "Generate a concise, professional executive security summary and management-level risk statement for this scan report based strictly on the findings.",
                            scan_id: r.scan_id
                        })
                    });

                    if (!res.ok) throw new Error("AI service unavailable");
                    const data = await res.json();
                    summaryEl.innerHTML = `<div style="border-left:3px solid #1bb369; padding-left:12px; margin-top:4px;">${UI.escapeHTML(data.reply)}</div>`;
                    UI.toast("AI Executive Summary generated.");
                } catch (e) {
                    console.error("AI summary error:", e);
                    summaryEl.innerHTML = `<span style="color:#ff6b6b;">AI summary could not be retrieved. Using standard summary:</span><br>${UI.escapeHTML(r.executive_summary || "")}`;
                    UI.toast("Could not connect to AI service.", "error");
                } finally {
                    aiBtn.disabled = false;
                    aiBtn.textContent = "🤖 AI Summary";
                }
            });
        }
    }

    loadList();
});