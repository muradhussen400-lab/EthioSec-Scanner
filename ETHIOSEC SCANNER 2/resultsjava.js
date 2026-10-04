if (!localStorage.getItem('token')) {
    window.location.href = 'login.html';
}
/* =====================================================
   VULNERABILITY RESULTS (resultsjava.js) - Real Backend Sync
   ===================================================== */

document.addEventListener("DOMContentLoaded", async () => {

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
            const map = { 
                high: "sev-high", 
                medium: "sev-medium", 
                low: "sev-low", 
                info: "sev-info" 
            };
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

    let scanId = UI.getQueryParam("id");
    const RING_LENGTH = 2 * Math.PI * 60;

    let findings = [];
    let filterSeverity = "all";
    let filterModule = "all";
    let search = "";

    const list = document.getElementById("findingList");
    const scanIdLabel = document.getElementById("scanIdLabel");
    const openReport = document.getElementById("openReport");

    // If no scan ID specified in URL, resolve the user's latest scan from backend
    if (!scanId) {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://127.0.0.1:8000/api/scans?limit=1", {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                if (data.scans && data.scans.length > 0) {
                    scanId = data.scans[0].id;
                    history.replaceState(null, "", `results.html?id=${encodeURIComponent(scanId)}`);
                }
            }
        } catch (e) {
            console.error("Could not resolve latest scan ID", e);
        }
    }

    if (scanIdLabel) scanIdLabel.textContent = scanId || "—";
    if (openReport && scanId) openReport.href = `reports.html?id=r${encodeURIComponent(scanId)}`;

    /* =====================================================
       DATA RESOLVER (Strict Backend API)
       ===================================================== */
    async function fetchScanData(id) {
        if (!id) {
            return {
                target: "No scan selected",
                depth: "—",
                scanned_at: new Date().toISOString(),
                security_score: 0,
                counts: { critical: 0, high: 0, medium: 0, low: 0, passed: 0 },
                findings: []
            };
        }

        try {
            const token = localStorage.getItem("token");
            const headers = { "Content-Type": "application/json" };
            if (token) headers["Authorization"] = `Bearer ${token}`;

            const res = await fetch(`http://127.0.0.1:8000/api/scans/${id}/results`, { headers });
            if (!res.ok) {
                if (res.status === 409) {
                    // Scan still running, redirect to livescan
                    window.location.href = `livescan.html?id=${encodeURIComponent(id)}`;
                    return null;
                }
                throw new Error(`Failed to load scan results (HTTP ${res.status})`);
            }
            
            return await res.json();
        } catch (err) {
            console.error("Scan results fetch error:", err);
            return {
                target: "Error loading scan data from backend",
                depth: "Unknown",
                scanned_at: new Date().toISOString(),
                security_score: 0,
                counts: { critical: 0, high: 0, medium: 0, low: 0, passed: 0 },
                findings: []
            };
        }
    }

    /* =====================================================
       LOAD CONTROLLER
       ===================================================== */
    async function load() {
        if (!scanId) {
            if (list) list.innerHTML = '<p class="empty-state">No scans found. <a href="scanfinal.html" style="color:#ff4b20">Start a new scan →</a></p>';
            const targetEl = document.getElementById("resultTarget");
            if (targetEl) targetEl.textContent = "No scan data";
            return;
        }

        const data = await fetchScanData(scanId);
        if (!data) return;

        findings = data.findings || [];

        const targetEl = document.getElementById("resultTarget");
        const depthEl = document.getElementById("depthLabel");
        const finishedEl = document.getElementById("finishedLabel");

        if (targetEl) targetEl.textContent = data.target;
        if (depthEl) depthEl.textContent = (data.depth || "standard").toUpperCase();
        if (finishedEl) finishedEl.textContent = UI.timeAgo(data.scanned_at || data.finished_at);

        paintScore(data.security_score ?? 0, data.counts || {});
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

        setSafeText("cHigh", counts.high || 0);
        setSafeText("cMedium", counts.medium || 0);
        setSafeText("cLow", counts.low || 0);
        setSafeText("cInconclusive", counts.inconclusive || 0);
        setSafeText("cPassed", counts.not_detected || counts.passed || 0);
        setSafeText("cError", counts.scanner_error || 0);

        const verdict = document.getElementById("verdict");
        const note = document.getElementById("verdictNote");

        const hasHigh = Boolean(counts.high);
        const hasMediumOrLow = Boolean(counts.medium || counts.low);
        const hasErrors = findings.some(f => f.status === "SCANNER_ERROR" || f.type === "scanner_error");

        if (verdict && note) {
            if (hasHigh) {
                verdict.textContent = "High Security Concerns";
                note.textContent = "High-severity vulnerabilities identified. Prompt remediation recommended.";
            } else if (hasMediumOrLow) {
                verdict.textContent = "Hardening Recommended";
                note.textContent = "Security misconfigurations or lower-severity issues detected.";
            } else if (hasErrors) {
                verdict.textContent = "Scan Completed with Warnings";
                note.textContent = "Some resources encountered network or connectivity notices.";
            } else {
                verdict.textContent = "No Vulnerabilities Detected";
                note.textContent = "All executed security checks completed without finding known vulnerabilities.";
            }
        }
    }

    function countUp(el, target) {
        const duration = 700;
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

        select.innerHTML = '<option value="all">All modules</option>';

        [...new Set(findings.map(f => f.type).filter(Boolean))].sort().forEach(type => {
            const opt = document.createElement("option");
            opt.value = type;
            opt.textContent = type.replace(/_/g, " ").toUpperCase();
            select.appendChild(opt);
        });
    }

    function visible() {
        return findings.filter(f => {
            const isPassed = f.status === "NOT_DETECTED" || f.status === "not_detected";
            const isError = f.status === "SCANNER_ERROR" || f.status === "scanner_error";
            const isInconclusive = f.status === "INCONCLUSIVE" || f.status === "inconclusive";
            
            // Completely hide inconclusive findings as requested
            if (isInconclusive) return false;
            const isConfirmed = f.status === "CONFIRMED" || f.status === "confirmed";

            if (filterSeverity === "confirmed" && !isConfirmed) return false;
            if (filterSeverity === "not_detected" && !isPassed) return false;
            if (filterSeverity === "scanner_error" && !isError) return false;
            if (filterSeverity === "inconclusive" && !isInconclusive) return false;
            
            if (!["all", "confirmed", "not_detected", "scanner_error", "inconclusive"].includes(filterSeverity)) {
                if (f.severity !== filterSeverity) return false;
            }

            if (filterModule !== "all" && f.type !== filterModule) return false;

            if (search) {
                const hay = `${f.title} ${f.description} ${f.type} ${f.owasp || ""} ${f.cwe || ""} ${f.evidence || ""}`.toLowerCase();
                if (!hay.includes(search)) return false;
            }

            return true;
        });
    }

    const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

    function render() {
        if (!list) return;

        const rows = visible().sort((a, b) => {
            const aPassed = a.status === "NOT_DETECTED" || a.status === "not_detected";
            const bPassed = b.status === "NOT_DETECTED" || b.status === "not_detected";
            if (aPassed !== bPassed) return aPassed ? 1 : -1;
            return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
        });

        if (!rows.length) {
            if (findings.length === 0) {
                list.innerHTML = '<p class="empty-state">No vulnerabilities detected. The target appears secure for all executed checks.</p>';
            } else {
                list.innerHTML = '<p class="empty-state">No findings match the selected filters.</p>';
            }
            return;
        }

        list.innerHTML = rows.map(f => {
            const isPassed = f.status === "NOT_DETECTED" || f.status === "not_detected";
            const isError = f.status === "SCANNER_ERROR" || f.status === "scanner_error";
            const isInconclusive = f.status === "INCONCLUSIVE" || f.status === "inconclusive";
            
            let badgeText = f.severity.toUpperCase();
            let badgeClass = UI.severityClass(f.severity);
            
            if (isError) {
                badgeText = "SCANNER ERROR";
                badgeClass = "sev-info";
            } else if (isPassed) {
                badgeText = "NOT DETECTED";
                badgeClass = "sev-passed";
            } else if (isInconclusive) {
                badgeText = "INCONCLUSIVE";
                badgeClass = "sev-info";
            }

            return `
            <div class="finding ${f.severity}" data-id="${UI.escapeHTML(f.id)}">
                <div class="finding-main">
                    <div class="finding-title">
                        <strong>${UI.escapeHTML(f.title)}</strong>
                        <span class="sev-badge ${badgeClass}">${badgeText}</span>
                    </div>
                    <div class="finding-desc">${UI.escapeHTML(f.description)}</div>
                    <div class="finding-tags">
                        <span class="tag">${UI.escapeHTML(f.type.toUpperCase())}</span>
                        ${f.owasp ? `<span class="tag">${UI.escapeHTML(f.owasp)}</span>` : ""}
                        ${f.cwe ? `<span class="tag">${UI.escapeHTML(f.cwe)}</span>` : ""}
                        ${f.parameter ? `<span class="tag">param: ${UI.escapeHTML(f.parameter)}</span>` : ""}
                        ${f.url ? `<span class="tag" style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${UI.escapeHTML(f.url)}</span>` : ""}
                    </div>
                </div>
                <span class="finding-arrow">›</span>
            </div>`;
        }).join("");

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

        const isPassed = f.status === "NOT_DETECTED" || f.status === "not_detected";
        const isError = f.status === "SCANNER_ERROR" || f.status === "scanner_error";
        const isInconclusive = f.status === "INCONCLUSIVE" || f.status === "inconclusive";

        document.getElementById("dTitle").textContent = f.title;
        document.getElementById("dUrl").textContent = f.url || "Target domain";

        const sev = document.getElementById("dSeverity");
        if (sev) {
            sev.textContent = isError ? "SCANNER ERROR" : isPassed ? "NOT DETECTED" : isInconclusive ? "INCONCLUSIVE" : f.severity.toUpperCase();
            sev.className = "sev-badge " + (isError ? "sev-info" : isPassed ? "sev-passed" : isInconclusive ? "sev-info" : UI.severityClass(f.severity));
        }

        document.getElementById("dConfidence").textContent = (f.confidence || "high") + " confidence";
        document.getElementById("dDescription").textContent = f.description || "—";
        document.getElementById("dEvidence").textContent = f.evidence || "No raw evidence captured for this check.";
        document.getElementById("dImpact").textContent = f.impact || (isPassed ? "No security impact — check verified as passed." : "Review technical details.");
        document.getElementById("dAi").textContent = f.ai_explanation || "You can consult the EthioSec AI Assistant for deep-dive contextual remediation.";

        const steps = document.getElementById("dRemediation");
        if (steps) {
            steps.innerHTML = (f.remediation && f.remediation.length)
                ? f.remediation.map(s => `<li>${UI.escapeHTML(s)}</li>`).join("")
                : (isPassed ? "<li>No remediation required — check verified as safe.</li>" : "<li>Implement defense-in-depth principles and context validation.</li>");
        }

        document.getElementById("dOwasp").textContent = f.owasp || "OWASP Standard";
        document.getElementById("dCwe").textContent = f.cwe || "CWE Category";

        const param = document.getElementById("dParam");
        if (param) {
            param.hidden = !f.parameter;
            if (f.parameter) param.textContent = "Parameter: " + f.parameter;
        }

        const askAi = document.getElementById("askAi");
        if (askAi) {
            askAi.href = `assistant.html?scan=${encodeURIComponent(scanId)}&finding=${encodeURIComponent(f.id)}`;
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
