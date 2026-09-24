/* =====================================================
   SCAN HISTORY (scan_historyjava.js) - Pure Frontend Standalone
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
        toast: (msg, type = "info") => {
            const toastEl = document.getElementById("toast");
            if (toastEl) {
                toastEl.textContent = msg;
                toastEl.className = "toast show " + type;
                setTimeout(() => toastEl.classList.remove("show"), 3000);
            } else {
                console.log(`[Toast ${type}]:`, msg);
            }
        }
    };

    const tableBody = document.getElementById("tableBody");
    const resultCount = document.getElementById("resultCount");
    const pageInfo = document.getElementById("pageInfo");

    const statusFilter = document.getElementById("statusFilter");
    const dateFrom = document.getElementById("dateFrom");
    const dateTo = document.getElementById("dateTo");
    const searchInput = document.getElementById("searchInput");

    const prevBtn = document.getElementById("prevBtn");
    const nextBtn = document.getElementById("nextBtn");

    const itemsPerPage = 8;

    let scans = [];
    let filtered = [];
    let currentPage = 1;

    /* =====================================================
       DEFAULT SEED SCANS (Fallback)
       ===================================================== */
    const DEFAULT_SCANS = [
        {
            id: "scan_001",
            target: "https://demo.ethio-security.org",
            status: "completed",
            security_score: 72,
            created_at: new Date(Date.now() - 3600000).toISOString(),
            finished_at: new Date(Date.now() - 3500000).toISOString(),
            counts: { total: 8, critical: 1, high: 2, medium: 2, low: 3, passed: 14 }
        },
        {
            id: "scan_002",
            target: "https://ecommerce.api.local",
            status: "completed",
            security_score: 94,
            created_at: new Date(Date.now() - 86400000).toISOString(),
            finished_at: new Date(Date.now() - 86300000).toISOString(),
            counts: { total: 3, critical: 0, high: 0, medium: 1, low: 2, passed: 22 }
        },
        {
            id: "scan_003",
            target: "https://staging.internal-services.net",
            status: "running",
            security_score: null,
            created_at: new Date().toISOString(),
            finished_at: null,
            counts: { total: 2, critical: 0, high: 2 }
        },
        {
            id: "scan_004",
            target: "https://payment-gateway.fintech.et",
            status: "completed",
            security_score: 58,
            created_at: new Date(Date.now() - 172800000).toISOString(),
            finished_at: new Date(Date.now() - 172700000).toISOString(),
            counts: { total: 11, critical: 2, high: 3, medium: 4, low: 2, passed: 10 }
        },
        {
            id: "scan_005",
            target: "https://blog.cybersecurity-ethiopia.org",
            status: "completed",
            security_score: 98,
            created_at: new Date(Date.now() - 259200000).toISOString(),
            finished_at: new Date(Date.now() - 259100000).toISOString(),
            counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, passed: 32 }
        }
    ];

    /* =====================================================
       SEVERITY BUCKET
       ===================================================== */
    function bucketOf(scan) {
        if (scan.status !== "completed") return "running";
        const c = scan.counts || {};
        if (c.critical || c.high) return "danger";
        if (c.medium || c.low) return "warning";
        return "safe";
    }

    const BUCKET_LABEL = {
        safe: "Clean",
        warning: "Warning",
        danger: "Critical",
        running: "Running"
    };

    /* =====================================================
       LOAD DATA
       ===================================================== */
    function load() {
        if (tableBody) {
            tableBody.innerHTML = `<tr><td colspan="6"><p class="loading-state">Loading scans…</p></td></tr>`;
        }

        try {
            // Read from local mock storage if available
            const raw = localStorage.getItem("ethio_mock_db");
            if (raw) {
                const db = JSON.parse(raw);
                if (db.scans && db.scans.length) {
                    scans = db.scans.map(s => ({
                        id: s.id,
                        target: s.target,
                        status: s.status,
                        security_score: s.security_score,
                        created_at: typeof s.created_at === "number" ? new Date(s.created_at).toISOString() : s.created_at,
                        finished_at: typeof s.finished_at === "number" ? new Date(s.finished_at).toISOString() : s.finished_at,
                        counts: s.counts || { total: 0 }
                    }));
                } else {
                    scans = DEFAULT_SCANS;
                }
            } else {
                scans = DEFAULT_SCANS;
            }

            paintStats();
            filterScans();

        } catch (err) {
            console.error("Load error:", err);
            scans = DEFAULT_SCANS;
            paintStats();
            filterScans();
        }
    }

    function paintStats() {
        const done = scans.filter(s => s.status === "completed");

        const setSafeText = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };

        setSafeText("statTotal", scans.length);
        setSafeText("statSafe", done.filter(s => bucketOf(s) === "safe").length);
        setSafeText("statWarning", done.filter(s => bucketOf(s) === "warning").length);
        setSafeText("statDanger", done.filter(s => bucketOf(s) === "danger").length);
    }

    /* =====================================================
       FILTER
       ===================================================== */
    function filterScans() {
        const status = statusFilter ? statusFilter.value : "all";
        const from = dateFrom ? dateFrom.value : "";
        const to = dateTo ? dateTo.value : "";
        const term = searchInput ? searchInput.value.trim().toLowerCase() : "";

        filtered = scans.filter(scan => {
            if (status !== "all" && bucketOf(scan) !== status) return false;

            const day = (scan.finished_at || scan.created_at || "").slice(0, 10);
            if (from && day < from) return false;
            if (to && day > to) return false;

            if (term && !(scan.target || "").toLowerCase().includes(term)) return false;

            return true;
        });

        currentPage = 1;
        if (resultCount) {
            resultCount.textContent = `${filtered.length} scan${filtered.length === 1 ? "" : "s"}`;
        }
        renderTable();
    }

    function validateDates() {
        if (!dateFrom || !dateTo) return;
        const bad = dateFrom.value && dateTo.value && dateFrom.value > dateTo.value;
        dateTo.setCustomValidity(bad ? "End date cannot be before start date." : "");
        if (bad) UI.toast("End date cannot be before the start date.", "error");
        filterScans();
    }

    /* =====================================================
       RENDER TABLE
       ===================================================== */
    function renderTable() {
        if (!tableBody) return;

        if (!filtered.length) {
            tableBody.innerHTML = `
                <tr><td colspan="6">
                    <p class="empty-state">No scans match these filters.
                       <a href="scanfinal.html" style="color:#ff4b20">Run a new scan →</a></p>
                </td></tr>`;
            updatePagination();
            return;
        }

        const start = (currentPage - 1) * itemsPerPage;
        const rows = filtered.slice(start, start + itemsPerPage);

        tableBody.innerHTML = rows.map(scan => {
            const bucket = bucketOf(scan);
            const done = scan.status === "completed";
            const when = scan.finished_at || scan.created_at;
            const issues = (scan.counts && (scan.counts.total ?? scan.counts.critical + (scan.counts.high || 0) + (scan.counts.medium || 0) + (scan.counts.low || 0))) || 0;

            return `
                <tr>
                    <td><span class="url-link">${UI.escapeHTML(scan.target)}</span></td>
                    <td><span class="status-badge status-${bucket}">${BUCKET_LABEL[bucket]}</span></td>
                    <td class="score-cell">${done && scan.security_score !== null ? scan.security_score : "—"}</td>
                    <td><span class="timestamp">${when ? new Date(when).toLocaleDateString() : "—"}<br><small style="color:var(--text-muted)">${UI.timeAgo(when)}</small></span></td>
                    <td><span class="issue-count">${done ? issues : "—"}</span></td>
                    <td><a class="view-btn" href="${done ? "results.html?id=" : "livescan.html?id="}${encodeURIComponent(scan.id)}">
                        ${done ? "View results →" : "Watch progress ◔"}</a></td>
                </tr>`;
        }).join("");

        updatePagination();
    }

    function updatePagination() {
        if (!pageInfo || !prevBtn || !nextBtn) return;
        const totalPages = Math.max(1, Math.ceil(filtered.length / itemsPerPage));
        if (currentPage > totalPages) currentPage = totalPages;

        pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
        prevBtn.disabled = currentPage === 1;
        nextBtn.disabled = currentPage === totalPages || !filtered.length;
    }

    function goTo(page) {
        currentPage = page;
        renderTable();
        const container = document.querySelector(".table-container");
        if (container) {
            container.scrollIntoView({ behavior: "smooth", block: "start" });
        }
    }

    /* =====================================================
       EVENT LISTENERS
       ===================================================== */
    if (statusFilter) statusFilter.addEventListener("change", filterScans);
    if (searchInput) searchInput.addEventListener("input", filterScans);
    if (dateFrom) dateFrom.addEventListener("change", validateDates);
    if (dateTo) dateTo.addEventListener("change", validateDates);

    if (nextBtn) {
        nextBtn.addEventListener("click", () => {
            const totalPages = Math.ceil(filtered.length / itemsPerPage);
            if (currentPage < totalPages) goTo(currentPage + 1);
        });
    }

    if (prevBtn) {
        prevBtn.addEventListener("click", () => {
            if (currentPage > 1) goTo(currentPage - 1);
        });
    }

    load();
});