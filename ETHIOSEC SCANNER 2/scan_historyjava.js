if (!localStorage.getItem('token')) {
    window.location.href = 'login.html';
}
/* =====================================================
   SCAN HISTORY (scan_historyjava.js) - Real Backend Sync
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
                setTimeout(() => toastEl.classList.remove("show"), 3200);
            }
        }
    };

    const tableBody = document.getElementById("tableBody");
    const resultCount = document.getElementById("resultCount");
    const pageInfo = document.getElementById("pageInfo");
    const deleteAllBtn = document.getElementById("deleteAllBtn");

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
       LOAD DATA (Strict Backend Only)
       ===================================================== */
    async function load() {
        if (tableBody) {
            tableBody.innerHTML = `<tr><td colspan="6"><p class="loading-state">Loading scans from backend database…</p></td></tr>`;
        }

        const token = localStorage.getItem("token");
        if (!token) {
            if (tableBody) {
                tableBody.innerHTML = `<tr><td colspan="6"><p class="empty-state" style="color:#cc2f0c">Authentication required. <a href="login.html" style="color:#ff4b20">Log in here →</a></p></td></tr>`;
            }
            return;
        }

        try {
            const res = await fetch(`http://127.0.0.1:8000/api/scans`, {
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`
                }
            });

            if (res.status === 401 || res.status === 403) {
                localStorage.removeItem("token");
                localStorage.removeItem("isLoggedIn");
                if (tableBody) {
                    tableBody.innerHTML = `<tr><td colspan="6"><p class="empty-state" style="color:#cc2f0c">Your session has expired. <a href="login.html" style="color:#ff4b20">Log in again →</a></p></td></tr>`;
                }
                return;
            }

            if (!res.ok) {
                throw new Error(`Server returned HTTP ${res.status}`);
            }

            const data = await res.json();
            
            scans = (data.scans || []).map(s => ({
                id: s.id,
                target: s.target,
                status: s.status,
                depth: s.depth || "standard",
                security_score: s.security_score,
                created_at: typeof s.created_at === "number" ? new Date(s.created_at).toISOString() : s.created_at,
                finished_at: typeof s.finished_at === "number" ? new Date(s.finished_at).toISOString() : s.finished_at,
                counts: s.counts || { total: 0, critical: 0, high: 0, medium: 0, low: 0, passed: 0 }
            }));

            paintStats();
            filterScans();

        } catch (err) {
            console.error("Load error:", err);
            scans = [];
            if (tableBody) {
                tableBody.innerHTML = `<tr><td colspan="6"><p class="empty-state" style="color:#cc2f0c">Unable to connect to backend server. Ensure the FastAPI service is running on port 8000.</p></td></tr>`;
            }
            paintStats();
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
        if (bad) UI.toast("End date cannot be before start date.", "error");
        filterScans();
    }

    /* =====================================================
       RENDER TABLE
       ===================================================== */
    function renderTable() {
        if (!tableBody) return;

        if (!filtered.length) {
            if (scans.length === 0) {
                tableBody.innerHTML = `
                    <tr><td colspan="6">
                        <p class="empty-state">No scans yet. Start your first security scan to build your scan history.<br>
                        <br><a href="scanfinal.html" class="primary-btn" style="display:inline-block;">⚡ Launch First Scan</a></p>
                    </td></tr>`;
            } else {
                tableBody.innerHTML = `
                    <tr><td colspan="6">
                        <p class="empty-state">No scans match these filters.
                           <br><a href="scanfinal.html" style="color:#ff4b20">Launch a new scan →</a></p>
                    </td></tr>`;
            }
            updatePagination();
            return;
        }

        const start = (currentPage - 1) * itemsPerPage;
        const rows = filtered.slice(start, start + itemsPerPage);

        tableBody.innerHTML = rows.map(scan => {
            const bucket = bucketOf(scan);
            const done = scan.status === "completed";
            const when = scan.finished_at || scan.created_at;
            const c = scan.counts || {};
            const issues = (c.total ?? ((c.critical || 0) + (c.high || 0) + (c.medium || 0) + (c.low || 0))) || 0;

            const severitySummary = done ? `
                <div style="font-size:0.8rem; display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
                    <span style="color:${issues > 0 ? '#ff5b5b' : '#1bb369'}; font-weight:600;">${issues} issue${issues === 1 ? '' : 's'}</span>
                    ${c.critical ? `<span style="background:rgba(255,91,91,0.15); color:#ff5b5b; padding:1px 5px; border-radius:4px; font-size:0.75rem;">${c.critical} crit</span>` : ''}
                    ${c.high ? `<span style="background:rgba(255,138,61,0.15); color:#ff8a3d; padding:1px 5px; border-radius:4px; font-size:0.75rem;">${c.high} high</span>` : ''}
                    ${c.passed ? `<span style="color:#1bb369; font-size:0.75rem;">${c.passed} passed</span>` : ''}
                </div>` : '<span>Testing in progress…</span>';

            return `
                <tr>
                    <td>
                        <span class="url-link" style="font-weight:600;">${UI.escapeHTML(scan.target)}</span>
                        <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase;">${UI.escapeHTML(scan.depth)}</div>
                    </td>
                    <td><span class="status-badge status-${bucket}">${BUCKET_LABEL[bucket]}</span></td>
                    <td class="score-cell">${done && scan.security_score !== null ? scan.security_score : "—"}</td>
                    <td><span class="timestamp">${when ? new Date(when).toLocaleDateString() : "—"}<br><small style="color:var(--text-muted)">${UI.timeAgo(when)}</small></span></td>
                    <td>${severitySummary}</td>
                    <td>
                        <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                            <a class="view-btn" href="${done ? `results.html?id=${encodeURIComponent(scan.id)}` : `livescan.html?id=${encodeURIComponent(scan.id)}`}">${done ? "Results →" : "Live ◔"}</a>
                            ${done ? `<a class="ghost-btn" href="reports.html?id=r${encodeURIComponent(scan.id)}" style="padding:4px 8px; font-size:0.75rem;">Report</a>` : ''}
                            <button class="delete-btn" data-id="${UI.escapeHTML(scan.id)}" style="background:transparent; border:none; color:var(--danger,#ff6b6b); cursor:pointer; font-size:1.1rem; padding:4px;" title="Delete Scan">🗑</button>
                        </div>
                    </td>
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
       ACTIONS (Delete single & Delete all)
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

    // Delete Single Scan
    if (tableBody) {
        tableBody.addEventListener("click", async (e) => {
            const btn = e.target.closest(".delete-btn");
            if (!btn) return;
            
            const scanId = btn.dataset.id;
            if (!scanId) return;
            
            if (confirm("Delete this scan from your history? This will permanently remove its findings and reports.")) {
                try {
                    const token = localStorage.getItem("token");
                    const res = await fetch(`http://127.0.0.1:8000/api/scans/${scanId}`, {
                        method: "DELETE",
                        headers: token ? { "Authorization": `Bearer ${token}` } : {}
                    });
                    
                    if (res.ok) {
                        UI.toast("Scan deleted successfully.");
                        scans = scans.filter(s => s.id !== scanId);
                        filterScans();
                        paintStats();
                    } else {
                        UI.toast("Failed to delete scan.", "error");
                    }
                } catch (err) {
                    console.error("Delete error:", err);
                    UI.toast("Network error deleting scan.", "error");
                }
            }
        });
    }

    // Delete All Scans
    if (deleteAllBtn) {
        deleteAllBtn.addEventListener("click", async () => {
            if (scans.length === 0) {
                UI.toast("History is already empty.");
                return;
            }

            if (confirm("Are you sure you want to delete ALL scans from your account? This action cannot be undone.")) {
                try {
                    const token = localStorage.getItem("token");
                    const res = await fetch(`http://127.0.0.1:8000/api/scans`, {
                        method: "DELETE",
                        headers: token ? { "Authorization": `Bearer ${token}` } : {}
                    });

                    if (res.ok) {
                        UI.toast("All scan history has been cleared.");
                        scans = [];
                        filterScans();
                        paintStats();
                    } else {
                        UI.toast("Failed to clear scan history.", "error");
                    }
                } catch (err) {
                    console.error("Delete all error:", err);
                    UI.toast("Network error clearing history.", "error");
                }
            }
        });
    }

    load();
});
