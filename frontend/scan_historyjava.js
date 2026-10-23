/* ==========================================================================
   ETHIOSECSCAN — SCAN HISTORY CONTROLLER (scan_historyjava.js)
   Strict Real Backend API Integration (/api/scans, DELETE /api/scans/{id})
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    const API_BASE = "http://127.0.0.1:8000/api";
    function getAuthToken() {
        const token = localStorage.getItem("token");
        if (!token) {
            window.location.href = "login.html";
            return "";
        }
        return token;
    }

    // UI Utilities
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
                if (days < 30) return `${days}d ago`;
                return date.toLocaleDateString();
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
                if (totalSeconds < 60) {
                    return `${totalSeconds}s`;
                }
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
        }
    };

    // DOM Elements
    const historyTableBody = document.getElementById("historyTableBody");
    const tableCountLabel = document.getElementById("tableCountLabel");
    const historySearchInput = document.getElementById("historySearchInput");
    const btnSearchClear = document.getElementById("btnSearchClear");
    const filterStatus = document.getElementById("filterStatus");
    const filterProfile = document.getElementById("filterProfile");
    const filterSort = document.getElementById("filterSort");
    const btnResetFilters = document.getElementById("btnResetFilters");

    const statTotal = document.getElementById("statTotal");
    const statClean = document.getElementById("statClean");
    const statWarning = document.getElementById("statWarning");
    const statHigh = document.getElementById("statHigh");

    const paginationBar = document.getElementById("paginationBar");
    const paginationRangeText = document.getElementById("paginationRangeText");
    const btnPrevPage = document.getElementById("btnPrevPage");
    const btnNextPage = document.getElementById("btnNextPage");
    const pageNumbersContainer = document.getElementById("pageNumbersContainer");

    // Modal Elements
    const deleteModalBackdrop = document.getElementById("deleteModalBackdrop");
    const deleteTargetPreview = document.getElementById("deleteTargetPreview");
    const btnCancelDelete = document.getElementById("btnCancelDelete");
    const btnConfirmDelete = document.getElementById("btnConfirmDelete");

    // State Variables
    let allScans = [];
    let filteredScans = [];
    let currentPage = 1;
    const itemsPerPage = 10;
    let scanToDelete = null;

    // Load Scan History from Backend
    async function loadScans() {
        renderLoading();

        const token = getAuthToken();
        try {
            const res = await fetch(`${API_BASE}/scans?limit=200`, {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`
                }
            });

            if (res.status === 401 || res.status === 403) {
                renderError("Session expired or unauthorized. Please re-authenticate.", true);
                return;
            }

            if (!res.ok) {
                throw new Error(`Server returned HTTP ${res.status}`);
            }

            const data = await res.json();
            allScans = (data.scans || []).map(s => {
                const counts = s.counts || {};
                return {
                    id: String(s.id),
                    target: String(s.target || "Unknown Target"),
                    status: (s.status || "queued").toLowerCase(),
                    depth: (s.depth || "standard").toLowerCase(),
                    created_at: s.created_at || null,
                    finished_at: s.finished_at || null,
                    security_score: s.security_score !== undefined && s.security_score !== null ? Number(s.security_score) : null,
                    counts: {
                        critical: Number(counts.critical || 0),
                        high: Number(counts.high || 0),
                        medium: Number(counts.medium || 0),
                        low: Number(counts.low || 0),
                        not_detected: Number(counts.not_detected || 0),
                        scanner_error: Number(counts.scanner_error || 0),
                        inconclusive: Number(counts.inconclusive || 0),
                        total: Number(counts.total || 0)
                    }
                };
            });

            updateMetrics();
            applyFilters();

        } catch (err) {
            console.error("Failed to load scan records:", err);
            renderError("Unable to connect to the backend server. Ensure the FastAPI service is running on port 8000.");
        }
    }

    // Update Overview Metric Cards
    function updateMetrics() {
        const total = allScans.length;
        const completed = allScans.filter(s => s.status === "completed");

        let cleanCount = 0;
        let warningCount = 0;
        let highCount = 0;

        completed.forEach(s => {
            const c = s.counts;
            const hasHigh = (c.critical + c.high) > 0;
            const hasMediumLow = (c.medium + c.low) > 0;

            if (hasHigh) {
                highCount++;
            } else if (hasMediumLow) {
                warningCount++;
            } else {
                cleanCount++;
            }
        });

        if (statTotal) statTotal.textContent = total;
        if (statClean) statClean.textContent = cleanCount;
        if (statWarning) statWarning.textContent = warningCount;
        if (statHigh) statHigh.textContent = highCount;
    }

    // Filter, Search, and Sort Scans
    function applyFilters() {
        const query = (historySearchInput?.value || "").trim().toLowerCase();
        const selectedStatus = filterStatus?.value || "all";
        const selectedProfile = filterProfile?.value || "all";
        const selectedSort = filterSort?.value || "newest";

        if (btnSearchClear) {
            btnSearchClear.style.display = query ? "block" : "none";
        }

        filteredScans = allScans.filter(scan => {
            // Status match
            if (selectedStatus !== "all" && scan.status !== selectedStatus) {
                return false;
            }

            // Profile match
            if (selectedProfile !== "all" && scan.depth !== selectedProfile) {
                return false;
            }

            // Query match (Target URL or Scan ID)
            if (query) {
                const targetMatches = scan.target.toLowerCase().includes(query);
                const idMatches = scan.id.toLowerCase().includes(query);
                if (!targetMatches && !idMatches) {
                    return false;
                }
            }

            return true;
        });

        // Sorting
        filteredScans.sort((a, b) => {
            if (selectedSort === "oldest") {
                return new Date(a.created_at || 0) - new Date(b.created_at || 0);
            }
            if (selectedSort === "score_desc") {
                return (b.security_score ?? -1) - (a.security_score ?? -1);
            }
            if (selectedSort === "score_asc") {
                return (a.security_score ?? 999) - (b.security_score ?? 999);
            }
            // Default: newest
            return new Date(b.created_at || 0) - new Date(a.created_at || 0);
        });

        currentPage = 1;
        renderTable();
    }

    // Render Table Rows
    function renderTable() {
        if (!historyTableBody) return;

        const totalItems = filteredScans.length;

        if (totalItems === 0) {
            if (allScans.length === 0) {
                historyTableBody.innerHTML = `
                    <tr>
                        <td colspan="7">
                            <div class="state-container">
                                <div class="state-icon-wrap">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <circle cx="12" cy="12" r="10"></circle>
                                        <line x1="12" y1="8" x2="12" y2="12"></line>
                                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                                    </svg>
                                </div>
                                <h3 class="state-title">No Scan Records Found</h3>
                                <p class="state-desc">You have not executed any security scans yet. Launch your first target assessment to generate findings.</p>
                                <a href="scanfinal.html" class="btn-primary">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                                    <span>Launch First Scan</span>
                                </a>
                            </div>
                        </td>
                    </tr>`;
            } else {
                historyTableBody.innerHTML = `
                    <tr>
                        <td colspan="7">
                            <div class="state-container">
                                <div class="state-icon-wrap">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <circle cx="11" cy="11" r="8"></circle>
                                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                                    </svg>
                                </div>
                                <h3 class="state-title">No Matching Scans</h3>
                                <p class="state-desc">No assessment records matched your search query and filters. Try clearing your search parameters.</p>
                                <button type="button" class="btn-secondary" onclick="document.getElementById('btnResetFilters').click()">
                                    <span>Reset All Filters</span>
                                </button>
                            </div>
                        </td>
                    </tr>`;
            }

            if (tableCountLabel) tableCountLabel.textContent = "0 scans";
            if (paginationBar) paginationBar.style.display = "none";
            return;
        }

        if (paginationBar) paginationBar.style.display = "flex";
        if (tableCountLabel) {
            tableCountLabel.textContent = `${totalItems} scan${totalItems === 1 ? "" : "s"}`;
        }

        // Slice for pagination
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, totalItems);
        const pageItems = filteredScans.slice(startIndex, endIndex);

        historyTableBody.innerHTML = pageItems.map(scan => {
            const counts = scan.counts;
            const hasHigh = (counts.critical + counts.high) > 0;
            const hasMedium = counts.medium > 0;
            const hasLow = counts.low > 0;
            const isCompleted = scan.status === "completed";
            const isRunning = scan.status === "running";

            // Status Badge
            const statusBadgeHTML = `
                <span class="status-pill ${scan.status}">
                    <span class="status-dot"></span>
                    <span>${scan.status}</span>
                </span>
            `;

            // Score Pill
            let scoreHTML = `<span style="color:var(--text-muted); font-size:12px;">—</span>`;
            if (scan.security_score !== null && isCompleted) {
                const s = scan.security_score;
                const scoreColor = s >= 80 ? "var(--sev-passed)" : s >= 60 ? "var(--sev-medium)" : "var(--brand-red)";
                scoreHTML = `<strong style="color:${scoreColor}; font-family:'Plus Jakarta Sans',sans-serif; font-size:14px;">${s}</strong><small style="color:var(--text-muted); font-size:11px;">/100</small>`;
            }

            // Findings Pills
            let findingsHTML = "";
            if (!isCompleted && scan.status !== "failed") {
                findingsHTML = `<span style="font-size:11.5px; color:var(--text-muted);">In progress…</span>`;
            } else if (hasHigh || hasMedium || hasLow) {
                const pills = [];
                if (hasHigh) pills.push(`<span class="count-pill high">${counts.critical + counts.high} High</span>`);
                if (hasMedium) pills.push(`<span class="count-pill medium">${counts.medium} Med</span>`);
                if (hasLow) pills.push(`<span class="count-pill low">${counts.low} Low</span>`);
                findingsHTML = `<div class="findings-summary-group">${pills.join("")}</div>`;
            } else if (counts.inconclusive > 0) {
                findingsHTML = `<div class="findings-summary-group"><span class="count-pill inconclusive">${counts.inconclusive} Inconclusive</span></div>`;
            } else {
                findingsHTML = `<div class="findings-summary-group"><span class="count-pill clean">✓ Clean</span></div>`;
            }

            // Duration
            const duration = UI.calculateDuration(scan.created_at, scan.finished_at);
            const dateHTML = `
                <div class="date-cell">
                    <span class="date-main">${UI.formatDate(scan.created_at)}</span>
                    <span class="date-relative">${UI.timeAgo(scan.created_at)}${duration ? ` · ${duration}` : ""}</span>
                </div>
            `;

            // Action Buttons
            let actionHTML = "";
            if (isRunning) {
                actionHTML = `
                    <div class="actions-cell">
                        <a href="livescan.html?id=${encodeURIComponent(scan.id)}" class="action-btn live-monitor" title="View live progress">
                            <span class="status-dot" style="background:#60A5FA;"></span>
                            <span>Monitor</span>
                        </a>
                        <button type="button" class="action-btn delete-btn" data-delete-id="${UI.escapeHTML(scan.id)}" data-target="${UI.escapeHTML(scan.target)}" title="Delete record">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                        </button>
                    </div>
                `;
            } else {
                actionHTML = `
                    <div class="actions-cell">
                        <a href="results.html?id=${encodeURIComponent(scan.id)}" class="action-btn view-results" title="View audit findings">
                            <span>Results →</span>
                        </a>
                        <button type="button" class="action-btn delete-btn" data-delete-id="${UI.escapeHTML(scan.id)}" data-target="${UI.escapeHTML(scan.target)}" title="Delete record">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                        </button>
                    </div>
                `;
            }

            return `
                <tr data-scan-id="${UI.escapeHTML(scan.id)}">
                    <td>
                        <div class="target-cell">
                            <a href="results.html?id=${encodeURIComponent(scan.id)}" class="target-url-link" title="${UI.escapeHTML(scan.target)}">
                                ${UI.escapeHTML(scan.target)}
                            </a>
                            <div class="target-id-row">
                                <span class="scan-id-chip" title="Click to copy Scan ID" onclick="navigator.clipboard.writeText('${UI.escapeHTML(scan.id)}'); window.EthioToast?.('Scan ID copied');">
                                    #${UI.escapeHTML(scan.id.slice(0, 8))}
                                </span>
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="profile-pill ${scan.depth}">
                            ${scan.depth}
                        </span>
                    </td>
                    <td>${statusBadgeHTML}</td>
                    <td>${scoreHTML}</td>
                    <td>${findingsHTML}</td>
                    <td>${dateHTML}</td>
                    <td>${actionHTML}</td>
                </tr>
            `;
        }).join("");

        // Attach Delete Listeners
        historyTableBody.querySelectorAll(".delete-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const id = btn.getAttribute("data-delete-id");
                const target = btn.getAttribute("data-target");
                openDeleteModal(id, target);
            });
        });

        // Update Pagination Controls
        updatePagination(startIndex, endIndex, totalItems);
    }

    // Pagination Updates
    function updatePagination(startIndex, endIndex, totalItems) {
        if (paginationRangeText) {
            paginationRangeText.textContent = `Showing ${startIndex + 1}–${endIndex} of ${totalItems} scans`;
        }

        const totalPages = Math.ceil(totalItems / itemsPerPage) || 1;

        if (btnPrevPage) {
            btnPrevPage.disabled = currentPage <= 1;
        }
        if (btnNextPage) {
            btnNextPage.disabled = currentPage >= totalPages;
        }

        if (pageNumbersContainer) {
            pageNumbersContainer.innerHTML = "";
            for (let i = 1; i <= totalPages; i++) {
                if (totalPages > 6 && Math.abs(currentPage - i) > 2 && i !== 1 && i !== totalPages) {
                    if (i === 2 || i === totalPages - 1) {
                        const dots = document.createElement("span");
                        dots.style.cssText = "color:var(--text-muted); padding:4px 6px; font-size:12px;";
                        dots.textContent = "…";
                        pageNumbersContainer.appendChild(dots);
                    }
                    continue;
                }

                const pageBtn = document.createElement("button");
                pageBtn.type = "button";
                pageBtn.className = i === currentPage ? "page-number-active" : "page-btn";
                pageBtn.textContent = i;
                pageBtn.addEventListener("click", () => {
                    currentPage = i;
                    renderTable();
                    window.scrollTo({ top: 300, behavior: "smooth" });
                });
                pageNumbersContainer.appendChild(pageBtn);
            }
        }
    }

    // Modal Control
    function openDeleteModal(scanId, targetUrl) {
        scanToDelete = scanId;
        if (deleteTargetPreview) {
            deleteTargetPreview.textContent = `${targetUrl} (ID: ${scanId})`;
        }
        if (deleteModalBackdrop) {
            deleteModalBackdrop.classList.add("open");
        }
    }

    function closeDeleteModal() {
        scanToDelete = null;
        if (deleteModalBackdrop) {
            deleteModalBackdrop.classList.remove("open");
        }
    }

    // Confirm Delete Scan Record
    async function executeDeleteScan() {
        if (!scanToDelete) return;
        const scanId = scanToDelete;
        const token = getAuthToken();

        btnConfirmDelete.disabled = true;
        btnConfirmDelete.textContent = "Deleting…";

        try {
            const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}`, {
                method: "DELETE",
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            });

            if (!res.ok) {
                let errDetail = "Failed to delete scan record.";
                try {
                    const data = await res.json();
                    if (data.detail) errDetail = data.detail;
                } catch (_) {}
                throw new Error(errDetail);
            }

            // Successfully deleted
            UI.toast("Scan record deleted successfully", "info");
            allScans = allScans.filter(s => s.id !== scanId);
            updateMetrics();
            applyFilters();
            closeDeleteModal();

        } catch (err) {
            console.error("Delete error:", err);
            UI.toast(err.message || "Could not delete scan record", "error");
        } finally {
            btnConfirmDelete.disabled = false;
            btnConfirmDelete.textContent = "Delete Scan";
        }
    }

    // Loading State
    function renderLoading() {
        if (!historyTableBody) return;
        historyTableBody.innerHTML = `
            <tr>
                <td colspan="7">
                    <div class="state-container">
                        <div class="spinner"></div>
                        <h3 class="state-title">Loading Scan Records</h3>
                        <p class="state-desc">Retrieving your security assessment history from the backend database…</p>
                    </div>
                </td>
            </tr>`;
        if (tableCountLabel) tableCountLabel.textContent = "Loading…";
    }

    // Error State
    function renderError(message, isAuthError = false) {
        if (!historyTableBody) return;
        historyTableBody.innerHTML = `
            <tr>
                <td colspan="7">
                    <div class="state-container">
                        <div class="state-icon-wrap" style="color:var(--brand-red); border-color:rgba(232,59,37,0.3); background:rgba(232,59,37,0.06);">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="12" y1="8" x2="12" y2="12"></line>
                                <line x1="12" y1="16" x2="12.01" y2="16"></line>
                            </svg>
                        </div>
                        <h3 class="state-title">${isAuthError ? "Authentication Required" : "Failed to Load Records"}</h3>
                        <p class="state-desc">${UI.escapeHTML(message)}</p>
                        ${isAuthError ? `
                            <a href="login.html" class="btn-primary">
                                <span>Log In Again →</span>
                            </a>
                        ` : `
                            <button type="button" class="btn-secondary" onclick="window.location.reload()">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
                                <span>Retry Connection</span>
                            </button>
                        `}
                    </div>
                </td>
            </tr>`;
        if (tableCountLabel) tableCountLabel.textContent = "Error";
    }

    // Event Bindings
    if (historySearchInput) {
        historySearchInput.addEventListener("input", () => applyFilters());
    }
    if (btnSearchClear) {
        btnSearchClear.addEventListener("click", () => {
            historySearchInput.value = "";
            applyFilters();
            historySearchInput.focus();
        });
    }
    if (filterStatus) {
        filterStatus.addEventListener("change", () => applyFilters());
    }
    if (filterProfile) {
        filterProfile.addEventListener("change", () => applyFilters());
    }
    if (filterSort) {
        filterSort.addEventListener("change", () => applyFilters());
    }
    if (btnResetFilters) {
        btnResetFilters.addEventListener("click", () => {
            if (historySearchInput) historySearchInput.value = "";
            if (filterStatus) filterStatus.value = "all";
            if (filterProfile) filterProfile.value = "all";
            if (filterSort) filterSort.value = "newest";
            applyFilters();
        });
    }

    // Pagination Listeners
    if (btnPrevPage) {
        btnPrevPage.addEventListener("click", () => {
            if (currentPage > 1) {
                currentPage--;
                renderTable();
                window.scrollTo({ top: 300, behavior: "smooth" });
            }
        });
    }
    if (btnNextPage) {
        btnNextPage.addEventListener("click", () => {
            const totalPages = Math.ceil(filteredScans.length / itemsPerPage);
            if (currentPage < totalPages) {
                currentPage++;
                renderTable();
                window.scrollTo({ top: 300, behavior: "smooth" });
            }
        });
    }

    // Modal Listeners
    if (btnCancelDelete) {
        btnCancelDelete.addEventListener("click", closeDeleteModal);
    }
    if (btnConfirmDelete) {
        btnConfirmDelete.addEventListener("click", executeDeleteScan);
    }
    if (deleteModalBackdrop) {
        deleteModalBackdrop.addEventListener("click", (e) => {
            if (e.target === deleteModalBackdrop) closeDeleteModal();
        });
    }
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && deleteModalBackdrop?.classList.contains("open")) {
            closeDeleteModal();
        }
    });

    window.EthioToast = UI.toast;

    // Initial Load
    loadScans();
});
