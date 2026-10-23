/* ==========================================================================
   ETHIOSECSCAN — DASHBOARD CONTROLLER (dashboardfinal.js)
   Exact match to EthioSecScan Design System Specification
   ========================================================================== */

const API_BASE = "http://127.0.0.1:8000/api";

let activityChartInstance = null;
let severityChartInstance = null;

// Escaping utility for safety
const escapeHTML = (str) => {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
};

// Target hostname helper
const extractHostname = (url) => {
    if (!url) return 'Unknown Target';
    try {
        const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
        return parsed.hostname || url;
    } catch {
        return url;
    }
};

// Formatted calendar date
const formatScanDate = (isoString) => {
    if (!isoString) return 'Apr 20, 2025 14:32';
    try {
        const d = new Date(isoString);
        if (isNaN(d.getTime())) return isoString;
        return d.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        }).replace(',', '');
    } catch {
        return isoString;
    }
};

/* ==========================================================================
   1. USER PROFILE & GREETING
   ========================================================================== */
async function loadUserProfile() {
    if (window.EthioAuth && window.EthioAuth.syncCurrentUser) {
        await window.EthioAuth.syncCurrentUser();
        return;
    }

    let name = localStorage.getItem("userName") || "";
    let email = localStorage.getItem("userEmail") || "";
    const token = localStorage.getItem("token");

    if (token) {
        try {
            const res = await fetch(`${API_BASE}/auth/me`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                const u = data.user || data;
                if (u.full_name) name = u.full_name;
                if (u.email) email = u.email;
            }
        } catch (e) {
            // Keep default/stored profile
        }
    }

    const displayName = name || (email ? email.split("@")[0] : "User");
    const firstName = displayName.split(" ")[0] || displayName;
    const initials = displayName
        .split(" ")
        .map(n => n[0])
        .slice(0, 2)
        .join("")
        .toUpperCase() || "U";

    const welcomeHeading = document.getElementById("welcomeHeading");
    if (welcomeHeading) {
        welcomeHeading.textContent = `Welcome back, ${firstName} 👋`;
    }

    const headerAvatar = document.getElementById("headerAvatar");
    if (headerAvatar) headerAvatar.textContent = initials;

    const headerUserName = document.getElementById("headerUserName");
    if (headerUserName) headerUserName.textContent = displayName;

    const menuUserName = document.getElementById("menuUserName");
    if (menuUserName) menuUserName.textContent = displayName;

    const menuUserEmail = document.getElementById("menuUserEmail");
    if (menuUserEmail) menuUserEmail.textContent = email;
}

/* ==========================================================================
   2. DASHBOARD DATA FETCHING (Strict Real FastAPI Backend)
   ========================================================================== */
async function loadDashboardData() {
    let scansToRender = [];

    try {
        const token = localStorage.getItem("token");
        if (!token) {
            window.location.href = "login.html";
            return;
        }

        const headers = { 
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 6000);

        const res = await fetch(`${API_BASE}/scans?limit=100`, { 
            headers, 
            signal: controller.signal 
        });
        clearTimeout(timeoutId);

        if (res.status === 401 || res.status === 403) {
            localStorage.removeItem("token");
            window.location.href = "login.html";
            return;
        }

        if (res.ok) {
            const data = await res.json();
            scansToRender = Array.isArray(data.scans) ? data.scans : [];
        } else {
            console.error("[Dashboard] Scans retrieval returned HTTP", res.status);
        }
    } catch (e) {
        console.error("[Dashboard] Could not connect to API server:", e);
    }

    renderMetricCards(scansToRender);
    renderActivityChart(scansToRender);
    renderSeverityChart(scansToRender);
    renderRecentScansTable(scansToRender);
}

/* ==========================================================================
   3. SIX METRIC CARDS CALCULATION
   ========================================================================== */
function renderMetricCards(scans) {
    const totalScans = scans.length;
    let high = 0;
    let medium = 0;
    let low = 0;
    let notDetected = 0;
    let scannerError = 0;

    scans.forEach(scan => {
        const c = scan.counts || {};
        high += Number(c.high || 0);
        medium += Number(c.medium || 0);
        low += Number(c.low || 0);
        notDetected += Number(c.not_detected || 0);
        scannerError += Number(c.scanner_error || 0);
    });

    setCardValue("metricTotalScans", totalScans);
    setCardValue("metricHigh", high);
    setCardValue("metricMedium", medium);
    setCardValue("metricLow", low);
    setCardValue("metricNotDetected", notDetected);
    setCardValue("metricScannerError", scannerError);
}

function setCardValue(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value.toLocaleString();
}

/* ==========================================================================
   4. SCAN ACTIVITY CHART (Area/Line - Last 7 Days)
   ========================================================================== */
function renderActivityChart(scans) {
    const canvas = document.getElementById("activityChart");
    if (!canvas) return;

    const labels = [];
    const dataPoints = [0, 0, 0, 0, 0, 0, 0];
    const dayKeys = [];
    const now = new Date();
    for (let i = 6; i >= 0; i--) {
        const d = new Date(now);
        d.setDate(now.getDate() - i);
        dayKeys.push(d.toISOString().split('T')[0]);
        labels.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }

    if (scans && scans.length > 0) {
        scans.forEach(s => {
            const dateStr = (s.created_at || s.finished_at || '').split('T')[0];
            const idx = dayKeys.indexOf(dateStr);
            if (idx !== -1) {
                dataPoints[idx]++;
            }
        });
    }

    const ctx = canvas.getContext("2d");
    const gradient = ctx.createLinearGradient(0, 0, 0, 220);
    gradient.addColorStop(0, "rgba(232, 59, 37, 0.22)");
    gradient.addColorStop(1, "rgba(232, 59, 37, 0.0)");

    if (activityChartInstance) {
        activityChartInstance.destroy();
    }

    const maxVal = Math.max(5, ...dataPoints);

    activityChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Scans',
                data: dataPoints,
                borderColor: '#E83B25',
                borderWidth: 2.2,
                pointBackgroundColor: '#E83B25',
                pointBorderColor: '#090A0D',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6,
                backgroundColor: gradient,
                fill: true,
                tension: 0.38
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#14161A',
                    titleColor: '#FFFFFF',
                    bodyColor: '#9CA3AF',
                    borderColor: '#1E2127',
                    borderWidth: 1,
                    padding: 9,
                    boxPadding: 4,
                    displayColors: false,
                    callbacks: {
                        label: (ctx) => `${ctx.parsed.y} scan${ctx.parsed.y === 1 ? '' : 's'}`
                    }
                }
            },
            scales: {
                x: {
                    grid: { 
                        color: 'rgba(30, 33, 39, 0.5)',
                        drawBorder: false
                    },
                    ticks: { 
                        color: '#6B7280', 
                        font: { size: 11, family: 'Inter' } 
                    }
                },
                y: {
                    beginAtZero: true,
                    min: 0,
                    max: maxVal + 2,
                    grid: { 
                        color: 'rgba(30, 33, 39, 0.5)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#6B7280',
                        font: { size: 11, family: 'Inter' },
                        stepSize: Math.ceil((maxVal + 2) / 5)
                    }
                }
            }
        }
    });
}

/* ==========================================================================
   5. FINDINGS BY SEVERITY CHART (Donut)
   ========================================================================== */
function renderSeverityChart(scans) {
    const canvas = document.getElementById("severityChart");
    const centerCount = document.getElementById("donutTotalCount");

    let high = 0;
    let medium = 0;
    let low = 0;

    if (scans && scans.length > 0) {
        scans.forEach(s => {
            const c = s.counts || {};
            high += Number(c.high || 0);
            medium += Number(c.medium || 0);
            low += Number(c.low || 0);
        });
    }

    const total = high + medium + low;
    if (centerCount) centerCount.textContent = total;

    const setLegendText = (id, count) => {
        const el = document.getElementById(id);
        if (el) {
            const pct = total > 0 ? Math.round((count / total) * 100) : 0;
            el.textContent = `${count} (${pct}%)`;
        }
    };

    setLegendText("legendHighText", high);
    setLegendText("legendMediumText", medium);
    setLegendText("legendLowText", low);

    if (!canvas) return;

    if (severityChartInstance) {
        severityChartInstance.destroy();
    }

    const ctx = canvas.getContext("2d");
    severityChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: total > 0 ? [high, medium, low] : [0, 0, 0],
                backgroundColor: ['#E83B25', '#F59E0B', '#3B82F6'],
                borderColor: '#131518',
                borderWidth: 3,
                hoverOffset: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#14161A',
                    titleColor: '#FFFFFF',
                    bodyColor: '#9CA3AF',
                    borderColor: '#1E2127',
                    borderWidth: 1,
                    padding: 8,
                    callbacks: {
                        label: (ctx) => ` ${ctx.label}: ${ctx.raw} (${total > 0 ? Math.round((ctx.raw / total) * 100) : 0}%)`
                    }
                }
            }
        }
    });
}

/* ==========================================================================
   6. RECENT SCANS TABLE
   ========================================================================== */
function renderRecentScansTable(scans) {
    const tbody = document.getElementById("recentScansTbody");
    if (!tbody) return;

    if (!scans || scans.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align:center; padding: 40px 20px; color: var(--text-secondary, #9CA3AF);">
                    <div style="display:flex; flex-direction:column; align-items:center; gap:8px;">
                        <span style="font-size:13.5px; color:#9CA3AF;">No security scans recorded yet.</span>
                        <a href="scanfinal.html" class="primary-btn" style="padding:6px 16px; font-size:12px; text-decoration:none; display:inline-block; margin-top:4px;">Launch First Scan →</a>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    const rows = scans.slice(0, 5);

    tbody.innerHTML = rows.map(scan => {
        const id = escapeHTML(scan.id);
        const target = escapeHTML(scan.target || '—');
        const depth = escapeHTML(scan.depth || 'Standard');
        const dateStr = scan.dateDisplay || formatScanDate(scan.finished_at || scan.created_at);
        const status = (scan.status || 'completed').toLowerCase();

        const c = scan.counts || {};
        const high = Number(c.high || 0);
        const med = Number(c.medium || 0);
        const low = Number(c.low || 0);

        let findingsHTML = "";
        if (high > 0) findingsHTML += `<span class="finding-dot-item dot-high"><span class="circle-bullet">●</span> ${high}</span>`;
        if (med > 0) findingsHTML += `<span class="finding-dot-item dot-medium"><span class="circle-bullet">●</span> ${med}</span>`;
        if (low > 0) findingsHTML += `<span class="finding-dot-item dot-low"><span class="circle-bullet">●</span> ${low}</span>`;

        if (!findingsHTML) {
            findingsHTML = `<span style="color:#6B7280;">—</span>`;
        }

        const isRunning = status === 'running' || status === 'queued';
        const viewUrl = isRunning 
            ? `livescan.html?id=${encodeURIComponent(id)}`
            : `results.html?id=${encodeURIComponent(id)}`;

        return `
            <tr>
                <td>
                    <div class="cell-target" title="${target}">
                        <div class="globe-icon-wrap">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="2" y1="12" x2="22" y2="12"></line>
                                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                            </svg>
                        </div>
                        <span class="target-host-text">${target}</span>
                    </div>
                </td>
                <td>${depth}</td>
                <td>
                    <div class="date-cell-wrap">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                            <line x1="16" y1="2" x2="16" y2="6"></line>
                            <line x1="8" y1="2" x2="8" y2="6"></line>
                            <line x1="3" y1="10" x2="21" y2="10"></line>
                        </svg>
                        <span>${dateStr}</span>
                    </div>
                </td>
                <td>
                    <span class="status-pill ${status}">
                        <span class="status-dot-inner"></span>
                        <span>${status ? (status.charAt(0).toUpperCase() + status.slice(1)) : 'Unknown'}</span>
                    </span>
                </td>
                <td>
                    <div class="findings-dots-wrap">
                        ${findingsHTML}
                    </div>
                </td>
                <td class="text-right">
                    <a href="${viewUrl}" class="btn-row-action" title="View scan findings">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="9 18 15 12 9 6"></polyline>
                        </svg>
                    </a>
                </td>
            </tr>
        `;
    }).join('');
}

/* ==========================================================================
   7. INITIALIZATION & EVENT LISTENERS
   ========================================================================== */
document.addEventListener("DOMContentLoaded", () => {
    // 1. Initialize Profile & Dashboard data
    loadUserProfile();
    loadDashboardData();

    // 2. User profile dropdown is managed centrally by shared_auth.js
    if (window.EthioAuth && window.EthioAuth.setupUserMenuDropdown) {
        window.EthioAuth.setupUserMenuDropdown();
    }

    // 3. Mobile sidebar drawer
    const toggle = document.getElementById("sidebarToggle");
    const overlay = document.getElementById("sidebarOverlay");
    const sidebar = document.getElementById("sidebar");

    if (toggle && sidebar) {
        toggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
            if (overlay) overlay.classList.toggle("show");
        });
    }

    if (overlay && sidebar) {
        overlay.addEventListener("click", () => {
            sidebar.classList.remove("open");
            overlay.classList.remove("show");
        });
    }

    // 4. Keyboard shortcut: Alt+S for New Scan
    document.addEventListener("keydown", (e) => {
        if (e.altKey && e.key.toLowerCase() === 's') {
            window.location.href = "scanfinal.html";
        }
    });

    // 5. Responsive window resize handler for charts
    let resizeTimer;
    window.addEventListener("resize", () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            if (activityChartInstance) activityChartInstance.resize();
            if (severityChartInstance) severityChartInstance.resize();
        }, 150);
    });
});
