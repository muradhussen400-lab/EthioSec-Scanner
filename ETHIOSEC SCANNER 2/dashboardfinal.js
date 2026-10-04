if (!localStorage.getItem('token')) {
    window.location.href = 'login.html';
}
/* =====================================================
   DASHBOARD CONTROLLER (dashboardfinal.js) - Pure Frontend
   ===================================================== */

const COLORS = {
    primary: '#cc2f0c',
    primaryLight: '#ff4b20',
    accent: '#1bb369',
    accentLight: '#27c840',
    muted: '#b0a9a6',
    grid: 'rgba(255, 255, 255, 0.10)'
};

let currentRange = 'week';

/* =====================================================
   INTERNAL FRONTEND HELPERS (Replaces EthioShell)
   ===================================================== */
const UI = {
    escapeHTML: (str) => {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },
    hostOf: (url) => {
        try {
            const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
            return parsed.hostname;
        } catch {
            return url || 'Unknown Target';
        }
    },
    timeAgo: (dateString) => {
        return '2 hours ago';
    },
    logout: () => {
        localStorage.removeItem('isLoggedIn');
        window.location.href = 'login.html';
    }
};

/* =====================================================
   MOCK DASHBOARD DATASETS (Self-contained)
   ===================================================== */
const MOCK_DATA = {
    week: {
        security_score: 85,
        last_scan: new Date().toISOString(),
        issues: 3,
        vulnerabilities: 3,
        warnings: 12,
        passed_checks: 47,
        total_scans: 24,
        breakdown: { security: 85, performance: 92, seo: 80 },
        range: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            mine: [4, 6, 8, 5, 9, 3, 7],
            all: [10, 14, 18, 12, 22, 9, 15],
            trendLabels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            trend: [120, 190, 300, 250, 420, 310, 480],
            websites: 8,
            requests: 1245,
            response: 234
        }
    },
    month: {
        security_score: 82,
        last_scan: new Date().toISOString(),
        issues: 5,
        vulnerabilities: 5,
        warnings: 18,
        passed_checks: 142,
        total_scans: 88,
        breakdown: { security: 82, performance: 88, seo: 79 },
        range: {
            labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
            mine: [24, 32, 28, 41],
            all: [60, 78, 71, 95],
            trendLabels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
            trend: [1200, 1850, 2100, 3400],
            websites: 22,
            requests: 8560,
            response: 245
        }
    },
    year: {
        security_score: 89,
        last_scan: new Date().toISOString(),
        issues: 2,
        vulnerabilities: 2,
        warnings: 9,
        passed_checks: 520,
        total_scans: 310,
        breakdown: { security: 89, performance: 94, seo: 85 },
        range: {
            labels: ['Q1', 'Q2', 'Q3', 'Q4'],
            mine: [85, 110, 95, 140],
            all: [210, 280, 260, 340],
            trendLabels: ['Q1', 'Q2', 'Q3', 'Q4'],
            trend: [12000, 18500, 22000, 31500],
            websites: 64,
            requests: 84200,
            response: 218
        }
    }
};

const MOCK_RECENT_SCANS = [
    {
        id: 'scan_001',
        target: 'https://demo.ethio-security.org',
        status: 'completed',
        security_score: 85,
        finished_at: new Date().toISOString(),
        counts: { total: 3, critical: 1, high: 2 }
    },
    {
        id: 'scan_002',
        target: 'https://ecommerce.api.local',
        status: 'completed',
        security_score: 92,
        finished_at: new Date(Date.now() - 3600000).toISOString(),
        counts: { total: 0, critical: 0, high: 0 }
    },
    {
        id: 'scan_003',
        target: 'https://staging.internal-services.net',
        status: 'running',
        security_score: 0,
        finished_at: null,
        counts: { total: 2, critical: 0, high: 2 }
    }
];

let series = MOCK_DATA.week.range;

/* =====================================================
   DATA LOADING
   ===================================================== */

async function loadSummary(range = 'week') {
    try {
        const token = localStorage.getItem("token");
        const headers = { "Content-Type": "application/json" };
        if (token) headers["Authorization"] = `Bearer ${token}`;

        const res = await fetch(`http://127.0.0.1:8000/api/dashboard/summary`, { headers });
        if (!res.ok) throw new Error("Failed to load dashboard summary");
        
        const summary = await res.json();
        series = summary.range;

        updateDashboardStats(summary);
        updateSummaryTiles();
        animateSecurityScore(summary.security_score || 0);
        animateCharts();
    } catch (e) {
        console.error("Dashboard summary error:", e);
        setText('scoreNumber', 'Err');
        setText('lastScan', 'Failed to load data');
        setText('issueCount', '—');
        const status = document.getElementById('scoreStatus');
        if (status) {
            status.textContent = '⚠ API Error';
            status.className = 'detail-value status-warning';
        }
    }
}

async function loadRecentScans() {
    const list = document.getElementById('scansList');
    if (!list) return;

    try {
        const token = localStorage.getItem("token");
        const headers = { "Content-Type": "application/json" };
        if (token) headers["Authorization"] = `Bearer ${token}`;

        const res = await fetch(`http://127.0.0.1:8000/api/scans?limit=5`, { headers });
        if (!res.ok) throw new Error("Failed to load recent scans");
        
        const data = await res.json();
        const recentScans = data.scans || [];

        if (!recentScans.length) {
            list.innerHTML = `<p class="empty-state">No scans yet. <a href="scanfinal.html" style="color:#ff4b20">Run your first scan →</a></p>`;
            return;
        }

        list.innerHTML = recentScans.map(renderScanRow).join('');

        list.querySelectorAll('.scan-item').forEach(item => {
            item.style.cursor = 'pointer';
            item.addEventListener('click', () => {
                const id = item.dataset.id;
                const status = item.dataset.status;

                window.location.href = status === 'completed'
                    ? `results.html?id=${encodeURIComponent(id)}`
                    : `livescan.html?id=${encodeURIComponent(id)}`;
            });
        });
    } catch (e) {
        console.error("Recent scans error:", e);
        list.innerHTML = `<p class="empty-state" style="color:#cc2f0c">Failed to load scans.</p>`;
    }
}

function renderScanRow(scan) {
    const counts = scan.counts || { total: 0, critical: 0, high: 0 };
    const issues = counts.total || 0;
    const done = scan.status === 'completed';

    const issueClass = counts.critical ? 'danger' : issues ? 'warning' : 'success';

    const statusBadge = done
        ? (counts.critical || counts.high
            ? '<span class="status-badge status-warning">⚠ Review Needed</span>'
            : '<span class="status-badge status-good">✓ Complete</span>')
        : `<span class="status-badge status-warning">◔ ${UI.escapeHTML(scan.status)}</span>`;

    return `
        <div class="scan-item" data-id="${UI.escapeHTML(scan.id)}" data-status="${UI.escapeHTML(scan.status)}">
            <div class="scan-left">
                <div class="scan-url">${UI.escapeHTML(UI.hostOf(scan.target))}</div>
                <div class="scan-time">${UI.timeAgo(scan.finished_at)}</div>
            </div>
            <div class="scan-middle">
                <div class="scan-stats">
                    <span class="stat-badge">Score: ${done ? scan.security_score : '—'}</span>
                    <span class="stat-badge ${issueClass}">${issues} Issue${issues === 1 ? '' : 's'}</span>
                </div>
            </div>
            <div class="scan-status">${statusBadge}</div>
        </div>`;
}

/* =====================================================
   STATS BINDINGS
   ===================================================== */

function updateDashboardStats(data) {
    const score = data.security_score || 0;

    setText('scoreNumber', score);
    setText('lastScan', data.last_scan ? UI.timeAgo(data.last_scan) : 'No scans yet');
    setText('issueCount', data.issues || 0);

    const status = document.getElementById('scoreStatus');
    if (status) {
        status.textContent = score >= 80 ? '✓ Good' : score >= 60 ? '⚠ Fair' : score ? '✕ At risk' : '— No data';
        status.className = 'detail-value ' + (score >= 80 ? 'status-good' : 'status-warning');
    }

    animateCounter('vulnCount', data.vulnerabilities || 0);
    animateCounter('warnCount', data.warnings || 0);
    animateCounter('passCount', data.passed_checks || 0);
    animateCounter('totalScans', data.total_scans || 0);

    const b = data.breakdown || {};
    setBar('barSecurity', 'valSecurity', b.security || 0);
    setBar('barPerformance', 'valPerformance', b.performance || 0);
    setBar('barSeo', 'valSeo', b.seo || 0);
}

function setBar(barId, valueId, value) {
    const bar = document.getElementById(barId);
    if (bar) bar.style.width = value + '%';
    setText(valueId, value + '%');
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function updateSummaryTiles() {
    setText('sumWebsites', series.websites || 0);
    setText('sumRequests', (series.requests || 0).toLocaleString());
    setText('sumResponse', (series.response || 0) + 'ms');
}

function animateCounter(elementId, finalValue) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const duration = 1000;
    const startTime = performance.now();

    function animate(now) {
        const progress = Math.min((now - startTime) / duration, 1);
        element.textContent = Math.floor(finalValue * progress);
        if (progress < 1) requestAnimationFrame(animate);
    }

    requestAnimationFrame(animate);
}

/* =====================================================
   CANVAS DRAWING METHODS
   ===================================================== */

function prepareCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || canvas.offsetWidth;
    const h = canvas.clientHeight || canvas.offsetHeight;

    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);

    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    return { ctx, w, h };
}

function roundedBar(ctx, x, y, w, h, r) {
    const radius = Math.min(r, w / 2, Math.max(h / 2, 0));
    ctx.beginPath();
    ctx.moveTo(x, y + h - radius);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.lineTo(x + w - radius, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + radius);
    ctx.lineTo(x + w, y + h - radius);
    ctx.quadraticCurveTo(x + w, y + h, x + w - radius, y + h);
    ctx.lineTo(x + radius, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - radius);
    ctx.closePath();
    ctx.fill();
}

function dashedLine(ctx, x1, y, x2) {
    ctx.save();
    ctx.setLineDash([5, 6]);
    ctx.strokeStyle = COLORS.grid;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(x1, y);
    ctx.lineTo(x2, y);
    ctx.stroke();
    ctx.restore();
}

function createScansChart(progress = 1) {
    const canvas = document.getElementById('scansChart');
    if (!canvas || !series.labels.length) return;

    const { ctx, w, h } = prepareCanvas(canvas);

    const padTop = 22, padBottom = 46, padSide = 10;
    const plotH = h - padTop - padBottom;
    const plotW = w - padSide * 2;

    const groups = series.labels.length;
    const groupW = plotW / groups;
    const barW = Math.min(14, groupW * 0.3);
    const gap = 6;
    const maxVal = Math.max(...series.all, ...series.mine, 1);
    const baseY = padTop + plotH;

    const avg = series.all.reduce((a, b) => a + b, 0) / groups;
    dashedLine(ctx, padSide, baseY - (avg / maxVal) * plotH, w - padSide);

    series.labels.forEach((label, i) => {
        const centerX = padSide + groupW * i + groupW / 2;
        const mineX = centerX - barW - gap / 2;
        const allX = centerX + gap / 2;

        const mineH = (series.mine[i] / maxVal) * plotH * progress;
        const mineGrad = ctx.createLinearGradient(0, baseY - mineH, 0, baseY);
        mineGrad.addColorStop(0, COLORS.accentLight);
        mineGrad.addColorStop(1, COLORS.accent);
        ctx.fillStyle = mineGrad;
        roundedBar(ctx, mineX, baseY - mineH, barW, mineH, barW / 2);

        const allH = (series.all[i] / maxVal) * plotH * progress;
        const allGrad = ctx.createLinearGradient(0, baseY - allH, 0, baseY);
        allGrad.addColorStop(0, COLORS.primaryLight);
        allGrad.addColorStop(1, COLORS.primary);
        ctx.fillStyle = allGrad;
        roundedBar(ctx, allX, baseY - allH, barW, allH, barW / 2);

        ctx.textAlign = 'center';
        ctx.fillStyle = COLORS.accentLight;
        ctx.font = '600 11px Inter, system-ui, sans-serif';
        ctx.fillText(series.mine[i], centerX, baseY + 18);

        ctx.fillStyle = COLORS.muted;
        ctx.font = '11px Inter, system-ui, sans-serif';
        ctx.fillText(label, centerX, baseY + 36);
    });
}

function createTrendChart(progress = 1) {
    const canvas = document.getElementById('trendChart');
    if (!canvas || !series.trend.length) return;

    const { ctx, w, h } = prepareCanvas(canvas);

    const padTop = 34, padBottom = 40, padSide = 34;
    const plotH = h - padTop - padBottom;
    const plotW = w - padSide * 2;

    const points = series.trend;
    const n = points.length;
    const max = Math.max(...points);
    const min = Math.min(...points);
    const span = (max - min) || 1;

    const xy = points.map((v, i) => ({
        x: padSide + (plotW / Math.max(n - 1, 1)) * i,
        y: padTop + plotH - ((v - min) / span) * plotH * 0.8 - plotH * 0.1
    }));

    const avg = points.reduce((a, b) => a + b, 0) / n;
    const avgY = padTop + plotH - ((avg - min) / span) * plotH * 0.8 - plotH * 0.1;
    dashedLine(ctx, padSide - 20, avgY, w - padSide + 20);

    const visible = Math.max(1, Math.round(n * progress));

    ctx.strokeStyle = 'rgba(204, 47, 12, 0.55)';
    ctx.lineWidth = 3;
    ctx.lineJoin = 'round';
    ctx.beginPath();
    xy.slice(0, visible).forEach((p, i) => {
        if (i === 0) ctx.moveTo(p.x, p.y);
        else ctx.lineTo(p.x, p.y);
    });
    ctx.stroke();

    xy.slice(0, visible).forEach((p, i) => {
        const grad = ctx.createLinearGradient(p.x - 7, p.y - 7, p.x + 7, p.y + 7);
        grad.addColorStop(0, COLORS.primaryLight);
        grad.addColorStop(1, COLORS.accent);

        ctx.beginPath();
        ctx.arc(p.x, p.y, 7, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(p.x, p.y, 7, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(8, 7, 7, 0.9)';
        ctx.lineWidth = 2;
        ctx.stroke();

        ctx.textAlign = 'center';
        ctx.fillStyle = COLORS.primaryLight;
        ctx.font = '600 12px Inter, system-ui, sans-serif';
        ctx.fillText(formatCompact(points[i]), p.x, p.y - 16);

        ctx.fillStyle = COLORS.muted;
        ctx.font = '11px Inter, system-ui, sans-serif';
        ctx.fillText(series.trendLabels[i], p.x, padTop + plotH + 26);
    });
}

function formatCompact(n) {
    if (n >= 1000) return (n / 1000).toFixed(n % 1000 === 0 ? 0 : 1) + 'K';
    return String(n);
}

function animateCharts() {
    const duration = 900;
    const start = performance.now();

    function frame(now) {
        const p = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        createScansChart(eased);
        createTrendChart(eased);
        if (p < 1) requestAnimationFrame(frame);
    }

    requestAnimationFrame(frame);
}

function animateSecurityScore(score) {
    const circle = document.getElementById('scoreProgress');
    if (!circle) return;

    const circumference = 2 * Math.PI * 90;
    circle.style.strokeDasharray = circumference;
    circle.style.strokeDashoffset = circumference - (score / 100) * circumference;
}

/* =====================================================
   RANGE FILTER
   ===================================================== */

function setupFilters() {
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            currentRange = btn.dataset.range || 'week';
            loadSummary(currentRange);
        });
    });
}

/* =====================================================
   INIT
   ===================================================== */

document.addEventListener('DOMContentLoaded', () => {
    setupFilters();
    loadSummary(currentRange);
    loadRecentScans();

    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            createScansChart();
            createTrendChart();
        }, 200);
    });
});

document.addEventListener('keydown', e => {
    if (e.altKey && e.key === 'l') UI.logout();
    if (e.altKey && e.key === 's') window.location.href = 'scanfinal.html';
});
