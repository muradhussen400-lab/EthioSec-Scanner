/* =====================================================
   SCANNER PAGE (scanjavafinal.js)
   Pure Frontend Standalone - No Backend Dependencies
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

    const urlInput = document.getElementById("url");
    const urlWrap = document.querySelector(".url-input");
    const clearUrlBtn = document.getElementById("clearUrl");
    const urlHelp = document.getElementById("urlHelp");

    const scanButton = document.getElementById("scanButton");
    const toggleAllBtn = document.getElementById("toggleAll");
    const authorized = document.getElementById("authorized");

    const depthSelect = document.getElementById("depth");
    const depthNote = document.getElementById("depthNote");

    const lastScanEl = document.getElementById("lastScan");
    const totalScansEl = document.getElementById("totalScans");
    const historyList = document.getElementById("historyList");
    const recentTargets = document.getElementById("recentTargets");

    const moduleInputs = Array.from(document.querySelectorAll("[data-module]"));

    /* =====================================================
       STANDALONE HELPERS (Replaces EthioShell & EthioAuth)
       ===================================================== */

    function getParam(key) {
        const params = new URLSearchParams(window.location.search);
        return params.get(key);
    }

    function escapeHTML(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function timeAgo(dateString) {
        if (!dateString) return "Recently";
        const date = new Date(dateString);
        const seconds = Math.floor((new Date() - date) / 1000);
        if (isNaN(seconds) || seconds < 60) return "Just now";
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes}m ago`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours}h ago`;
        const days = Math.floor(hours / 24);
        return `${days}d ago`;
    }

    function showToast(message, type = "info") {
        let toast = document.querySelector(".toast");
        if (!toast) {
            toast = document.createElement("div");
            toast.className = "toast";
            document.body.appendChild(toast);
        }
        toast.textContent = message;
        toast.className = `toast show ${type === "error" ? "error" : ""}`;
        setTimeout(() => toast.classList.remove("show"), 3500);
    }

    /* =====================================================
       URL HANDLING
       ===================================================== */

    function normalizeURL(value) {
        const trimmed = (value || "").trim();
        if (!trimmed) return "";
        return /^https?:\/\//i.test(trimmed) ? trimmed : "https://" + trimmed;
    }

    function isValidURL(value) {
        try {
            const url = new URL(value);
            return (url.protocol === "http:" || url.protocol === "https:") && url.hostname.includes(".");
        } catch {
            return false;
        }
    }

    function refreshUrlField() {
        if (urlWrap && urlInput) {
            urlWrap.classList.toggle("filled", urlInput.value.trim().length > 0);
        }
        refreshButtonState();
    }

    function showUrlError(message) {
        if (urlWrap) urlWrap.classList.add("invalid");
        if (urlHelp) {
            urlHelp.classList.add("error");
            urlHelp.textContent = message;
        }
    }

    function clearUrlError() {
        if (urlWrap) urlWrap.classList.remove("invalid");
        if (urlHelp) {
            urlHelp.classList.remove("error");
            urlHelp.textContent = "We only read publicly available information.";
        }
    }

    if (urlInput) {
        urlInput.addEventListener("input", () => {
            clearUrlError();
            refreshUrlField();
        });

        urlInput.addEventListener("keydown", e => {
            if (e.key === "Enter" && scanButton && !scanButton.disabled) {
                startScan();
            }
        });
    }

    if (clearUrlBtn && urlInput) {
        clearUrlBtn.addEventListener("click", () => {
            urlInput.value = "";
            clearUrlError();
            refreshUrlField();
            urlInput.focus();
        });
    }

    /* =====================================================
       SETTINGS & DEPTH NOTES
       ===================================================== */

    const DEPTH_NOTES = {
        quick: "Roughly 7 seconds — headers, TLS and DNS only",
        standard: "Roughly 10 seconds — recommended",
        deep: "Roughly 16 seconds — adds OWASP and access-control tests"
    };

    if (depthSelect && depthNote) {
        depthSelect.addEventListener("change", () => {
            depthNote.textContent = DEPTH_NOTES[depthSelect.value] || DEPTH_NOTES.standard;
        });
        depthNote.textContent = DEPTH_NOTES[depthSelect.value] || DEPTH_NOTES.standard;
    }

    if (toggleAllBtn) {
        toggleAllBtn.addEventListener("click", () => {
            const allOn = moduleInputs.every(i => i.checked);
            moduleInputs.forEach(i => { i.checked = !allOn; });
            toggleAllBtn.textContent = allOn ? "Select all" : "Clear all";
            refreshButtonState();
        });
    }

    moduleInputs.forEach(i => i.addEventListener("change", refreshButtonState));
    if (authorized) {
        authorized.addEventListener("change", refreshButtonState);
    }

    function refreshButtonState() {
        if (!scanButton || !urlInput || !authorized) return;
        const hasUrl = urlInput.value.trim().length > 0;
        const hasModule = moduleInputs.length === 0 || moduleInputs.some(i => i.checked);
        scanButton.disabled = !(hasUrl && hasModule && authorized.checked);
    }

    function applyScanDefaults() {
        let prefs = null;
        try { 
            prefs = JSON.parse(localStorage.getItem("ethioSettings")); 
        } catch { 
            prefs = null; 
        }
        if (!prefs) return;

        const map = { headers: "defHeaders", ssl: "defSsl", dns: "defDns", meta: "defMeta" };
        moduleInputs.forEach(input => {
            const key = map[input.dataset.module];
            if (key && typeof prefs[key] === "boolean") input.checked = prefs[key];
        });

        if (prefs.defDepth && depthSelect && depthNote) {
            depthSelect.value = prefs.defDepth;
            depthNote.textContent = DEPTH_NOTES[depthSelect.value] || DEPTH_NOTES.standard;
        }
    }

    /* =====================================================
       START SCAN (100% Offline / LocalStorage Mock)
       ===================================================== */

    function startScan() {
        const target = normalizeURL(urlInput.value);

        if (!isValidURL(target)) {
            showUrlError("Enter a full website address, for example https://example.com");
            urlInput.focus();
            return;
        }

        if (!authorized.checked) {
            showToast("Confirm you are authorized to test this target first.", "error");
            return;
        }

        const modules = {};
        moduleInputs.forEach(i => { modules[i.dataset.module] = i.checked; });

        const originalText = scanButton.innerHTML;
        scanButton.disabled = true;
        scanButton.innerHTML = "<span>⏳</span> Starting scan…";

        // Generate mock scan record
        const scanId = "scan_" + Date.now();
        const newScan = {
            id: scanId,
            target: target,
            url: target,
            depth: depthSelect ? depthSelect.value : "standard",
            modules: modules,
            status: "completed",
            created_at: new Date().toISOString(),
            finished_at: new Date().toISOString(),
            security_score: Math.floor(Math.random() * 25) + 70, // Realistic random score between 70-95
            issues: Math.floor(Math.random() * 5) + 1
        };

        // Persist to local scan history database
        try {
            const rawDb = localStorage.getItem("ethio_mock_db");
            const db = rawDb ? JSON.parse(rawDb) : [];
            db.unshift(newScan);
            localStorage.setItem("ethio_mock_db", JSON.stringify(db));
        } catch (e) {
            console.warn("Could not save to history:", e);
        }

        // Store active job for the live scanner simulator
        localStorage.setItem("ethio_active_scan", JSON.stringify(newScan));

        // Redirect to live progress screen if available, otherwise direct to results
        setTimeout(() => {
            window.location.href = `livescan.html?id=${encodeURIComponent(scanId)}&target=${encodeURIComponent(target)}`;
        }, 500);
    }

    if (scanButton) {
        scanButton.addEventListener("click", startScan);
    }

    /* =====================================================
       RECENT SCANS (From LocalStorage)
       ===================================================== */

    function scoreClass(score) {
        if (score == null) return "mid";
        return score >= 80 ? "good" : score >= 60 ? "mid" : "bad";
    }

    function loadRecent() {
        let scans = [];
        try {
            const raw = localStorage.getItem("ethio_mock_db");
            scans = raw ? JSON.parse(raw) : [];
        } catch {
            scans = [];
        }

        if (totalScansEl) totalScansEl.textContent = scans.length;
        if (lastScanEl) {
            const done = scans.filter(s => s.status === "completed" || s.finished_at);
            lastScanEl.textContent = done.length ? timeAgo(done[0].finished_at || done[0].created_at) : "—";
        }

        renderHistory(scans);
        renderChips(scans);
    }

    function renderHistory(scans) {
        if (!historyList) return;
        if (!scans.length) {
            historyList.innerHTML = '<p class="empty-state">No scans yet. Run your first scan above.</p>';
            return;
        }

        historyList.innerHTML = scans.slice(0, 6).map(s => `
            <div class="history-item" data-id="${escapeHTML(s.id)}" data-status="${escapeHTML(s.status || 'completed')}">
              <div class="history-main">
                <div class="history-url">${escapeHTML(s.target || s.url)}</div>
                <div class="history-time">${timeAgo(s.finished_at || s.created_at)} · ${escapeHTML(s.depth || "standard")}</div>
              </div>
              <span class="history-score ${scoreClass(s.security_score || s.score)}">${s.security_score || s.score || 85}</span>
            </div>`).join("");

        historyList.querySelectorAll(".history-item").forEach(item => {
            item.style.cursor = "pointer";
            item.addEventListener("click", () => {
                const id = item.dataset.id;
                window.location.href = `results.html?id=${encodeURIComponent(id)}`;
            });
        });
    }

    function renderChips(scans) {
        if (!recentTargets) return;
        const unique = [...new Set(scans.map(s => s.target || s.url))].filter(Boolean).slice(0, 4);

        if (!unique.length) {
            recentTargets.innerHTML = "";
            return;
        }

        recentTargets.innerHTML = unique
            .map(u => `<button class="chip" type="button" data-url="${escapeHTML(u)}">${escapeHTML(u.replace(/^https?:\/\//, ""))}</button>`)
            .join("");

        recentTargets.querySelectorAll(".chip").forEach(chip => {
            chip.addEventListener("click", () => {
                if (urlInput) {
                    urlInput.value = chip.dataset.url;
                    refreshUrlField();
                    urlInput.focus();
                }
            });
        });
    }

    /* =====================================================
       INIT
       ===================================================== */

    applyScanDefaults();

    // Read incoming target from URL params (?url=, ?target=, or ?site=)
    const incoming = getParam("url") || getParam("target") || getParam("site");
    if (incoming && urlInput) {
        urlInput.value = normalizeURL(incoming);
        if (urlHelp) {
            urlHelp.textContent = "Target carried over from your last step — tick the authorization box to run it.";
        }
    }

    refreshUrlField();
    loadRecent();
});