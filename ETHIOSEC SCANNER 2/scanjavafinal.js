if (!localStorage.getItem('token')) {
    window.location.href = 'login.html';
}
/* =====================================================
   SCANNER PAGE (scanjavafinal.js)
   Real Backend API Client
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

    const urlInput = document.getElementById("url");
    const urlWrap = document.querySelector(".url-input");
    const clearUrlBtn = document.getElementById("clearUrl");
    const urlHelp = document.getElementById("urlHelp");

    const scanButton = document.getElementById("scanButton");
    const toggleAllBtn = document.getElementById("toggleAll");
    const authorized = document.getElementById("authorized");

    const lastScanEl = document.getElementById("lastScan");
    const totalScansEl = document.getElementById("totalScans");
    const historyList = document.getElementById("historyList");
    const recentTargets = document.getElementById("recentTargets");

    const moduleInputs = Array.from(document.querySelectorAll("[data-module]"));
    const depthRadios = Array.from(document.querySelectorAll('input[name="depth"]'));
    const cardStandard = document.getElementById("cardStandard");
    const cardDeep = document.getElementById("cardDeep");

    /* =====================================================
       HELPERS
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
            return (url.protocol === "http:" || url.protocol === "https:") && (url.hostname.includes(".") || url.hostname === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname));
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
            urlHelp.textContent = "Specify the fully qualified domain or endpoint to audit.";
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
       PROFILE & DEPTH SELECTION
       ===================================================== */

    function syncProfileCards() {
        const selected = document.querySelector('input[name="depth"]:checked')?.value || "standard";
        if (cardStandard) cardStandard.classList.toggle("active", selected === "standard");
        if (cardDeep) cardDeep.classList.toggle("active", selected === "deep");
    }

    depthRadios.forEach(radio => {
        radio.addEventListener("change", syncProfileCards);
    });

    if (cardStandard) {
        cardStandard.addEventListener("click", () => {
            const r = cardStandard.querySelector('input[type="radio"]');
            if (r) { r.checked = true; syncProfileCards(); }
        });
    }

    if (cardDeep) {
        cardDeep.addEventListener("click", () => {
            const r = cardDeep.querySelector('input[type="radio"]');
            if (r) { r.checked = true; syncProfileCards(); }
        });
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

    async function applyScanDefaults() {
        try {
            const token = localStorage.getItem("token");
            if (!token) return;
            const res = await fetch("http://127.0.0.1:8000/api/user/settings", {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const apiSet = await res.json();
                const depthRadio = document.querySelector(`input[name="depth"][value="${apiSet.default_scan_depth}"]`);
                if (depthRadio) {
                    depthRadio.checked = true;
                    syncProfileCards();
                }
                
                let prefs = null;
                try { prefs = JSON.parse(localStorage.getItem("ethioSettings")); } catch {}
                if (prefs) {
                    const map = { sqli: "defSqli", xss: "defXss", headers: "defHeaders", https: "defSsl" };
                    moduleInputs.forEach(input => {
                        const key = map[input.dataset.module];
                        if (key && typeof prefs[key] === "boolean") input.checked = prefs[key];
                    });
                }
                refreshButtonState();
            }
        } catch (e) {
            console.error("Failed to load scan defaults", e);
        }
    }

    /* =====================================================
       START SCAN (Real API)
       ===================================================== */

    async function startScan() {
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

        const checkedDepthEl = document.querySelector('input[name="depth"]:checked');
        const depth = checkedDepthEl ? checkedDepthEl.value : "standard";

        // Build exact module selection
        const selectedModules = {};
        moduleInputs.forEach(i => {
            selectedModules[i.dataset.module] = Boolean(i.checked);
        });

        const originalText = scanButton.innerHTML;
        scanButton.disabled = true;
        scanButton.innerHTML = "<span>⏳</span> Launching real scan…";

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                showToast("You must be logged in to start a scan.", "error");
                scanButton.disabled = false;
                scanButton.innerHTML = originalText;
                return;
            }

            const headers = {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            };

            // 1. Create Target
            const targetRes = await fetch("http://127.0.0.1:8000/api/targets", {
                method: "POST",
                headers,
                body: JSON.stringify({ url: target })
            });
            if (!targetRes.ok) {
                let errDetail = "Failed to create target";
                try { const eData = await targetRes.json(); if (eData.detail) errDetail = eData.detail; } catch(_) {}
                throw new Error(errDetail);
            }
            const targetData = await targetRes.json();

            // 2. Create Scan with exact module selection
            const scanRes = await fetch("http://127.0.0.1:8000/api/scans", {
                method: "POST",
                headers,
                body: JSON.stringify({
                    target_id: targetData.id,
                    depth: depth,
                    modules: selectedModules,
                    authorized: true,
                    auth_context_1: null,
                    auth_context_2: null
                })
            });
            if (!scanRes.ok) {
                let errDetail = "Failed to create scan";
                try { const eData = await scanRes.json(); if (eData.detail) errDetail = eData.detail; } catch(_) {}
                throw new Error(errDetail);
            }
            const scanData = await scanRes.json();
            const scanId = scanData.scan_id || scanData.id;

            // 3. Start Scan
            const startRes = await fetch(`http://127.0.0.1:8000/api/scans/${scanId}/start`, {
                method: "POST",
                headers
            });
            if (!startRes.ok) {
                let errDetail = "Failed to start scan";
                try { const eData = await startRes.json(); if (eData.detail) errDetail = eData.detail; } catch(_) {}
                throw new Error(errDetail);
            }

            // Redirect to live progress screen
            window.location.href = `livescan.html?id=${encodeURIComponent(scanId)}&target=${encodeURIComponent(target)}`;
            
        } catch (error) {
            console.error("Scan start error:", error);
            showToast(error.message || "Error starting scan. Please try again.", "error");
            scanButton.disabled = false;
            scanButton.innerHTML = originalText;
        }
    }

    if (scanButton) {
        scanButton.addEventListener("click", startScan);
    }

    /* =====================================================
       RECENT SCANS (Real API)
       ===================================================== */

    function scoreClass(score) {
        if (score == null) return "mid";
        return score >= 80 ? "good" : score >= 60 ? "mid" : "bad";
    }

    async function loadRecent() {
        let scans = [];
        try {
            const token = localStorage.getItem("token");
            if (token) {
                const res = await fetch("http://127.0.0.1:8000/api/scans?limit=6", {
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${token}`
                    }
                });
                if (res.ok) {
                    const data = await res.json();
                    scans = data.scans || [];
                }
            }
        } catch (e) {
            console.error("Failed to load recent scans", e);
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
            historyList.innerHTML = '<p class="empty-state">No scans yet. Launch your first security scan above.</p>';
            return;
        }

        historyList.innerHTML = scans.slice(0, 6).map(s => {
            const score = s.security_score !== null ? s.security_score : "—";
            return `
            <div class="history-item" data-id="${escapeHTML(s.id)}" data-status="${escapeHTML(s.status || 'completed')}">
              <div class="history-main">
                <div class="history-url">${escapeHTML(s.target || s.url)}</div>
                <div class="history-time">${timeAgo(s.finished_at || s.created_at)} · ${escapeHTML(s.depth || "standard")}</div>
              </div>
              <span class="history-score ${scoreClass(s.security_score)}">${score}</span>
            </div>`;
        }).join("");

        historyList.querySelectorAll(".history-item").forEach(item => {
            item.style.cursor = "pointer";
            item.addEventListener("click", () => {
                const id = item.dataset.id;
                const status = item.dataset.status;
                window.location.href = status === "completed"
                    ? `results.html?id=${encodeURIComponent(id)}`
                    : `livescan.html?id=${encodeURIComponent(id)}`;
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

    const incoming = getParam("url") || getParam("target") || getParam("site");
    if (incoming && urlInput) {
        urlInput.value = normalizeURL(incoming);
        if (urlHelp) {
            urlHelp.textContent = "Target carried over — check the authorization box to launch.";
        }
    }

    refreshUrlField();
    loadRecent();
});
