/**
 * ETHIOSECSCAN — NEW SECURITY SCAN CONTROLLER (scanjavafinal.js)
 * Real Backend API Integration & Seamless Truthful Scanning Telemetry
 */

document.addEventListener("DOMContentLoaded", () => {

    const host = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") 
        ? window.location.hostname 
        : "127.0.0.1";
    const API_BASE = `http://${host}:8000/api`;
    const HEALTH_URL = `http://${host}:8000/health`;

    // Authentication Guard
    let token = localStorage.getItem("token");
    if (!token) {
        window.location.href = "login.html";
        return;
    }

    // DOM Elements — Target & Config
    const targetUrlInput = document.getElementById("targetUrl");
    const clearUrlBtn = document.getElementById("clearUrlBtn");
    const urlValidIcon = document.getElementById("urlValidIcon");
    const targetHelperText = document.getElementById("targetHelperText");
    const valFormatIndicator = document.getElementById("valFormatIndicator");
    const valSchemeIndicator = document.getElementById("valSchemeIndicator");
    
    const cardStandard = document.getElementById("cardStandard");
    const cardDeep = document.getElementById("cardDeep");
    const cardSuper = document.getElementById("cardSuper");

    const checksCountBadge = document.getElementById("checksCountBadge");
    const checkCards = document.querySelectorAll(".check-card");

    const summaryTargetUrl = document.getElementById("summaryTargetUrl");
    const summaryProfileName = document.getElementById("summaryProfileName");
    const summaryMaxPages = document.getElementById("summaryMaxPages");
    const summaryMaxDepth = document.getElementById("summaryMaxDepth");
    const summaryChecksCount = document.getElementById("summaryChecksCount");

    const authCheckbox = document.getElementById("authCheckbox");
    const launchBtn = document.getElementById("launchBtn");
    
    const reviewModal = document.getElementById("reviewModal");
    const modalTargetUrl = document.getElementById("modalTargetUrl");
    const modalProfileName = document.getElementById("modalProfileName");
    const modalProfileLimits = document.getElementById("modalProfileLimits");
    const modalChecksNum = document.getElementById("modalChecksNum");
    const modalSelectedTags = document.getElementById("modalSelectedTags");
    const modalAuthWarning = document.getElementById("modalAuthWarning");
    const modalLaunchBtn = document.getElementById("modalLaunchBtn");

    const sidebar = document.getElementById("sidebar");
    const sidebarToggle = document.getElementById("sidebarToggle");
    const sidebarOverlay = document.getElementById("sidebarOverlay");

    // DOM Elements — Active Scan Monitor & Notices
    const serverNoticeBanner = document.getElementById("serverNoticeBanner");
    const scanConfigGrid = document.getElementById("scanConfigGrid");
    const activeScanSection = document.getElementById("activeScanSection");

    const liveStatusPill = document.getElementById("liveStatusPill");
    const liveStatusText = document.getElementById("liveStatusText");
    const liveTargetUrl = document.getElementById("liveTargetUrl");
    const liveTargetUrlText = document.getElementById("liveTargetUrlText");
    const liveScanId = document.getElementById("liveScanId");
    const liveProfileBadge = document.getElementById("liveProfileBadge");
    const liveStartTime = document.getElementById("liveStartTime");
    const liveElapsed = document.getElementById("liveElapsed");

    const liveRingFill = document.getElementById("liveRingFill");
    const liveProgressPercent = document.getElementById("liveProgressPercent");
    const liveRingStatusLabel = document.getElementById("liveRingStatusLabel");
    const liveStageHeadline = document.getElementById("liveStageHeadline");
    const liveStageDesc = document.getElementById("liveStageDesc");
    const liveChecksCountSummary = document.getElementById("liveChecksCountSummary");
    const liveModulesStatusGrid = document.getElementById("liveModulesStatusGrid");

    const liveCountHigh = document.getElementById("liveCountHigh");
    const liveCountMedium = document.getElementById("liveCountMedium");
    const liveCountLow = document.getElementById("liveCountLow");
    const liveCountPassed = document.getElementById("liveCountPassed");
    const liveCountTotal = document.getElementById("liveCountTotal");

    const liveCancelBtn = document.getElementById("liveCancelBtn");
    const liveViewResultsBtn = document.getElementById("liveViewResultsBtn");
    const liveResetBtn = document.getElementById("liveResetBtn");

    const RING_CIRCUMFERENCE = 2 * Math.PI * 58; // r=58 -> ~364.4px
    if (liveRingFill) {
        liveRingFill.style.strokeDasharray = RING_CIRCUMFERENCE;
        liveRingFill.style.strokeDashoffset = RING_CIRCUMFERENCE;
    }

    // State
    let selectedProfile = "standard"; // standard or deep
    const profileLimits = {
        standard: { name: "Standard Scan", pages: 15, depth: 2 },
        deep: { name: "Deep Scan", pages: 50, depth: 4 }
    };

    const modulesState = {
        sqli: true,
        xss: true,
        headers: true,
        cookies: false,
        cors: false,
        https: true,
        auth: true,
        access_control: true,
        exposed_files: true,
        http_methods: false,
        info_disclosure: false,
        csrf: false,
        ssrf: false,
        misconfig: false
    };

    const moduleLabels = {
        sqli: "SQL Injection",
        xss: "Cross-Site Scripting (XSS)",
        headers: "Security Headers",
        cookies: "Cookie Security",
        cors: "CORS Configuration",
        https: "HTTPS/TLS Configuration",
        auth: "Authentication Security",
        access_control: "Broken Access Control",
        exposed_files: "Exposed Files",
        http_methods: "HTTP Methods",
        info_disclosure: "Information Disclosure",
        csrf: "Cross-Site Request Forgery (CSRF)",
        ssrf: "Server-Side Request Forgery (SSRF)",
        misconfig: "Security Misconfiguration"
    };

    const moduleIcons = {
        sqli: "🗄️",
        xss: "⚡",
        headers: "🛡️",
        cookies: "🍪",
        cors: "🌐",
        https: "🔒",
        auth: "🔑",
        access_control: "🚪",
        exposed_files: "📁",
        http_methods: "📡",
        info_disclosure: "ℹ️",
        csrf: "🔄",
        ssrf: "🎯",
        misconfig: "⚙️"
    };

    let isSubmitting = false;
    let currentActiveScanId = null;
    let pollIntervalId = null;
    let timerIntervalId = null;
    let scanStartEpoch = null;

    // Toast Feedback
    function showToast(message, type = "info") {
        const toast = document.getElementById("toast");
        if (!toast) return;
        toast.textContent = message;
        toast.className = `toast show ${type === "error" ? "error" : ""}`;
        setTimeout(() => toast.classList.remove("show"), 4200);
    }

    // Mobile Sidebar Handling
    if (sidebarToggle && sidebar && sidebarOverlay) {
        sidebarToggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
            sidebarOverlay.classList.toggle("open");
        });
        sidebarOverlay.addEventListener("click", () => {
            sidebar.classList.remove("open");
            sidebarOverlay.classList.remove("open");
        });
    }

    // User Profile Display
    function updateUserData() {
        const userName = localStorage.getItem("userName") || "";
        const userNameLabel = document.getElementById("userNameLabel");
        const userAvatarSmall = document.getElementById("userAvatarSmall");
        if (userName) {
            if (userNameLabel) userNameLabel.textContent = userName;
            if (userAvatarSmall) {
                const initials = userName.split(" ").map(n => n[0]).join("").slice(0, 2).toUpperCase();
                userAvatarSmall.textContent = initials || "U";
            }
        }
    }
    updateUserData();

    // =========================================================================
    // BACKEND CONNECTIVITY & HEALTH CHECK
    // =========================================================================

    async function checkBackendHealth(showFeedback = false) {
        const statusDot = document.querySelector("#serviceStatusBox .service-status-dot");
        const statusName = document.querySelector("#serviceStatusBox .service-name");
        const statusState = document.querySelector("#serviceStatusBox .service-state");

        // Try both window.location.hostname and loopback fallbacks
        const endpointsToTry = [
            HEALTH_URL,
            "http://127.0.0.1:8000/health",
            "http://localhost:8000/health"
        ];
        const uniqueEndpoints = [...new Set(endpointsToTry)];

        let isOnline = false;
        for (const ep of uniqueEndpoints) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 2500);
                const res = await fetch(ep, { signal: controller.signal });
                clearTimeout(timeoutId);
                if (res.ok) {
                    isOnline = true;
                    break;
                }
            } catch (_) {}
        }

        if (isOnline) {
            if (serverNoticeBanner) serverNoticeBanner.classList.remove("visible");
            if (statusDot) {
                statusDot.classList.remove("offline");
                statusDot.classList.add("online");
                statusDot.style.background = "#10B981";
            }
            if (statusName) statusName.textContent = "Backend Online";
            if (statusState) statusState.textContent = "FastAPI 8000 operational";
            if (showFeedback) showToast("FastAPI scanner backend is healthy and reachable!", "info");
            return true;
        }

        if (serverNoticeBanner) serverNoticeBanner.classList.add("visible");
        if (statusDot) {
            statusDot.classList.remove("online");
            statusDot.classList.add("offline");
            statusDot.style.background = "#E83B25";
        }
        if (statusName) statusName.textContent = "Backend Offline";
        if (statusState) statusState.textContent = "FastAPI 8000 unreachable";
        if (showFeedback) {
            showToast("FastAPI scanner backend is offline at http://127.0.0.1:8000. Start it via start.bat or uvicorn.", "error");
        }
        return false;
    }
    window.checkBackendHealth = checkBackendHealth;

    // Automatic polling: Re-check backend every 5 seconds if the offline banner is visible
    setInterval(() => {
        if (serverNoticeBanner && serverNoticeBanner.classList.contains("visible")) {
            checkBackendHealth(false);
        }
    }, 5000);

    // =========================================================================
    // URL VALIDATION & NORMALIZATION
    // =========================================================================

    function normalizeURL(urlStr) {
        const trimmed = (urlStr || "").trim();
        if (!trimmed) return "";
        return /^https?:\/\//i.test(trimmed) ? trimmed : "https://" + trimmed;
    }

    function validateURL(urlStr) {
        const trimmed = (urlStr || "").trim();
        if (!trimmed) return { valid: false, scheme: false, hostname: false, isEmail: false, normalized: "" };

        // Check if user accidentally entered an email address
        if (trimmed.includes("@") || trimmed.toLowerCase().startsWith("mailto:")) {
            return {
                valid: false,
                scheme: false,
                hostname: false,
                isEmail: true,
                normalized: ""
            };
        }

        const normalized = normalizeURL(trimmed);
        try {
            const parsed = new URL(normalized);
            const isHttpScheme = parsed.protocol === "http:" || parsed.protocol === "https:";
            const hasValidHost = parsed.hostname.length > 0 && (
                parsed.hostname.includes(".") || 
                parsed.hostname === "localhost" || 
                /^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname)
            );

            return {
                valid: isHttpScheme && hasValidHost,
                scheme: isHttpScheme,
                hostname: hasValidHost,
                isEmail: false,
                normalized
            };
        } catch {
            return { valid: false, scheme: false, hostname: false, isEmail: false, normalized: "" };
        }
    }

    function onUrlInputChanged() {
        const userEmail = (localStorage.getItem("userEmail") || "").toLowerCase().trim();
        let raw = (targetUrlInput ? targetUrlInput.value : "").trim();

        // If field contains the registered user's email (plain or prefixed), clear it immediately
        if (userEmail && (raw.toLowerCase() === userEmail || raw.toLowerCase() === "https://" + userEmail || raw.toLowerCase() === "http://" + userEmail)) {
            targetUrlInput.value = "";
            raw = "";
        }

        clearUrlBtn.style.display = raw.length > 0 ? "flex" : "none";

        if (!raw) {
            urlValidIcon.style.display = "none";
            valFormatIndicator.className = "validation-indicator";
            valFormatIndicator.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle></svg><span>URL Format</span>';
            valSchemeIndicator.className = "validation-indicator";
            valSchemeIndicator.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle></svg><span>HTTP/HTTPS Scheme</span>';
            targetHelperText.textContent = "Specify the fully qualified domain or endpoint to audit.";
            targetHelperText.classList.remove("error");
            summaryTargetUrl.textContent = "Not specified";
            refreshLaunchButtonState();
            return;
        }

        const res = validateURL(raw);
        if (res.valid) {
            urlValidIcon.style.display = "flex";
            valFormatIndicator.className = "validation-indicator valid";
            valFormatIndicator.innerHTML = '<span>✓</span><span>Valid URL format</span>';
            valSchemeIndicator.className = "validation-indicator valid";
            valSchemeIndicator.innerHTML = '<span>✓</span><span>' + (res.normalized.startsWith("https") ? "HTTPS scheme (TLS)" : "HTTP scheme") + '</span>';
            targetHelperText.textContent = "Target verified for safety checks.";
            targetHelperText.classList.remove("error");
            summaryTargetUrl.textContent = res.normalized;
        } else if (res.isEmail) {
            urlValidIcon.style.display = "none";
            valFormatIndicator.className = "validation-indicator invalid";
            valFormatIndicator.innerHTML = '<span>✕</span><span>Email address entered</span>';
            valSchemeIndicator.className = "validation-indicator invalid";
            valSchemeIndicator.innerHTML = '<span>✕</span><span>Requires web URL</span>';
            targetHelperText.textContent = "You entered an email address. Please enter a target web URL (e.g. https://example.com).";
            targetHelperText.classList.add("error");
            summaryTargetUrl.textContent = raw;
        } else {
            urlValidIcon.style.display = "none";
            valFormatIndicator.className = "validation-indicator invalid";
            valFormatIndicator.innerHTML = '<span>✕</span><span>Invalid URL structure</span>';
            valSchemeIndicator.className = res.scheme ? "validation-indicator valid" : "validation-indicator invalid";
            valSchemeIndicator.innerHTML = res.scheme ? '<span>✓</span><span>HTTP/HTTPS Scheme</span>' : '<span>✕</span><span>Requires http:// or https://</span>';
            targetHelperText.textContent = "Please enter a valid web address, e.g. https://example.com";
            targetHelperText.classList.add("error");
            summaryTargetUrl.textContent = raw;
        }

        refreshLaunchButtonState();
    }

    if (targetUrlInput) {
        targetUrlInput.addEventListener("input", onUrlInputChanged);
        targetUrlInput.addEventListener("blur", () => {
            const raw = targetUrlInput.value.trim();
            // If raw is empty or contains an email address or @, NEVER prepend https://
            if (!raw || raw.includes("@") || raw.toLowerCase().startsWith("mailto:")) {
                const userEmail = (localStorage.getItem("userEmail") || "").toLowerCase().trim();
                if (raw && (raw.toLowerCase() === userEmail || raw.toLowerCase() === "https://" + userEmail || raw.toLowerCase() === "http://" + userEmail)) {
                    targetUrlInput.value = "";
                }
                onUrlInputChanged();
                return;
            }
            if (!/^https?:\/\//i.test(raw)) {
                targetUrlInput.value = "https://" + raw;
                onUrlInputChanged();
            }
        });
        targetUrlInput.addEventListener("change", onUrlInputChanged);
    }

    if (clearUrlBtn) {
        clearUrlBtn.addEventListener("click", () => {
            targetUrlInput.value = "";
            onUrlInputChanged();
            targetUrlInput.focus();
        });
    }

    // =========================================================================
    // PROFILE SELECTION (Standard vs Deep, Super Disabled)
    // =========================================================================

    window.selectProfile = function(profileKey) {
        if (profileKey === "super") {
            showToast("Super Scan is currently under active development and not yet available.", "info");
            return;
        }

        selectedProfile = profileKey;
        cardStandard.classList.toggle("selected", profileKey === "standard");
        cardDeep.classList.toggle("selected", profileKey === "deep");

        const limits = profileLimits[profileKey];
        if (limits) {
            summaryProfileName.textContent = limits.name;
            summaryMaxPages.textContent = limits.pages;
            summaryMaxDepth.textContent = limits.depth;
        }
    };

    async function loadUserSettings() {
        const token = localStorage.getItem("token");
        if (!token) return;
        try {
            const res = await fetch(`${API_BASE}/user/settings`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                const settings = await res.json();
                if (settings && settings.default_scan_depth) {
                    const depth = settings.default_scan_depth.toLowerCase();
                    if (depth === "deep") {
                        selectProfile("deep");
                    } else if (depth === "standard") {
                        selectProfile("standard");
                    }
                }
            }
        } catch (_) {}
    }
    loadUserSettings();

    // =========================================================================
    // SECURITY CHECKS SELECTION
    // =========================================================================

    function updateCheckCardsUI() {
        let selectedCount = 0;
        checkCards.forEach(card => {
            const mod = card.getAttribute("data-module");
            const isChecked = Boolean(modulesState[mod]);
            card.classList.toggle("checked", isChecked);
            const box = card.querySelector(".check-checkbox-custom");
            if (box) {
                box.textContent = isChecked ? "✓" : "";
            }
            if (isChecked) selectedCount++;
        });

        if (checksCountBadge) {
            checksCountBadge.textContent = `${selectedCount} selected`;
        }
        if (summaryChecksCount) {
            summaryChecksCount.textContent = `${selectedCount} of 12`;
        }

        refreshLaunchButtonState();
    }

    window.toggleCheckCard = function(modKey) {
        if (modKey in modulesState) {
            modulesState[modKey] = !modulesState[modKey];
            updateCheckCardsUI();
        }
    };

    window.selectAllChecks = function(enableAll) {
        for (const k in modulesState) {
            modulesState[k] = enableAll;
        }
        updateCheckCardsUI();
    };

    // Optional Auth Context Collapsible
    window.toggleAuthContextBox = function() {
        const box = document.getElementById("authContextContent");
        const icon = document.getElementById("authToggleIcon");
        if (box) {
            const isOpen = box.classList.toggle("open");
            if (icon) icon.textContent = isOpen ? "▲" : "▼";
        }
    };

    // =========================================================================
    // BUTTON STATE & STEP NAVIGATION
    // =========================================================================

    function refreshLaunchButtonState() {
        if (!launchBtn || !authCheckbox || !targetUrlInput) return;
        const res = validateURL(targetUrlInput.value);
        const hasChecks = Object.values(modulesState).some(Boolean);
        const isAuthorized = authCheckbox.checked;

        const canLaunch = res.valid && hasChecks && isAuthorized;
        launchBtn.disabled = !canLaunch || isSubmitting;

        const step1 = document.getElementById("stepIndicator1");
        const step2 = document.getElementById("stepIndicator2");
        const stepLine1 = document.getElementById("stepLine1");
        const stepLine2 = document.getElementById("stepLine2");

        if (res.valid) {
            step1.classList.add("completed");
            stepLine1.classList.add("active");
        } else {
            step1.classList.remove("completed");
            stepLine1.classList.remove("active");
        }

        if (hasChecks) {
            step2.classList.add("completed");
            stepLine2.classList.add("active");
        } else {
            step2.classList.remove("completed");
            stepLine2.classList.remove("active");
        }
    }

    if (authCheckbox) {
        authCheckbox.addEventListener("change", refreshLaunchButtonState);
    }

    window.navigateToStep = function(stepNum) {
        // If a scan is currently running, ignore step click or return to config
        if (currentActiveScanId && activeScanSection && activeScanSection.style.display !== "none") {
            return;
        }

        const secTarget = document.getElementById("sectionTarget");
        const secChecks = document.getElementById("sectionChecks");

        document.querySelectorAll(".step-item").forEach(s => s.classList.remove("active"));
        const activeItem = document.getElementById(`stepIndicator${stepNum}`);
        if (activeItem) activeItem.classList.add("active");

        if (stepNum === 1 && secTarget) {
            secTarget.scrollIntoView({ behavior: "smooth", block: "start" });
            targetUrlInput.focus();
        } else if (stepNum === 2 && secChecks) {
            secChecks.scrollIntoView({ behavior: "smooth", block: "start" });
        } else if (stepNum === 3) {
            openReviewModal();
        }
    };

    // =========================================================================
    // REVIEW MODAL (Step 3)
    // =========================================================================

    window.openReviewModal = function() {
        const valRes = validateURL(targetUrlInput.value);
        if (!valRes.valid) {
            showToast("Please provide a valid target URL first.", "error");
            targetUrlInput.focus();
            return;
        }

        const selectedKeys = Object.keys(modulesState).filter(k => modulesState[k]);
        if (selectedKeys.length === 0) {
            showToast("Select at least one security check module before review.", "error");
            return;
        }

        if (!authCheckbox.checked) {
            showToast("Confirm authorization by checking the Legal Authorization box.", "error");
            return;
        }

        // Populate Modal Fields
        modalTargetUrl.textContent = valRes.normalized;
        const limits = profileLimits[selectedProfile];
        modalProfileName.textContent = limits.name;
        modalProfileLimits.textContent = `Max Pages: ${limits.pages} · Max Crawl Depth: ${limits.depth}`;
        modalChecksNum.textContent = selectedKeys.length;

        modalSelectedTags.innerHTML = selectedKeys.map(k => `
            <span class="review-tag">${moduleLabels[k] || k}</span>
        `).join("");

        const authSelected = modulesState.auth || modulesState.access_control;
        const h1Key = document.getElementById("authHeader1Key")?.value.trim();
        const h1Val = document.getElementById("authHeader1Val")?.value.trim();
        const hasAuthContext = Boolean(h1Key && h1Val);

        if (authSelected && !hasAuthContext) {
            modalAuthWarning.style.display = "block";
        } else {
            modalAuthWarning.style.display = "none";
        }

        if (reviewModal) {
            reviewModal.style.display = "flex";
            reviewModal.classList.add("open");
        }
    };

    window.closeReviewModal = function() {
        if (reviewModal) {
            reviewModal.classList.remove("open");
            reviewModal.style.display = "none";
        }
    };

    if (reviewModal) {
        reviewModal.addEventListener("click", (e) => {
            if (e.target === reviewModal) {
                closeReviewModal();
            }
        });
    }

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" || e.key === "Esc") {
            closeReviewModal();
        }
    });

    window.onLaunchClicked = function() {
        openReviewModal();
    };

    // =========================================================================
    // SCAN EXECUTION & REAL-TIME TELEMETRY ENGINE
    // =========================================================================

    window.executeScanLaunch = async function() {
        if (isSubmitting) return;

        const rawTarget = (targetUrlInput ? targetUrlInput.value : "").trim();
        if (!rawTarget) {
            showToast("Target URL cannot be blank. Please enter a valid web URL.", "error");
            closeReviewModal();
            return;
        }

        const valRes = validateURL(rawTarget);
        if (!valRes.valid) {
            showToast("Invalid target URL format.", "error");
            closeReviewModal();
            return;
        }

        let authToken = localStorage.getItem("token");
        if (!authToken) {
            showToast("Session expired. Please log in again.", "error");
            window.location.href = "login.html";
            return;
        }

        // First verify backend connectivity to avoid generic "Failed to fetch"
        const backendReady = await checkBackendHealth(false);
        if (!backendReady) {
            showToast("Cannot connect to backend scanner at http://127.0.0.1:8000. Please start the server.", "error");
            closeReviewModal();
            return;
        }

        const headers = {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken}`
        };

        const selectedModulesPayload = {};
        for (const k in modulesState) {
            selectedModulesPayload[k] = Boolean(modulesState[k]);
        }

        // Build optional auth contexts strictly in memory
        let authContext1 = null;
        let authContext2 = null;

        const h1KeyEl = document.getElementById("authHeader1Key");
        const h1ValEl = document.getElementById("authHeader1Val");
        const h2KeyEl = document.getElementById("authHeader2Key");
        const h2ValEl = document.getElementById("authHeader2Val");

        const h1Key = h1KeyEl?.value.trim();
        const h1Val = h1ValEl?.value.trim();
        if (h1Key && h1Val) {
            authContext1 = { headers: { [h1Key]: h1Val } };
        }

        const h2Key = h2KeyEl?.value.trim();
        const h2Val = h2ValEl?.value.trim();
        if (h2Key && h2Val) {
            authContext2 = { headers: { [h2Key]: h2Val } };
        }

        // Ephemeral hygiene: Clear DOM input secret values immediately
        if (h1ValEl) h1ValEl.value = "";
        if (h2ValEl) h2ValEl.value = "";

        isSubmitting = true;
        modalLaunchBtn.disabled = true;
        modalLaunchBtn.innerHTML = `<span>⏳ Initiating Scan…</span>`;
        launchBtn.disabled = true;
        launchBtn.innerHTML = `<span>⏳ Initiating Scan…</span>`;

        try {
            // Step 1: Target Registration
            let targetRes;
            try {
                targetRes = await fetch(`${API_BASE}/targets`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({ url: valRes.normalized })
                });
            } catch (netErr) {
                throw new Error("Failed to communicate with scanner service at http://127.0.0.1:8000. Check server status.");
            }

            if (!targetRes.ok) {
                if (targetRes.status === 401) {
                    showToast("Authentication session expired. Redirecting to login…", "error");
                    setTimeout(() => window.location.href = "login.html", 1500);
                    return;
                }
                let errDetail = "Target registration failed.";
                try {
                    const eData = await targetRes.json();
                    if (eData.detail) errDetail = eData.detail;
                } catch (_) {}
                throw new Error(errDetail);
            }

            const targetData = await targetRes.json();
            const targetId = targetData.id;

            // Step 2: Create Scan with explicit module dispatch
            let scanRes;
            try {
                scanRes = await fetch(`${API_BASE}/scans`, {
                    method: "POST",
                    headers,
                    body: JSON.stringify({
                        target_id: targetId,
                        depth: selectedProfile,
                        modules: selectedModulesPayload,
                        authorized: true,
                        auth_context_1: authContext1,
                        auth_context_2: authContext2
                    })
                });
            } catch (netErr) {
                throw new Error("Connection failed while creating scan record.");
            }

            if (!scanRes.ok) {
                if (scanRes.status === 401) {
                    showToast("Authentication session expired. Please log in again.", "error");
                    setTimeout(() => window.location.href = "login.html", 1500);
                    return;
                }
                let errDetail = "Scan configuration failed.";
                try {
                    const eData = await scanRes.json();
                    if (eData.detail) errDetail = eData.detail;
                } catch (_) {}
                throw new Error(errDetail);
            }

            const scanData = await scanRes.json();
            const scanId = scanData.scan_id || scanData.id;

            // Step 3: Start Scan Task
            let startRes;
            try {
                startRes = await fetch(`${API_BASE}/scans/${scanId}/start`, {
                    method: "POST",
                    headers
                });
            } catch (netErr) {
                throw new Error("Connection failed while starting scan engine.");
            }

            if (!startRes.ok) {
                let errDetail = "Failed to launch scan engine.";
                try {
                    const eData = await startRes.json();
                    if (eData.detail) errDetail = eData.detail;
                } catch (_) {}
                throw new Error(errDetail);
            }

            // Close modal & redirect to canonical Live Scan page
            closeReviewModal();
            showToast("Security scan launched! Opening Live Telemetry…", "info");

            setTimeout(() => {
                window.location.href = `livescan.html?id=${encodeURIComponent(scanId)}&target=${encodeURIComponent(valRes.normalized)}`;
            }, 300);

        } catch (error) {
            console.error("[EthioSec Launch Error]:", error);
            showToast(error.message || "An error occurred while launching scan.", "error");
        } finally {
            isSubmitting = false;
            modalLaunchBtn.disabled = false;
            modalLaunchBtn.innerHTML = `<span>Launch Security Scan</span>`;
            launchBtn.disabled = false;
            launchBtn.innerHTML = `<span>Review & Launch →</span>`;
            refreshLaunchButtonState();
        }
    };

    // =========================================================================
    // ACTIVE TELEMETRY CONTROLLER
    // =========================================================================

    function startLiveScanMonitor(scanId, targetUrl, profileKey, requestedModules) {
        currentActiveScanId = scanId;
        scanStartEpoch = Date.now();

        // Switch page layout to active scanning telemetry view
        if (scanConfigGrid) scanConfigGrid.style.display = "none";
        if (activeScanSection) activeScanSection.style.display = "flex";

        // Update Stepper
        const step1 = document.getElementById("stepIndicator1");
        const step2 = document.getElementById("stepIndicator2");
        const step3 = document.getElementById("stepIndicator3");
        const stepLine1 = document.getElementById("stepLine1");
        const stepLine2 = document.getElementById("stepLine2");

        if (step1) step1.className = "step-item completed";
        if (step2) step2.className = "step-item completed";
        if (step3) step3.className = "step-item active";
        if (stepLine1) stepLine1.className = "step-divider-line active";
        if (stepLine2) stepLine2.className = "step-divider-line active";

        // Populate header fields
        if (liveScanId) liveScanId.textContent = scanId;
        if (liveTargetUrlText) liveTargetUrlText.textContent = targetUrl;
        if (liveTargetUrl) liveTargetUrl.href = targetUrl;

        const pLimits = profileLimits[profileKey] || profileLimits.standard;
        if (liveProfileBadge) {
            liveProfileBadge.textContent = `${pLimits.name} (Max ${pLimits.pages} pages · Depth ${pLimits.depth})`;
        }

        if (liveStartTime) {
            liveStartTime.textContent = new Date().toLocaleTimeString();
        }

        if (liveStatusPill && liveStatusText) {
            liveStatusPill.className = "live-status-pill running";
            liveStatusText.textContent = "RUNNING";
        }
        if (liveRingStatusLabel) liveRingStatusLabel.textContent = "RUNNING";

        if (liveCancelBtn) liveCancelBtn.style.display = "inline-flex";
        if (liveViewResultsBtn) {
            liveViewResultsBtn.hidden = true;
            liveViewResultsBtn.href = `results.html?id=${encodeURIComponent(scanId)}`;
        }

        // Render initial modules list
        renderModulesList(requestedModules, {}, "Queued");

        // Start elapsed timer
        if (timerIntervalId) clearInterval(timerIntervalId);
        timerIntervalId = setInterval(() => {
            if (liveElapsed && scanStartEpoch) {
                const secs = Math.floor((Date.now() - scanStartEpoch) / 1000);
                liveElapsed.textContent = formatElapsedTime(secs);
            }
        }, 1000);

        // Start polling
        if (pollIntervalId) clearInterval(pollIntervalId);
        pollActiveScan(scanId, requestedModules);
        pollIntervalId = setInterval(() => pollActiveScan(scanId, requestedModules), 1500);

        // Scroll to telemetry view
        activeScanSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function formatElapsedTime(seconds) {
        if (seconds < 60) return `${seconds}s`;
        const mins = Math.floor(seconds / 60);
        const remSecs = seconds % 60;
        return `${mins}m ${remSecs}s`;
    }

    function renderModulesList(requestedModules, completedChecks, currentStage) {
        if (!liveModulesStatusGrid) return;

        const req = requestedModules || modulesState;
        const comp = completedChecks || {};
        const stageLower = (currentStage || "").toLowerCase();

        let totalSelected = 0;
        let totalCompleted = 0;

        let html = "";
        for (const modKey in moduleLabels) {
            const isSelected = Boolean(req[modKey]);
            const isDone = Boolean(comp[modKey]);
            
            if (isSelected) totalSelected++;
            if (isSelected && isDone) totalCompleted++;

            let statusClass = "queued";
            let statusBadge = "QUEUED";

            if (!isSelected) {
                statusClass = "skipped";
                statusBadge = "SKIPPED";
            } else if (isDone) {
                statusClass = "completed";
                statusBadge = "✓ COMPLETED";
            } else if (
                stageLower.includes(modKey) || 
                (modKey === "headers" && stageLower.includes("header")) ||
                (modKey === "cookies" && stageLower.includes("cookie")) ||
                (modKey === "cors" && stageLower.includes("cors")) ||
                (modKey === "https" && stageLower.includes("https")) ||
                (modKey === "sqli" && stageLower.includes("sql")) ||
                (modKey === "xss" && stageLower.includes("xss")) ||
                (modKey === "auth" && stageLower.includes("auth")) ||
                (modKey === "access_control" && (stageLower.includes("access") || stageLower.includes("idor"))) ||
                (modKey === "exposed_files" && stageLower.includes("exposed")) ||
                (modKey === "http_methods" && stageLower.includes("methods")) ||
                (modKey === "info_disclosure" && stageLower.includes("info"))
            ) {
                statusClass = "running";
                statusBadge = "ANALYZING…";
            }

            html += `
                <div class="live-module-status-item ${statusClass}">
                    <div class="live-mod-name">
                        <span>${moduleIcons[modKey] || "🔍"}</span>
                        <span>${moduleLabels[modKey]}</span>
                    </div>
                    <span class="live-mod-badge ${statusClass}">${statusBadge}</span>
                </div>
            `;
        }

        liveModulesStatusGrid.innerHTML = html;

        if (liveChecksCountSummary) {
            liveChecksCountSummary.textContent = `${totalCompleted} of ${totalSelected} Completed`;
        }
    }

    async function pollActiveScan(scanId, requestedModules) {
        try {
            const authToken = localStorage.getItem("token");
            if (!authToken) return;

            const res = await fetch(`${API_BASE}/scans/${scanId}/status`, {
                headers: {
                    "Authorization": `Bearer ${authToken}`,
                    "Accept": "application/json"
                }
            });

            if (!res.ok) {
                if (res.status === 401) {
                    console.warn("[EthioSec Telemetry] Token expired during polling.");
                }
                return;
            }

            const data = await res.json();

            // Progress percentage
            const p = Math.max(0, Math.min(100, Number(data.progress || 0)));
            if (liveProgressPercent) liveProgressPercent.textContent = `${p}%`;
            if (liveRingFill) {
                const offset = RING_CIRCUMFERENCE - (p / 100) * RING_CIRCUMFERENCE;
                liveRingFill.style.strokeDashoffset = offset;
            }

            // Headline & stage descriptions
            if (liveStageHeadline && data.stage) {
                liveStageHeadline.textContent = data.stage;
            }
            if (liveStageDesc) {
                if (p < 20) {
                    liveStageDesc.textContent = "Target verified. Crawling site structure and cataloging attack surface.";
                } else if (p < 60) {
                    liveStageDesc.textContent = "Evaluating passive security policies, cookie flags, and transport headers.";
                } else if (p < 99) {
                    liveStageDesc.textContent = "Executing injection vectors, boundary checks, and active security probes.";
                } else {
                    liveStageDesc.textContent = "Consolidating observations, rating severity scores, and building report.";
                }
            }

            // Status Badge
            const statusUpper = (data.status || "RUNNING").toUpperCase();
            if (liveStatusText) liveStatusText.textContent = statusUpper;
            if (liveRingStatusLabel) liveRingStatusLabel.textContent = statusUpper;
            if (liveStatusPill) {
                liveStatusPill.className = `live-status-pill ${data.status.toLowerCase()}`;
            }

            // Update real module items
            const activeMods = data.modules || requestedModules || modulesState;
            const completedMods = data.completed_checks || {};
            renderModulesList(activeMods, completedMods, data.stage);

            // Update real incremental findings counters
            if (data.findings_count) {
                const fc = data.findings_count;
                if (liveCountHigh) liveCountHigh.textContent = (fc.critical || 0) + (fc.high || 0);
                if (liveCountMedium) liveCountMedium.textContent = fc.medium || 0;
                if (liveCountLow) liveCountLow.textContent = fc.low || 0;
                if (liveCountPassed) liveCountPassed.textContent = fc.not_detected || 0;
                if (liveCountTotal) liveCountTotal.textContent = fc.total || 0;
            }

            // Scan Completion or Failure
            if (data.status === "completed" || data.status === "failed" || data.status === "cancelled") {
                clearInterval(pollIntervalId);
                clearInterval(timerIntervalId);
                pollIntervalId = null;
                timerIntervalId = null;

                if (liveCancelBtn) liveCancelBtn.style.display = "none";
                if (liveViewResultsBtn) {
                    liveViewResultsBtn.hidden = false;
                    liveViewResultsBtn.href = `results.html?id=${encodeURIComponent(scanId)}`;
                }

                if (data.status === "completed") {
                    if (liveProgressPercent) liveProgressPercent.textContent = "100%";
                    if (liveRingFill) liveRingFill.style.strokeDashoffset = 0;
                    if (liveStageHeadline) liveStageHeadline.textContent = "Security Assessment Completed Successfully";
                    if (liveStageDesc) liveStageDesc.textContent = "All selected checks have finalized. Real findings are safely persisted.";
                    showToast("Security scan completed! Results ready.", "info");
                } else if (data.status === "failed") {
                    if (liveStageHeadline) liveStageHeadline.textContent = "Assessment Halted or Warning Reported";
                    if (liveStageDesc) liveStageDesc.textContent = "Scanner encountered a target constraint or security halt.";
                    showToast("Scan finished with warnings or error state.", "error");
                } else if (data.status === "cancelled") {
                    if (liveStageHeadline) liveStageHeadline.textContent = "Scan Assessment Cancelled by User";
                    if (liveStageDesc) liveStageDesc.textContent = "All active check workers have been terminated.";
                    showToast("Security scan cancelled.", "info");
                }
            }

        } catch (pollErr) {
            console.warn("[EthioSec] Status polling transient error:", pollErr);
        }
    }

    window.cancelActiveScan = async function() {
        if (!currentActiveScanId) return;

        const confirmCancel = confirm("Are you sure you want to cancel this running security assessment?");
        if (!confirmCancel) return;

        const authToken = localStorage.getItem("token");
        if (liveCancelBtn) {
            liveCancelBtn.disabled = true;
            liveCancelBtn.textContent = "Cancelling…";
        }

        try {
            await fetch(`${API_BASE}/scans/${currentActiveScanId}/cancel`, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${authToken}`
                }
            });
            showToast("Scan cancelled.", "info");
        } catch (err) {
            console.error("Failed to cancel scan on server:", err);
        }

        if (pollIntervalId) clearInterval(pollIntervalId);
        if (timerIntervalId) clearInterval(timerIntervalId);

        if (liveStatusPill) liveStatusPill.className = "live-status-pill cancelled";
        if (liveStatusText) liveStatusText.textContent = "CANCELLED";
        if (liveRingStatusLabel) liveRingStatusLabel.textContent = "CANCELLED";
        if (liveCancelBtn) liveCancelBtn.style.display = "none";
        if (liveStageHeadline) liveStageHeadline.textContent = "Scan Assessment Cancelled by User";
    };

    window.returnToScanConfig = function() {
        if (pollIntervalId) clearInterval(pollIntervalId);
        if (timerIntervalId) clearInterval(timerIntervalId);
        pollIntervalId = null;
        timerIntervalId = null;
        currentActiveScanId = null;

        // Clear query param
        try {
            const cleanUrl = window.location.pathname;
            window.history.replaceState({}, "", cleanUrl);
        } catch (_) {}

        if (activeScanSection) activeScanSection.style.display = "none";
        if (scanConfigGrid) scanConfigGrid.style.display = "grid";

        // Reset Stepper
        const step1 = document.getElementById("stepIndicator1");
        const step2 = document.getElementById("stepIndicator2");
        const step3 = document.getElementById("stepIndicator3");
        if (step1) step1.className = "step-item active";
        if (step2) step2.className = "step-item";
        if (step3) step3.className = "step-item";

        refreshLaunchButtonState();
    };

    window.copyLiveScanId = function() {
        if (!currentActiveScanId) return;
        navigator.clipboard.writeText(currentActiveScanId).then(() => {
            showToast("Scan ID copied to clipboard!", "info");
        }).catch(() => {
            showToast(currentActiveScanId, "info");
        });
    };

    // =========================================================================
    // INITIALIZATION & URL QUERY PARAMS
    // =========================================================================

    // Check query params on load (e.g. ?scan_id=... to resume monitor or ?target=... to pre-fill)
    const urlParams = new URLSearchParams(window.location.search);
    const existingScanId = urlParams.get("scan_id") || urlParams.get("id");
    const incomingUrl = urlParams.get("url") || urlParams.get("target") || urlParams.get("site");

    // CHANGE 1: Target field must start blank whenever a user opens a fresh New Scan page.
    // Do NOT populate with user email, account details, previous targets, or email query strings.
    // Only accept an incoming URL if it is a valid non-email web URL (explicit workflow)
    if (targetUrlInput) {
        if (incomingUrl && !incomingUrl.includes("@") && !incomingUrl.toLowerCase().startsWith("mailto:") && /^https?:\/\//i.test(incomingUrl.trim())) {
            targetUrlInput.value = incomingUrl.trim();
        } else {
            targetUrlInput.value = "";
        }
    }

    // Initialize UI
    updateCheckCardsUI();
    onUrlInputChanged();

    // Browser Autofill Guard: Ensure target field remains completely blank if browser/password manager attempts to autofill credentials or email
    function purgeAutofillEmail() {
        if (!targetUrlInput) return;
        const val = (targetUrlInput.value || "").trim();
        const userEmail = (localStorage.getItem("userEmail") || "").toLowerCase().trim();
        if (
            val.includes("@") ||
            val.toLowerCase().startsWith("mailto:") ||
            (userEmail && (val.toLowerCase() === userEmail || val.toLowerCase() === "https://" + userEmail || val.toLowerCase() === "http://" + userEmail))
        ) {
            targetUrlInput.value = "";
            onUrlInputChanged();
        }
    }

    // Run purge immediately and over multiple browser lifecycle moments
    purgeAutofillEmail();
    [20, 60, 120, 250, 500, 900, 1500, 2500].forEach(delay => setTimeout(purgeAutofillEmail, delay));
    window.addEventListener("pageshow", purgeAutofillEmail);
    window.addEventListener("focus", purgeAutofillEmail);
    if (targetUrlInput) {
        targetUrlInput.addEventListener("focus", purgeAutofillEmail);
        targetUrlInput.addEventListener("animationstart", (e) => {
            if (e.animationName && e.animationName.toLowerCase().includes("autofill")) {
                purgeAutofillEmail();
            }
        });
    }

    // Check backend health silently on page load
    checkBackendHealth(false);

    // If an existing scan ID is provided in query params, immediately resume monitoring
    if (existingScanId) {
        startLiveScanMonitor(existingScanId, (incomingUrl && !incomingUrl.includes("@") ? incomingUrl : "Target Web Application"), selectedProfile, modulesState);
    }
});
