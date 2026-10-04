if (!localStorage.getItem('token')) {
    window.location.href = 'login.html';
}

const STORE_KEY = "ethioSettings";

const DEFAULTS = {
    theme: "dark",
    accent: "#cc2f0c",
    animations: true,
    compact: false,
    language: "English",
    timezone: "EAT",
    twoFactor: true,
    loginAlerts: true,
    defSqli: true,
    defXss: true,
    defHeaders: true,
    defSsl: true,
    defDepth: "standard",
    notifCritical: true,
    notifHigh: true,
    notifSecurity: true,
    notifComplete: true,
    notifDigest: true,
    notifQuiet: false
};

let settings = { ...DEFAULTS };
let dirty = false;

function $(id) { return document.getElementById(id); }

function safeParse(value) {
    try { return JSON.parse(value); } catch { return null; }
}

function showToast(title, message, type = "success") {
    const toast = $("toast");
    if (!toast) return;

    const icon = toast.querySelector(".toast-icon");
    const titleEl = $("toastTitle") || toast.querySelector("strong");
    const msgEl = $("toastMsg") || toast.querySelector("small");

    if (titleEl) titleEl.textContent = title;
    if (msgEl) msgEl.textContent = message;

    if (icon) {
        if (type === "error") {
            icon.textContent = "!";
            icon.style.color = "var(--danger, #ff6b6b)";
            icon.style.background = "rgba(255, 107, 107, 0.12)";
        } else {
            icon.textContent = "✓";
            icon.style.color = "var(--accent, #1bb369)";
            icon.style.background = "rgba(27, 179, 105, 0.12)";
        }
    }

    toast.classList.add("show");
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => toast.classList.remove("show"), 2800);
}

async function loadProfile() {
    const token = localStorage.getItem("token");
    if (!token) return;

    try {
        const res = await fetch("http://127.0.0.1:8000/api/user/profile", {
            headers: { "Authorization": `Bearer ${token}` }
        });
        if (res.ok) {
            const user = await res.json();
            fillProfile(user);
            return;
        }
    } catch (e) {
        console.error("Failed to load profile from backend", e);
    }

    const email = localStorage.getItem("userEmail") || "admin@ethiosec.local";
    fillProfile({ full_name: "Security Administrator", email: email, role: "Security Administrator" });
}

function fillProfile(user) {
    const name = user.full_name || "Security Administrator";

    if ($("fullName")) $("fullName").value = name;
    if ($("email")) $("email").value = user.email || "";
    if ($("username")) $("username").value = (user.email || "").split("@")[0];
    if ($("role") && user.role) $("role").value = user.role;

    refreshProfilePreview();
}

function refreshProfilePreview() {
    const fullNameInput = $("fullName");
    const emailInput = $("email");

    const name = (fullNameInput ? fullNameInput.value.trim() : "") || "Security Administrator";
    const email = (emailInput ? emailInput.value.trim() : "") || "admin@ethiosec.local";
    const initials = name.split(/\s+/).filter(Boolean).map(n => n[0]).join("").toUpperCase().slice(0, 2);

    if ($("previewName")) $("previewName").textContent = name;
    if ($("previewEmail")) $("previewEmail").textContent = email;
    if ($("avatarLetter")) $("avatarLetter").textContent = initials || "S";

    const sidebarName = $("userName");
    const sidebarEmail = $("userEmail");
    const sidebarInitial = $("userInitial");
    if (sidebarName) sidebarName.textContent = name;
    if (sidebarEmail) sidebarEmail.textContent = email;
    if (sidebarInitial) sidebarInitial.textContent = initials || "S";
}

function setupTabs() {
    const tabs = document.querySelectorAll(".tab-btn");
    const sections = document.querySelectorAll(".settings-section");

    function activate(id) {
        const tab = document.querySelector(`.tab-btn[data-section="${id}"]`);
        const section = $(id);
        if (!tab || !section) return;

        tabs.forEach(t => t.classList.remove("active"));
        sections.forEach(s => s.classList.remove("active"));

        tab.classList.add("active");
        section.classList.add("active");
        history.replaceState(null, "", "#" + id);
    }

    tabs.forEach(tab => tab.addEventListener("click", () => activate(tab.dataset.section)));

    const hash = location.hash.replace("#", "");
    if (hash) activate(hash);
}

function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);

    if ($("themeIcon")) $("themeIcon").textContent = theme === "light" ? "☀️" : "🌙";
    if ($("themeToggle")) {
        $("themeToggle").setAttribute("aria-label", theme === "light" ? "Switch to dark mode" : "Switch to light mode");
    }

    document.querySelectorAll(".theme-option").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.themeChoice === theme);
    });
}

function applyAccent(hex) {
    document.documentElement.style.setProperty("--primary", hex);
    document.documentElement.style.setProperty("--primary-light", lighten(hex, 28));
    document.documentElement.style.setProperty("--primary-dark", lighten(hex, -28));

    document.querySelectorAll(".swatch").forEach(sw => {
        sw.classList.toggle("active", sw.dataset.accent === hex);
    });
}

function lighten(hex, amount) {
    const cleanHex = hex.replace("#", "");
    const num = parseInt(cleanHex, 16);
    const clamp = v => Math.max(0, Math.min(255, v));

    const r = clamp((num >> 16) + amount);
    const g = clamp(((num >> 8) & 0xff) + amount);
    const b = clamp((num & 0xff) + amount);

    return "#" + ((r << 16) | (g << 8) | b).toString(16).padStart(6, "0");
}

function applyPreferences() {
    applyTheme(settings.theme);
    applyAccent(settings.accent);
    document.documentElement.setAttribute("data-animations", String(settings.animations));
    document.documentElement.setAttribute("data-compact", String(settings.compact));
}

const CONTROL_MAP = {
    twoFactor: "twoFactor",
    loginAlerts: "loginAlerts",
    defSqli: "defSqli",
    defXss: "defXss",
    defHeaders: "defHeaders",
    defSsl: "defSsl",
    animations: "animations",
    compactMode: "compact",
    notifCritical: "notifCritical",
    notifHigh: "notifHigh",
    notifSecurity: "notifSecurity",
    notifComplete: "notifComplete",
    notifDigest: "notifDigest",
    notifQuiet: "notifQuiet"
};

async function loadSettings() {
    let localSet = safeParse(localStorage.getItem(STORE_KEY)) || {};
    settings = { ...DEFAULTS, ...localSet };

    const token = localStorage.getItem('token');
    if (token) {
        try {
            const res = await fetch('http://127.0.0.1:8000/api/user/settings', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const apiSet = await res.json();
                settings.defDepth = apiSet.default_scan_depth || settings.defDepth;
                settings.notifComplete = apiSet.notif_scan_completed !== null ? apiSet.notif_scan_completed : settings.notifComplete;
                settings.notifSecurity = apiSet.notif_security_findings !== null ? apiSet.notif_security_findings : settings.notifSecurity;
            }
        } catch (e) {
            console.error("API Settings Load Error", e);
        }
    }
    reflectSettings();
}

function reflectSettings() {
    Object.entries(CONTROL_MAP).forEach(([elementId, key]) => {
        const el = $(elementId);
        if (el) el.checked = Boolean(settings[key]);
    });

    if ($("defDepth")) $("defDepth").value = settings.defDepth || "standard";
    if ($("language")) $("language").value = settings.language || "English";
    if ($("timezone")) $("timezone").value = settings.timezone || "EAT";

    applyPreferences();
}

function collectSettings() {
    return {
        theme: document.documentElement.getAttribute("data-theme") || "dark",
        accent: document.querySelector(".swatch.active")?.dataset.accent || DEFAULTS.accent,
        animations: $("animations") ? $("animations").checked : true,
        compact: $("compactMode") ? $("compactMode").checked : false,
        language: $("language") ? $("language").value : "English",
        timezone: $("timezone") ? $("timezone").value : "EAT",
        twoFactor: $("twoFactor") ? $("twoFactor").checked : true,
        loginAlerts: $("loginAlerts") ? $("loginAlerts").checked : true,
        defSqli: $("defSqli") ? $("defSqli").checked : true,
        defXss: $("defXss") ? $("defXss").checked : true,
        defHeaders: $("defHeaders") ? $("defHeaders").checked : true,
        defSsl: $("defSsl") ? $("defSsl").checked : true,
        defDepth: $("defDepth") ? $("defDepth").value : "standard",
        notifCritical: $("notifCritical") ? $("notifCritical").checked : true,
        notifHigh: $("notifHigh") ? $("notifHigh").checked : true,
        notifSecurity: $("notifSecurity") ? $("notifSecurity").checked : true,
        notifComplete: $("notifComplete") ? $("notifComplete").checked : true,
        notifDigest: $("notifDigest") ? $("notifDigest").checked : true,
        notifQuiet: $("notifQuiet") ? $("notifQuiet").checked : false
    };
}

function markDirty() {
    if (dirty) return;
    dirty = true;
    if ($("saveStatus")) {
        $("saveStatus").innerHTML =
            '<span class="save-status-dot" style="background: var(--warning, #ffa500)"></span> Unsaved changes';
    }
}

function markSaved() {
    dirty = false;
    if ($("saveStatus")) {
        $("saveStatus").innerHTML = '<span class="save-status-dot"></span> All changes saved';
    }
}

async function saveSettings() {
    const btn = $("saveChanges");
    const name = $("fullName") ? $("fullName").value.trim() : "";
    const email = $("email") ? $("email").value.trim() : "";

    if (!name) {
        showToast("Name is required", "Enter your full name", "error");
        return $("fullName")?.focus();
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showToast("Check email address", "Please provide a valid email format", "error");
        return $("email")?.focus();
    }

    const original = btn ? btn.innerHTML : "Save changes";
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = "⏳ Saving…";
    }

    try {
        const token = localStorage.getItem('token');
        if (token) {
            // Update Profile on backend
            await fetch('http://127.0.0.1:8000/api/user/profile', {
                method: 'PUT',
                headers: { 
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    full_name: name
                })
            });

            // Update Settings on backend
            settings = collectSettings();
            localStorage.setItem(STORE_KEY, JSON.stringify(settings));

            await fetch('http://127.0.0.1:8000/api/user/settings', {
                method: 'PUT',
                headers: { 
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    default_scan_depth: settings.defDepth,
                    notif_scan_completed: settings.notifComplete,
                    notif_security_findings: settings.notifSecurity
                })
            });
        }

        markSaved();
        refreshProfilePreview();
        showToast("Settings saved", "Your preferences have been saved to your account.");

    } catch (err) {
        showToast("Could not save", err.message || "Unknown error", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = original;
        }
    }
}

function updateStrength(password) {
    const bar = $("strengthBar");
    const text = $("strengthText");
    if (!bar || !text) return;

    const rules = {
        length: password.length >= 8,
        case: /[a-z]/.test(password) && /[A-Z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password)
    };

    document.querySelectorAll("#strengthRules li").forEach(li => {
        li.classList.toggle("met", Boolean(rules[li.dataset.rule]));
    });

    const score = Object.values(rules).filter(Boolean).length;

    if (!password) {
        bar.style.width = "0%";
        text.textContent = "Not checked";
        text.style.color = "var(--text-muted, #b0a9a6)";
        return;
    }

    const levels = [
        { width: "25%", label: "Weak", color: "var(--danger, #ff6b6b)" },
        { width: "50%", label: "Fair", color: "var(--warning, #ffa500)" },
        { width: "75%", label: "Good", color: "var(--primary-light, #ff4b20)" },
        { width: "100%", label: "Strong", color: "var(--accent, #1bb369)" }
    ];

    const level = levels[Math.max(0, score - 1)];
    bar.style.width = level.width;
    bar.style.background = level.color;
    text.textContent = level.label;
    text.style.color = level.color;
}

function checkPasswordMatch() {
    const field = $("confirmPassword");
    const newField = $("newPassword");
    if (!field || !newField) return;

    if (!field.value) {
        field.style.borderColor = "";
        return;
    }
    field.style.borderColor = field.value === newField.value ? "var(--accent, #1bb369)" : "var(--danger, #ff6b6b)";
}

function setupControls() {
    ["fullName", "email"].forEach(id => {
        if ($(id)) $(id).addEventListener("input", () => { refreshProfilePreview(); markDirty(); });
    });

    if ($("username")) $("username").addEventListener("input", markDirty);

    document.querySelectorAll('.switch input[type="checkbox"]').forEach(input => {
        input.addEventListener("change", markDirty);
    });

    document.querySelectorAll("select").forEach(select => select.addEventListener("change", markDirty));

    if ($("animations")) {
        $("animations").addEventListener("change", e => {
            document.documentElement.setAttribute("data-animations", String(e.target.checked));
        });
    }

    if ($("compactMode")) {
        $("compactMode").addEventListener("change", e => {
            document.documentElement.setAttribute("data-compact", String(e.target.checked));
        });
    }

    if ($("themeToggle")) {
        $("themeToggle").addEventListener("click", () => {
            const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
            applyTheme(next);
            markDirty();
        });
    }

    document.querySelectorAll(".theme-option").forEach(btn => {
        btn.addEventListener("click", () => { applyTheme(btn.dataset.themeChoice); markDirty(); });
    });

    document.querySelectorAll(".swatch").forEach(sw => {
        sw.addEventListener("click", () => { applyAccent(sw.dataset.accent); markDirty(); });
    });

    if ($("newPassword")) {
        $("newPassword").addEventListener("input", e => {
            updateStrength(e.target.value);
            checkPasswordMatch();
            markDirty();
        });
    }

    if ($("confirmPassword")) $("confirmPassword").addEventListener("input", checkPasswordMatch);

    if ($("resetDefaults")) {
        $("resetDefaults").addEventListener("click", () => {
            if (!confirm("Reset all preferences to their defaults?")) return;

            settings = { ...DEFAULTS };
            localStorage.setItem(STORE_KEY, JSON.stringify(settings));
            reflectSettings();
            markSaved();
            showToast("Settings reset", "Default configurations restored.");
        });
    }

    if ($("saveChanges")) $("saveChanges").addEventListener("click", saveSettings);

    document.addEventListener("keydown", e => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
            e.preventDefault();
            saveSettings();
        }
    });
}

document.addEventListener("DOMContentLoaded", () => {
    setupTabs();
    loadSettings();
    loadProfile();
    setupControls();
    updateStrength("");
    markSaved();
});
