

const STORE_KEY = "ethioSettings";
const USER_KEY = "ethio_user";

const DEFAULTS = {
    theme: "dark",
    accent: "#cc2f0c",
    animations: true,
    compact: false,
    language: "English",
    timezone: "EAT",
    twoFactor: true,
    loginAlerts: true,
    defHeaders: true,
    defSsl: true,
    defDns: true,
    defMeta: true,
    defDepth: "standard",
    notifCritical: true,
    notifHigh: true,
    notifSecurity: true,
    notifComplete: false,
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


function getStoredUser() {
    const raw = localStorage.getItem(USER_KEY);
    const parsed = safeParse(raw) || {};
    const email = localStorage.getItem("userEmail") || parsed.email || "analyst@ethiosec.local";
    const name = parsed.full_name || email.split("@")[0];

    return {
        full_name: name,
        email: email,
        username: parsed.username || name.toLowerCase().replace(/\s+/g, ""),
        role: parsed.role || "Security Administrator"
    };
}

function loadProfile() {
    const user = getStoredUser();
    fillProfile(user);
}

function fillProfile(user) {
    const name = user.full_name || "Security Analyst";

    if ($("fullName")) $("fullName").value = name;
    if ($("email")) $("email").value = user.email || "";
    if ($("username")) $("username").value = user.username || name.toLowerCase().replace(/\s+/g, "");
    if ($("role") && user.role) $("role").value = user.role;

    refreshProfilePreview();
}

function refreshProfilePreview() {
    const fullNameInput = $("fullName");
    const emailInput = $("email");

    const name = (fullNameInput ? fullNameInput.value.trim() : "") || "Security Analyst";
    const email = (emailInput ? emailInput.value.trim() : "") || "analyst@ethiosec.local";
    const initials = name.split(/\s+/).filter(Boolean).map(n => n[0]).join("").toUpperCase().slice(0, 2);

    if ($("previewName")) $("previewName").textContent = name;
    if ($("previewEmail")) $("previewEmail").textContent = email;
    if ($("avatarLetter")) $("avatarLetter").textContent = initials || "A";

    const sidebarName = $("userName");
    const sidebarEmail = $("userEmail");
    const sidebarInitial = $("userInitial");
    if (sidebarName) sidebarName.textContent = name;
    if (sidebarEmail) sidebarEmail.textContent = email;
    if (sidebarInitial) sidebarInitial.textContent = initials || "A";
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
    defHeaders: "defHeaders",
    defSsl: "defSsl",
    defDns: "defDns",
    defMeta: "defMeta",
    animations: "animations",
    compactMode: "compact",
    notifCritical: "notifCritical",
    notifHigh: "notifHigh",
    notifSecurity: "notifSecurity",
    notifComplete: "notifComplete",
    notifDigest: "notifDigest",
    notifQuiet: "notifQuiet"
};

function loadSettings() {
    settings = { ...DEFAULTS, ...(safeParse(localStorage.getItem(STORE_KEY)) || {}) };
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
        defHeaders: $("defHeaders") ? $("defHeaders").checked : true,
        defSsl: $("defSsl") ? $("defSsl").checked : true,
        defDns: $("defDns") ? $("defDns").checked : true,
        defMeta: $("defMeta") ? $("defMeta").checked : true,
        defDepth: $("defDepth") ? $("defDepth").value : "standard",
        notifCritical: $("notifCritical") ? $("notifCritical").checked : true,
        notifHigh: $("notifHigh") ? $("notifHigh").checked : true,
        notifSecurity: $("notifSecurity") ? $("notifSecurity").checked : true,
        notifComplete: $("notifComplete") ? $("notifComplete").checked : false,
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
    const newPass = $("newPassword") ? $("newPassword").value : "";
    const confirmPass = $("confirmPassword") ? $("confirmPassword").value : "";

    const name = $("fullName") ? $("fullName").value.trim() : "";
    const email = $("email") ? $("email").value.trim() : "";

    if (!name) {
        showToast("Name is required", "Enter your full name", "error");
        return $("fullName")?.focus();
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showToast("Check the email address", "That doesn't look valid", "error");
        return $("email")?.focus();
    }

    if (newPass || confirmPass) {
        if (!$("currentPassword") \vert{}\vert{} !$("currentPassword").value) {
            showToast("Current password needed", "Enter it to change your password", "error");
            return $("currentPassword")?.focus();
        }
        if (newPass.length < 8) {
            showToast("Password too short", "Use at least 8 characters", "error");
            return $("newPassword")?.focus();
        }
        if (newPass !== confirmPass) {
            showToast("Passwords don't match", "Check both fields", "error");
            return $("confirmPassword")?.focus();
        }
    }

    const original = btn ? btn.innerHTML : "Save changes";
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = "⏳ Saving…";
    }

    try {
        const updatedUser = {
            full_name: name,
            email: email,
            username: ($("username") ? $("username").value.trim() : "") || name.toLowerCase().replace(/\s+/g, ""),
            role: $("role") ? $("role").value : "Security Administrator"
        };
        localStorage.setItem(USER_KEY, JSON.stringify(updatedUser));
        localStorage.setItem("userEmail", email);

        if (newPass) {
            ["currentPassword", "newPassword", "confirmPassword"].forEach(id => { 
                if ($(id))$(id).value = ""; 
            });
            updateStrength("");
        }

        settings = collectSettings();
        localStorage.setItem(STORE_KEY, JSON.stringify(settings));

        markSaved();
        refreshProfilePreview();
        showToast("Settings saved", "Your changes are stored on your account");

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
        if ($(id))$(id).addEventListener("input", () => { refreshProfilePreview(); markDirty(); });
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

    document.querySelectorAll(".password-toggle").forEach(btn => {
        btn.addEventListener("click", () => {
            const input = btn.parentElement.querySelector("input");
            if (!input) return;
            const hidden = input.type === "password";
            input.type = hidden ? "text" : "password";
            btn.textContent = hidden ? "🙈" : "👁";
        });
    });

    if ($("newPassword")) {
        $("newPassword").addEventListener("input", e => {
            updateStrength(e.target.value);
            checkPasswordMatch();
            markDirty();
        });
    }

    if ($("confirmPassword")) $("confirmPassword").addEventListener("input", checkPasswordMatch);

    if ($("deleteAccount")) {
        $("deleteAccount").addEventListener("click", () => {
            if (!confirm("Reset and clear all saved settings, custom profile data, and scans?")) return;

            localStorage.removeItem(STORE_KEY);
            localStorage.removeItem(USER_KEY);
            localStorage.removeItem("isLoggedIn");
            localStorage.removeItem("ethio_mock_db");

            window.location.href = "login.html";
        });
    }

    if ($("resetDefaults")) {
        $("resetDefaults").addEventListener("click", () => {
            if (!confirm("Reset all settings to their defaults?")) return;

            settings = { ...DEFAULTS };
            localStorage.setItem(STORE_KEY, JSON.stringify(settings));
            reflectSettings();
            markSaved();
            showToast("Settings reset", "Everything is back to defaults");
        });
    }

    if ($("saveChanges")) $("saveChanges").addEventListener("click", saveSettings);

    document.addEventListener("keydown", e => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
            e.preventDefault();
            saveSettings();
        }
        if (e.key === "Escape" && $("toast")) $("toast").classList.remove("show");
    });

    window.addEventListener("beforeunload", e => {
        if (!dirty) return;
        e.preventDefault();
        e.returnValue = "";
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