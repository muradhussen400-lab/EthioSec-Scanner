/**
 * ETHIOSECSCAN — ENTERPRISE SETTINGS CONTROLLER (settingsjava.js)
 * Real backend profile, security, and preferences synchronization.
 * Supports: Profile, Security, Scan Defaults, Preferences, and Notifications.
 */

(function () {
    "use strict";

    const API_BASE = "http://127.0.0.1:8000/api";
    const token = localStorage.getItem("token");

    if (!token) {
        window.location.href = "login.html";
        return;
    }

    // Helper: DOM query
    function $(id) {
        return document.getElementById(id);
    }

    // Toast notification
    function showToast(title, message, isError = false) {
        const toast = $("toast");
        const titleEl = $("toastTitle");
        const msgEl = $("toastMsg");
        const iconEl = toast ? toast.querySelector(".toast-icon") : null;

        if (!toast) return;

        if (titleEl) titleEl.textContent = title;
        if (msgEl) msgEl.textContent = message;

        if (iconEl) {
            if (isError) {
                iconEl.textContent = "✕";
                iconEl.style.color = "var(--danger, #EF4444)";
                iconEl.style.background = "var(--danger-subtle, rgba(239, 68, 68, 0.12))";
                iconEl.style.borderColor = "rgba(239, 68, 68, 0.3)";
            } else {
                iconEl.textContent = "✓";
                iconEl.style.color = "var(--accent-green, #10B981)";
                iconEl.style.background = "var(--accent-green-subtle, rgba(16, 185, 129, 0.12))";
                iconEl.style.borderColor = "rgba(16, 185, 129, 0.3)";
            }
        }

        toast.classList.add("show");
        clearTimeout(showToast._timer);
        showToast._timer = setTimeout(() => {
            toast.classList.remove("show");
        }, 3600);
    }

    // Helper: Compute clean initials
    function computeInitials(name) {
        if (!name) return "U";
        const parts = name.trim().split(/\s+/).filter(Boolean);
        if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
        return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }

    // Helper: Format ISO date string
    function formatDate(isoStr) {
        if (!isoStr) return "Recent";
        try {
            const d = new Date(isoStr);
            return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
        } catch (_) {
            return isoStr;
        }
    }

    // Eye Icons for Password Fields (SVG only, no emoji)
    const EYE_OPEN_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
    const EYE_SLASHED_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;

    // Toggle password field visibility with clean SVG icons
    window.togglePassVisibility = function (inputId, btnEl) {
        const input = $(inputId);
        if (!input) return;

        const isPassword = input.type === "password";
        input.type = isPassword ? "text" : "password";

        if (btnEl) {
            btnEl.innerHTML = isPassword ? EYE_SLASHED_SVG : EYE_OPEN_SVG;
            btnEl.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
        }
    };

    // =========================================================================
    // 1. TAB CONTROLLER (5 Supported Sections)
    // =========================================================================
    function setupTabs() {
        const tabs = document.querySelectorAll(".tab-btn");
        const sections = document.querySelectorAll(".settings-section");

        function activateTab(sectionId) {
            let found = false;
            tabs.forEach(tab => {
                const match = tab.dataset.section === sectionId;
                tab.classList.toggle("active", match);
                tab.setAttribute("aria-selected", match ? "true" : "false");
                if (match) found = true;
            });

            sections.forEach(sec => {
                sec.classList.toggle("active", sec.id === sectionId);
            });

            if (found && window.history.replaceState) {
                window.history.replaceState(null, "", "#" + sectionId);
            }
        }

        tabs.forEach(tab => {
            tab.addEventListener("click", () => {
                activateTab(tab.dataset.section);
            });

            // Keyboard accessibility
            tab.addEventListener("keydown", (e) => {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    activateTab(tab.dataset.section);
                }
            });
        });

        // Activate tab from URL hash on load
        const initialHash = window.location.hash.replace("#", "").trim();
        if (initialHash && $(initialHash)) {
            activateTab(initialHash);
        }

        // Listen for dynamic hash changes (e.g. from top-right user menu Profile link)
        window.addEventListener("hashchange", () => {
            const hash = window.location.hash.replace("#", "").trim();
            if (hash && $(hash)) {
                activateTab(hash);
            }
        });
    }

    // =========================================================================
    // 2. REAL PROFILE MANAGEMENT (GET & PUT /api/user/profile)
    // =========================================================================
    async function loadProfile() {
        try {
            const res = await fetch(`${API_BASE}/user/profile`, {
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Accept": "application/json"
                }
            });

            if (res.status === 401 || res.status === 403) {
                localStorage.removeItem("token");
                window.location.href = "login.html";
                return;
            }

            if (res.ok) {
                const user = await res.json();
                populateProfileUI(user);
                return;
            }
        } catch (err) {
            console.warn("[EthioSec Settings] Could not load profile:", err);
        }

        // Fallback to cached identity if offline
        const cachedName = localStorage.getItem("userName") || "Security Analyst";
        const cachedEmail = localStorage.getItem("userEmail") || "";
        populateProfileUI({
            full_name: cachedName,
            email: cachedEmail,
            role: "Security Administrator",
            is_verified: true
        });
    }

    function populateProfileUI(user) {
        const displayName = (user.full_name || "").trim() || (user.email ? user.email.split("@")[0] : "User");
        const initials = computeInitials(displayName);

        // Previews
        if ($("previewName")) $("previewName").textContent = displayName;
        if ($("previewEmail")) $("previewEmail").textContent = user.email || "";
        if ($("previewRole")) $("previewRole").textContent = user.role ? `${user.role} • Administrator` : "Security Analyst • Administrator";
        if ($("avatarLetter")) $("avatarLetter").textContent = initials;
        if ($("avatarLetterSide")) $("avatarLetterSide").textContent = initials;
        if ($("quickInfoRole")) $("quickInfoRole").textContent = user.role || "Administrator";

        // Form Fields
        const formattedUserId = user.id ? (String(user.id).startsWith("usr_") ? user.id : `usr_${String(user.id).slice(0, 12)}`) : "—";
        const formattedMemberSince = user.created_at ? formatDate(user.created_at) : "—";

        if ($("fullName")) $("fullName").value = user.full_name || displayName;
        if ($("website")) $("website").value = user.website || "";
        if ($("email")) $("email").value = user.email || "";
        if ($("userId")) $("userId").value = formattedUserId;
        if ($("memberSince")) $("memberSince").value = formattedMemberSince;
        
        if ($("role")) {
            const rVal = user.role || "Security Analyst";
            for (let opt of $("role").options) {
                if (opt.value.toLowerCase() === rVal.toLowerCase()) {
                    opt.selected = true;
                    break;
                }
            }
        }

        // Account Overview (Right Card)
        if ($("overviewFullName")) $("overviewFullName").textContent = displayName;
        if ($("overviewEmail")) $("overviewEmail").textContent = user.email || "—";
        if ($("overviewRole")) $("overviewRole").textContent = user.role || "Security Analyst";
        if ($("overviewUserId")) $("overviewUserId").textContent = formattedUserId;
        if ($("overviewMemberSince")) $("overviewMemberSince").textContent = formattedMemberSince;

        // Verified status badge
        const badge = $("verifiedStatusBadge");
        if (badge) {
            badge.textContent = user.is_verified ? "✓ Verified" : "○ Pending Verification";
            badge.className = user.is_verified ? "badge-pill verified" : "badge-pill sync-pending";
        }

        // Quick Info & Session Timestamps
        const loginTimestamp = user.last_login ? formatDate(user.last_login) : (user.created_at ? formatDate(user.created_at) : "Active session");
        if ($("quickInfoLastLogin")) $("quickInfoLastLogin").textContent = loginTimestamp;
        if ($("sessionLoginTime")) $("sessionLoginTime").textContent = loginTimestamp;
        if ($("sessionLocation")) $("sessionLocation").textContent = "Localhost (127.0.0.1)";
        if ($("sessionDevice")) $("sessionDevice").textContent = `${navigator.platform || 'Desktop'} · Authenticated`;

        // Synchronize application header & storage
        if (window.EthioAuth && window.EthioAuth.applyUserIdentity) {
            window.EthioAuth.applyUserIdentity(user);
        }
    }

    window.cancelProfileEdit = function () {
        loadProfile();
        showToast("Changes Discarded", "Profile form reset to last saved values.");
    };

    window.saveProfile = async function (event) {
        event.preventDefault();

        const btn = $("btnSaveProfile");
        const feedback = $("profileFeedback");
        const fullName = ($("fullName") ? $("fullName").value : "").trim();
        const website = ($("website") ? $("website").value : "").trim();

        if (btn) btn.classList.add("loading");
        if (btn) btn.disabled = true;
        if (feedback) feedback.textContent = "";

        try {
            const res = await fetch(`${API_BASE}/user/profile`, {
                method: "PUT",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    full_name: fullName || null,
                    website: website || null
                })
            });

            if (res.ok) {
                const updated = await res.json();
                populateProfileUI(updated);
                showToast("Profile Updated", "Your profile changes were saved successfully.");
                if (feedback) {
                    feedback.textContent = "✓ Saved";
                    feedback.className = "action-feedback success";
                    setTimeout(() => { if (feedback) feedback.textContent = ""; }, 3000);
                }
            } else {
                const errData = await res.json().catch(() => ({}));
                const msg = errData.detail || "Failed to update profile.";
                showToast("Update Failed", msg, true);
                if (feedback) {
                    feedback.textContent = `✕ ${msg}`;
                    feedback.className = "action-feedback error";
                }
            }
        } catch (err) {
            showToast("Network Error", "Could not reach the server to save profile.", true);
            if (feedback) {
                feedback.textContent = "✕ Network error";
                feedback.className = "action-feedback error";
            }
        } finally {
            if (btn) btn.classList.remove("loading");
            if (btn) btn.disabled = false;
        }
    };

    // =========================================================================
    // 3. REAL PASSWORD MANAGEMENT & STRENGTH METER (POST /api/auth/change-password)
    // =========================================================================
    function setupPasswordMeter() {
        const newPassInput = $("newPassword");
        if (!newPassInput) return;

        newPassInput.addEventListener("input", () => {
            const val = newPassInput.value;
            const bar = $("strengthBar");
            const text = $("strengthText");

            const hasLength = val.length >= 8;
            const hasCase = /[a-z]/.test(val) && /[A-Z]/.test(val);
            const hasNum = /\d/.test(val);
            const hasSymbol = /[^A-Za-z0-9]/.test(val);

            // Update rule items
            const rLen = $("ruleLength");
            const rCase = $("ruleCase");
            const rNum = $("ruleNumber");
            const rSym = $("ruleSymbol");

            if (rLen) rLen.classList.toggle("met", hasLength);
            if (rCase) rCase.classList.toggle("met", hasCase);
            if (rNum) rNum.classList.toggle("met", hasNum);
            if (rSym) rSym.classList.toggle("met", hasSymbol);

            // Score calculation (0 to 4)
            let score = 0;
            if (hasLength) score++;
            if (hasCase) score++;
            if (hasNum) score++;
            if (hasSymbol) score++;

            if (!bar || !text) return;

            if (val.length === 0) {
                bar.style.width = "0%";
                text.textContent = "Enter password";
                text.style.color = "var(--text-secondary)";
            } else if (score <= 1) {
                bar.style.width = "25%";
                bar.style.backgroundColor = "var(--danger, #EF4444)";
                text.textContent = "Weak";
                text.style.color = "var(--danger, #EF4444)";
            } else if (score === 2) {
                bar.style.width = "50%";
                bar.style.backgroundColor = "var(--warning, #F59E0B)";
                text.textContent = "Fair";
                text.style.color = "var(--warning, #F59E0B)";
            } else if (score === 3) {
                bar.style.width = "75%";
                bar.style.backgroundColor = "var(--warning, #F59E0B)";
                text.textContent = "Good";
                text.style.color = "var(--warning, #F59E0B)";
            } else {
                bar.style.width = "100%";
                bar.style.backgroundColor = "var(--accent-green, #10B981)";
                text.textContent = "Strong";
                text.style.color = "var(--accent-green, #10B981)";
            }
        });
    }

    window.changePassword = async function (event) {
        event.preventDefault();

        const btn = $("btnChangePassword");
        const feedback = $("passwordFeedback");
        const currentPassword = ($("currentPassword") ? $("currentPassword").value : "");
        const newPassword = ($("newPassword") ? $("newPassword").value : "");
        const confirmPassword = ($("confirmPassword") ? $("confirmPassword").value : "");

        if (!currentPassword) {
            showToast("Missing Field", "Please enter your current password.", true);
            return;
        }

        if (newPassword.length < 8) {
            showToast("Password Too Short", "New password must be at least 8 characters long.", true);
            return;
        }

        if (newPassword !== confirmPassword) {
            showToast("Password Mismatch", "New password and confirm password do not match.", true);
            return;
        }

        if (btn) btn.classList.add("loading");
        if (btn) btn.disabled = true;
        if (feedback) feedback.textContent = "";

        try {
            const res = await fetch(`${API_BASE}/auth/change-password`, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword
                })
            });

            if (res.ok) {
                // Clear inputs
                if ($("currentPassword")) $("currentPassword").value = "";
                if ($("newPassword")) {
                    $("newPassword").value = "";
                    $("newPassword").dispatchEvent(new Event("input"));
                }
                if ($("confirmPassword")) $("confirmPassword").value = "";

                showToast("Password Updated", "Your authentication password was updated successfully.");
                if (feedback) {
                    feedback.textContent = "✓ Password updated";
                    feedback.className = "action-feedback success";
                    setTimeout(() => { if (feedback) feedback.textContent = ""; }, 3000);
                }
            } else {
                const errData = await res.json().catch(() => ({}));
                const msg = errData.detail || "Failed to update password.";
                showToast("Password Update Failed", msg, true);
                if (feedback) {
                    feedback.textContent = `✕ ${msg}`;
                    feedback.className = "action-feedback error";
                }
            }
        } catch (err) {
            showToast("Network Error", "Could not reach server to change password.", true);
            if (feedback) {
                feedback.textContent = "✕ Network error";
                feedback.className = "action-feedback error";
            }
        } finally {
            if (btn) btn.classList.remove("loading");
            if (btn) btn.disabled = false;
        }
    };

    // =========================================================================
    // 4. SCAN DEFAULTS (UserSettings.default_scan_depth & Scanner Modules)
    // =========================================================================
    const MODULE_IDS = [
        "mod_sqli",
        "mod_xss",
        "mod_access_control",
        "mod_headers",
        "mod_https",
        "mod_exposed_files",
        "mod_info_disclosure",
        "mod_cookies"
    ];

    async function loadScanDefaults() {
        // Load depth from backend
        try {
            const res = await fetch(`${API_BASE}/user/settings`, {
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Accept": "application/json"
                }
            });

            if (res.ok) {
                const settings = await res.json();
                if ($("defaultScanDepth") && settings.default_scan_depth) {
                    $("defaultScanDepth").value = settings.default_scan_depth.toLowerCase();
                }
            }
        } catch (err) {
            console.warn("[EthioSec Settings] Could not load scan depth:", err);
        }

        // Load modules from local preferences
        try {
            const savedModules = JSON.parse(localStorage.getItem("ethiosec_scan_modules") || "{}");
            MODULE_IDS.forEach(id => {
                const el = $(id);
                if (el) {
                    el.checked = savedModules[id] !== undefined ? savedModules[id] : true;
                }
            });
        } catch (_) {
            MODULE_IDS.forEach(id => {
                const el = $(id);
                if (el) el.checked = true;
            });
        }
    }

    window.markScanDefaultsPending = function () {
        const badge = $("scanDepthSyncBadge");
        if (badge) {
            badge.textContent = "○ Unsaved changes";
            badge.className = "badge-pill sync-pending";
        }
    };

    window.onScanDepthChanged = function () {
        window.markScanDefaultsPending();
    };

    window.saveScanDefaults = async function () {
        const btn = $("btnSaveScanDefaults");
        const feedback = $("scanDefaultsFeedback");
        const depth = $("defaultScanDepth") ? $("defaultScanDepth").value : "standard";

        // Collect module toggle states
        const modulesState = {};
        MODULE_IDS.forEach(id => {
            const el = $(id);
            if (el) modulesState[id] = el.checked;
        });

        if (btn) btn.classList.add("loading");
        if (btn) btn.disabled = true;
        if (feedback) feedback.textContent = "";

        try {
            // Save depth to backend user settings
            const res = await fetch(`${API_BASE}/user/settings`, {
                method: "PUT",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    default_scan_depth: depth
                })
            });

            // Save modules to local storage
            localStorage.setItem("ethiosec_scan_modules", JSON.stringify(modulesState));

            if (res.ok) {
                showToast("Scan Defaults Saved", "Default scan depth and module configurations were updated.");
                const badge = $("scanDepthSyncBadge");
                if (badge) {
                    badge.textContent = "● Persisted";
                    badge.className = "badge-pill verified";
                }
                if (feedback) {
                    feedback.textContent = "✓ Scan defaults saved";
                    feedback.className = "action-feedback success";
                    setTimeout(() => { if (feedback) feedback.textContent = ""; }, 3000);
                }
            } else {
                const errData = await res.json().catch(() => ({}));
                const msg = errData.detail || "Failed to update scan defaults.";
                showToast("Save Failed", msg, true);
                if (feedback) {
                    feedback.textContent = `✕ ${msg}`;
                    feedback.className = "action-feedback error";
                }
            }
        } catch (err) {
            showToast("Network Error", "Could not reach server to save scan defaults.", true);
            if (feedback) {
                feedback.textContent = "✕ Network error";
                feedback.className = "action-feedback error";
            }
        } finally {
            if (btn) btn.classList.remove("loading");
            if (btn) btn.disabled = false;
        }
    };

    // Reset Defaults Confirmation Modal Handling
    window.openResetModal = function () {
        const modal = $("resetModal");
        if (modal) modal.classList.add("show");
    };

    window.closeResetModal = function () {
        const modal = $("resetModal");
        if (modal) modal.classList.remove("show");
    };

    window.confirmResetDefaults = async function () {
        window.closeResetModal();

        // Reset inputs
        if ($("defaultScanDepth")) $("defaultScanDepth").value = "standard";
        MODULE_IDS.forEach(id => {
            const el = $(id);
            if (el) el.checked = true;
        });

        // Trigger save with defaults
        await window.saveScanDefaults();
        showToast("Defaults Restored", "Audit profile reset to Standard and all 8 modules re-enabled.");
    };

    // =========================================================================
    // 5. PREFERENCES (Theme, UI Animations, Compact Density)
    // =========================================================================
    function loadUiPreferences() {
        const animations = localStorage.getItem("ethiosec_animations") !== "false";
        const compact = localStorage.getItem("ethiosec_compact") === "true";

        if ($("prefAnimations")) $("prefAnimations").checked = animations;
        if ($("prefCompact")) $("prefCompact").checked = compact;
    }

    window.saveUiPreferences = function (event) {
        event.preventDefault();

        const btn = $("btnSavePreferences");
        const feedback = $("prefFeedback");

        const animations = $("prefAnimations") ? $("prefAnimations").checked : true;
        const compact = $("prefCompact") ? $("prefCompact").checked : false;

        localStorage.setItem("ethiosec_animations", animations.toString());
        localStorage.setItem("ethiosec_compact", compact.toString());

        // Apply immediately
        document.body.classList.toggle("compact-density", compact);

        if (feedback) {
            feedback.textContent = "✓ Preferences saved";
            feedback.className = "action-feedback success";
            setTimeout(() => { if (feedback) feedback.textContent = ""; }, 3000);
        }
        showToast("Preferences Updated", "Interface density and animation preferences saved.");
    };

    // =========================================================================
    // 6. REAL NOTIFICATIONS (UserSettings)
    // =========================================================================
    async function loadNotifications() {
        try {
            const res = await fetch(`${API_BASE}/user/settings`, {
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Accept": "application/json"
                }
            });

            if (res.ok) {
                const settings = await res.json();
                if ($("notifScanCompleted")) $("notifScanCompleted").checked = settings.notif_scan_completed !== false;
                if ($("notifScanFailed")) $("notifScanFailed").checked = settings.notif_scan_failed !== false;
                if ($("notifSecurityFindings")) $("notifSecurityFindings").checked = settings.notif_security_findings !== false;

                const badge = $("notifSyncBadge");
                if (badge) {
                    badge.textContent = "● All changes saved";
                    badge.className = "badge-pill sync-saved";
                }
            }
        } catch (err) {
            console.warn("[EthioSec Settings] Could not load notification settings:", err);
        }
    }

    window.markNotifPending = function () {
        const badge = $("notifSyncBadge");
        if (badge) {
            badge.textContent = "○ Unsaved changes";
            badge.className = "badge-pill sync-pending";
        }
    };

    window.saveNotifications = async function (event) {
        event.preventDefault();

        const btn = $("btnSaveNotifications");
        const feedback = $("notifFeedback");

        const notifCompleted = $("notifScanCompleted") ? $("notifScanCompleted").checked : true;
        const notifFailed = $("notifScanFailed") ? $("notifScanFailed").checked : true;
        const notifFindings = $("notifSecurityFindings") ? $("notifSecurityFindings").checked : true;

        if (btn) btn.classList.add("loading");
        if (btn) btn.disabled = true;
        if (feedback) feedback.textContent = "";

        try {
            const res = await fetch(`${API_BASE}/user/settings`, {
                method: "PUT",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    notif_scan_completed: notifCompleted,
                    notif_scan_failed: notifFailed,
                    notif_security_findings: notifFindings
                })
            });

            if (res.ok) {
                showToast("Preferences Saved", "Your notification alert preferences were synchronized.");
                const badge = $("notifSyncBadge");
                if (badge) {
                    badge.textContent = "● All changes saved";
                    badge.className = "badge-pill sync-saved";
                }
                if (feedback) {
                    feedback.textContent = "✓ Notifications saved";
                    feedback.className = "action-feedback success";
                    setTimeout(() => { if (feedback) feedback.textContent = ""; }, 3000);
                }
            } else {
                const errData = await res.json().catch(() => ({}));
                const msg = errData.detail || "Failed to update notification settings.";
                showToast("Update Failed", msg, true);
                if (feedback) {
                    feedback.textContent = `✕ ${msg}`;
                    feedback.className = "action-feedback error";
                }
            }
        } catch (err) {
            showToast("Network Error", "Could not reach server to save notifications.", true);
            if (feedback) {
                feedback.textContent = "✕ Network error";
                feedback.className = "action-feedback error";
            }
        } finally {
            if (btn) btn.classList.remove("loading");
            if (btn) btn.disabled = false;
        }
    };

    // =========================================================================
    // INITIALIZATION
    // =========================================================================
    document.addEventListener("DOMContentLoaded", () => {
        setupTabs();
        setupPasswordMeter();
        loadProfile();
        loadScanDefaults();
        loadUiPreferences();
        loadNotifications();

        // Browser session description
        const agentDesc = $("sessionAgentDesc");
        if (agentDesc) {
            agentDesc.textContent = `${navigator.userAgent.split(" ").slice(0, 3).join(" ")} · Active Bearer JWT`;
        }

        // Close modal when clicking outside dialog
        const resetModal = $("resetModal");
        if (resetModal) {
            resetModal.addEventListener("click", (e) => {
                if (e.target === resetModal) {
                    window.closeResetModal();
                }
            });
        }
    });

})();
