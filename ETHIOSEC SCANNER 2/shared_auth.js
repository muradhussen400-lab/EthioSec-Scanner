/**
 * ETHIOSECSCAN — SHARED IDENTITY & AUTHENTICATION MANAGER (shared_auth.js)
 * Single source of truth for user identity, session lifecycle, and profile badges
 * across Dashboard, New Scan, Scan History, Results, AI Assistant, and Settings.
 */

(function () {
    "use strict";

    const API_BASE = "http://127.0.0.1:8000/api";
    const LOGIN_PAGE = "login.html";

    // Immediate session guard: If no token exists on an authenticated page, redirect to login.
    const token = localStorage.getItem("token");
    const currentPath = window.location.pathname.split("/").pop() || "index.html";
    const publicPages = [
        "login.html",
        "signup.html",
        "verify.html",
        "reset-password.html",
        "index.html",
        "features.html",
        "contact.html"
    ];
    const isPublic = publicPages.some(page => currentPath.toLowerCase().endsWith(page.toLowerCase()));

    if (!token && !isPublic) {
        sessionStorage.setItem("ethio_redirect_after_login", window.location.href);
        window.location.href = LOGIN_PAGE;
        return;
    }

    /**
     * Compute clean initials from full name or email (e.g. "Miftah Hussen" -> "MH", "bob" -> "B")
     */
    function computeInitials(name) {
        if (!name) return "U";
        const parts = name.trim().split(/\s+/).filter(Boolean);
        if (parts.length === 1) {
            return parts[0].slice(0, 2).toUpperCase();
        }
        return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }

    /**
     * Sync user identity to all standard badge elements across all pages
     */
    function applyUserIdentity(user) {
        if (!user) return;

        const email = user.email || "";
        const fullName = (user.full_name || "").trim();
        const displayName = fullName || (email ? email.split("@")[0] : "User");
        const firstName = displayName.split(/\s+/)[0] || displayName;
        const initials = computeInitials(displayName);
        const role = user.role || "Security Administrator";

        // Persist fresh verified data to localStorage
        localStorage.setItem("userName", displayName);
        if (email) localStorage.setItem("userEmail", email);
        localStorage.setItem("userRole", role);
        localStorage.setItem("isLoggedIn", "true");

        // 1. Top-Right User Badge (shared across New Scan, History, Results, AI, Settings)
        const userNameLabel = document.getElementById("userNameLabel");
        if (userNameLabel) userNameLabel.textContent = displayName;

        const userAvatarSmall = document.getElementById("userAvatarSmall");
        if (userAvatarSmall) userAvatarSmall.textContent = initials;

        // 2. Dashboard Top Header Pill & Popover Menu
        const headerUserName = document.getElementById("headerUserName");
        if (headerUserName) headerUserName.textContent = displayName;

        const headerUserRole = document.getElementById("headerUserRole");
        if (headerUserRole) headerUserRole.textContent = role;

        const headerAvatar = document.getElementById("headerAvatar");
        if (headerAvatar) headerAvatar.textContent = initials;

        const menuUserName = document.getElementById("menuUserName");
        if (menuUserName) menuUserName.textContent = displayName;

        const menuUserEmail = document.getElementById("menuUserEmail");
        if (menuUserEmail) menuUserEmail.textContent = email;

        const menuUserRole = document.getElementById("menuUserRole");
        if (menuUserRole) menuUserRole.textContent = role;

        // 3. Welcome Banner Greeting (Dashboard)
        const welcomeHeading = document.getElementById("welcomeHeading");
        if (welcomeHeading) {
            welcomeHeading.textContent = `Welcome back, ${firstName} 👋`;
        }

        // 4. Settings Profile Form & Previews
        const previewName = document.getElementById("previewName");
        if (previewName) previewName.textContent = displayName;

        const previewEmail = document.getElementById("previewEmail");
        if (previewEmail) previewEmail.textContent = email;

        const previewRole = document.getElementById("previewRole");
        if (previewRole) previewRole.textContent = role;

        const avatarLetter = document.getElementById("avatarLetter");
        if (avatarLetter) avatarLetter.textContent = initials;

        const avatarLetterSide = document.getElementById("avatarLetterSide");
        if (avatarLetterSide) avatarLetterSide.textContent = initials;

        const quickInfoRole = document.getElementById("quickInfoRole");
        if (quickInfoRole) quickInfoRole.textContent = role;

        const inputFullName = document.getElementById("fullName");
        if (inputFullName && !inputFullName.value) inputFullName.value = displayName;

        const inputEmail = document.getElementById("email");
        if (inputEmail && !inputEmail.value) inputEmail.value = email;

        const inputRole = document.getElementById("role");
        if (inputRole) inputRole.value = role;

        // 5. Generic class-based badge fallbacks
        document.querySelectorAll(".user-badge-name, .user-pill-name").forEach(el => {
            el.textContent = displayName;
        });
        document.querySelectorAll(".user-badge-role, .user-pill-role").forEach(el => {
            el.textContent = role;
        });
        document.querySelectorAll(".user-avatar-circle, .user-avatar-small").forEach(el => {
            el.textContent = initials;
        });
    }

    /**
     * Wire user profile dropdown popover toggle globally
     */
    function setupUserMenuDropdown() {
        const userPillBtn = document.getElementById("userPillBtn");
        const userMenuPopover = document.getElementById("userMenuPopover");
        const container = document.querySelector(".user-pill-dropdown-container");

        if (userPillBtn && userMenuPopover) {
            if (userPillBtn._hasUserMenuHandler) return;
            userPillBtn._hasUserMenuHandler = true;

            userPillBtn.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                const willOpen = !userMenuPopover.classList.contains("show") && !(container && container.classList.contains("open"));
                userMenuPopover.classList.toggle("show", willOpen);
                if (container) container.classList.toggle("open", willOpen);
                userPillBtn.setAttribute("aria-expanded", willOpen.toString());
            });

            document.addEventListener("click", (e) => {
                if (container && !container.contains(e.target)) {
                    userMenuPopover.classList.remove("show");
                    container.classList.remove("open");
                    userPillBtn.setAttribute("aria-expanded", "false");
                }
            });

            // Close on escape
            document.addEventListener("keydown", (e) => {
                if (e.key === "Escape") {
                    userMenuPopover.classList.remove("show");
                    if (container) container.classList.remove("open");
                    userPillBtn.setAttribute("aria-expanded", "false");
                }
            });
        }
    }

    /**
     * Fetch authenticated user profile from backend
     */
    async function syncCurrentUser() {
        const authToken = localStorage.getItem("token");
        if (!authToken) return;

        try {
            const res = await fetch(`${API_BASE}/auth/me`, {
                headers: {
                    "Authorization": `Bearer ${authToken}`,
                    "Accept": "application/json"
                }
            });

            if (res.status === 401 || res.status === 403) {
                console.warn("[EthioSec Auth] Token invalid or session expired. Logging out.");
                clearClientSession();
                window.location.href = LOGIN_PAGE;
                return;
            }

            if (res.ok) {
                const data = await res.json();
                const user = data.user || data;
                applyUserIdentity(user);
                return;
            }
        } catch (err) {
            console.warn("[EthioSec Auth] Could not reach backend identity service:", err);
        }

        // Offline / fallback to last stored identity without hardcoding Miftah
        const cachedName = localStorage.getItem("userName");
        const cachedEmail = localStorage.getItem("userEmail");
        if (cachedName || cachedEmail) {
            applyUserIdentity({
                full_name: cachedName || "",
                email: cachedEmail || "",
                role: localStorage.getItem("userRole") || "Security Administrator"
            });
        }
    }

    /**
     * Clear all sensitive client-side session state
     */
    function clearClientSession() {
        localStorage.removeItem("token");
        localStorage.removeItem("isLoggedIn");
        localStorage.removeItem("userName");
        localStorage.removeItem("userEmail");
        localStorage.removeItem("userRole");
        sessionStorage.clear();
    }

    /**
     * Unified Logout function across all pages
     */
    window.logout = async function (event) {
        if (event && event.preventDefault) event.preventDefault();

        const authToken = localStorage.getItem("token");
        if (authToken) {
            try {
                await fetch(`${API_BASE}/auth/logout`, {
                    method: "POST",
                    headers: { "Authorization": `Bearer ${authToken}` }
                });
            } catch (_) {
                // Best-effort network logout
            }
        }

        clearClientSession();
        window.location.href = LOGIN_PAGE;
    };

    // Auto-run on DOM ready
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => {
            syncCurrentUser();
            setupUserMenuDropdown();
        });
    } else {
        syncCurrentUser();
        setupUserMenuDropdown();
    }

    // Expose helpers globally
    window.EthioAuth = {
        syncCurrentUser,
        applyUserIdentity,
        clearClientSession,
        setupUserMenuDropdown,
        getToken: () => localStorage.getItem("token"),
        getUserName: () => localStorage.getItem("userName"),
        getUserEmail: () => localStorage.getItem("userEmail")
    };
})();
