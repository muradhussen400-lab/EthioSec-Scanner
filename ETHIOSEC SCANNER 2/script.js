/* =====================================================
   LANDING PAGE CONTROLLER (script.js) - Pure Frontend
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ============ SESSION-AWARE NAV ============ */
    const isMockSignedIn = localStorage.getItem("isLoggedIn") === "true";
    const dash = document.getElementById("openDashboard");
    const login = document.getElementById("openLogin");

    if (isMockSignedIn) {
        if (dash) dash.hidden = false;
        if (login) login.hidden = true;
    }

    /* ============ MOBILE MENU ============ */
    const menuBtn = document.getElementById("menuBtn");
    const navLinks = document.getElementById("navLinks");

    if (menuBtn && navLinks) {
        menuBtn.addEventListener("click", () => {
            menuBtn.classList.toggle("active");
            navLinks.classList.toggle("active");
        });

        navLinks.querySelectorAll("a").forEach((link) => {
            link.addEventListener("click", () => {
                menuBtn.classList.remove("active");
                navLinks.classList.remove("active");
            });
        });
    }

    /* ============ ACTIVE NAV LINK ON SCROLL ============ */
    const sections = document.querySelectorAll("main section[id]");
    const navAnchors = document.querySelectorAll(".nav-links a[href^='#']");

    if (sections.length && navAnchors.length) {
        const observer = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (!entry.isIntersecting) return;
                    const id = entry.target.getAttribute("id");
                    navAnchors.forEach((a) => {
                        a.classList.toggle("active", a.getAttribute("href") === `#${id}`);
                    });
                });
            },
            { rootMargin: "-45% 0px -50% 0px", threshold: 0 }
        );

        sections.forEach((section) => observer.observe(section));
    }

    /* ============ SCAN FORM ============ */
    const scanForm = document.getElementById("scanForm");
    const urlInput = document.getElementById("urlInput");
    const scanBtn = document.getElementById("scanBtn");
    const scannerStatus = document.getElementById("scannerStatus");
    const scanProgress = document.getElementById("scanProgress");
    const progressFill = document.getElementById("progressFill");
    const progressPercent = document.getElementById("progressPercent");

    function normalizeUrl(value) {
        const trimmed = (value || "").trim();
        if (!trimmed) return null;

        const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

        try {
            const url = new URL(candidate);
            if (!url.hostname.includes(".")) return null;
            return url.toString();
        } catch {
            return null;
        }
    }

    if (scanForm && urlInput) {
        scanForm.addEventListener("submit", (e) => {
            e.preventDefault();

            const target = normalizeUrl(urlInput.value);

            if (!target) {
                urlInput.focus();
                urlInput.classList.add("input-error");
                showNotification("That doesn't look like a valid website address.", true);
                setTimeout(() => urlInput.classList.remove("input-error"), 1200);
                return;
            }

            if (scanBtn) scanBtn.disabled = true;
            if (scanProgress) scanProgress.classList.add("show");
            if (scannerStatus) scannerStatus.textContent = "LAUNCHING SCANNER";

            const scanText = document.getElementById("scanText");
            const authed = localStorage.getItem("isLoggedIn") === "true";

            if (scanText) {
                scanText.textContent = authed 
                    ? "Redirecting you to scanner…" 
                    : "Redirecting you to secure login…";
            }

            // Route destination based on authentication state
            const destination = authed
                ? `scanfinal.html?target=${encodeURIComponent(target)}`
                : `login.html?target=${encodeURIComponent(target)}`;

            // Visual handoff bar animation
            let pct = 0;
            const tick = setInterval(() => {
                pct = Math.min(100, pct + 25);
                if (progressFill) progressFill.style.width = `${pct}%`;
                if (progressPercent) progressPercent.textContent = `${pct}%`;

                if (pct >= 100) {
                    clearInterval(tick);
                    window.location.href = destination;
                }
            }, 80);
        });
    }

    /* ============ CTA "START YOUR SCAN" BUTTONS ============ */
    document.querySelectorAll(".cta-btn[data-scroll-to-scan]").forEach((btn) => {
        btn.addEventListener("click", () => {
            const el = document.getElementById("urlInput");
            if (el) {
                el.scrollIntoView({ behavior: "smooth", block: "center" });
                el.focus();
            }
        });
    });

    /* ============ CONTACT FORM ============ */
    const contactForm = document.getElementById("contactForm");

    if (contactForm) {
        contactForm.addEventListener("submit", (e) => {
            e.preventDefault();
            showNotification("Message sent successfully. We'll be in touch soon.");
            contactForm.reset();
        });
    }

    /* ============ NOTIFICATION TOAST ============ */
    const notification = document.getElementById("notification");
    const notificationText = document.getElementById("notificationText");
    let notificationTimer = null;

    function showNotification(message, isError = false) {
        if (!notification || !notificationText) return;

        notificationText.textContent = message;
        notification.classList.toggle("error", isError);
        notification.classList.add("show");

        clearTimeout(notificationTimer);
        notificationTimer = setTimeout(() => notification.classList.remove("show"), 4000);
    }
});