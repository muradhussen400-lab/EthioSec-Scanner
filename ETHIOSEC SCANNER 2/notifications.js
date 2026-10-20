/* ==========================================================================
   ETHIOSECSCAN — NOTIFICATIONS & HEADER CONTROLLER (notifications.js)
   Controls top-right notifications dropdown, badge state, and profile sync
   ========================================================================== */

(function() {
    function initNotificationsAndHeader() {
        const notifWrapper = document.getElementById("notifDropdownWrapper");
        const notifBtn = document.getElementById("notifBtn");
        const notifBadge = document.getElementById("notifBadge");
        const markAllReadBtn = document.getElementById("markAllReadBtn");
        const notifList = document.getElementById("notifList");
        const avatarEl = document.getElementById("userAvatarSmall") || document.getElementById("headerAvatar");
        const nameEl = document.getElementById("userNameLabel") || document.getElementById("headerUserName");

        // Sync Profile Data from LocalStorage
        const userName = localStorage.getItem("userName");
        if (userName) {
            if (nameEl) nameEl.textContent = userName;
            if (avatarEl) {
                const initials = userName.split(" ").map(n => n[0]).join("").slice(0, 2).toUpperCase() || "U";
                avatarEl.textContent = initials;
            }
        }

        // Toggle Notifications Panel
        if (notifBtn && notifWrapper) {
            notifBtn.addEventListener("click", function(e) {
                e.stopPropagation();
                notifWrapper.classList.toggle("open");
            });
        }

        // Close on Outside Click
        document.addEventListener("click", function(e) {
            if (notifWrapper && !notifWrapper.contains(e.target)) {
                notifWrapper.classList.remove("open");
            }
        });

        // Mark All Read
        if (markAllReadBtn) {
            markAllReadBtn.addEventListener("click", function(e) {
                e.stopPropagation();
                if (notifBadge) {
                    notifBadge.classList.add("hidden");
                }
                const items = document.querySelectorAll(".notif-item");
                items.forEach(item => item.classList.remove("unread"));
                localStorage.setItem("ethiosec_notifs_read", "true");
            });
        }

        // Check if previously marked read
        if (localStorage.getItem("ethiosec_notifs_read") === "true" && notifBadge) {
            notifBadge.classList.add("hidden");
            const items = document.querySelectorAll(".notif-item");
            items.forEach(item => item.classList.remove("unread"));
        }

        // Item Click
        if (notifList) {
            notifList.addEventListener("click", function(e) {
                const item = e.target.closest(".notif-item");
                if (item) {
                    item.classList.remove("unread");
                    const unreadItems = notifList.querySelectorAll(".notif-item.unread");
                    if (unreadItems.length === 0 && notifBadge) {
                        notifBadge.classList.add("hidden");
                        localStorage.setItem("ethiosec_notifs_read", "true");
                    }
                }
            });
        }

        // Mobile drawer toggle integration
        const sidebarToggle = document.getElementById("sidebarToggle");
        const sidebar = document.getElementById("sidebar");
        const sidebarOverlay = document.getElementById("sidebarOverlay");

        if (sidebarToggle && sidebar) {
            sidebarToggle.onclick = function(e) {
                e.stopPropagation();
                sidebar.classList.toggle("open");
                if (sidebarOverlay) sidebarOverlay.classList.toggle("show");
            };
        }
        if (sidebarOverlay && sidebar) {
            sidebarOverlay.onclick = function() {
                sidebar.classList.remove("open");
                sidebarOverlay.classList.remove("show");
            };
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initNotificationsAndHeader);
    } else {
        initNotificationsAndHeader();
    }
})();
