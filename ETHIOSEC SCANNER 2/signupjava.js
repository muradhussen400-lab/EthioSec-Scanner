/* ==========================================================================
   ETHIOSEC SCANNER — SIGNUP CONTROLLER (signupjava.js)
   Integrates directly with FastAPI /api/auth/register & routes to email verification
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    const API_BASE = window.location.origin.includes(":8000") 
        ? `${window.location.origin}/api` 
        : "http://127.0.0.1:8000/api";

    const urlParams = new URLSearchParams(window.location.search);
    const heldTarget = urlParams.get("target") || urlParams.get("url");

    // 1. Auto-redirect if already authenticated
    if (localStorage.getItem("isLoggedIn") === "true" && localStorage.getItem("token")) {
        window.location.href = heldTarget 
            ? `scanfinal.html?target=${encodeURIComponent(heldTarget)}` 
            : "dashboardfinal.html";
        return;
    }

    // 2. DOM Elements
    const signupForm = document.getElementById("signupForm");
    const fullnameInput = document.getElementById("fullname");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirmPassword");
    const signupBtn = document.getElementById("signupBtn");
    const togglePasswordBtn = document.getElementById("togglePasswordBtn");
    const toggleConfirmBtn = document.getElementById("toggleConfirmBtn");
    const eyeIcon1 = document.getElementById("eyeIcon1");
    const eyeIcon2 = document.getElementById("eyeIcon2");
    const loginLink = document.getElementById("loginLink");
    const signupSubtext = document.getElementById("signupSubtext");
    const formError = document.getElementById("formError");
    const formSuccess = document.getElementById("formSuccess");
    const googleBtn = document.getElementById("googleBtn");

    const roleCardUser = document.getElementById("roleCardUser");
    const roleCardAdmin = document.getElementById("roleCardAdmin");

    const ORIGINAL_BTN_HTML = signupBtn ? signupBtn.innerHTML : `<span>Create Account</span>`;

    // 3. Feedback Helpers
    function showError(message, isHtml = false) {
        if (formSuccess) formSuccess.style.display = "none";
        if (formError) {
            if (isHtml) {
                formError.innerHTML = message;
            } else {
                formError.textContent = message;
            }
            formError.style.display = "flex";
            formError.scrollIntoView({ behavior: "smooth", block: "nearest" });
        } else {
            alert(message);
        }
        if (signupBtn) {
            signupBtn.innerHTML = ORIGINAL_BTN_HTML;
            signupBtn.disabled = false;
        }
    }

    function showSuccess(message) {
        if (formError) formError.style.display = "none";
        if (formSuccess) {
            formSuccess.textContent = message;
            formSuccess.style.display = "flex";
        }
    }

    function clearAlerts() {
        if (formError) formError.style.display = "none";
        if (formSuccess) formSuccess.style.display = "none";
    }

    // 4. Carry Held Scan Target in Subtext and Login Link
    if (heldTarget) {
        if (signupSubtext) {
            signupSubtext.textContent = `Create an account to start scanning ${heldTarget}`;
        }
        if (loginLink) {
            loginLink.href = `login.html?target=${encodeURIComponent(heldTarget)}`;
        }
    }

    // 5. Password Visibility Toggles
    function wirePasswordToggle(button, input, icon) {
        if (!button || !input) return;
        button.addEventListener("click", () => {
            const isPassword = input.type === "password";
            input.type = isPassword ? "text" : "password";
            if (icon) {
                icon.innerHTML = isPassword
                    ? `<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"></path><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"></path><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"></path><line x1="2" y1="2" x2="22" y2="22"></line>`
                    : `<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle>`;
            }
        });
    }
    wirePasswordToggle(togglePasswordBtn, passwordInput, eyeIcon1);
    wirePasswordToggle(toggleConfirmBtn, confirmInput, eyeIcon2);

    // 6. Role Selector Radio Card Toggle
    if (roleCardUser && roleCardAdmin) {
        const userRadio = roleCardUser.querySelector("input[type='radio']");
        const adminRadio = roleCardAdmin.querySelector("input[type='radio']");

        function updateRoleCards() {
            roleCardUser.classList.toggle("selected", userRadio.checked);
            roleCardAdmin.classList.toggle("selected", adminRadio.checked);
        }

        userRadio.addEventListener("change", updateRoleCards);
        adminRadio.addEventListener("change", updateRoleCards);
    }

    // 7. Input Event Listeners
    [fullnameInput, emailInput, passwordInput, confirmInput].forEach(inp => {
        if (inp) inp.addEventListener("input", clearAlerts);
    });

    // 8. Google SSO Click Handler
    if (googleBtn) {
        googleBtn.addEventListener("click", () => {
            showError("Google Workspace SSO is configured for cloud deployments. Please register using your email address.");
        });
    }

    // 9. Submit Handler (FastAPI Integration)
    if (signupForm) {
        signupForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            clearAlerts();

            const fullname = fullnameInput ? fullnameInput.value.trim() : "";
            const email = emailInput ? emailInput.value.trim().toLowerCase() : "";
            const password = passwordInput ? passwordInput.value : "";
            const confirmPassword = confirmInput ? confirmInput.value : "";

            if (!fullname || !email || !password || !confirmPassword) {
                return showError("Please fill in all required fields.");
            }

            if (fullname.length < 2) {
                return showError("Please enter your real full name (at least 2 characters).");
            }

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return showError("Please enter a valid email address.");
            }

            if (password.length < 8) {
                return showError("Password must be at least 8 characters long.");
            }

            if (password.length > 128) {
                return showError("Password cannot exceed 128 characters.");
            }

            if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password)) {
                return showError("Password must contain at least one uppercase letter, one lowercase letter, and one number.");
            }

            if (password !== confirmPassword) {
                return showError("The passwords do not match. Please re-enter your password confirmation.");
            }

            // Set loading state
            if (signupBtn) {
                signupBtn.innerHTML = `<span>⏳ Creating Account…</span>`;
                signupBtn.disabled = true;
            }

            try {
                const response = await fetch(`${API_BASE}/auth/register`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        email: email,
                        password: password,
                        full_name: fullname
                    })
                });

                const data = await response.json();

                // A. Handle Email Already Registered (HTTP 409)
                if (response.status === 409) {
                    return showError(
                        `An account with this email already exists. <a href="login.html" style="color:var(--brand-red); font-weight:700; text-decoration:underline; margin-left:6px;">Sign in here →</a>`,
                        true
                    );
                }

                // B. Handle Other Errors
                if (!response.ok) {
                    let errDetail = "Registration failed. Please check your inputs.";
                    if (data.detail) {
                        errDetail = Array.isArray(data.detail) 
                            ? data.detail.map(d => d.msg || d.detail).join("; ") 
                            : data.detail;
                    }
                    return showError(errDetail);
                }

                // C. Registration Successful
                const isVerified = data.user && data.user.is_verified;

                if (!isVerified) {
                    // Account requires verification: redirect to verification screen
                    localStorage.setItem("pendingVerificationEmail", email);
                    showSuccess("✓ Account created! Redirecting to email verification…");

                    setTimeout(() => {
                        window.location.href = `verify.html?email=${encodeURIComponent(email)}${heldTarget ? `&target=${encodeURIComponent(heldTarget)}` : ""}`;
                    }, 500);
                } else {
                    // Verification was bypassed/disabled on server: establish session directly
                    localStorage.setItem("isLoggedIn", "true");
                    localStorage.setItem("token", data.token);
                    localStorage.setItem("userEmail", data.user.email);
                    localStorage.setItem("userName", data.user.full_name || fullname);
                    localStorage.setItem("userRole", data.user.role || "Security Administrator");

                    showSuccess("✓ Account created successfully! Redirecting to dashboard…");
                    setTimeout(() => {
                        window.location.href = heldTarget 
                            ? `scanfinal.html?target=${encodeURIComponent(heldTarget)}` 
                            : "dashboardfinal.html";
                    }, 500);
                }

            } catch (err) {
                console.error("Signup network failure:", err);
                showError("Unable to reach the EthioSec authentication server. Please check your connection.");
            }
        });
    }
});