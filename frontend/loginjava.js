/* ==========================================================================
   ETHIOSEC SCANNER — LOGIN CONTROLLER (loginjava.js)
   Integrates directly with FastAPI /api/auth/login & handles unverified accounts
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    const API_BASE = window.location.origin.includes(":8000") 
        ? `${window.location.origin}/api` 
        : "http://127.0.0.1:8000/api";

    const urlParams = new URLSearchParams(window.location.search);
    const heldTarget = urlParams.get("target") || urlParams.get("url");

    // 1. Auto-redirect if already fully authenticated
    const hasToken = Boolean(localStorage.getItem("token"));
    const isAuthed = localStorage.getItem("isLoggedIn") === "true";

    if (isAuthed && hasToken) {
        window.location.href = heldTarget 
            ? `scanfinal.html?target=${encodeURIComponent(heldTarget)}` 
            : "dashboardfinal.html";
        return;
    } else if (isAuthed && !hasToken) {
        localStorage.removeItem("isLoggedIn");
    }

    // 2. DOM Elements
    const loginForm = document.getElementById("loginForm");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const rememberInput = document.getElementById("remember");
    const loginBtn = document.getElementById("loginBtn");
    const toggleBtn = document.getElementById("togglePasswordBtn");
    const eyeIcon = document.getElementById("eyeIcon");
    const signupLink = document.getElementById("signupLink");
    const loginSubtext = document.getElementById("loginSubtext");
    const formError = document.getElementById("formError");
    const formSuccess = document.getElementById("formSuccess");
    const googleBtn = document.getElementById("googleBtn");

    const ORIGINAL_BTN_HTML = loginBtn ? loginBtn.innerHTML : `<span>Login</span>`;

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
        } else {
            alert(message);
        }
        if (loginBtn) {
            loginBtn.innerHTML = ORIGINAL_BTN_HTML;
            loginBtn.disabled = false;
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

    // 4. Carry Held Scan Target in Subtext and Signup Link
    if (heldTarget) {
        if (loginSubtext) {
            loginSubtext.textContent = `Sign in to run your security assessment on ${heldTarget}`;
        }
        if (signupLink) {
            signupLink.href = `signup.html?target=${encodeURIComponent(heldTarget)}`;
        }
    }

    // 5. Pre-fill Remembered Email
    const savedEmail = localStorage.getItem("savedEmail");
    if (savedEmail && emailInput && rememberInput) {
        emailInput.value = savedEmail;
        rememberInput.checked = true;
    }

    // 6. Password Visibility Toggle
    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener("click", () => {
            const isPassword = passwordInput.type === "password";
            passwordInput.type = isPassword ? "text" : "password";
            if (eyeIcon) {
                eyeIcon.innerHTML = isPassword
                    ? `<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"></path><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"></path><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"></path><line x1="2" y1="2" x2="22" y2="22"></line>`
                    : `<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle>`;
            }
        });
    }

    if (emailInput) emailInput.addEventListener("input", clearAlerts);
    if (passwordInput) passwordInput.addEventListener("input", clearAlerts);

    // 7. Google SSO Click Handler
    if (googleBtn) {
        googleBtn.addEventListener("click", () => {
            showError("Google Workspace SSO is configured for cloud deployments. Please use your email and password credentials.");
        });
    }

    // 8. Submit Handler (FastAPI Integration)
    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            clearAlerts();

            const email = emailInput ? emailInput.value.trim().toLowerCase() : "";
            const password = passwordInput ? passwordInput.value : "";
            const remember = rememberInput ? rememberInput.checked : false;

            if (!email || !password) {
                return showError("Please enter both your email address and password.");
            }

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return showError("Please enter a valid email address.");
            }

            if (password.length < 8) {
                return showError("Password must be at least 8 characters long.");
            }

            // Set loading state
            if (loginBtn) {
                loginBtn.innerHTML = `<span>⏳ Signing In…</span>`;
                loginBtn.disabled = true;
            }

            try {
                const response = await fetch(`${API_BASE}/auth/login`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                // A. Handle Unverified Account (HTTP 403)
                if (response.status === 403 && (response.headers.get("X-Error-Code") === "EMAIL_NOT_VERIFIED" || (data.detail && data.detail.toLowerCase().includes("verify")))) {
                    localStorage.setItem("pendingVerificationEmail", email);
                    const verifyUrl = `verify.html?email=${encodeURIComponent(email)}&reason=unverified${heldTarget ? `&target=${encodeURIComponent(heldTarget)}` : ""}`;
                    return showError(
                        `<div>
                            <strong>Email Verification Required:</strong> Your account is registered but has not been verified yet.
                            <div style="margin-top: 10px;">
                                <a href="${verifyUrl}" class="btn-submit-primary" style="text-decoration:none; height:36px; font-size:12.5px; width:auto; display:inline-flex; padding: 0 16px;">
                                    Verify Account Now →
                                </a>
                            </div>
                        </div>`,
                        true
                    );
                }

                // B. Handle Other Errors
                if (!response.ok) {
                    const errDetail = data.detail || "Authentication failed. Please check your credentials.";
                    return showError(errDetail);
                }

                // C. Successful Login
                showSuccess("✓ Authentication successful. Redirecting to dashboard…");

                // Establish authenticated session
                localStorage.setItem("isLoggedIn", "true");
                localStorage.setItem("token", data.token);
                localStorage.setItem("userEmail", data.user.email);
                localStorage.setItem("userRole", data.user.role || "Security Administrator");

                const displayName = data.user.full_name || (data.user.email ? data.user.email.split("@")[0] : "User");
                localStorage.setItem("userName", displayName);

                if (remember) {
                    localStorage.setItem("savedEmail", email);
                } else {
                    localStorage.removeItem("savedEmail");
                }

                setTimeout(() => {
                    if (heldTarget) {
                        window.location.href = `scanfinal.html?target=${encodeURIComponent(heldTarget)}`;
                    } else {
                        window.location.href = "dashboardfinal.html";
                    }
                }, 400);

            } catch (err) {
                console.error("Login network failure:", err);
                showError("Unable to reach the EthioSec authentication server. Please check your connection.");
            }
        });
    }
});