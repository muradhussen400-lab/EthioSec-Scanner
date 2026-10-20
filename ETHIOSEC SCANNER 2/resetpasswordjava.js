/**
 * ETHIOSEC SCANNER — PASSWORD RECOVERY CONTROLLER (resetpasswordjava.js)
 * Manages request token flow, token verification, password policy check,
 * and secure credential update.
 */

(function () {
    "use strict";

    const API_BASE = "http://127.0.0.1:8000/api";

    // Tabs & Forms
    const tabRequest = document.getElementById("tabRequest");
    const tabReset = document.getElementById("tabReset");
    const requestForm = document.getElementById("requestForm");
    const resetForm = document.getElementById("resetForm");
    const requestBtn = document.getElementById("requestBtn");
    const resetBtn = document.getElementById("resetBtn");
    const recoveryTitle = document.getElementById("recoveryTitle");
    const recoverySubtitle = document.getElementById("recoverySubtitle");

    // Inputs
    const requestEmailInput = document.getElementById("requestEmail");
    const resetEmailInput = document.getElementById("resetEmail");
    const resetTokenInput = document.getElementById("resetToken");
    const newPasswordInput = document.getElementById("newPassword");
    const confirmNewPasswordInput = document.getElementById("confirmNewPassword");

    // Alerts
    const formError = document.getElementById("formError");
    const formSuccess = document.getElementById("formSuccess");

    // Visibility toggles
    const toggleNewPw = document.getElementById("toggleNewPw");
    const toggleConfirmNewPw = document.getElementById("toggleConfirmNewPw");

    // Password visibility helper
    function setupToggle(button, input) {
        if (!button || !input) return;
        button.addEventListener("click", () => {
            const isPassword = input.type === "password";
            input.type = isPassword ? "text" : "password";
            button.style.color = isPassword ? "var(--primary-red)" : "var(--text-muted)";
        });
    }

    setupToggle(toggleNewPw, newPasswordInput);
    setupToggle(toggleConfirmNewPw, confirmNewPasswordInput);

    function showError(msg) {
        if (formError) {
            formError.textContent = msg;
            formError.style.display = "block";
        }
        if (formSuccess) formSuccess.style.display = "none";
    }

    function showSuccess(msg) {
        if (formSuccess) {
            formSuccess.textContent = msg;
            formSuccess.style.display = "block";
        }
        if (formError) formError.style.display = "none";
    }

    function hideAlerts() {
        if (formError) formError.style.display = "none";
        if (formSuccess) formSuccess.style.display = "none";
    }

    // Tab Switching
    function setStep(step) {
        hideAlerts();
        if (step === 1) {
            tabRequest.classList.add("active");
            tabRequest.setAttribute("aria-selected", "true");
            tabReset.classList.remove("active");
            tabReset.setAttribute("aria-selected", "false");
            requestForm.style.display = "block";
            resetForm.style.display = "none";
            recoveryTitle.textContent = "Forgot Password?";
            recoverySubtitle.textContent = "Enter your registered email address to receive password reset instructions.";
            setTimeout(() => requestEmailInput && requestEmailInput.focus(), 100);
        } else {
            tabReset.classList.add("active");
            tabReset.setAttribute("aria-selected", "true");
            tabRequest.classList.remove("active");
            tabRequest.setAttribute("aria-selected", "false");
            requestForm.style.display = "none";
            resetForm.style.display = "block";
            recoveryTitle.textContent = "Set New Password";
            recoverySubtitle.textContent = "Enter the reset token sent to your email and your new password.";
            setTimeout(() => {
                if (resetTokenInput && !resetTokenInput.value) {
                    resetTokenInput.focus();
                } else if (newPasswordInput) {
                    newPasswordInput.focus();
                }
            }, 100);
        }
    }

    if (tabRequest) tabRequest.addEventListener("click", () => setStep(1));
    if (tabReset) tabReset.addEventListener("click", () => setStep(2));

    // Inspect URL Params for prefilling token and email
    const urlParams = new URLSearchParams(window.location.search);
    const paramEmail = urlParams.get("email") || "";
    const paramToken = urlParams.get("token") || "";

    if (paramEmail) {
        if (requestEmailInput) requestEmailInput.value = paramEmail;
        if (resetEmailInput) resetEmailInput.value = paramEmail;
    }

    if (paramToken) {
        if (resetTokenInput) resetTokenInput.value = paramToken;
        setStep(2);
    } else {
        setStep(1);
    }

    // Step 1: Request Reset Token
    if (requestForm) {
        requestForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            hideAlerts();

            const email = requestEmailInput.value.trim().toLowerCase();
            if (!email) {
                showError("Please enter your registered email address.");
                return;
            }

            requestBtn.disabled = true;
            const originalBtnText = requestBtn.innerHTML;
            requestBtn.innerHTML = `
                <svg class="spinner" viewBox="0 0 50 50" style="width:18px;height:18px;margin-right:8px;animation:spin 1s linear infinite;">
                    <circle cx="25" cy="25" r="20" fill="none" stroke="#FFFFFF" stroke-width="5" stroke-dasharray="80" stroke-dashoffset="60"></circle>
                </svg>
                <span>Sending Instructions...</span>
            `;

            try {
                const response = await fetch(`${API_BASE}/auth/forgot-password`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({ email: email })
                });

                const data = await response.json();

                // Response is generic to prevent account enumeration
                showSuccess(data.message || "If an account with that email exists, password reset instructions have been sent.");

                if (resetEmailInput) {
                    resetEmailInput.value = email;
                }

                // Switch user to Step 2 so they can enter the token
                setTimeout(() => {
                    setStep(2);
                    showSuccess("Instructions sent. Please enter the reset token from your email below.");
                }, 1800);

            } catch (err) {
                console.error("[EthioSec Auth] Forgot password request failed:", err);
                showError("Network error: Could not reach authentication server.");
            } finally {
                requestBtn.disabled = false;
                requestBtn.innerHTML = originalBtnText;
            }
        });
    }

    // Step 2: Reset Password
    if (resetForm) {
        resetForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            hideAlerts();

            const email = resetEmailInput.value.trim().toLowerCase();
            const token = resetTokenInput.value.trim();
            const newPassword = newPasswordInput.value;
            const confirmNewPassword = confirmNewPasswordInput.value;

            if (!email) {
                showError("Please enter your registered email address.");
                return;
            }

            if (!token) {
                showError("Please enter the single-use reset token.");
                return;
            }

            if (newPassword.length < 8) {
                showError("New password must be at least 8 characters long.");
                return;
            }

            if (newPassword !== confirmNewPassword) {
                showError("Passwords do not match. Please verify both password entries.");
                return;
            }

            resetBtn.disabled = true;
            const originalBtnText = resetBtn.innerHTML;
            resetBtn.innerHTML = `
                <svg class="spinner" viewBox="0 0 50 50" style="width:18px;height:18px;margin-right:8px;animation:spin 1s linear infinite;">
                    <circle cx="25" cy="25" r="20" fill="none" stroke="#FFFFFF" stroke-width="5" stroke-dasharray="80" stroke-dashoffset="60"></circle>
                </svg>
                <span>Updating Password...</span>
            `;

            try {
                const response = await fetch(`${API_BASE}/auth/reset-password`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({
                        email: email,
                        token: token,
                        new_password: newPassword
                    })
                });

                const data = await response.json();

                if (!response.ok) {
                    showError(data.detail || "Password reset failed. Token may be invalid or expired.");
                    resetBtn.disabled = false;
                    resetBtn.innerHTML = originalBtnText;
                    return;
                }

                showSuccess("✓ " + (data.message || "Password reset successful! Redirecting to login..."));

                // Clear any outdated session
                localStorage.removeItem("token");
                localStorage.removeItem("isLoggedIn");

                setTimeout(() => {
                    window.location.href = "login.html";
                }, 1500);

            } catch (err) {
                console.error("[EthioSec Auth] Reset password request failed:", err);
                showError("Network error: Could not reach the authentication server.");
                resetBtn.disabled = false;
                resetBtn.innerHTML = originalBtnText;
            }
        });
    }

})();
