/**
 * ETHIOSEC SCANNER — EMAIL VERIFICATION CONTROLLER (verifyjava.js)
 * Handles 6-digit input navigation, clipboard paste, real API verification,
 * resend cooldown countdown, and seamless session establishment.
 */

(function () {
    "use strict";

    const API_BASE = "http://127.0.0.1:8000/api";

    // DOM Elements
    const verifyForm = document.getElementById("verifyForm");
    const verifyBtn = document.getElementById("verifyBtn");
    const resendBtn = document.getElementById("resendBtn");
    const recipientEmailEl = document.getElementById("recipientEmail");
    const formError = document.getElementById("formError");
    const formSuccess = document.getElementById("formSuccess");
    const digitInputs = [
        document.getElementById("digit1"),
        document.getElementById("digit2"),
        document.getElementById("digit3"),
        document.getElementById("digit4"),
        document.getElementById("digit5"),
        document.getElementById("digit6")
    ];

    // Determine target email
    const urlParams = new URLSearchParams(window.location.search);
    let targetEmail = urlParams.get("email") || localStorage.getItem("pendingVerificationEmail") || localStorage.getItem("userEmail") || "";
    targetEmail = targetEmail.trim().toLowerCase();

    if (recipientEmailEl) {
        recipientEmailEl.textContent = targetEmail || "your email address";
    }

    if (!targetEmail) {
        showError("No email address specified. Please register or log in first.");
    }

    // Auto-focus first digit
    if (digitInputs[0]) {
        setTimeout(() => digitInputs[0].focus(), 150);
    }

    // Digit Boxes Navigation & Validation
    digitInputs.forEach((input, index) => {
        if (!input) return;

        // Handle single numeric input & auto-advance
        input.addEventListener("input", (e) => {
            const val = input.value.replace(/\D/g, "");
            input.value = val ? val[val.length - 1] : "";

            if (input.value && index < digitInputs.length - 1) {
                digitInputs[index + 1].focus();
            }

            // Check if all filled -> auto submit if desired or enable
            checkIfCodeComplete();
        });

        // Handle Backspace navigation
        input.addEventListener("keydown", (e) => {
            if (e.key === "Backspace") {
                if (!input.value && index > 0) {
                    digitInputs[index - 1].focus();
                    digitInputs[index - 1].value = "";
                }
            } else if (e.key === "ArrowLeft" && index > 0) {
                digitInputs[index - 1].focus();
            } else if (e.key === "ArrowRight" && index < digitInputs.length - 1) {
                digitInputs[index + 1].focus();
            }
        });

        // Handle Paste across the digit grid
        input.addEventListener("paste", (e) => {
            e.preventDefault();
            const pastedData = (e.clipboardData || window.clipboardData).getData("text").trim();
            const digits = pastedData.replace(/\D/g, "");

            if (digits.length >= 6) {
                for (let i = 0; i < 6; i++) {
                    if (digitInputs[i]) digitInputs[i].value = digits[i];
                }
                digitInputs[5].focus();
                hideError();
                // Auto trigger verification on 6 digits pasted
                setTimeout(() => {
                    if (verifyForm) verifyForm.requestSubmit();
                }, 100);
            } else if (digits.length > 0) {
                for (let i = 0; i < digits.length && index + i < 6; i++) {
                    digitInputs[index + i].value = digits[i];
                }
                const nextFocus = Math.min(index + digits.length, 5);
                digitInputs[nextFocus].focus();
            }
        });
    });

    function getEnteredCode() {
        return digitInputs.map(input => (input ? input.value : "")).join("");
    }

    function checkIfCodeComplete() {
        const code = getEnteredCode();
        return code.length === 6 && /^\d{6}$/.test(code);
    }

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

    function hideError() {
        if (formError) formError.style.display = "none";
    }

    // Submit Verification
    if (verifyForm) {
        verifyForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            hideError();

            if (!targetEmail) {
                showError("Missing email address. Please register or return to login.");
                return;
            }

            const code = getEnteredCode();
            if (code.length !== 6 || !/^\d{6}$/.test(code)) {
                showError("Please enter the complete 6-digit numeric verification code.");
                return;
            }

            // Loading state
            verifyBtn.disabled = true;
            const originalBtnHtml = verifyBtn.innerHTML;
            verifyBtn.innerHTML = `
                <svg class="spinner" viewBox="0 0 50 50" style="width:18px;height:18px;margin-right:8px;animation:spin 1s linear infinite;">
                    <circle cx="25" cy="25" r="20" fill="none" stroke="#FFFFFF" stroke-width="5" stroke-dasharray="80" stroke-dashoffset="60"></circle>
                </svg>
                <span>Verifying...</span>
            `;

            try {
                const response = await fetch(`${API_BASE}/auth/verify-email`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({
                        email: targetEmail,
                        code: code
                    })
                });

                const data = await response.json();

                if (!response.ok) {
                    showError(data.detail || "Verification failed. The code may be invalid or expired.");
                    verifyBtn.disabled = false;
                    verifyBtn.innerHTML = originalBtnHtml;
                    return;
                }

                // Verification Successful
                showSuccess("✓ Email verified successfully! Activating your security workspace...");

                // Establish authenticated session with verified token
                if (data.token) {
                    localStorage.setItem("token", data.token);
                }
                if (data.user) {
                    localStorage.setItem("userName", data.user.full_name || targetEmail.split("@")[0]);
                    localStorage.setItem("userEmail", data.user.email || targetEmail);
                    localStorage.setItem("userRole", data.user.role || "Security Administrator");
                }
                localStorage.setItem("isLoggedIn", "true");
                localStorage.removeItem("pendingVerificationEmail");

                const returnUrl = sessionStorage.getItem("ethio_redirect_after_login") || "dashboardfinal.html";
                sessionStorage.removeItem("ethio_redirect_after_login");

                setTimeout(() => {
                    window.location.href = returnUrl;
                }, 1200);

            } catch (err) {
                console.error("[EthioSec Auth] Verification request failed:", err);
                showError("Network error: Unable to reach the EthioSec authentication server. Please check your connection.");
                verifyBtn.disabled = false;
                verifyBtn.innerHTML = originalBtnHtml;
            }
        });
    }

    // Resend Verification Code with Cooldown Timer
    let cooldownRemaining = 0;
    let cooldownTimer = null;

    if (resendBtn) {
        resendBtn.addEventListener("click", async (e) => {
            e.preventDefault();
            if (cooldownRemaining > 0) return;

            hideError();

            if (!targetEmail) {
                showError("Cannot resend code: no target email address found.");
                return;
            }

            resendBtn.disabled = true;
            resendBtn.textContent = "Sending...";

            try {
                const response = await fetch(`${API_BASE}/auth/resend-verification`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({ email: targetEmail })
                });

                const data = await response.json();

                if (!response.ok) {
                    showError(data.detail || "Unable to resend verification code. Please wait before retrying.");
                    resendBtn.disabled = false;
                    resendBtn.textContent = "Resend Code";
                    return;
                }

                showSuccess("✓ A new 6-digit verification code has been dispatched. Please check your inbox or server terminal.");
                startCooldown(60);

            } catch (err) {
                console.error("[EthioSec Auth] Resend request failed:", err);
                showError("Network error: Failed to request a new verification code.");
                resendBtn.disabled = false;
                resendBtn.textContent = "Resend Code";
            }
        });
    }

    function startCooldown(seconds) {
        cooldownRemaining = seconds;
        resendBtn.disabled = true;

        if (cooldownTimer) clearInterval(cooldownTimer);

        updateCooldownText();
        cooldownTimer = setInterval(() => {
            cooldownRemaining--;
            if (cooldownRemaining <= 0) {
                clearInterval(cooldownTimer);
                resendBtn.disabled = false;
                resendBtn.textContent = "Resend Code";
            } else {
                updateCooldownText();
            }
        }, 1000);
    }

    function updateCooldownText() {
        if (resendBtn) {
            resendBtn.textContent = `Resend Code (${cooldownRemaining}s)`;
        }
    }

})();
