/* =====================================================
   SIGN UP PAGE (signupjava.js) - Pure Frontend Standalone
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

    const urlParams = new URLSearchParams(window.location.search);
    const heldTarget = urlParams.get("target") || urlParams.get("url");

    // Redirect if already authenticated
    if (localStorage.getItem("isLoggedIn") === "true") {
        window.location.href = heldTarget 
            ? `scanfinal.html?target=${encodeURIComponent(heldTarget)}` 
            : "scanfinal.html";
        return;
    }

    const signupForm = document.getElementById("signupForm");
    const fullnameInput = document.getElementById("fullname");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirm-password");
    const termsInput = document.getElementById("terms");
    const newsletterInput = document.getElementById("newsletter");
    const signupBtn = document.getElementById("signupBtn");
    const toggleBtn = document.getElementById("togglePasswordBtn");
    const loginLink = document.getElementById("loginLink");
    const signupSubtext = document.getElementById("signupSubtext");
    const formError = document.getElementById("formError");

    const googleBtn = document.getElementById("googleBtn");
    const githubBtn = document.getElementById("githubBtn");

    const BTN_HTML = signupBtn ? signupBtn.innerHTML : "<span>CREATE ACCOUNT</span> <span class=\"btn-arrow\">→</span>";

    function showError(message) {
        if (!formError) return alert(message);
        formError.textContent = message;
        formError.hidden = false;
        formError.scrollIntoView({ behavior: "smooth", block: "center" });

        if (signupBtn) {
            signupBtn.innerHTML = BTN_HTML;
            signupBtn.disabled = false;
        }
    }

    function clearError() {
        if (formError) formError.hidden = true;
    }

    /* ============ PRE-FILL FROM A HELD SCAN TARGET ============ */
    if (heldTarget) {
        if (signupSubtext) {
            signupSubtext.textContent = `Create an account and we'll take you straight to scanning ${heldTarget}`;
        }
    }

    if (loginLink) {
        loginLink.href = heldTarget ? `login.html?target=${encodeURIComponent(heldTarget)}` : "login.html";
    }

    /* ============ PASSWORD VISIBILITY ============ */
    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener("click", () => {
            const showing = passwordInput.type === "text";
            passwordInput.type = showing ? "password" : "text";
            if (confirmInput) {
                confirmInput.type = showing ? "password" : "text";
            }
            toggleBtn.textContent = showing ? "👁" : "🔓";
        });
    }

    /* ============ LIVE VALIDATION FEEDBACK ============ */
    function validatePassword(password) {
        const checks = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            numbers: /[0-9]/.test(password),
            special: /[!@#$%^&*]/.test(password)
        };
        return { strength: Object.values(checks).filter(Boolean).length, checks };
    }

    if (passwordInput) {
        passwordInput.addEventListener("input", () => {
            clearError();
            const { strength } = validatePassword(passwordInput.value);

            passwordInput.style.borderColor =
                passwordInput.value.length === 0 ? "rgba(255, 255, 255, 0.09)"
                : strength < 2 ? "#cc2f0c"
                : strength < 4 ? "#ff4b20"
                : "#1bb369";
        });
    }

    if (emailInput) {
        emailInput.addEventListener("input", () => {
            clearError();
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            emailInput.style.borderColor =
                emailInput.value.length === 0 ? "rgba(255, 255, 255, 0.09)"
                : emailRegex.test(emailInput.value) ? "#1bb369" : "#cc2f0c";
        });
    }

    if (confirmInput) {
        confirmInput.addEventListener("input", () => {
            clearError();
            confirmInput.style.borderColor =
                confirmInput.value.length === 0 ? "rgba(255, 255, 255, 0.09)"
                : confirmInput.value === passwordInput.value ? "#1bb369" : "#cc2f0c";
        });

        confirmInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter" && signupBtn) signupBtn.click();
        });
    }

    /* ============ SOCIAL SIGNUP CLICKS ============ */
    [googleBtn, githubBtn].forEach(btn => {
        if (btn) {
            btn.addEventListener("click", () => {
                showError("Social authentication is configured for live cloud environments. Use email signup for offline testing.");
            });
        }
    });

    /* ============ SUBMIT (MOCK REGISTRATION) ============ */
    if (signupForm) {
        signupForm.addEventListener("submit", (e) => {
            e.preventDefault();
            clearError();

            const fullname = fullnameInput ? fullnameInput.value.trim() : "";
            const email = emailInput ? emailInput.value.trim() : "";
            const password = passwordInput ? passwordInput.value : "";
            const confirmPassword = confirmInput ? confirmInput.value : "";
            const agreed = termsInput ? termsInput.checked : false;

            if (!fullname || !email || !password || !confirmPassword) {
                return showError("Please fill in all required fields.");
            }

            if (fullname.length < 2) return showError("Please enter your full name.");

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) return showError("Please enter a valid email address.");

            const { strength } = validatePassword(password);
            if (strength < 2 || password.length < 8) {
                return showError("Password is too weak. Use at least 8 characters with letters and numbers.");
            }

            if (password !== confirmPassword) return showError("The two passwords do not match.");
            if (!agreed) return showError("You must agree to the Terms of Service.");

            if (signupBtn) {
                signupBtn.innerHTML = "<span>⏳ CREATING ACCOUNT...</span>";
                signupBtn.disabled = true;
            }

            (async () => {
                try {
                    const res = await fetch("http://127.0.0.1:8000/api/auth/register", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            email: email,
                            password: password,
                            full_name: fullname
                        })
                    });

                    if (!res.ok) {
                        let errMessage = "Registration failed.";
                        try {
                            const data = await res.json();
                            if (data.detail) errMessage = data.detail;
                        } catch (e) {}
                        throw new Error(errMessage);
                    }

                    const data = await res.json();
                    
                    localStorage.setItem("isLoggedIn", "true");
                    localStorage.setItem("userEmail", data.user.email);
                    localStorage.setItem("token", data.token);

                    if (heldTarget) {
                        window.location.href = `scanfinal.html?target=${encodeURIComponent(heldTarget)}`;
                    } else {
                        window.location.href = "scanfinal.html";
                    }
                } catch (error) {
                    showError(error.message || "Network error. Please try again.");
                }
            })();
        });
    }

});