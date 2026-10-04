/* =====================================================
   LOGIN PAGE (login.html) - Pure Frontend Standalone
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

    // Auto-redirect if already authenticated
    const urlParams = new URLSearchParams(window.location.search);
    const heldTarget = urlParams.get("target");

    if (localStorage.getItem("isLoggedIn") === "true") {
        window.location.href = heldTarget 
            ? `scanfinal.html?target=${encodeURIComponent(heldTarget)}` 
            : "scanfinal.html";
        return;
    }

    const loginForm = document.getElementById("loginForm");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const rememberInput = document.getElementById("remember");
    const loginBtn = document.getElementById("loginBtn");
    const toggleBtn = document.getElementById("togglePasswordBtn");
    const signupLink = document.getElementById("signupLink");
    const loginSubtext = document.getElementById("loginSubtext");
    const formError = document.getElementById("formError");

    const BTN_HTML = loginBtn ? loginBtn.innerHTML : "<span>SIGN IN</span> <span class=\"btn-arrow\">→</span>";

    /* ============ ERROR BANNER ============ */
    function showError(message) {
        if (!formError) return alert(message);
        formError.textContent = message;
        formError.hidden = false;
        if (loginBtn) {
            loginBtn.innerHTML = BTN_HTML;
            loginBtn.disabled = false;
        }
    }

    function clearError() {
        if (formError) formError.hidden = true;
    }

    /* ============ CARRY THE HELD SCAN TARGET ============ */
    if (heldTarget && loginSubtext) {
        loginSubtext.textContent = `Sign in to run your scan on ${heldTarget}`;
    }

    if (signupLink && heldTarget) {
        signupLink.href = `signup.html?target=${encodeURIComponent(heldTarget)}`;
    }

    /* ============ PRE-FILL REMEMBERED EMAIL ============ */
    const savedEmail = localStorage.getItem("savedEmail");
    if (savedEmail && emailInput && rememberInput) {
        emailInput.value = savedEmail;
        rememberInput.checked = true;
    }

    /* ============ PASSWORD VISIBILITY ============ */
    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener("click", () => {
            const showing = passwordInput.type === "text";
            passwordInput.type = showing ? "password" : "text";
            toggleBtn.textContent = showing ? "👁" : "🔓";
        });
    }

    if (passwordInput) {
        passwordInput.addEventListener("input", (e) => {
            const len = e.target.value.length;
            e.target.style.borderColor =
                len > 0 && len < 8 ? "#cc2f0c" : "rgba(255, 255, 255, 0.09)";
            clearError();
        });
    }

    if (emailInput) {
        emailInput.addEventListener("input", clearError);
    }

    /* ============ SUBMIT (PURE FRONTEND MOCK) ============ */
    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            clearError();

            const email = emailInput ? emailInput.value.trim() : "";
            const password = passwordInput ? passwordInput.value : "";
            const remember = rememberInput ? rememberInput.checked : false;

            if (!email || !password) return showError("Please fill in all fields.");

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) return showError("Please enter a valid email address.");

            if (password.length < 8) return showError("Password must be at least 8 characters.");

            if (loginBtn) {
                loginBtn.innerHTML = "<span>⏳ SIGNING IN...</span>";
                loginBtn.disabled = true;
            }

            try {
                const response = await fetch(`http://127.0.0.1:8000/api/auth/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, password })
                });

                if (!response.ok) {
                    let errMessage = "Login failed.";
                    try {
                        const data = await response.json();
                        if (data.detail) errMessage = data.detail;
                    } catch (e) {}
                    return showError(errMessage);
                }

                const data = await response.json();

                localStorage.setItem("isLoggedIn", "true");
                localStorage.setItem("userEmail", data.user.email);
                localStorage.setItem("token", data.token);

                if (remember) {
                    localStorage.setItem("savedEmail", email);
                } else {
                    localStorage.removeItem("savedEmail");
                }

                if (heldTarget) {
                    window.location.href = `scanfinal.html?target=${encodeURIComponent(heldTarget)}`;
                } else {
                    window.location.href = "scanfinal.html";
                }
            } catch (error) {
                showError("Network error. Please try again.");
            }
        });
    }

});