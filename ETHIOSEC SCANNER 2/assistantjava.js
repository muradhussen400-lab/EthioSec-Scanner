/* =====================================================
   AI SECURITY ASSISTANT (assistant.html) - Pure Frontend
   ===================================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ---------- FRONTEND UTILITIES (Replaces EthioShell & EthioAuth) ---------- */
    const UI = {
        getQueryParam: (param) => new URLSearchParams(window.location.search).get(param),
        toast: (msg) => {
            const toastEl = document.getElementById("toast");
            if (toastEl) {
                toastEl.textContent = msg;
                toastEl.classList.add("show");
                setTimeout(() => toastEl.classList.remove("show"), 3000);
            }
        }
    };

    const scanId = UI.getQueryParam("scan");
    const findingId = UI.getQueryParam("finding");

    const chat = document.getElementById("chat");
    const form = document.getElementById("composer");
    const input = document.getElementById("message");
    const sendBtn = document.getElementById("sendBtn");
    const contextRow = document.getElementById("contextRow");
    const backLink = document.getElementById("backLink");

    let history = [];

    /* ---------- MOCK FINDINGS DATABASE ---------- */
    const mockFindings = {
        "f-01": {
            id: "f-01",
            title: "SQL Injection in Authentication Route",
            severity: "critical",
            url: "https://demo.ethio-security.org/login.php",
            owasp: "A03:2021-Injection",
            cwe: "CWE-89",
            fix: "Use parameterized queries / prepared statements (e.g. PDO in PHP or Prisma/TypeORM) instead of direct string concatenation."
        },
        "f-02": {
            id: "f-02",
            title: "Missing Content-Security-Policy",
            severity: "high",
            url: "https://demo.ethio-security.org/",
            owasp: "A05:2021-Security Misconfiguration",
            cwe: "CWE-693",
            fix: "Add a Content-Security-Policy HTTP response header to restrict the sources where scripts, images, and styles can load from."
        },
        "f-03": {
            id: "f-03",
            title: "Exposed Git Repository",
            severity: "medium",
            url: "https://demo.ethio-security.org/.git/",
            owasp: "A01:2021-Broken Access Control",
            cwe: "CWE-538",
            fix: "Block public access to hidden directories starting with '.' in your web server configuration (Nginx: 'location ~ /\\. { deny all; }')."
        }
    };

    /* ---------- CONTEXT CHIPS ---------- */

    function buildContext() {
        if (!scanId) return;

        const chipNone = document.getElementById("chipNone");
        if (chipNone) chipNone.remove();

        if (backLink) {
            backLink.hidden = false;
            backLink.href = `results.html?id=${encodeURIComponent(scanId)}`;
        }

        addChip(`Scan: ${scanId}`);

        if (!findingId) return;

        const currentFinding = mockFindings[findingId] || {
            title: `Finding #${findingId}`,
            severity: "medium",
            url: "Target endpoint",
            fix: "Review input validation and sanitization."
        };

        addChip(`${currentFinding.severity.toUpperCase()} · ${currentFinding.title}`);
        if (input) input.placeholder = `Ask about "${currentFinding.title}"…`;

        say("ai", `You are reviewing "${currentFinding.title}" on ${currentFinding.url}. What would you like to know — the real-world impact, how severe it is, or how to implement the remediation?`);
    }

    function addChip(text) {
        if (!contextRow) return;
        const chip = document.createElement("span");
        chip.className = "context-chip";
        chip.textContent = text;
        contextRow.appendChild(chip);
    }

    /* ---------- CHAT SYSTEM ---------- */

    function say(role, text) {
        if (!chat) return null;
        const bubble = document.createElement("div");
        bubble.className = "bubble " + role;
        bubble.textContent = text;
        chat.appendChild(bubble);
        chat.scrollTop = chat.scrollHeight;
        return bubble;
    }

    function generateMockAIResponse(query, finding) {
        const q = query.toLowerCase();

        if (q.includes("fix") || q.includes("how do i fix")) {
            return finding 
                ? `To fix "${finding.title}": ${finding.fix}`
                : "To remediate this issue, apply the principle of least privilege, sanitize all user-supplied inputs, and deploy secure HTTP response headers.";
        }

        if (q.includes("severe") || q.includes("severity") || q.includes("bad")) {
            return finding 
                ? `This is rated as ${finding.severity.toUpperCase()}. It poses a real risk because an attacker can exploit this behavior directly without prior authentication.`
                : "The severity depends on whether an attacker can achieve remote code execution, database compromise, or session hijacking.";
        }

        if (q.includes("owasp") || q.includes("cwe")) {
            return finding && finding.owasp
                ? `This finding maps to ${finding.owasp} (${finding.cwe}). These categories describe standard web application vulnerabilities outlined by the Open Worldwide Application Security Project.`
                : "OWASP categories represent the top 10 most critical security risks facing web applications today.";
        }

        return `Regarding "${query}": In a production deployment, ensure this endpoint enforces strict server-side validation and logs any anomalous traffic. Always re-run the scan after patching.`;
    }

    async function send(text) {
        if (!text) return;

        say("user", text);
        history.push({ role: "user", content: text });
        if (input) input.value = "";
        if (sendBtn) sendBtn.disabled = true;

        const pending = say("ai", "Analyzing findings…");
        if (pending) pending.classList.add("typing");

        // Simulate AI inference delay (600ms)
        setTimeout(() => {
            if (pending) pending.remove();

            const currentFinding = mockFindings[findingId] || null;
            const reply = generateMockAIResponse(text, currentFinding);

            say("ai", reply);
            history.push({ role: "assistant", content: reply });

            if (sendBtn) sendBtn.disabled = false;
            if (input) input.focus();
        }, 600);
    }

    if (form) {
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            if (input) send(input.value.trim());
        });
    }

    document.querySelectorAll(".suggestion").forEach((btn) => {
        btn.addEventListener("click", () => send(btn.textContent.trim()));
    });

    /* ---------- INITIAL GREETING ---------- */

    if (!scanId) {
        say("ai", "Hello! I am your AI Security Assistant. I explain the findings from your scans — severity, real-world impact, and remediation steps. Ask a question or click a suggestion below to get started.");
    }

    buildContext();
});