if (!localStorage.getItem('token')) {
    window.location.href = 'login.html';
}
/* =====================================================
   AI SECURITY ASSISTANT (assistantjava.js) - Real AI Backend Sync
   ===================================================== */

document.addEventListener("DOMContentLoaded", async () => {

    const UI = {
        escapeHTML: (str) => {
            if (!str) return "";
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        },
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

    const scanId = UI.getQueryParam("scan") || UI.getQueryParam("scan_id");
    const findingId = UI.getQueryParam("finding") || UI.getQueryParam("finding_id");

    const chat = document.getElementById("chat");
    const form = document.getElementById("composer");
    const input = document.getElementById("message");
    const sendBtn = document.getElementById("sendBtn");
    const contextRow = document.getElementById("contextRow");
    const backLink = document.getElementById("backLink");

    let history = [];

    /* ---------- CONTEXT INITIALIZATION ---------- */
    async function buildContext() {
        if (!scanId && !findingId) {
            say("ai", "Hello! I am your EthioSec AI Security Assistant. I can explain vulnerabilities, assess real-world business risks, and guide you through secure remediation code. Ask any cybersecurity question or click a prompt below.");
            return;
        }

        const chipNone = document.getElementById("chipNone");
        if (chipNone) chipNone.remove();

        if (scanId) {
            if (backLink) {
                backLink.hidden = false;
                backLink.href = `results.html?id=${encodeURIComponent(scanId)}`;
            }
            addChip(`Scan: ${scanId.slice(0, 8)}…`);
        }

        if (findingId) {
            try {
                const token = localStorage.getItem("token");
                const res = await fetch(`http://127.0.0.1:8000/api/findings/${findingId}`, {
                    headers: { "Authorization": `Bearer ${token}` }
                });
                if (res.ok) {
                    const data = await res.json();
                    const finding = data.finding;
                    addChip(`${finding.severity.toUpperCase()} · ${finding.title}`);
                    if (input) input.placeholder = `Ask about "${finding.title}"…`;
                    say("ai", `I have loaded finding context: **${finding.title}** (${finding.severity.toUpperCase()}) on \`${finding.url || 'target'}\`. What would you like to explore — the technical root cause, exploitation mechanism, or exact patch code?`);
                    return;
                }
            } catch (e) {
                console.error("Could not load finding context", e);
            }
        }

        if (scanId) {
            say("ai", `I have linked scan assessment context \`${scanId}\`. What would you like to analyze regarding this target?`);
        }
    }

    function addChip(text) {
        if (!contextRow) return;
        const chip = document.createElement("span");
        chip.className = "context-chip";
        chip.textContent = text;
        contextRow.appendChild(chip);
    }

    /* ---------- CHAT SYSTEM ---------- */

    function formatMessage(text) {
        if (!text) return "";
        let formatted = UI.escapeHTML(text);
        formatted = formatted.replace(/### (.*?)\n/g, '<h4 style="margin:8px 0 4px 0; color:#ff8a3d;">$1</h4>');
        formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        formatted = formatted.replace(/`([^`]+)`/g, '<code style="background:rgba(0,0,0,0.4); padding:2px 5px; border-radius:4px; font-size:0.85em;">$1</code>');
        formatted = formatted.replace(/\n/g, '<br>');
        return formatted;
    }

    function say(role, text) {
        if (!chat) return null;
        const bubble = document.createElement("div");
        bubble.className = "bubble " + role;
        bubble.innerHTML = role === "ai" ? formatMessage(text) : UI.escapeHTML(text);
        chat.appendChild(bubble);
        chat.scrollTop = chat.scrollHeight;
        return bubble;
    }

    async function send(text) {
        if (!text) return;

        say("user", text);
        history.push({ role: "user", content: text });
        if (input) input.value = "";
        if (sendBtn) sendBtn.disabled = true;

        const pending = document.createElement("div");
        pending.className = "bubble ai typing";
        pending.textContent = "Analyzing security context with EthioSec AI…";
        chat.appendChild(pending);
        chat.scrollTop = chat.scrollHeight;

        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://127.0.0.1:8000/api/ai/chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`
                },
                body: JSON.stringify({
                    message: text,
                    scan_id: scanId || null,
                    finding_id: findingId || null,
                    history: history.slice(-6)
                })
            });

            pending.remove();

            if (!res.ok) {
                let errText = "AI service is currently unavailable.";
                try {
                    const eData = await res.json();
                    if (eData.detail) errText = eData.detail;
                } catch(_) {}
                say("ai", `⚠ ${errText}`);
                return;
            }

            const data = await res.json();
            const reply = data.reply || "No response received.";
            say("ai", reply);
            history.push({ role: "assistant", content: reply });

        } catch (error) {
            console.error("AI Assistant request error:", error);
            pending.remove();
            say("ai", "⚠ Network error: Could not reach the EthioSec backend server.");
        } finally {
            if (sendBtn) sendBtn.disabled = false;
            if (input) input.focus();
        }
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

    await buildContext();
});
