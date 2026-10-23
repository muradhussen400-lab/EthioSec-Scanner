/* ==========================================================================
   ETHIOSECSCAN — AI SECURITY ASSISTANT CONTROLLER (assistantjava.js)
   Real Backend AI Integration via FastAPI (/api/ai/chat) & Gemini Intelligence
   Scan-Aware Context Binding · Safe DOM Rendering · Error Resilience
   ========================================================================== */

document.addEventListener("DOMContentLoaded", async () => {
    "use strict";

    const API_BASE = "http://127.0.0.1:8000/api";

    function getAuthToken() {
        const token = localStorage.getItem("token");
        if (!token) {
            window.location.href = "login.html";
            return "";
        }
        return token;
    }

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
        getQueryParam: (name) => {
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get(name);
        },
        toast: (msg, type = "info") => {
            const toastEl = document.getElementById("toast");
            if (toastEl) {
                toastEl.textContent = msg;
                toastEl.className = `toast show ${type === "error" ? "error" : ""}`;
                setTimeout(() => toastEl.classList.remove("show"), 3500);
            }
        }
    };

    // DOM Elements
    const scanSelect = document.getElementById("scanSelect");
    const contextDetails = document.getElementById("contextDetails");
    const ctxTarget = document.getElementById("ctxTarget");
    const ctxScore = document.getElementById("ctxScore");
    const ctxFindings = document.getElementById("ctxFindings");
    const ctxFindingStat = document.getElementById("ctxFindingStat");
    const ctxFindingBadge = document.getElementById("ctxFindingBadge");
    const btnClearContext = document.getElementById("btnClearContext");
    const linkToResults = document.getElementById("linkToResults");

    const chatMessages = document.getElementById("chatMessages");
    const chatSuggestions = document.getElementById("chatSuggestions");
    const chatForm = document.getElementById("chatForm");
    const chatInput = document.getElementById("chatInput");
    const sendBtn = document.getElementById("sendBtn");
    const btnClearChat = document.getElementById("btnClearChat");
    const chatStatusText = document.getElementById("chatStatusText");

    // State Variables
    let activeScanId = UI.getQueryParam("scan") || UI.getQueryParam("scan_id") || null;
    let activeFindingId = UI.getQueryParam("finding") || UI.getQueryParam("finding_id") || null;
    let activeFindingData = null;
    let userScans = [];
    let conversationHistory = [];
    let isRequestInProgress = false;
    let lastSentMessage = "";

    /* =====================================================
       1. INITIALIZE SCAN CONTEXT SELECTOR & AUTHENTICATION
       ===================================================== */
    async function initScanSelector() {
        const token = getAuthToken();
        if (!token) return;

        try {
            const res = await fetch(`${API_BASE}/scans?limit=50`, {
                headers: { "Authorization": `Bearer ${token}` }
            });

            if (res.status === 401 || res.status === 403) {
                window.location.href = "login.html";
                return;
            }

            if (res.ok) {
                const data = await res.json();
                userScans = data.scans || [];
                populateScanDropdown();
            }
        } catch (err) {
            console.warn("[AI Assistant] Could not retrieve scan list:", err);
        }

        // Check if query param finding exists first (priority focus)
        if (activeFindingId) {
            await fetchFindingAndFocus(activeFindingId);
        } else if (activeScanId) {
            applyActiveScan(activeScanId);
        } else {
            renderGeneralWelcome();
        }
    }

    async function fetchFindingAndFocus(findingId) {
        const token = getAuthToken();
        try {
            const res = await fetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}`, {
                headers: { "Authorization": `Bearer ${token}` }
            });

            if (res.ok) {
                const data = await res.json();
                activeFindingData = data.finding;
                if (activeFindingData) {
                    if (!activeScanId && activeFindingData.scan_id) {
                        activeScanId = activeFindingData.scan_id;
                    }

                    // Apply parent scan context
                    applyActiveScan(activeScanId);

                    // Show active finding focus in header badge
                    if (ctxFindingStat && ctxFindingBadge) {
                        ctxFindingStat.style.display = "flex";
                        const sev = (activeFindingData.severity || "info").toUpperCase();
                        ctxFindingBadge.textContent = `${sev}: ${activeFindingData.title}`;
                        ctxFindingBadge.title = activeFindingData.title;
                    }

                    if (linkToResults && activeScanId) {
                        linkToResults.href = `results.html?id=${encodeURIComponent(activeScanId)}`;
                        linkToResults.style.display = "inline-flex";
                    }

                    renderFindingSpecificWelcome(activeFindingData);

                    // Automatically start structured technical explanation request
                    const prompt = `Explain the finding "${activeFindingData.title}" (${(activeFindingData.severity || "info").toUpperCase()} on ${activeFindingData.url || "target"}): explain what the scanner actually observed, analyze the evidence, explain demonstrated impact vs potential impact, and provide practical remediation code.`;
                    setTimeout(() => {
                        sendMessage(prompt);
                    }, 350);
                    return;
                }
            }
        } catch (e) {
            console.error("Could not fetch finding details:", e);
        }

        // Fallback if finding fetch failed
        if (activeScanId) applyActiveScan(activeScanId);
        else renderGeneralWelcome();
    }

    function populateScanDropdown() {
        if (!scanSelect) return;

        scanSelect.innerHTML = `<option value="">General Cybersecurity Assistant (No scan selected)</option>`;

        userScans.forEach(scan => {
            const opt = document.createElement("option");
            opt.value = scan.id;

            const counts = scan.counts || {};
            const cHigh = Number(counts.high || 0) + Number(counts.critical || 0);
            const cMed = Number(counts.medium || 0);
            const scoreText = scan.security_score !== null && scan.security_score !== undefined ? `${scan.security_score}/100` : "Score: —";

            opt.textContent = `${scan.target} — ${scoreText} (${cHigh} High, ${cMed} Med) — #${scan.id.slice(0, 8)}`;
            if (activeScanId && scan.id === activeScanId) {
                opt.selected = true;
            }
            scanSelect.appendChild(opt);
        });
    }

    function applyActiveScan(scanId) {
        if (!scanId) {
            clearScanContext();
            return;
        }

        activeScanId = scanId;
        const scan = userScans.find(s => s.id === scanId);

        if (scanSelect) {
            scanSelect.value = scanId;
        }

        if (contextDetails) {
            contextDetails.style.display = "flex";
        }

        if (linkToResults) {
            linkToResults.href = `results.html?id=${encodeURIComponent(scanId)}`;
            linkToResults.style.display = "inline-flex";
        }

        if (scan) {
            if (ctxTarget) {
                ctxTarget.textContent = scan.target;
                ctxTarget.href = scan.target.startsWith("http") ? scan.target : `https://${scan.target}`;
            }
            if (ctxScore) {
                const score = scan.security_score !== null && scan.security_score !== undefined ? Number(scan.security_score) : null;
                ctxScore.textContent = score !== null ? `${score} Score` : "In Progress";
                ctxScore.className = "stat-badge " + (score >= 80 ? "score-good" : score >= 60 ? "score-mid" : "score-bad");
            }
            if (ctxFindings) {
                const c = scan.counts || {};
                const cHigh = Number(c.high || 0) + Number(c.critical || 0);
                const cMed = Number(c.medium || 0);
                const cLow = Number(c.low || 0);
                ctxFindings.textContent = `${cHigh} High, ${cMed} Med, ${cLow} Low`;
            }
        } else {
            // Scan not yet in cache, fetch single status
            fetchScanDetails(scanId);
        }

        if (!activeFindingId) {
            renderScanSpecificWelcome(scan);
        }
        renderSuggestions(true);
    }

    async function fetchScanDetails(scanId) {
        const token = getAuthToken();
        try {
            const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/status`, {
                headers: { "Authorization": `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                if (ctxTarget) {
                    ctxTarget.textContent = data.target;
                    ctxTarget.href = data.target.startsWith("http") ? data.target : `https://${data.target}`;
                }
                if (ctxScore) {
                    ctxScore.textContent = (data.status || "").toUpperCase();
                }
            }
        } catch (_) {}
    }

    function clearScanContext() {
        activeScanId = null;
        activeFindingId = null;
        activeFindingData = null;
        if (scanSelect) scanSelect.value = "";
        if (contextDetails) contextDetails.style.display = "none";
        if (ctxFindingStat) ctxFindingStat.style.display = "none";
        if (linkToResults) linkToResults.style.display = "none";

        history.replaceState(null, "", "assistant.html");
        renderGeneralWelcome();
        renderSuggestions(false);
    }

    function renderFindingSpecificWelcome(finding) {
        if (!chatMessages) return;
        chatMessages.innerHTML = "";

        const empty = document.createElement("div");
        empty.className = "chat-empty-state";
        empty.innerHTML = `
            <div class="empty-state-shield" style="border-color: rgba(232, 59, 37, 0.4); background: rgba(232, 59, 37, 0.1);">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--brand-red)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <circle cx="12" cy="11" r="1"></circle>
                    <line x1="12" y1="7" x2="12" y2="9"></line>
                </svg>
            </div>
            <h3>Finding Focus: ${UI.escapeHTML(finding.title)}</h3>
            <p>Loaded verified probe evidence and endpoint telemetry for <code class="inline-code">${UI.escapeHTML(finding.url || "audited endpoint")}</code>. EthioSec AI is generating a technical risk analysis and concrete remediation code below.</p>
        `;
        chatMessages.appendChild(empty);
    }

    // Event listener for Scan Dropdown change
    if (scanSelect) {
        scanSelect.addEventListener("change", (e) => {
            const selectedVal = e.target.value;
            if (selectedVal) {
                history.replaceState(null, "", `assistant.html?scan_id=${encodeURIComponent(selectedVal)}`);
                applyActiveScan(selectedVal);
            } else {
                clearScanContext();
            }
        });
    }

    if (btnClearContext) {
        btnClearContext.addEventListener("click", () => {
            clearScanContext();
            UI.toast("Context reset to General Cybersecurity Assistant.");
        });
    }

    /* =====================================================
       2. SUGGESTION CHIPS & EMPTY STATES
       ===================================================== */
    function renderSuggestions(isScanSelected) {
        if (!chatSuggestions) return;
        chatSuggestions.innerHTML = "";

        const scanPrompts = [
            "Summarize verified findings for this scan",
            "What are the highest risk vulnerabilities and their impact?",
            "Provide step-by-step remediation code for detected issues",
            "Are there any inconclusive checks requiring manual testing?",
            "Explain the attack surface and exposed endpoints found"
        ];

        const generalPrompts = [
            "How do I prevent SQL Injection in backend APIs?",
            "Explain OWASP Top 10 A01: Broken Access Control & IDOR",
            "What security headers should every modern web application send?",
            "How does Content-Security-Policy mitigate XSS attacks?",
            "Best practices for secure JWT session invalidation"
        ];

        const prompts = isScanSelected ? scanPrompts : generalPrompts;

        prompts.forEach(p => {
            const chip = document.createElement("button");
            chip.type = "button";
            chip.className = "suggestion-chip";
            chip.textContent = p;
            chip.addEventListener("click", () => {
                if (chatInput) chatInput.value = p;
                sendMessage(p);
            });
            chatSuggestions.appendChild(chip);
        });
    }

    function renderGeneralWelcome() {
        if (!chatMessages) return;
        chatMessages.innerHTML = "";

        const empty = document.createElement("div");
        empty.className = "chat-empty-state";
        empty.innerHTML = `
            <div class="empty-state-shield">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4" stroke-width="2"/>
                </svg>
            </div>
            <h3>EthioSec AI Assistant</h3>
            <p>I am your application security co-pilot powered by Gemini. Ask any technical cybersecurity question, request code patches, or select an active scan above to ground answers in verified scanner evidence.</p>
        `;
        chatMessages.appendChild(empty);
        renderSuggestions(false);
    }

    function renderScanSpecificWelcome(scan) {
        if (!chatMessages) return;
        chatMessages.innerHTML = "";

        const target = scan ? scan.target : (activeScanId ? `#${activeScanId.slice(0, 8)}` : "selected target");
        const empty = document.createElement("div");
        empty.className = "chat-empty-state";
        empty.innerHTML = `
            <div class="empty-state-shield">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="11" width="18" height="10" rx="2"></rect>
                    <circle cx="12" cy="5" r="2"></circle>
                    <path d="M12 7v4"></path>
                    <line x1="8" y1="16" x2="8" y2="16"></line>
                    <line x1="16" y1="16" x2="16" y2="16"></line>
                </svg>
            </div>
            <h3>Assessment Context Linked: ${UI.escapeHTML(target)}</h3>
            <p>EthioSec AI has loaded your scanner telemetry. You can ask for technical root causes, verified payload evidence, exploit vectors, or tailored remediation code for this scan.</p>
        `;
        chatMessages.appendChild(empty);
    }

    /* =====================================================
       3. MESSAGE RENDERING & SAFE MARKDOWN PARSER
       ===================================================== */

    function appendUserMessage(text) {
        if (!chatMessages) return;

        // Remove empty state if present
        const empty = chatMessages.querySelector(".chat-empty-state");
        if (empty) empty.remove();

        const row = document.createElement("div");
        row.className = "msg-row user";

        const avatar = document.createElement("div");
        avatar.className = "msg-avatar";
        const storedName = localStorage.getItem("userName") || "User";
        const initials = storedName.split(" ").map(n => n[0]).join("").slice(0, 2).toUpperCase() || "U";
        avatar.textContent = initials;

        const bodyWrapper = document.createElement("div");
        bodyWrapper.className = "msg-body-wrapper";

        const bubble = document.createElement("div");
        bubble.className = "msg-bubble";
        bubble.textContent = text; // 100% immune to XSS, textContent only

        const meta = document.createElement("div");
        meta.className = "msg-meta";
        meta.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        bodyWrapper.appendChild(bubble);
        bodyWrapper.appendChild(meta);
        row.appendChild(avatar);
        row.appendChild(bodyWrapper);

        chatMessages.appendChild(row);
        scrollToBottom();
    }

    function formatAIMarkdown(rawText) {
        if (!rawText) return "";

        // Step 1: Escape all raw HTML entities first to guarantee XSS prevention
        let safe = UI.escapeHTML(rawText);

        // Step 2: Extract & replace fenced code blocks ```lang\ncode\n```
        const codeBlocks = [];
        safe = safe.replace(/```([a-zA-Z0-9_\-\+]*)\n?([\s\S]*?)```/g, (match, lang, code) => {
            const placeholder = `__CODE_BLOCK_${codeBlocks.length}__`;
            codeBlocks.push({ lang: lang || "code", code: code.trim() });
            return placeholder;
        });

        // Step 3: Inline code `code`
        safe = safe.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

        // Step 4: Headings ### Title or ## Title
        safe = safe.replace(/^### (.*$)/gim, '<h4>$1</h4>');
        safe = safe.replace(/^## (.*$)/gim, '<h4>$1</h4>');

        // Step 5: Bold text **bold**
        safe = safe.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

        // Step 6: Bullet list items
        safe = safe.replace(/^\s*[\-\*]\s+(.*)$/gim, '<li>$1</li>');
        safe = safe.replace(/(<li>.*<\/li>(\s*<li>.*<\/li>)*)/gim, '<ul>$1</ul>');

        // Step 7: Linebreaks
        safe = safe.replace(/\n\n+/g, '<br><br>');
        safe = safe.replace(/([^\n])\n([^\n])/g, '$1<br>$2');

        // Step 8: Re-insert safe syntax-highlighted code blocks with Copy button
        codeBlocks.forEach((block, idx) => {
            const html = `
                <div class="code-block-container">
                    <div class="code-header">
                        <span class="code-lang">${UI.escapeHTML(block.lang)}</span>
                        <button type="button" class="btn-copy-code" data-code="${UI.escapeHTML(block.code)}">Copy Code</button>
                    </div>
                    <pre><code>${block.code}</code></pre>
                </div>
            `;
            safe = safe.replace(`__CODE_BLOCK_${idx}__`, html);
        });

        return safe;
    }

    function appendAIMessage(text) {
        if (!chatMessages) return;

        const row = document.createElement("div");
        row.className = "msg-row ai";

        const avatar = document.createElement("div");
        avatar.className = "msg-avatar";
        avatar.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;

        const bodyWrapper = document.createElement("div");
        bodyWrapper.className = "msg-body-wrapper";

        const bubble = document.createElement("div");
        bubble.className = "msg-bubble";
        bubble.innerHTML = formatAIMarkdown(text);

        // Wire Copy buttons in code blocks
        bubble.querySelectorAll(".btn-copy-code").forEach(btn => {
            btn.addEventListener("click", () => {
                const code = btn.getAttribute("data-code");
                if (code) {
                    navigator.clipboard.writeText(code).then(() => {
                        const orig = btn.textContent;
                        btn.textContent = "Copied ✓";
                        setTimeout(() => { btn.textContent = orig; }, 2000);
                    }).catch(() => {
                        UI.toast("Could not copy to clipboard", "error");
                    });
                }
            });
        });

        const meta = document.createElement("div");
        meta.className = "msg-meta";
        meta.textContent = "EthioSec AI · " + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        bodyWrapper.appendChild(bubble);
        bodyWrapper.appendChild(meta);
        row.appendChild(avatar);
        row.appendChild(bodyWrapper);

        chatMessages.appendChild(row);
        scrollToBottom();
    }

    function showTypingIndicator() {
        if (!chatMessages) return null;

        const row = document.createElement("div");
        row.className = "msg-row ai typing";
        row.id = "typingRow";

        const avatar = document.createElement("div");
        avatar.className = "msg-avatar";
        avatar.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;

        const bodyWrapper = document.createElement("div");
        bodyWrapper.className = "msg-body-wrapper";

        const bubble = document.createElement("div");
        bubble.className = "msg-bubble";
        bubble.innerHTML = `
            <span>Analyzing security context with EthioSec AI</span>
            <span class="typing-dots">
                <span class="typing-dot"></span>
                <span class="typing-dot"></span>
                <span class="typing-dot"></span>
            </span>
        `;

        bodyWrapper.appendChild(bubble);
        row.appendChild(avatar);
        row.appendChild(bodyWrapper);

        chatMessages.appendChild(row);
        scrollToBottom();
        return row;
    }

    function removeTypingIndicator() {
        const typingEl = document.getElementById("typingRow");
        if (typingEl) typingEl.remove();
    }

    function appendErrorMessage(errorMsg, canRetry = true) {
        if (!chatMessages) return;

        const row = document.createElement("div");
        row.className = "msg-row ai";

        const avatar = document.createElement("div");
        avatar.className = "msg-avatar";
        avatar.style.borderColor = "var(--brand-red)";
        avatar.style.color = "var(--brand-red)";
        avatar.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

        const bodyWrapper = document.createElement("div");
        bodyWrapper.className = "msg-body-wrapper";

        const bubble = document.createElement("div");
        bubble.className = "msg-bubble error-bubble";

        const titleDiv = document.createElement("div");
        titleDiv.style.fontWeight = "700";
        titleDiv.style.marginBottom = "4px";
        titleDiv.textContent = "Request Failed";

        const descDiv = document.createElement("div");
        descDiv.textContent = errorMsg;

        bubble.appendChild(titleDiv);
        bubble.appendChild(descDiv);

        if (canRetry && lastSentMessage) {
            const actionsDiv = document.createElement("div");
            actionsDiv.className = "error-actions";

            const retryBtn = document.createElement("button");
            retryBtn.type = "button";
            retryBtn.className = "btn-retry";
            retryBtn.textContent = "↺ Retry Message";
            retryBtn.addEventListener("click", () => {
                row.remove();
                sendMessage(lastSentMessage);
            });

            actionsDiv.appendChild(retryBtn);
            bubble.appendChild(actionsDiv);
        }

        bodyWrapper.appendChild(bubble);
        row.appendChild(avatar);
        row.appendChild(bodyWrapper);

        chatMessages.appendChild(row);
        scrollToBottom();
    }

    function scrollToBottom() {
        if (chatMessages) {
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    }

    /* =====================================================
       4. SEND MESSAGE & REAL BACKEND DISPATCH
       ===================================================== */
    async function sendMessage(text) {
        if (!text || !text.trim() || isRequestInProgress) return;

        const trimmed = text.trim();
        lastSentMessage = trimmed;
        isRequestInProgress = true;

        appendUserMessage(trimmed);
        conversationHistory.push({ role: "user", content: trimmed });

        if (chatInput) {
            chatInput.value = "";
            chatInput.style.height = "auto";
        }
        if (sendBtn) sendBtn.disabled = true;
        if (chatStatusText) chatStatusText.textContent = "Gemini Security Intelligence · Generating…";

        showTypingIndicator();

        const token = getAuthToken();

        try {
            const payload = {
                message: trimmed,
                scan_id: activeScanId || null,
                finding_id: activeFindingId || null,
                history: conversationHistory.slice(-6)
            };

            const res = await fetch(`${API_BASE}/ai/chat`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`
                },
                body: JSON.stringify(payload)
            });

            removeTypingIndicator();

            if (res.status === 401 || res.status === 403) {
                appendErrorMessage("Your session has expired or you are not authorized to view this scan. Please log in again.", false);
                setTimeout(() => { window.location.href = "login.html"; }, 3000);
                return;
            }

            if (res.status === 404) {
                appendErrorMessage("The requested scan or finding was not found. It may have been deleted.", false);
                return;
            }

            if (res.status === 429) {
                appendErrorMessage("The AI Assistant rate limit has been reached. Please wait 30 seconds before sending another question.");
                return;
            }

            if (!res.ok) {
                let detail = "AI Assistant service error.";
                try {
                    const errData = await res.json();
                    if (errData.detail) detail = errData.detail;
                } catch (_) {}
                appendErrorMessage(detail);
                return;
            }

            const data = await res.json();
            const reply = data.reply || "No response generated.";
            appendAIMessage(reply);
            conversationHistory.push({ role: "assistant", content: reply });

        } catch (err) {
            console.error("AI Assistant network error:", err);
            removeTypingIndicator();
            appendErrorMessage("Could not connect to the EthioSec backend server. Please verify the backend service is running on port 8000.");
        } finally {
            isRequestInProgress = false;
            if (sendBtn) sendBtn.disabled = false;
            if (chatStatusText) chatStatusText.textContent = "Gemini Security Intelligence · Ready";
            if (chatInput) chatInput.focus();
        }
    }

    /* =====================================================
       5. COMPOSER & EVENT HANDLERS
       ===================================================== */
    if (chatForm) {
        chatForm.addEventListener("submit", (e) => {
            e.preventDefault();
            if (chatInput) sendMessage(chatInput.value);
        });
    }

    if (chatInput) {
        chatInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage(chatInput.value);
            }
        });

        // Auto-expand textarea
        chatInput.addEventListener("input", () => {
            chatInput.style.height = "auto";
            chatInput.style.height = Math.min(chatInput.scrollHeight, 140) + "px";
        });
    }

    if (btnClearChat) {
        btnClearChat.addEventListener("click", () => {
            conversationHistory = [];
            lastSentMessage = "";
            if (activeScanId) {
                const scan = userScans.find(s => s.id === activeScanId);
                renderScanSpecificWelcome(scan);
            } else {
                renderGeneralWelcome();
            }
            UI.toast("Conversation history reset.");
        });
    }

    // Startup Execution
    await initScanSelector();
});
