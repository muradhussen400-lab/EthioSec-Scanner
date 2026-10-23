/* ==============================================================================
   ETHIOSECSCAN — DEPRECATED LEGACY MOCK FIXTURE (mockapi.js)
   STATUS: DISABLED / DEPRECATED IN NORMAL APPLICATION OPERATION.
   EthioSecScan is strictly integrated with the live FastAPI backend.
   This file is retained exclusively as an isolated offline dev fixture.
   ============================================================================== */

window.EthioMock = (() => {

    const DB_KEY = "ethio_mock_db";
    const LATENCY = 200; // ms

    /* ---------------- storage ---------------- */

    function db() {
        try {
            const raw = localStorage.getItem(DB_KEY);
            return raw ? JSON.parse(raw) : seed();
        } catch {
            return seed();
        }
    }

    function save(data) {
        try {
            localStorage.setItem(DB_KEY, JSON.stringify(data));
        } catch (e) {
            console.warn("Storage quota exceeded or disabled", e);
        }
        return data;
    }

    function seed() {
        return save({
            users: [],
            scans: [
                {
                    id: "demo_scan_01",
                    target: "https://demo.ethio-security.org",
                    depth: "standard",
                    modules: { headers: true, ssl: true, dns: true, meta: true },
                    status: "completed",
                    created_at: Date.now() - 3600000,
                    started_at: Date.now() - 3600000,
                    duration_ms: 11000,
                    finished_at: Date.now() - 3589000,
                    security_score: 72,
                    counts: { critical: 1, high: 2, medium: 2, low: 3, passed: 14, total: 8 },
                    findings: []
                }
            ],
            settings: null,
            nextId: 2
        });
    }

    function wait(ms) {
        return new Promise(r => setTimeout(r, ms));
    }

    function fail(message, status = 400) {
        const err = new Error(message);
        err.status = status;
        return err;
    }

    /* ---------------- helpers ---------------- */

    function hash(str) {
        let h = 0;
        const s = String(str);
        for (let i = 0; i < s.length; i++) {
            h = (h << 5) - h + s.charCodeAt(i);
            h |= 0;
        }
        return Math.abs(h);
    }

    function hostOf(url) {
        try {
            const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
            return parsed.hostname;
        } catch {
            return String(url);
        }
    }

    function currentUser() {
        try {
            const raw = localStorage.getItem("ethio_user");
            if (raw) return JSON.parse(raw);
            const email = localStorage.getItem("userEmail");
            if (email) return { full_name: email.split("@")[0], email, role: "Security Analyst" };
        } catch {
            // fallback
        }
        return { full_name: "Security Analyst", email: "analyst@ethiosec.local", role: "Security Analyst" };
    }

    function durationFor(depth) {
        return depth === "quick" ? 5000 : depth === "deep" ? 12000 : 8000;
    }

    /* =====================================================
       FINDINGS GENERATOR
       ===================================================== */

    const SEVERITY_WEIGHT = { critical: 25, high: 14, medium: 7, low: 3, info: 0 };

    function buildFindings(scan) {
        const seedVal = hash(scan.target);
        const secure = /^https:/i.test(scan.target);
        const m = scan.modules || {};
        const out = [];
        let n = 0;

        const add = (f) => out.push(Object.assign({
            id: `${scan.id}-f${++n}`,
            scan_id: scan.id,
            url: scan.target,
            parameter: null,
            confidence: "high",
            status: "open"
        }, f));

        /* --- Transport --- */
        if (secure) {
            add({
                type: "transport", severity: "info", status: "passed",
                title: "HTTPS Enabled",
                description: "All traffic to the target is served over TLS.",
                evidence: "301 http://" + hostOf(scan.target) + " → https://" + hostOf(scan.target),
                impact: "No action needed.",
                remediation: [],
                owasp: "A02:2021 – Cryptographic Failures", cwe: "CWE-319",
                ai_explanation: "The site redirects insecure requests to HTTPS, so credentials and session cookies cannot be read in transit."
            });
        } else {
            add({
                type: "transport", severity: "critical",
                title: "Site Served Over Plain HTTP",
                description: "The target responds on HTTP with no redirect to HTTPS.",
                evidence: "GET / HTTP/1.1 → 200 OK (no Strict-Transport-Security, no redirect)",
                impact: "Anyone on the network path can intercept or tamper with unencrypted plaintext traffic.",
                remediation: [
                    "Install a valid TLS certificate.",
                    "Redirect all HTTP traffic to HTTPS via 301 Permanent Redirect.",
                    "Enable HTTP Strict Transport Security (HSTS)."
                ],
                owasp: "A02:2021 – Cryptographic Failures", cwe: "CWE-319",
                ai_explanation: "Plain HTTP leaves all session parameters exposed to eavesdropping and MITM attacks."
            });
        }

        /* --- Security Headers --- */
        if (m.headers !== false) {
            const missing = seedVal % 3;
            if (missing === 0) {
                add({
                    type: "headers", severity: "info", status: "passed",
                    title: "Security Headers Present",
                    description: "CSP, HSTS and X-Frame-Options are configured.",
                    evidence: "content-security-policy: default-src 'self'",
                    impact: "No action needed.", remediation: [],
                    owasp: "A05:2021 – Security Misconfiguration", cwe: "CWE-16",
                    ai_explanation: "Key defensive HTTP headers are enforced."
                });
            } else {
                add({
                    type: "headers", severity: "medium", confidence: "high",
                    title: missing === 1 ? "Content-Security-Policy Not Set" : "HSTS Header Missing",
                    description: missing === 1
                        ? "No Content-Security-Policy header was returned by the web server."
                        : "Strict-Transport-Security header is not enforced.",
                    evidence: "HTTP/1.1 200 OK\n(missing defensive header)",
                    impact: "Increases exposure to cross-site scripting (XSS) and protocol downgrade exploits.",
                    remediation: [
                        "Configure a restrictive Content-Security-Policy header.",
                        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."
                    ],
                    owasp: "A05:2021 – Security Misconfiguration", cwe: "CWE-693",
                    ai_explanation: "Response headers inform browser security contexts to reject unauthorized inline executions."
                });
            }
        }

        /* --- Injection Checks --- */
        if (scan.depth !== "quick") {
            add({
                type: "injection", severity: "critical", confidence: "high",
                parameter: "id",
                url: scan.target.replace(/\/$/, "") + "/api/item?id=1",
                title: "SQL Injection Vulnerability",
                description: "Dynamic SQL constructed with direct concatenation of client parameters.",
                evidence: "GET /api/item?id=1' → 500 Syntax error near line 1",
                impact: "Full arbitrary database disclosure, credential exfiltration, and administrative compromise.",
                remediation: [
                    "Implement parameterized prepared statements across all queries.",
                    "Use ORM parameter binding and enforce strict input casting."
                ],
                owasp: "A03:2021 – Injection", cwe: "CWE-89",
                ai_explanation: "Untrusted input escapes string literals and executes directly inside the query execution engine."
            });
        }

        return out;
    }

    function scoreOf(findings) {
        let score = 100;
        findings.filter(f => f.status !== "passed").forEach(f => {
            score -= SEVERITY_WEIGHT[f.severity] || 0;
        });
        return Math.max(10, Math.min(100, score));
    }

    function countsOf(findings) {
        const open = findings.filter(f => f.status !== "passed");
        return {
            critical: open.filter(f => f.severity === "critical").length,
            high: open.filter(f => f.severity === "high").length,
            medium: open.filter(f => f.severity === "medium").length,
            low: open.filter(f => f.severity === "low").length,
            passed: findings.filter(f => f.status === "passed").length,
            total: open.length
        };
    }

    /* ---------------- Lifecycle ---------------- */

    const STAGES = [
        { until: 15, status: "queued", stage: "Queued — waiting for a scanner worker" },
        { until: 40, status: "running", stage: "Crawling pages and mapping endpoints" },
        { until: 70, status: "running", stage: "Running active OWASP test vectors" },
        { until: 90, status: "analyzing", stage: "AI engine generating remediation guidance" },
        { until: 100, status: "completed", stage: "Finalizing scoring and report" }
    ];

    function progressOf(scan) {
        if (scan.status === "completed" || scan.status === "cancelled" || scan.status === "failed") {
            return 100;
        }
        const elapsed = Date.now() - scan.started_at;
        return Math.max(5, Math.min(100, Math.round((elapsed / scan.duration_ms) * 100)));
    }

    function refresh(scan, data) {
        if (scan.status === "completed" || scan.status === "cancelled" || scan.status === "failed") {
            return scan;
        }

        const p = progressOf(scan);
        if (p >= 100) {
            const findings = buildFindings(scan);
            scan.findings = findings;
            scan.security_score = scoreOf(findings);
            scan.counts = countsOf(findings);
            scan.status = "completed";
            scan.finished_at = Date.now();
            save(data);
        }
        return scan;
    }

    /* ---------------- Router ---------------- */

    async function handle(method, rawPath, body = {}) {
        await wait(LATENCY);

        const [path, query] = rawPath.split("?");
        const params = new URLSearchParams(query || "");
        const data = db();
        const route = `${method.toUpperCase()} ${path}`;

        /* --- Auth --- */
        if (route === "POST /auth/login" || route === "POST /auth/register") {
            const email = body.email || "analyst@ethiosec.local";
            const user = {
                id: "u1",
                full_name: body.full_name || email.split("@")[0],
                email: email,
                role: "Security Administrator"
            };
            localStorage.setItem("isLoggedIn", "true");
            localStorage.setItem("userEmail", email);
            localStorage.setItem("ethio_user", JSON.stringify(user));
            return { token: "mock-token-session", user };
        }

        if (route === "GET /auth/me") {
            return { user: currentUser() };
        }

        /* --- Dashboard --- */
        if (route === "GET /dashboard/summary") {
            const done = data.scans.filter(s => refresh(s, data).status === "completed");
            const latest = done[0] || null;
            const c = latest ? latest.counts : { critical: 0, high: 0, medium: 0, low: 0, passed: 0, total: 0 };

            return {
                security_score: latest ? latest.security_score : 85,
                last_scan: latest ? new Date(latest.finished_at).toISOString() : new Date().toISOString(),
                last_target: latest ? latest.target : "https://demo.ethio-security.org",
                vulnerabilities: c.critical + c.high,
                warnings: c.medium + c.low,
                passed_checks: c.passed || 20,
                issues: c.total || 3,
                total_scans: done.length || 1,
                breakdown: {
                    security: latest ? latest.security_score : 85,
                    performance: 92,
                    seo: 84
                },
                range: {
                    labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                    mine: [3, 5, 8, 4, 7, 2, 6],
                    all: [10, 14, 18, 12, 20, 8, 15],
                    trendLabels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                    trend: [120, 180, 290, 240, 410, 300, 470],
                    websites: 8,
                    requests: 1245,
                    response: 234
                }
            };
        }

        /* --- Scans --- */
        if (route === "GET /scans") {
            const limit = Number(params.get("limit")) || 50;
            const scans = data.scans
                .map(s => refresh(s, data))
                .sort((a, b) => b.created_at - a.created_at)
                .slice(0, limit)
                .map(s => ({
                    id: s.id,
                    target: s.target,
                    status: s.status,
                    depth: s.depth,
                    created_at: new Date(s.created_at).toISOString(),
                    finished_at: s.finished_at ? new Date(s.finished_at).toISOString() : null,
                    security_score: s.security_score,
                    counts: s.counts
                }));
            return { scans, total: data.scans.length };
        }

        if (route === "POST /scans") {
            if (!body.target) throw fail("A target URL is required.");

            const scan = {
                id: "s" + data.nextId++,
                target: body.target,
                depth: body.depth || "standard",
                modules: body.modules || { headers: true, ssl: true, dns: true, meta: true },
                status: "queued",
                created_at: Date.now(),
                started_at: Date.now(),
                duration_ms: durationFor(body.depth),
                finished_at: null,
                security_score: null,
                counts: null,
                findings: []
            };

            data.scans.unshift(scan);
            save(data);
            return { scan_id: scan.id, status: scan.status };
        }

        let m;

        if ((m = path.match(/^\/scans\/([^/]+)\/status$/)) && method.toUpperCase() === "GET") {
            const scan = data.scans.find(s => s.id === m[1]);
            if (!scan) throw fail("Scan not found.", 404);
            refresh(scan, data);

            const p = progressOf(scan);
            const phase = STAGES.find(s => p <= s.until) || STAGES[STAGES.length - 1];

            return {
                scan_id: scan.id,
                target: scan.target,
                status: scan.status,
                progress: p,
                stage: scan.status === "completed" ? "Scan complete" : phase.stage,
                checks: {
                    headers: p > 25,
                    ssl: p > 45,
                    dns: p > 60,
                    meta: p > 75,
                    owasp: p > 85,
                    ai: p >= 100
                }
            };
        }

        if ((m = path.match(/^\/scans\/([^/]+)\/results$/)) && method.toUpperCase() === "GET") {
            const scan = data.scans.find(s => s.id === m[1]);
            if (!scan) throw fail("Scan not found.", 404);
            refresh(scan, data);

            if (scan.status !== "completed") throw fail("Scan is still running.", 409);

            return {
                scan_id: scan.id,
                target: scan.target,
                depth: scan.depth,
                scanned_at: new Date(scan.finished_at).toISOString(),
                security_score: scan.security_score,
                counts: scan.counts,
                findings: scan.findings
            };
        }

        if ((m = path.match(/^\/scans\/([^/]+)$/)) && method.toUpperCase() === "DELETE") {
            const idx = data.scans.findIndex(s => s.id === m[1]);
            if (idx !== -1) {
                data.scans.splice(idx, 1);
                save(data);
            }
            return { ok: true };
        }

        /* --- AI Assistant --- */
        if (route === "POST /ai/assistant") {
            const q = (body.message || "").toLowerCase();
            let reply = "Ensure strong input sanitization, enforce strict security headers, and verify least-privilege database roles.";

            if (q.includes("fix")) {
                reply = "Address critical vulnerabilities first: replace dynamic SQL string building with prepared statements and verify TLS enforcement.";
            } else if (q.includes("severe") || q.includes("risk")) {
                reply = "Severity corresponds to exploitability: critical flaws permit unauthorized remote access without interaction.";
            } else if (q.includes("owasp")) {
                reply = "OWASP Top 10 classifications identify standard industry security categories (e.g., A03: Injection, A01: Broken Access Control).";
            }

            return {
                reply,
                scan_id: body.scan_id || null,
                finding_id: body.finding_id || null
            };
        }

        throw fail(`No mock route defined for ${route}`, 404);
    }

    return {
        handle,
        reset: seed
    };

})();