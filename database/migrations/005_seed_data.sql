-- ============================================================================
-- Migration: 005_seed_data.sql
-- Description: Complete test fixtures for EthioSec Scanner frontend/backend
-- Target: Supabase (PostgreSQL 15+)
-- ============================================================================

DO $$
DECLARE
    v_user_id UUID := '00000000-0000-0000-0000-000000000001'::uuid;
    v_target1_id UUID := '11111111-1111-1111-1111-111111111111'::uuid;
    v_target2_id UUID := '22222222-2222-2222-2222-222222222222'::uuid;
    v_scan1_id UUID := '33333333-3333-3333-3333-333333333331'::uuid;
    v_scan2_id UUID := '33333333-3333-3333-3333-333333333332'::uuid;
BEGIN
    -- 1. SEED USER (Mocking auth.users entry and profile)
    INSERT INTO auth.users (
        id, instance_id, aud, role, email, encrypted_password, 
        email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at
    ) VALUES (
        v_user_id,
        '00000000-0000-0000-0000-000000000000'::uuid,
        'authenticated',
        'authenticated',
        'john.smith@ethiosec.et',
        crypt('EthioSec2026!SecurePass', gen_salt('bf')),
        NOW(),
        '{"provider": "email", "providers": ["email"]}'::jsonb,
        '{"full_name": "John Smith", "role": "Lead AppSec Engineer"}'::jsonb,
        NOW() - INTERVAL '14 days',
        NOW()
    ) ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.profiles (id, email, full_name, role, website)
    VALUES (
        v_user_id,
        'john.smith@ethiosec.et',
        'John Smith',
        'Lead AppSec Engineer',
        'https://ethiosec.et'
    ) ON CONFLICT (id) DO UPDATE SET
        full_name = EXCLUDED.full_name;

    -- 2. SEED TARGETS
    -- Target 1: Verified Production Banking API
    INSERT INTO public.targets (
        id, user_id, url, normalized_url, verification_token, 
        verification_method, verification_status, verified_at, created_at
    ) VALUES (
        v_target1_id,
        v_user_id,
        'https://api.ethiosec-demo.et',
        'api.ethiosec-demo.et',
        'ethiosec-verify-8f9d72e6b01a',
        'meta_tag',
        'verified',
        NOW() - INTERVAL '10 days',
        NOW() - INTERVAL '12 days'
    ) ON CONFLICT (id) DO NOTHING;

    -- Target 2: Pending Staging Customer Portal
    INSERT INTO public.targets (
        id, user_id, url, normalized_url, verification_token, 
        verification_method, verification_status, verified_at, created_at
    ) VALUES (
        v_target2_id,
        v_user_id,
        'https://portal.bank-staging.et',
        'portal.bank-staging.et',
        'ethiosec-verify-4c2a11b899ff',
        'dns_txt',
        'pending',
        NULL,
        NOW() - INTERVAL '2 days'
    ) ON CONFLICT (id) DO NOTHING;

    -- 3. SEED SCANS
    -- Scan 1: Completed Scan with Findings & Score 64
    INSERT INTO public.scans (
        id, user_id, target_id, target_url, depth, status, progress, 
        stage, security_score, checks, created_at, started_at, finished_at
    ) VALUES (
        v_scan1_id,
        v_user_id,
        v_target1_id,
        'https://api.ethiosec-demo.et',
        'standard',
        'completed',
        100,
        'Completed',
        64,
        '{"headers": true, "ssl": true, "dns": true, "meta": true, "owasp": true, "ai": true}'::jsonb,
        NOW() - INTERVAL '2 days',
        NOW() - INTERVAL '2 days' + INTERVAL '1 minute',
        NOW() - INTERVAL '2 days' + INTERVAL '12 minutes'
    ) ON CONFLICT (id) DO NOTHING;

    -- Scan 2: In-Progress Scan
    INSERT INTO public.scans (
        id, user_id, target_id, target_url, depth, status, progress, 
        stage, security_score, checks, created_at, started_at, finished_at
    ) VALUES (
        v_scan2_id,
        v_user_id,
        v_target2_id,
        'https://portal.bank-staging.et',
        'deep',
        'running',
        65,
        'Testing Business Logic & Access Control',
        NULL,
        '{"headers": true, "ssl": true, "dns": true, "meta": false, "owasp": false, "ai": false}'::jsonb,
        NOW() - INTERVAL '15 minutes',
        NOW() - INTERVAL '14 minutes',
        NULL
    ) ON CONFLICT (id) DO NOTHING;

    -- 4. SEED SCAN MODULES (for Scan 1)
    INSERT INTO public.scan_modules (
        scan_id, module_key, module_name, status, progress,
        execution_order, findings_count, duration_ms
    )
    VALUES
        (v_scan1_id, 'discovery', 'Crawler & Endpoint Discovery', 'completed', 100, 1, 0, 15400),
        (v_scan1_id, 'headers_ssl', 'Security Headers & TLS Validation', 'completed', 100, 2, 3, 4200),
        (v_scan1_id, 'owasp_active', 'Active Injection (SQLi & XSS)', 'completed', 100, 3, 2, 45100),
        (v_scan1_id, 'auth_session', 'Authentication & JWT Hygiene', 'completed', 100, 4, 2, 28300),
        (v_scan1_id, 'access_control', 'Broken Access Control & IDOR', 'completed', 100, 5, 1, 32100),
        (v_scan1_id, 'business_logic', 'Business Logic & Rate Limiting', 'completed', 100, 6, 1, 21400),
        (v_scan1_id, 'ai_validation', 'AI Triaging & Remediation Synthesis', 'completed', 100, 7, 1, 8900)
    ON CONFLICT DO NOTHING;

    -- 5. SEED 10 REALISTIC FINDINGS ACROSS SEVERITIES (for Scan 1)
    INSERT INTO public.findings (
        scan_id, target_id, type, severity, status, confidence, title, 
        description, url, parameter, http_method, evidence, request, 
        response_summary, impact, remediation, owasp_category, cwe_id, 
        ai_explanation, ai_validated, created_at
    ) VALUES

    -- 1. CRITICAL: SQL Injection
    (
        v_scan1_id, v_target1_id, 'sqli', 'critical', 'open', 'certain',
        'Blind Boolean-Based SQL Injection in Login Authentication',
        'The username parameter of the auth endpoint is concatenated directly into an unfiltered SQL statement.',
        'https://api.ethiosec-demo.et/api/v1/auth/login',
        'username', 'POST',
        'Payload: admin'' AND (SELECT 1 FROM pg_sleep(5))=1 -- yielded a 5082ms response variance.',
        'POST /api/v1/auth/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"username": "admin'' AND 1=1 --", "password": "x"}',
        'HTTP/1.1 200 OK (Auth bypassed / Database metadata extracted)',
        'Full administrative database compromise, customer record exfiltration, and potential remote OS execution.',
        '["Utilize parameterized SQL queries or ORM models exclusively.", "Never perform raw string concatenation in queries.", "Enforce least-privilege database user credentials."]'::jsonb,
        'A03:2021-Injection', 'CWE-89',
        'EthioSec AI validated that the parameter directly altered backend query structure based on statistical latency differential analysis.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '4 minutes'
    ),

    -- 2. CRITICAL: IDOR / Broken Access Control
    (
        v_scan1_id, v_target1_id, 'access_control', 'critical', 'open', 'certain',
        'Horizontal Insecure Direct Object Reference (IDOR) on Invoice PDF',
        'An authenticated user can access any other customer invoice by simply incrementing the numeric account id parameter.',
        'https://api.ethiosec-demo.et/api/v1/billing/invoice/1092',
        'invoice_id', 'GET',
        'Context User A (Token UUID 000...01) retrieved Invoice belonging to User B (Tax ID 98214) with status 200 OK.',
        'GET /api/v1/billing/invoice/1092 HTTP/1.1\r\nAuthorization: Bearer <User_A_Token>',
        'HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n[Contains PII of User B]',
        'Severe regulatory breach and unauthorized exposure of confidential financial transactions.',
        '["Implement row-level authorization validating that session user_id owns the requested invoice.", "Replace sequential auto-incrementing IDs with cryptographically secure UUIDv4 identifiers."]'::jsonb,
        'A01:2021-Broken Access Control', 'CWE-639',
        'The AI verified dual-session disparity: User A successfully accessed User B resources without authorization.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '5 minutes'
    ),

    -- 3. HIGH: Reflected Cross-Site Scripting (XSS)
    (
        v_scan1_id, v_target1_id, 'xss', 'high', 'open', 'high',
        'Reflected Cross-Site Scripting (XSS) in Search Filter',
        'The query parameter q is echoed into the returned HTML DOM without contextual HTML/attribute escaping.',
        'https://api.ethiosec-demo.et/search',
        'q', 'GET',
        'Injected payload <script>alert(document.domain)</script> reflected verbatim inside <div> tag.',
        'GET /search?q=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1',
        'HTTP/1.1 200 OK\r\n<body><div>Results for: <script>alert(document.domain)</script></div></body>',
        'Attacker can execute arbitrary JavaScript in the victim browser context, hijack session cookies, or initiate unauthorized transactions.',
        '["Apply contextual HTML entity encoding on all reflected user inputs.", "Adopt a strict Content-Security-Policy (CSP) with nonce-based script restrictions."]'::jsonb,
        'A03:2021-Injection', 'CWE-79',
        'AI verified execution vector: payload executed in DOM parsing context without sanitizer intervention.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '6 minutes'
    ),

    -- 4. HIGH: Hardcoded API Secret Key
    (
        v_scan1_id, v_target1_id, 'info_disclosure', 'high', 'open', 'certain',
        'Exposed Third-Party Payment Gateway Secret Key in Frontend Asset',
        'A production secret key was identified hardcoded in client-side static JavaScript bundles.',
        'https://api.ethiosec-demo.et/static/js/bundle.main.js',
        'N/A', 'GET',
        'Found regex match: sk_live_51M087x... in bundle.main.js line 412.',
        'GET /static/js/bundle.main.js HTTP/1.1',
        'HTTP/1.1 200 OK\r\nconst STRIPE_KEY="sk_live_51M087x...";',
        'Immediate unauthorized access to third-party payment infrastructure and fund manipulation.',
        '["Immediately rotate the compromised secret key in the payment vendor console.", "Store credentials exclusively in environment variables on the backend.", "Implement git-secrets pre-commit hooks."]'::jsonb,
        'A07:2021-Identification and Authentication Failures', 'CWE-798',
        'AI validated against live provider format definitions; string matches live production secret key entropy.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '7 minutes'
    ),

    -- 5. HIGH: Broken Authentication (JWT Algorithm None / Weak Key)
    (
        v_scan1_id, v_target1_id, 'auth', 'high', 'open', 'certain',
        'JWT Authentication Accepts Unsigned "none" Algorithm',
        'The backend token verification library permits authentication tokens signed with alg: none.',
        'https://api.ethiosec-demo.et/api/v1/user/me',
        'Authorization', 'GET',
        'Submitted JWT header {"alg":"none","typ":"JWT"} payload {"sub":"admin"} without signature, returned 200 OK.',
        'GET /api/v1/user/me HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',
        'HTTP/1.1 200 OK\r\n{"user": "admin", "role": "superadmin"}',
        'Complete administrative account takeover without requiring password or private key knowledge.',
        '["Explicitly whitelist HMAC-SHA256 (HS256) or RSA/ECDSA (RS256/ES256) in JWT verification options.", "Disallow alg: none globally."]'::jsonb,
        'A07:2021-Identification and Authentication Failures', 'CWE-347',
        'AI confirmed full authentication bypass: arbitrary admin role forged without cryptographic signature.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '8 minutes'
    ),

    -- 6. MEDIUM: Overly Permissive CORS
    (
        v_scan1_id, v_target1_id, 'cors', 'medium', 'open', 'high',
        'Overly Permissive Cross-Origin Resource Sharing (CORS) with Credentials',
        'The API reflects the request Origin header verbatim while enabling Access-Control-Allow-Credentials: true.',
        'https://api.ethiosec-demo.et/api/v1/user/profile',
        'Origin', 'OPTIONS',
        'Request header Origin: https://evil-attacker.com returned Access-Control-Allow-Origin: https://evil-attacker.com and Allow-Credentials: true.',
        'OPTIONS /api/v1/user/profile HTTP/1.1\r\nOrigin: https://evil-attacker.com',
        'HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: https://evil-attacker.com\r\nAccess-Control-Allow-Credentials: true',
        'Enables malicious third-party websites to extract sensitive API responses using authenticated victim sessions.',
        '["Replace dynamic origin reflection with a strict whitelist of approved partner origins.", "Never combine Access-Control-Allow-Credentials: true with wildcards or arbitrary origins."]'::jsonb,
        'A05:2021-Security Misconfiguration', 'CWE-942',
        'AI tested origin reflection: response reflects unverified external origins with credentials enabled.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '8 minutes'
    ),

    -- 7. MEDIUM: Missing CSRF Protection on Sensitive Endpoint
    (
        v_scan1_id, v_target1_id, 'auth', 'medium', 'open', 'medium',
        'Missing Anti-CSRF Token on Password Reset Request Form',
        'State-changing POST endpoint does not validate anti-forgery tokens or SameSite cookie protection.',
        'https://api.ethiosec-demo.et/user/password/reset',
        'N/A', 'POST',
        'Cross-site POST successfully triggered password reset email dispatch without CSRF token.',
        'POST /user/password/reset HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemail=victim@target.et',
        'HTTP/1.1 200 OK\r\n{"status":"reset_link_dispatched"}',
        'Attackers can force authenticated users into initiating unsolicited actions via forged requests.',
        '["Incorporate synchronized anti-CSRF tokens in all state-altering forms.", "Configure SameSite=Strict or SameSite=Lax on all session cookies."]'::jsonb,
        'A01:2021-Broken Access Control', 'CWE-352',
        'AI flagged absent CSRF token validation and permissive cross-origin execution.',
        FALSE, NOW() - INTERVAL '2 days' + INTERVAL '9 minutes'
    ),

    -- 8. LOW: Missing Security Headers (HSTS, CSP)
    (
        v_scan1_id, v_target1_id, 'headers', 'low', 'open', 'high',
        'Missing HTTP Strict Transport Security (HSTS) and Content-Security-Policy',
        'Response lacks Strict-Transport-Security, Content-Security-Policy, and Permissions-Policy headers.',
        'https://api.ethiosec-demo.et/',
        'Headers', 'GET',
        'Headers verified absent: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options.',
        'GET / HTTP/1.1',
        'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n[Missing HSTS/CSP headers]',
        'Vulnerability to SSL-stripping man-in-the-middle attacks and clickjacking framing.',
        '["Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload.", "Implement a comprehensive Content-Security-Policy."]'::jsonb,
        'A05:2021-Security Misconfiguration', 'CWE-1021',
        'AI confirmed absence of baseline HTTP hardening headers across all root responses.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '10 minutes'
    ),

    -- 9. LOW: Insecure Cookie Flags
    (
        v_scan1_id, v_target1_id, 'cookies', 'low', 'open', 'high',
        'Session Cookie Missing HttpOnly and SameSite Attributes',
        'The sessionid cookie is issued without the HttpOnly flag, permitting access from client-side scripts.',
        'https://api.ethiosec-demo.et/api/v1/auth/session',
        'Set-Cookie', 'POST',
        'Set-Cookie: sessionid=8fa20...; Path=/; Secure (HttpOnly and SameSite missing).',
        'POST /api/v1/auth/session HTTP/1.1',
        'HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=8fa20e...; Path=/; Secure',
        'If an XSS vulnerability exists anywhere on the site, scripts can directly extract the session identifier.',
        '["Append HttpOnly and SameSite=Lax flags to all Set-Cookie directives for session identifiers."]'::jsonb,
        'A05:2021-Security Misconfiguration', 'CWE-1004',
        'AI inspected cookie attributes and verified client-script accessibility.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '10 minutes'
    ),

    -- 10. INFO: Server Header Banner Disclosure
    (
        v_scan1_id, v_target1_id, 'info_disclosure', 'info', 'open', 'certain',
        'Detailed Web Server Version Banner Disclosure',
        'The server advertises exact software builds in the Server response header.',
        'https://api.ethiosec-demo.et/',
        'Server', 'GET',
        'Server: Apache/2.4.41 (Ubuntu) mod_wsgi/4.6.8 Python/3.8',
        'GET / HTTP/1.1',
        'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu) mod_wsgi/4.6.8 Python/3.8',
        'Provides precise fingerprinting telemetry assisting attackers in selecting known CVE exploits.',
        '["Configure ServerTokens Prod in Apache httpd.conf.", "Disable descriptive software banners across all web server proxies."]'::jsonb,
        'A05:2021-Security Misconfiguration', 'CWE-200',
        'AI analyzed server headers and confirmed explicit package and OS version disclosure.',
        TRUE, NOW() - INTERVAL '2 days' + INTERVAL '11 minutes'
    )
    ON CONFLICT DO NOTHING;

    -- 6. SEED REPORT ARTIFACT
    INSERT INTO public.reports (
        scan_id, user_id, format, storage_path, file_size_bytes, expires_at
    ) VALUES (
        v_scan1_id,
        v_user_id,
        'pdf',
        'reports/00000000-0000-0000-0000-000000000001/scan_33333333-3333-3333-3333-333333333331_summary.pdf',
        245890,
        NOW() + INTERVAL '28 days'
    ) ON CONFLICT (scan_id, format) DO NOTHING;

    -- 7. SEED NOTIFICATIONS
    INSERT INTO public.notifications (
        user_id, type, title, message, link, is_read, read_at
    )
    VALUES
        (
            v_user_id,
            'scan_completed',
            'Scan Completed for api.ethiosec-demo.et',
            'Scan completed with a security score of 64/100. 2 Critical and 3 High severity findings discovered.',
            '/scans/33333333-3333-3333-3333-333333333331',
            FALSE,
            NULL
        ),
        (
            v_user_id,
            'critical_finding',
            'CRITICAL Finding: SQL Injection',
            'Blind Boolean-Based SQL Injection detected in https://api.ethiosec-demo.et/api/v1/auth/login.',
            '/findings/33333333-3333-3333-3333-333333333331',
            TRUE,
            NOW() - INTERVAL '1 day'
        )
    ON CONFLICT DO NOTHING;

    -- 8. SEED AUDIT LOG
    INSERT INTO public.audit_logs (
        user_id, action, entity, entity_id, ip_address, changes
    )
    VALUES (
        v_user_id,
        'SCAN_INITIATED',
        'scans',
        v_scan1_id,
        '196.188.241.10'::inet,
        '{"depth": "standard", "target": "https://api.ethiosec-demo.et", "mode": "authenticated"}'::jsonb
    );
END $$;