# EthioSec Backend API

EthioSec is a professional web vulnerability scanner backend and frontend platform designed to automatically discover, report, and explain security vulnerabilities including SQL Injection, Reflected XSS, Broken Access Control (IDOR), and Insecure Authentication.

---

## Architecture Overview

```text
Frontend (Vanilla HTML/CSS/JS in "ETHIOSEC SCANNER 2")
      ↓ REST API (JWT Bearer Token / CORS / Security Headers)
FastAPI (main.py + routers.py)
      ↓ SlidingWindowRateLimiter (rate_limiter.py)
      ↓ Security Layer (Argon2id + Session Revocation + Verified User Gate)
      ↓ Email Service (email_service.py - SMTP / Dev Capture)
Database Layer (database.py + models.py) -> PostgreSQL (Prod) / SQLite (Dev)
      ↓ 
Scanner Engine (scanner/engine.py)
      ↓ SSRF & Safety Enforcer (safety.py)
      ↓ Crawler & Safe HTTP Client (crawler.py, http_client.py)
      ↓ Check Modules (sqli.py, xss.py, access_control.py, headers.py, etc.)
      ↓ 
AI Security Assistant (ai/service.py) -> Ollama / Google Gemini
```

---

## Security Hardening Controls

- **Email Verification:** All new registrations require verifying email ownership via a 6-digit random code with 15-minute expiration before gaining access to protected scanner APIs.
- **Argon2id Password Hashing:** Replaced legacy bcrypt with memory-hard Argon2id (`t=3, m=64MB, p=4`). Transparently upgrades existing accounts upon login.
- **Session Revocation & Logout:** `POST /api/auth/logout` invalidates active sessions. Password reset automatically revokes all previous session tokens.
- **Account Lockout:** 5 consecutive failed login attempts trigger a 15-minute temporary lockout.
- **PostgreSQL Fail-Fast:** In `ENVIRONMENT=production`, PostgreSQL connection failures raise a fatal exception prohibiting silent fallback to SQLite.
- **Production Rate Limiting:** Endpoint-specific sliding window limits prevent brute-force attacks and email flooding.
- **Browser Security:** Strict CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- **SSRF Defense:** Strict loopback, link-local, carrier-grade NAT, private, and non-global IP filtering on every redirect hop.

---

## Setup & Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables:**
   Copy `.env.example` to `.env` and fill in your settings:
   ```env
   ENVIRONMENT=development
   DATABASE_URL=sqlite:///./ethiosec.db
   JWT_SECRET_KEY=your_secure_random_secret_here
   REQUIRE_EMAIL_VERIFICATION=true
   ACCESS_TOKEN_EXPIRE_MINUTES=60
   ALLOW_LOCAL_TARGETS=false
   ```

3. **Email Delivery Configuration (Optional for Dev):**
   To send real verification emails via SMTP:
   ```env
   SMTP_HOST=smtp.yourprovider.com
   SMTP_PORT=587
   SMTP_USER=your_username
   SMTP_PASSWORD=your_password
   SMTP_FROM=security@yourdomain.com
   SMTP_TLS=true
   ```
   *In development mode with empty SMTP settings, verification codes are safely captured in memory and logged securely.*

---

## Running the Servers

### One-Click Startup (Windows)
Double-click `start.bat` in the project root to start both backend and frontend.

### Manual Startup
1. **Start Backend (Port 8000):**
   ```bash
   cd backend
   python -m uvicorn main:app --reload --port 8000
   ```
   - API Docs: `http://127.0.0.1:8000/docs`

2. **Start Frontend (Port 5500):**
   ```bash
   cd "ETHIOSEC SCANNER 2"
   python -m http.server 5500
   ```
   - Frontend: `http://127.0.0.1:5500/index.html`

---

## Automated Testing Suite

To run the complete automated test suite (114 tests):
```bash
python -m pytest -v
```

To run security hardening regression tests only:
```bash
python -m pytest test_security_hardening.py -v
```

---

## Documentation References

- [`SECURITY_AUDIT.md`](file:///c:/Users/Student/Downloads/insa%20project%20antigravity/SECURITY_AUDIT.md): Detailed vulnerability audit register and status.
- [`SECURITY_IMPLEMENTATION_REPORT.md`](file:///c:/Users/Student/Downloads/insa%20project%20antigravity/SECURITY_IMPLEMENTATION_REPORT.md): Architecture report and changed files inventory.
- [`TEST_REPORT.md`](file:///c:/Users/Student/Downloads/insa%20project%20antigravity/TEST_REPORT.md): Comprehensive test execution record.
