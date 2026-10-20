# EthioSec Scanner — Web Application Security Scanning Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Argon2id%20%7C%20JWT%20%7C%20ASVS-FF2028.svg)](#security-architecture)
[![License](https://img.shields.io/badge/Access-Private%20Team-A90012.svg)](#team-collaboration)

EthioSec Scanner is an evidence-based web application vulnerability scanning and analysis platform. It provides automated detection of critical vulnerabilities (SQL Injection, Cross-Site Scripting, Broken Access Control, and Insecure Authentication), AI-assisted vulnerability remediation, professional reporting, and a hardened authentication system.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | Vanilla HTML5, CSS3, JavaScript (ES6+), Modern Cybersecurity Theme (`#080808` / `#FF2028`) |
| **Backend API** | Python 3.11+, FastAPI, Starlette, Uvicorn |
| **Database** | SQLAlchemy 2.0 ORM (PostgreSQL in production, SQLite for local dev) |
| **Authentication** | Argon2id password hashing, Stateless JWT (HS256) with centralized session revocation, 6-digit email verification |
| **Scanning Engine** | Asynchronous HTTP crawler, differential analysis, timing-attack verification, heuristic payload injection |
| **AI Analysis** | Multi-provider AI module (Google Gemini API & Local Ollama LLM support) |

---

## 📁 Repository Structure

```text
├── ETHIOSEC SCANNER 2/          # Frontend Web Application
│   ├── login.html / loginjava.js          # Hardened login interface
│   ├── signup.html / signupjava.js        # Registration with password validation
│   ├── verify.html / verifyjava.js        # 6-digit email verification
│   ├── reset-password.html                # 2-step password recovery interface
│   ├── dashboardfinal.html / js           # Main security dashboard
│   ├── livescan.html / livejava.js        # Live scan execution & real-time telemetry
│   ├── results.html / resultsjava.js      # Vulnerability findings & proof-of-concept
│   ├── reports.html / reportjava.js       # Executive and technical PDF/HTML reports
│   ├── settings.html / settingsjava.js    # Profile & credential management
│   ├── auth_theme.css                     # Unified black-and-red design system
│   └── shared_auth.js                     # Identity manager & route guards
│
├── backend/                     # FastAPI Backend API
│   ├── main.py                            # FastAPI app, security headers, CORS
│   ├── routers.py                         # Authentication, Target, Scan & Report routes
│   ├── models.py                          # SQLAlchemy User, Target, Scan & Finding entities
│   ├── schemas.py                         # Pydantic request/response schemas
│   ├── security.py                        # Argon2id password hashing & JWT management
│   ├── email_service.py                   # SMTP delivery & dev-mode email capture
│   ├── rate_limiter.py                    # Sliding window brute-force rate limiters
│   ├── scanner/                           # Security checks (SQLi, XSS, Access Control, etc.)
│   ├── ai/                                # AI assistant and executive summary generators
│   └── requirements.txt                   # Backend Python dependencies
│
├── .github/                     # GitHub Collaboration Templates
│   └── pull_request_template.md           # Standardized PR submission checklist
├── CONTRIBUTING.md              # Team workflow and branch guidelines
└── README.md                    # Platform documentation
```

---

## 🚀 Quickstart & Local Setup

### 1. Prerequisites
- **Python**: Version 3.11 or higher
- **Git**: Installed and configured
- **Web Browser**: Chrome, Firefox, or Edge

### 2. Backend Setup
```bash
# 1. Navigate to the backend directory
cd backend

# 2. Create and activate a virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure local environment variables
cp .env.example .env
```

Review `backend/.env`. By default, it operates in safe local development mode:
- `ENVIRONMENT=development`
- `DATABASE_URL=sqlite:///./ethiosec.db`
- `REQUIRE_EMAIL_VERIFICATION=true`
- SMTP credentials left blank (verification codes log directly to terminal)

### 3. Start the Backend API
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
API docs available at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) (development mode only).

### 4. Start the Frontend
In a separate terminal:
```bash
cd "ETHIOSEC SCANNER 2"
python -m http.server 5500
```
Open your browser to: [http://127.0.0.1:5500/login.html](http://127.0.0.1:5500/login.html)

---

## 🧪 Running Automated Tests

Run the full pytest suite (237+ tests):
```bash
cd backend
python -m pytest -q
```

Run the end-to-end authentication and recovery test suite:
```bash
python -m pytest test_auth_e2e_comprehensive.py -v
```

---

## 🔐 Security & Responsible Use

1. **Authorized Scanning Only**: This software is designed exclusively for testing systems you own or have explicit, documented authorization to assess.
2. **SSRF Protections**: The scanner includes strict IP filtering preventing requests against internal metadata services (`169.254.169.254`), private RFC1918 subnets, and loopback addresses unless `ALLOW_LOCAL_TARGETS=true` is set for local lab testing.
3. **No Secret Commits**: Never commit `.env` files, production credentials, or database dumps to this repository.

---

## 👥 Team Collaboration

Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for branch strategy, coding standards, and PR guidelines.
