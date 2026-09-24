# EthioSec Backend API

EthioSec is an educational web vulnerability scanner backend designed to automatically discover and report security vulnerabilities such as SQL Injection, Reflected XSS, Broken Access Control (IDOR), and Insecure Authentication.

## Project Architecture

```text
Frontend (HTML/JS)
      ↓ REST API 
FastAPI (main.py + routers.py)
      ↓ 
Scanner Engine (engine.py)
      ↓ 
Crawler & HTTP Client (crawler.py, http_client.py)
      ↓ 
Vulnerability Checks (sqli.py, xss.py, access_control.py, etc.)
      ↓ 
Database (database.py, models.py)
```

## Setup & Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Environment Variables

Copy `.env.example` to `.env` and fill in the required variables.
```text
DATABASE_URL=sqlite:///./ethiosec.db
JWT_SECRET_KEY=your_secure_secret_here
ALLOW_LOCAL_TARGETS=false
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=gemma2
```

## Running the Backend

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start FastAPI:**
   ```bash
   uvicorn main:app --reload --port 8000
   ```
   The API will be accessible at `http://127.0.0.1:8000/api`.
   Interactive documentation is available at `http://127.0.0.1:8000/docs`.

3. **Configure Ollama (AI Assistant):**
   - Install Ollama from [ollama.com](https://ollama.com).
   - Pull the default model:
     ```bash
     ollama pull gemma2
     ```
   - Ensure the Ollama daemon is running.

## Testing

To run the automated test suite (API boundaries, auth isolation, scanner, and AI):
```bash
python -m pytest
```

To test the scanner's vulnerability detection modules against the local vulnerable app:
```bash
# Terminal 1: Run vulnerable app
python vulnerable_app.py

# Terminal 2: Run targeted tests
python -m pytest test_sqli_xss.py
```

## API Documentation

See `API.md` for the complete frontend/backend API contract.

## Security & Limitations

- **Authorization:** Only scan systems for which you have explicit permission.
- **SSRF Protection:** The scanner validates all hostnames against private, loopback, and link-local IP addresses before making HTTP requests. Local scanning can be enabled via `ALLOW_LOCAL_TARGETS=true` for testing.
- **Resource Limits:** The crawler enforces maximum depth (2), maximum pages (15), and the HTTP client enforces maximum concurrency (10) and response size (5MB).
- **Destructive Testing:** Vulnerability modules use safe arithmetic, boolean comparison, and syntax error induction to prevent database corruption. No destructive operations are performed.
- **OWASP Top 10:2025 Coverage:** This scanner implements checks for Injection (A05:2025), Security Misconfiguration (A02:2025), Cryptographic Failures (A04:2025), and basic Auth/Access Control (A01:2025/A07:2025). Categories like Insecure Design (A06:2025) and Supply Chain Failures (A03:2025) explicitly require manual verification and cannot be reliably fully automated by a black-box URL scanner. The API does **not** falsely claim 100% coverage.

> "EthioSec is an authorized web security assessment platform. Only scan systems for which you have permission."
