# EthioSec Scanner — Team Contribution Guidelines

Welcome to the EthioSec Scanner development team! These guidelines outline our Git branch strategy, review standards, and testing expectations.

---

## 🌿 Branch Strategy

We follow a structured branch naming convention:

| Branch Pattern | Purpose | Example |
|---|---|---|
| `main` | Production-ready, reviewed, and tested code. Protected branch. | `main` |
| `feature/<name>` | New capabilities, UI screens, scanner checks, or APIs. | `feature/ssrf-dns-pinning` |
| `fix/<name>` | Bug fixes and security patches. | `fix/verification-code-ttl` |
| `refactor/<name>` | Code reorganization without functional changes. | `refactor/scanner-crawler` |

---

## 🔄 Development Workflow

1. **Keep Your Local Repository Updated:**
   ```bash
   git checkout main
   git pull team main
   ```

2. **Create a Dedicated Branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Focused Changes:**
   - Keep commits small, atomic, and descriptive.
   - Follow existing style guidelines (vanilla JS for frontend, type-hinted PEP 8 for Python).
   - Never commit sensitive secrets (`.env`, `.db`, production keys).

4. **Run Test Suites Locally:**
   Before pushing, ensure all existing and new tests pass:
   ```bash
   cd backend
   python -m pytest -q
   ```

5. **Push Your Branch to GitHub:**
   ```bash
   git push -u team feature/your-feature-name
   ```

6. **Open a Pull Request:**
   - Target the `main` branch.
   - Fill out the standardized Pull Request template.
   - Request review from at least one team member.
   - Merge only after approval and passing test suites.

---

## 🔒 Security Commitments

Every contributor must adhere to:

- **Zero Plaintext Credentials**: Never hardcode API keys, SMTP passwords, database URLs, or JWT secrets in code or commits.
- **Constant-Time Verification**: Use `verify_secret_hash` or `hmac.compare_digest` for security secrets.
- **Database Schema Safety**: Never execute destructive schema migrations (`DROP TABLE`) without team discussion and approval.
- **ASVS Compliance**: Follow OWASP Application Security Verification Standards for authentication, session handling, and input validation.
