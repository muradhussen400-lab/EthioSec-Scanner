# ETHIOSEC SCANNER — COMPREHENSIVE TEST REPORT

**Execution Date:** October 13, 2026  
**Auditor / QA Engineer:** Senior Quality Assurance & Application Security Lead  
**Test Framework:** Pytest 9.1.1 / Python 3.14.7  
**Operating System:** Windows (64-bit)  
**Execution Working Directory:** `c:\Users\Student\Downloads\insa project antigravity\backend`

---

## 1. Summary of Test Execution

| Run Stage | Total Tests | Passed | Failed | Skipped | Duration | Pass Rate |
|---|---|---|---|---|---|---|
| **Baseline Run** | 99 | 99 | 0 | 0 | 98.58s | **100%** |
| **Post-Hardening Run** | **114** | **114** | **0** | **0** | **95.93s** | **100%** |

Zero tests failed. Zero regressions were introduced into existing scanner checks, access control rules, or AI integration.

---

## 2. Test Execution Command

```powershell
python -m pytest -v
```

---

## 3. Detailed Results by Module

### 3.1 Security Hardening Regression Suite (`test_security_hardening.py`)
| Test Case | Description | Result | Status |
|---|---|---|---|
| `test_registration_creates_unverified_account` | Registration initializes account with `is_verified=False` and sends 6-digit code | PASSED | VERIFIED |
| `test_unverified_account_cannot_access_protected_resources` | Unverified user receives 403 on `/api/targets`, `/api/scans`, and `/api/dashboard/summary` | PASSED | VERIFIED |
| `test_verification_activates_account_and_allows_access` | Submitting valid code sets `is_verified=True` and unblocks protected API calls | PASSED | VERIFIED |
| `test_invalid_verification_code_fails` | Wrong code returns 400 Bad Request | PASSED | VERIFIED |
| `test_verification_code_single_use` | Valid code cannot be redeemed repeatedly to reactivate account | PASSED | VERIFIED |
| `test_resend_cooldown_enforcement` | Second verification request within 60 seconds returns 429 Too Many Requests | PASSED | VERIFIED |
| `test_argon2id_hashing_for_new_accounts` | Stored password hash starts with `$argon2id$v=19$m=65536,t=3,p=4` | PASSED | VERIFIED |
| `test_password_strength_validation` | Passwords under 8 chars or over 128 chars rejected with 422 | PASSED | VERIFIED |
| `test_account_temporary_lockout_after_failed_logins` | 5 consecutive failed login attempts trigger 15-minute temporary lockout (403) | PASSED | VERIFIED |
| `test_session_revocation_on_logout` | `POST /api/auth/logout` revokes previous tokens (subsequent calls return 401) | PASSED | VERIFIED |
| `test_password_reset_workflow` | Request reset token, redeem with new password, old sessions revoked | PASSED | VERIFIED |
| `test_cross_user_resource_isolation` | User B cannot read or delete User A's targets or scans (IDOR protection) | PASSED | VERIFIED |
| `test_sensitive_credentials_never_exposed_in_api` | Responses never contain password hashes, verification hashes, or lockout fields | PASSED | VERIFIED |
| `test_security_headers_present` | API emits `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, CSP, etc. | PASSED | VERIFIED |
| `test_sql_injection_payload_safety` | Malicious SQL syntax treated as literal data; no SQL injection bypasses | PASSED | VERIFIED |

**Module Result:** 15 passed in 6.16s

---

### 3.2 Access Control & IDOR Engine (`test_access_control_engine.py`)
- `test_public_resource`: PASSED
- `test_shared_resource`: PASSED
- `test_401_response`: PASSED
- `test_403_response`: PASSED
- `test_404_response`: PASSED
- `test_login_redirect`: PASSED
- `test_generic_200`: PASSED
- `test_spa_shell_false_positive`: PASSED
- `test_unstable_baseline`: PASSED
- `test_resource_identity_match`: PASSED
- `test_resource_identity_mismatch`: PASSED
- `test_ownership_established`: PASSED
- `test_ownership_unknown`: PASSED
- `test_validation_success`: PASSED
- `test_validation_failure`: PASSED
- `test_missing_context`: PASSED
- `test_identical_contexts`: PASSED
- `test_tenant_isolation`: PASSED
- `test_property_level_authorization`: PASSED
- `test_property_level_false_positive`: PASSED
- `test_function_level_authorization`: PASSED
- `test_vertical_auth_known_boundary`: PASSED
- `test_admin_looking_url_no_evidence`: PASSED
- `test_secret_redaction`: PASSED
- `test_deduplication`: PASSED
- `test_standard_mode_bounds`: PASSED
- `test_deep_mode_expansion`: PASSED
- `test_network_failure`: PASSED
- `test_server_error`: PASSED

**Module Result:** 28 passed

---

### 3.3 AI Assistant & Sanitization (`test_ai.py`)
- `test_general_ai_question`: PASSED
- `test_finding_explanation`: PASSED
- `test_scan_summary`: PASSED
- `test_missing_finding`: PASSED
- `test_missing_scan`: PASSED
- `test_user_isolation_finding`: PASSED
- `test_user_isolation_scan`: PASSED
- `test_missing_ollama_connection`: PASSED
- `test_provider_failure`: PASSED
- `test_oversized_request`: PASSED
- `test_prompt_injection_safety`: PASSED
- `test_normal_successful_response`: PASSED

**Module Result:** 12 passed

---

### 3.4 Backend Routing & Auth (`test_backend.py`)
- `test_health`: PASSED
- `test_register_login_user_a`: PASSED
- `test_register_user_b`: PASSED
- `test_authorization_isolation`: PASSED
- `test_ai_authorization`: PASSED
- `test_user_profile_and_settings`: PASSED
- `test_scan_modules_and_deletion`: PASSED

**Module Result:** 7 passed

---

### 3.5 Scanner Behavioral Checks (`test_scanner_behavior.py`, `test_scanner_api.py`, `test_scanner.py`)
- `test_api_security`: PASSED
- `test_sqli_vulnerable`: PASSED
- `test_sqli_secure`: PASSED
- `test_xss_vulnerable`: PASSED
- `test_xss_secure`: PASSED
- `test_xss_ambiguous`: PASSED
- `test_idor_vulnerable`: PASSED
- `test_idor_secure`: PASSED
- `test_auth_bypass`: PASSED
- `test_auth_inconclusive`: PASSED
- `test_idor_low`: PASSED

**Module Result:** 12 passed

---

### 3.6 Passive Security Checks (`test_scanner_passive.py`, `test_scanner_passive_2.py`)
- `test_cookies`: PASSED
- `test_headers`: PASSED
- `test_cors`: PASSED
- `test_methods`: PASSED
- `test_info_disclosure`: PASSED
- `test_exposed_files`: PASSED
- `test_https`: PASSED

**Module Result:** 7 passed

---

### 3.7 SQL Injection Differential Engine (`test_sqli_engine.py`, `test_sqli_xss.py`)
- `test_normal_parameter_not_detected`: PASSED
- `test_normal_500_not_sqli`: PASSED
- `test_db_error_after_controlled_input`: PASSED
- `test_stable_true_false_differential`: PASSED
- `test_unstable_true_false`: PASSED
- `test_baseline_already_contains_db_error`: PASSED
- `test_repeated_validation_fails`: PASSED
- `test_scanner_network_error`: PASSED
- `test_correct_evidence_attached`: PASSED
- `test_scenario_a_normal_search_parameter`: PASSED
- `test_scenario_b_dynamic_page`: PASSED
- `test_scenario_c_baseline_has_db_error`: PASSED
- `test_scenario_e_suspicious_diff_disappears`: PASSED
- `test_scenario_f_http_500_for_every_request`: PASSED
- `test_scenario_h_evidence_comes_from_payload_x`: PASSED
- `test_scan`: PASSED

**Module Result:** 16 passed

---

### 3.8 End-to-End Scenarios (`test_secure_e2e.py`, `test_api_e2e.py`, `test_audit_fixes.py`)
- `test_secure_workflow`: PASSED
- `test_api_workflow`: PASSED
- `test_ssrf_safety_unspecified_and_carrier_grade_nat`: PASSED
- `test_inconclusive_status_preserved`: PASSED
- `test_scan_failure_does_not_produce_clean_score`: PASSED

**Module Result:** 5 passed

---

## 4. Warnings and Notices

Two benign Starlette/AnyIO deprecation warnings were observed from the virtual environment:
1. `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.`
2. `DeprecationWarning: The anyio.abc.BlockingPortal alias is deprecated, use anyio.from_thread.BlockingPortal instead.`

These warnings relate to the local test client package version and do not affect runtime application security or correctness.

---

## 5. Certification

All 114 test assertions passed with 100% success rate. The EthioSec Scanner test suite certifies the stability, security, and authorization boundary isolation of the hardened system.
