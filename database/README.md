# EthioSec Scanner - Database Infrastructure

Enterprise-grade PostgreSQL database architecture designed for **EthioSec Scanner**, an AI-powered web security scanning platform.

Built for **Supabase (PostgreSQL 15+, Auth, Storage, Row Level Security, pg_cron)** + **Python Flask/FastAPI Backend (Service Role)** + **Vanilla JS Frontend**.

---

## Directory Structure

```
/home/maraki/database for ethiosec scanner/
├── README.md                                  # This guide & implementation checklist
├── migrations/
│   ├── 001_initial_schema.sql                 # Tables, ENUMs, triggers, constraints, auth sync
│   ├── 002_indexes_and_performance.sql        # FK indexes, composite filters, partial indexes
│   ├── 003_row_level_security.sql             # Strict tenant isolation RLS policies
│   ├── 004_retention_and_maintenance.sql      # Automated cleanup functions & pg_cron schedule
│   └── 005_seed_data.sql                      # Realistic test fixtures (1 user, 2 targets, 2 scans, 10 findings)
├── queries/
│   └── performance_verification.sql           # EXPLAIN ANALYZE queries for Dashboard, History, Findings
└── docs/
    ├── erd.md                                 # Mermaid ER diagram & FK justifications
    └── retention_and_api_contract.md          # Retention rules & RFC-7807 410 Gone API spec
```

---

## Deployment & Setup Guide

### 1. In Supabase Dashboard SQL Editor
Run the migration files in strict sequential order:
1. `migrations/001_initial_schema.sql`
2. `migrations/002_indexes_and_performance.sql`
3. `migrations/003_row_level_security.sql`
4. `migrations/004_retention_and_maintenance.sql`
5. `migrations/005_seed_data.sql`

### 2. Using Supabase CLI (Local Development)
```bash
supabase db push
# or run seed directly:
psql -h localhost -p 54322 -U postgres -d postgres -f migrations/001_initial_schema.sql
psql -h localhost -p 54322 -U postgres -d postgres -f migrations/002_indexes_and_performance.sql
psql -h localhost -p 54322 -U postgres -d postgres -f migrations/003_row_level_security.sql
psql -h localhost -p 54322 -U postgres -d postgres -f migrations/004_retention_and_maintenance.sql
psql -h localhost -p 54322 -U postgres -d postgres -f migrations/005_seed_data.sql
```

---

## Self-Check Quality Checklist

| # | Requirement Item | Status | Verification Reference |
| :-: | :--- | :---: | :--- |
| **1** | **Tables:** profiles (linked to auth.users), targets (with ownership verification), scans (status, progress 0-100, security score 0-100, timestamps), scan_modules, findings (severity, evidence, impact, fix, OWASP, CWE, AI explanation, AI validated flag), reports (format, storage path), notifications (is_read, user scope), audit_logs. | **PASS** | Implemented in `migrations/001_initial_schema.sql` |
| **2** | **Primary Keys & Constraints:** UUID primary keys, justified ON DELETE behavior, NOT NULL, DEFAULT values, CHECK constraints (score/progress 0-100, enums for status/severity), unique keys. | **PASS** | Implemented in `migrations/001_initial_schema.sql` & detailed in `docs/erd.md` |
| **3** | **Indexes:** Indexes on every FK, on created_at/finished_at, findings(scan_id, severity), notifications(user_id, is_read), scans(user_id, status). | **PASS** | Implemented in `migrations/002_indexes_and_performance.sql` |
| **4** | **Row Level Security (RLS):** Enabled on all tables with policies isolating user data; backend service role support. | **PASS** | Implemented in `migrations/003_row_level_security.sql` |
| **5** | **Sequential Migrations & Seed Script:** Runnable migration files (001-004) + seed script with 1 user, 2 targets, 2 scans, and 10 findings across all severities. | **PASS** | Implemented in `migrations/` directory |
| **6** | **Retention Policy:** Cleanup of old evidence and report files (pg_cron job) and API response contract for expired items. | **PASS** | Implemented in `migrations/004_retention_and_maintenance.sql` & `docs/retention_and_api_contract.md` |
| **7** | **ER Diagram & EXPLAIN ANALYZE:** Mermaid ER diagram and EXPLAIN ANALYZE queries verifying index usage for dashboard, scan history, and findings. | **PASS** | Documented in `docs/erd.md` and `queries/performance_verification.sql` |
| **8** | **Checklist Verification:** Verified output against all requirements and marked each item PASS/FAIL. | **PASS** | Verified and confirmed above. |
