# EthioSec Scanner - Database Layer

This directory contains the production-grade PostgreSQL database layer for the EthioSec Scanner backend, managed via Alembic migrations.

The schema matches the backend SQLAlchemy models (`backend/models.py`) exactly:
- Identical table names, column names, data types, nullability, and primary/foreign keys.
- Preserves `VARCHAR` representation for text UUIDs and ISO 8601 date strings.
- Pure Python client-side defaults and relationships preserved without drift.

---

## Architecture Overview

```
database/
├── alembic.ini                   # Alembic configuration (no hardcoded credentials)
├── env.py                        # Dynamic migration environment; imports models.py
├── script.py.mako                # Migration template
├── versions/
│   └── 0001_initial_schema.py    # Explicit initial migration (upgrade & downgrade)
├── seed.py                       # Idempotent demo data seeder using backend Argon2id
├── IMPROVEMENT_PROPOSALS.md      # Future architectural recommendations for team review
├── .env.example                  # Template with credential placeholders
├── README.md                     # Step-by-step operations guide
└── legacy_reference/             # Archived prior work preserved untouched
```

---

## 1. Prerequisites

- **PostgreSQL 14+** installed and running.
- **Python 3.12+** with required packages installed:
  - `SQLAlchemy>=2.0.0`
  - `alembic>=1.13.0`
  - `psycopg2-binary>=2.9.0`
  - `argon2-cffi>=23.1.0`
  - `python-dotenv>=1.0.1`

---

## 2. PostgreSQL Setup (Database & Role)

Log in to PostgreSQL as an administrative user (`postgres` or your superuser account) to create the application user and database:

```bash
# Connect to PostgreSQL prompt
psql -U postgres

# Inside psql prompt, run:
CREATE ROLE ethiosec_user WITH LOGIN PASSWORD 'your_secure_password';
CREATE DATABASE ethiosec_db OWNER ethiosec_user;
GRANT ALL PRIVILEGES ON DATABASE ethiosec_db TO ethiosec_user;
\q
```

---

## 3. Environment Configuration

Copy `database/.env.example` to `database/.env` (or configure `backend/.env`):

```bash
cp database/.env.example database/.env
```

Edit `database/.env` with your PostgreSQL connection URL and seed password:

```env
# Format: postgresql+psycopg2://<user>:<password>@<host>:<port>/<dbname>
DATABASE_URL=postgresql+psycopg2://ethiosec_user:your_secure_password@localhost:5432/ethiosec_db

# Password for demo user accounts created by seed.py
# (Requires min 8 characters, 1 uppercase, 1 lowercase, 1 digit)
SEED_PASSWORD=DemoSecurePassword2026!
```

Alternatively, export the environment variables directly in your active shell:

```bash
export DATABASE_URL="postgresql+psycopg2://ethiosec_user:your_secure_password@localhost:5432/ethiosec_db"
export SEED_PASSWORD="DemoSecurePassword2026!"
```

---

## 4. Running Migrations

All Alembic commands read `DATABASE_URL` dynamically from the environment. Credentials are never committed to version control.

### Run Migrations (Upgrade to Head)
Apply all pending schema migrations:

```bash
alembic -c database/alembic.ini upgrade head
```

### Check for Schema Drift
Verify that the PostgreSQL database matches the SQLAlchemy models in `backend/models.py` with zero discrepancies:

```bash
alembic -c database/alembic.ini check
```

### Downgrade (Roll Back)
Roll back all migrations to a completely blank database:

```bash
alembic -c database/alembic.ini downgrade base
```

---

## 5. Seeding Demo Data

The seed script creates a representative demo dataset:
- **Admin user**: `admin@ethiosec.local` (role: `admin`)
- **Standard user**: `analyst@ethiosec.local` (role: `user`)
- User preferences / settings
- Scan targets (`https://demo-app.ethiosec.local`, etc.)
- Scans in various stages (`completed`, `running`, `queued`)
- Vulnerability findings (`headers`, `xss`, `https`, `sqli`)

The password is read from the `SEED_PASSWORD` environment variable and hashed at runtime using the backend's Argon2id hasher (`backend/security.py`).

Run the seeder:

```bash
# Ensure SEED_PASSWORD and DATABASE_URL are set:
SEED_PASSWORD="DemoSecurePassword2026!" python database/seed.py
```

> **Note on Idempotency**:
> The seed script is fully idempotent. Running it repeatedly will detect existing records and safely exit without duplicating data or throwing integrity errors.

---

## 6. Starting the Backend Against PostgreSQL

To start the FastAPI backend connected to your PostgreSQL instance, set `DATABASE_URL` before running Uvicorn:

```bash
export DATABASE_URL="postgresql+psycopg2://ethiosec_user:your_secure_password@localhost:5432/ethiosec_db"
uvicorn main:app --app-dir backend --host 0.0.0.0 --port 8000
```

Verify in the console log that the server process starts cleanly:
- Check for `Started server process [...]` and `Application startup complete.`
- Verify that **no** `[DEV WARNING] Could not connect to default database...` warning is emitted (which would indicate fallback to SQLite).

---

## 7. How to Reset the Database

To completely wipe and rebuild the database from scratch:

```bash
# 1. Roll back all tables via Alembic
alembic -c database/alembic.ini downgrade base

# 2. Re-apply the initial migration
alembic -c database/alembic.ini upgrade head

# 3. Seed fresh demo data
SEED_PASSWORD="DemoSecurePassword2026!" python database/seed.py
```

Or via PostgreSQL CLI commands:

```bash
# Drop and re-create database
dropdb -U postgres ethiosec_db
createdb -U postgres -O ethiosec_user ethiosec_db

# Re-run migration and seed
alembic -c database/alembic.ini upgrade head
SEED_PASSWORD="DemoSecurePassword2026!" python database/seed.py
```
