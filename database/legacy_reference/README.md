# EthioSec Scanner - Database Setup Guide

This guide walks through setting up a standard local PostgreSQL installation for EthioSec Scanner.

---

## 1. Install PostgreSQL

### Fedora / Red Hat
```bash
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

### Ubuntu / Debian
```bash
sudo apt update && sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

### macOS (Homebrew)
```bash
brew install postgresql@15
brew services start postgresql@15
```

### Windows
Download and install the official PostgreSQL installer from [postgresql.org](https://www.postgresql.org/download/windows/). Keep the default port as `5432`.

---

## 2. Create the Database User & Databases

Connect to PostgreSQL as administrator:

```bash
sudo -u postgres psql
```

*(On Windows or macOS, open SQL Shell (psql) or run `psql -U postgres`)*

Execute the following SQL commands:

```sql
-- 1. Create dedicated application user (replace 'your_secure_password' with your own password)
CREATE USER ethiosec_user WITH PASSWORD 'your_secure_password';

-- 2. Create development database and test database owned by ethiosec_user
CREATE DATABASE ethiosec_db OWNER ethiosec_user;
CREATE DATABASE ethiosec_test_db OWNER ethiosec_user;

-- 3. Grant schema permissions
GRANT ALL PRIVILEGES ON DATABASE ethiosec_db TO ethiosec_user;
GRANT ALL PRIVILEGES ON DATABASE ethiosec_test_db TO ethiosec_user;

\q
```

---

## 3. Configure `.env`

In the root of the project:

```bash
cp .env.example .env
```

Open `.env` in your editor and configure your database connection strings:

```ini
DATABASE_URL=postgresql://ethiosec_user:your_secure_password@localhost:5432/ethiosec_db
TEST_DATABASE_URL=postgresql://ethiosec_user:your_secure_password@localhost:5432/ethiosec_test_db
```

> **Security Note:** The `.env` file is gitignored. Never commit `.env` or plain credentials to version control.

---

## 4. Run Migrations, Seed, and Tests

Activate the Python virtual environment:

```bash
source venv/bin/activate
```

### Step A: Apply Schema Migrations
```bash
alembic upgrade head
```
*Creates all six tables (`users`, `user_settings`, `targets`, `scans`, `findings`, `reports`) in `ethiosec_db`.*

### Step B: Populate Demonstration Data
```bash
python database/seed/seed.py
```
*Populates a verified target, a completed scan, findings across all five severities (Critical, High, Medium, Low, Info), and summary metrics. This script is idempotent and safe to run multiple times without duplicating data.*

> **IMPORTANT WARNING:** The demo seed account (`demo@ethiosec.local`) is strictly for local development and demonstration. It must **never** be run on a production deployment.

### Step C: Run Automated Tests
```bash
pytest -v backend/tests/test_database.py
```
*Executes against `TEST_DATABASE_URL` (`ethiosec_test_db`), verifying connection, table existence, CHECK constraints, UNIQUE constraints, and cascade delete behavior without touching your development data.*

---

## 5. View Tables and Data

### Option 1: Command Line (`psql`)
```bash
psql -h localhost -p 5432 -U ethiosec_user -d ethiosec_db
```

Useful inspection commands:
```sql
\dt                          -- List all tables
SELECT email, role FROM users;
SELECT severity, title, module FROM findings;
\q                           -- Exit
```

### Option 2: VS Code PostgreSQL Extension
1. Install the **PostgreSQL** extension (by Chris Kolkman) from the VS Code Extensions marketplace.
2. In the PostgreSQL Explorer panel, click **+ Add Connection**.
3. Enter connection settings:
   * **Host:** `localhost`
   * **Port:** `5432`
   * **User:** `ethiosec_user`
   * **Password:** *your password*
   * **Database:** `ethiosec_db`
4. Expand the connection tree to browse schemas, tables, and rows visually.

---

## 6. Troubleshooting Common Issues

### Issue 1: `FATAL: password authentication failed for user "ethiosec_user"`
* **Cause:** The password specified in `.env` does not match the password set in PostgreSQL.
* **Fix:** Reset the password via `sudo -u postgres psql`:
  ```sql
  ALTER USER ethiosec_user WITH PASSWORD 'your_new_password';
  ```
  Then update `DATABASE_URL` and `TEST_DATABASE_URL` in `.env`.

### Issue 2: `connection to server at "localhost" (127.0.0.1), port 5432 failed: Connection refused`
* **Cause:** The PostgreSQL service is stopped or listening on a non-standard port.
* **Fix:** Check service status and start PostgreSQL:
  ```bash
  sudo systemctl status postgresql
  sudo systemctl start postgresql
  ```
  Verify port listening:
  ```bash
  ss -tulpn | grep 5432
  ```

### Issue 3: `FATAL: database "ethiosec_db" does not exist`
* **Cause:** The database was not created prior to running migrations.
* **Fix:** Connect via `sudo -u postgres psql` and create the databases:
  ```sql
  CREATE DATABASE ethiosec_db OWNER ethiosec_user;
  CREATE DATABASE ethiosec_test_db OWNER ethiosec_user;
  ```
