# Database Schema Improvement Proposals

This document outlines recommended database schema and architecture enhancements for the EthioSec Scanner project. 

Per project instructions, these enhancements **have not been applied** to the current Alembic migration (`0001_initial_schema.py`) to maintain strict, 1-to-1 compatibility with the existing `backend/models.py` codebase. They are submitted here for team discussion and future architectural planning.

---

### Proposal 1: Native PostgreSQL `UUID` Types

- **Current State**: Primary keys and foreign keys (`users.id`, `scan_targets.id`, `scans.id`, `findings.id`, etc.) are defined as `Column(String)` and store 36-character string representations (`VARCHAR`).
- **Proposed Enhancement**: Migrate identifier columns to PostgreSQL native `UUID` (`sa.dialects.postgresql.UUID(as_uuid=True)` or SQLAlchemy 2.0 `sa.Uuid()`).
- **Rationale**:
  - **Storage Optimization**: Native UUIDs consume 16 bytes per row instead of 36 bytes (or more) for text. In large tables (such as `findings`), this reduces table and index size by over 50%.
  - **Index & Join Performance**: Integer/binary comparison of 128-bit values is significantly faster in PostgreSQL B-trees than lexical string comparison.
  - **Integrity**: Prevents non-UUID or malformed strings from being inserted.
- **Backend Changes Required**:
  - In `backend/models.py`: update `id = Column(String, ...)` to `id = Column(Uuid, default=uuid.uuid4, ...)`.
  - In `backend/schemas.py`: ensure Pydantic models parse `UUID` objects and serialize them to string representations in API responses (handled natively by Pydantic v2).

---

### Proposal 2: Native `TIMESTAMPTZ` for Timestamps

- **Current State**: Columns like `created_at`, `finished_at`, `verification_expires_at`, `reset_expires_at`, and `locked_until` are defined as `Column(String)` storing ISO 8601 strings (e.g. `2026-10-23T12:00:00+00:00`).
- **Proposed Enhancement**: Convert timestamp columns to `sa.DateTime(timezone=True)` (`TIMESTAMPTZ` in PostgreSQL).
- **Rationale**:
  - **SQL Query Capabilities**: Enables date/time arithmetic, interval queries (e.g. `WHERE created_at >= NOW() - INTERVAL '30 days'`), and aggregate grouping by day/month in SQL.
  - **Sorting & Filtering Accuracy**: Lexicographical string comparisons fail if dates are stored in differing UTC offsets or formats.
  - **Storage & Indexing**: PostgreSQL stores `timestamptz` in 8 bytes, whereas ISO strings consume 25-35 bytes.
- **Backend Changes Required**:
  - In `backend/models.py`: change `Column(String)` to `Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))`.
  - In `backend/routers.py`: adjust date parsing or comparison logic where string operations are currently performed.

---

### Proposal 3: Database-Level `ON DELETE CASCADE` Foreign Keys

- **Current State**: Foreign keys in `backend/models.py` do not specify `ondelete="CASCADE"`. For example, `Column(String, ForeignKey("users.id"))`. Cascading is handled exclusively in Python by SQLAlchemy ORM relationships (`cascade="all, delete-orphan"`).
- **Proposed Enhancement**: Add `ondelete="CASCADE"` to foreign key constraints at the database schema level:
  - `scan_targets.user_id` -> `users.id` ON DELETE CASCADE
  - `scans.user_id` -> `users.id` ON DELETE CASCADE
  - `findings.scan_id` -> `scans.id` ON DELETE CASCADE
  - `findings.target_id` -> `scan_targets.id` ON DELETE SET NULL (or CASCADE)
  - `user_settings.user_id` -> `users.id` ON DELETE CASCADE
- **Rationale**:
  - Deleting records via direct SQL queries, administrative scripts, or bulk SQL queries currently triggers foreign key constraint violations (`violates foreign key constraint`).
  - Guarantees referential integrity regardless of whether deletions originate from SQLAlchemy ORM or external database tooling.
- **Backend Changes Required**:
  - Update `ForeignKey("users.id")` to `ForeignKey("users.id", ondelete="CASCADE")` across `backend/models.py`.

---

### Proposal 4: CHECK Constraints for State and Severity Enumerations

- **Current State**: Columns with discrete allowed sets of values are unrestricted `VARCHAR`:
  - `users.role`: `'user'`, `'admin'`
  - `scans.depth`: `'quick'`, `'standard'`, `'deep'`
  - `scans.status`: `'queued'`, `'running'`, `'completed'`, `'failed'`
  - `findings.severity`: `'critical'`, `'high'`, `'medium'`, `'low'`, `'info'`
  - `findings.status`: `'HIGH'`, `'MEDIUM'`, `'LOW'`, `'NOT_DETECTED'`, `'SCANNER_ERROR'`
- **Proposed Enhancement**: Add database-level `CHECK` constraints (or PostgreSQL `ENUM` types).
  - Example: `sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'info')", name="ck_findings_severity")`
- **Rationale**:
  - Defends against invalid state transitions or corrupted data being written by buggy workers, manual SQL patches, or future microservices.
- **Backend Changes Required**:
  - Add `__table_args__ = (CheckConstraint(...),)` to corresponding model classes in `backend/models.py`.

---

### Proposal 5: Composite & Performance Indexes

- **Current State**: Only single-column indexes exist on primary keys and `users.email`, `users.full_name`.
- **Proposed Enhancement**: Add targeted composite indexes reflecting common query patterns in the dashboard and scanner:
  - `findings`: Index on `(scan_id, severity)` and `(scan_id, status)` for rapid vulnerability aggregation and report generation.
  - `scans`: Index on `(user_id, status)` and `(user_id, created_at DESC)` for user dashboard scan listings.
  - `scan_targets`: Index on `(user_id, url)`.
- **Rationale**:
  - The findings table will be the highest volume table in the system. Filtering findings for a specific scan by severity currently requires filtering all scan findings. Composite indexes allow index-only scans.
- **Backend Changes Required**:
  - Add `Index` declarations in `__table_args__` in `backend/models.py`.

---

### Proposal 6: Database Server-Side Defaults (`server_default`)

- **Current State**: Column defaults (such as `is_verified = Column(Boolean, default=True)`, `progress = Column(Integer, default=0)`) are Python-level defaults evaluated by SQLAlchemy upon object creation, not database server defaults.
- **Proposed Enhancement**: Add `server_default` to all columns with constant defaults:
  - `is_verified`: `server_default=sa.text("true")`
  - `verification_attempts`, `reset_attempts`, `failed_login_attempts`, `progress`: `server_default=sa.text("0")`
  - `role`: `server_default=sa.text("'user'")`
  - `status`: `server_default=sa.text("'queued'")`
  - `depth`: `server_default=sa.text("'standard'")`
- **Rationale**:
  - Allows raw SQL `INSERT` statements (such as batch ETL or migration scripts) to omit default columns without inserting `NULL`.
- **Backend Changes Required**:
  - Add `server_default=...` alongside `default=...` in `backend/models.py`.

---

### Proposal 7: Gate `Base.metadata.create_all()` Behind Environment Check

- **Current State**: `backend/main.py` unconditionally executes `Base.metadata.create_all(bind=engine)` at module load time on line 14.
- **Proposed Enhancement**: Gate this call so it only runs in local SQLite development, and rely on Alembic for production PostgreSQL deployments:
  ```python
  if ENVIRONMENT != "production" and DATABASE_URL.startswith("sqlite"):
      Base.metadata.create_all(bind=engine)
  ```
- **Rationale**:
  - In a multi-worker production deployment (e.g. Uvicorn with multiple workers or Kubernetes pods), concurrent `create_all` calls can trigger database lock contention and race conditions.
  - `create_all` does not apply column alterations, renames, or index drops; mixing `create_all` with Alembic creates configuration drift.
- **Backend Changes Required**:
  - Add conditional check in `backend/main.py`.
