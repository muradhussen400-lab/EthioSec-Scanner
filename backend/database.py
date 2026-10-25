import os
import re
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("ethiosec.database")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()

# Database configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_DB_PATH = os.path.join(BASE_DIR, "ethiosec.db")
RAW_DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{SQLITE_DB_PATH}")

def normalize_db_url(url: str) -> str:
    """
    Normalizes PostgreSQL connection strings so that SQLAlchemy uses psycopg2 correctly
    and handles legacy postgres:// syntax.
    """
    if not url:
        return f"sqlite:///{SQLITE_DB_PATH}"
    u = url.strip()
    if u.startswith("postgres://"):
        return "postgresql+psycopg2://" + u[len("postgres://"):]
    if u.startswith("postgresql://") and not u.startswith("postgresql+"):
        return "postgresql+psycopg2://" + u[len("postgresql://"):]
    return u

DATABASE_URL = normalize_db_url(RAW_DATABASE_URL)

def redact_db_url(url: str) -> str:
    """Masks database credentials in logs and exception messages."""
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", url)

def init_engine():
    global DATABASE_URL
    is_sqlite = DATABASE_URL.startswith("sqlite")
    
    engine_kwargs = {
        "pool_pre_ping": True,
    }
    if is_sqlite:
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # PostgreSQL-specific connection pooling and timeouts
        engine_kwargs["pool_size"] = int(os.getenv("DB_POOL_SIZE", "10"))
        engine_kwargs["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", "20"))
        engine_kwargs["pool_timeout"] = int(os.getenv("DB_POOL_TIMEOUT", "30"))
        engine_kwargs["pool_recycle"] = int(os.getenv("DB_POOL_RECYCLE", "1800"))

    try:
        eng = create_engine(DATABASE_URL, **engine_kwargs)
        # Verify connection immediately with basic query
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info(f"Connected to database successfully ({'SQLite' if is_sqlite else 'PostgreSQL'}).")
        return eng
    except Exception as e:
        safe_url = redact_db_url(DATABASE_URL)
        if ENVIRONMENT == "production":
            logger.critical(f"FATAL: Failed to connect to production database ({safe_url}): {e}")
            raise RuntimeError(
                f"FATAL: Production database connection failed ({e}). "
                "Silent fallback to SQLite in production is strictly prohibited."
            ) from e
        
        # Development / test mode fallback with explicit warning
        fallback_url = f"sqlite:///{SQLITE_DB_PATH}"
        logger.warning(
            f"[DEV WARNING] Could not connect to default database ({safe_url}): {e}. "
            f"In development mode, falling back to local SQLite at {fallback_url}."
        )
        DATABASE_URL = fallback_url
        return create_engine(
            fallback_url,
            connect_args={"check_same_thread": False},
            pool_pre_ping=True
        )

engine = init_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def safe_upgrade_schema():
    """
    Non-destructive schema migration: safely ensures new security, phone verification,
    and profile columns exist on existing tables without dropping or resetting data.
    """
    try:
        # Ensure any newly declared models exist without dropping anything
        Base.metadata.create_all(bind=engine)
        
        with engine.connect() as conn:
            if DATABASE_URL.startswith("sqlite"):
                cursor = conn.connection.cursor()
                cursor.execute("PRAGMA table_info(users)")
                columns = [col[1] for col in cursor.fetchall()]
                
                new_columns = [
                    ("is_verified", "BOOLEAN DEFAULT 0"),
                    ("verification_code_hash", "TEXT"),
                    ("verification_expires_at", "TEXT"),
                    ("verification_attempts", "INTEGER DEFAULT 0"),
                    ("verification_sent_at", "TEXT"),
                    ("reset_token_hash", "TEXT"),
                    ("reset_expires_at", "TEXT"),
                    ("reset_attempts", "INTEGER DEFAULT 0"),
                    ("session_revoked_at", "TEXT"),
                    ("failed_login_attempts", "INTEGER DEFAULT 0"),
                    ("locked_until", "TEXT"),
                    ("google_id", "TEXT"),
                    ("auth_provider", "TEXT DEFAULT 'local'"),
                    ("avatar_url", "TEXT"),
                    ("phone_number", "TEXT"),
                    ("phone_verified", "BOOLEAN DEFAULT 0"),
                    ("phone_verified_at", "TEXT"),
                    ("phone_verification_sent_at", "TEXT"),
                    ("phone_verification_attempts", "INTEGER DEFAULT 0"),
                ]
                
                for col_name, col_type in new_columns:
                    if col_name not in columns:
                        try:
                            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                            conn.connection.commit()
                            logger.info(f"Added column {col_name} to users table.")
                        except Exception as ex:
                            logger.debug(f"Column {col_name} check/add notice: {ex}")

                # Safe migration for findings table (verification_status, owasp_category, cwe_id)
                cursor.execute("PRAGMA table_info(findings)")
                findings_cols = [col[1] for col in cursor.fetchall()]
                finding_adds = [
                    ("verification_status", "TEXT"),
                    ("owasp_category", "TEXT"),
                    ("cwe_id", "TEXT"),
                ]
                for col_name, col_type in finding_adds:
                    if col_name not in findings_cols:
                        try:
                            cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}")
                            conn.connection.commit()
                            logger.info(f"Added column {col_name} to findings table.")
                        except Exception as ex:
                            logger.debug(f"Column {col_name} check notice: {ex}")
            else:
                # PostgreSQL safe migration
                pg_columns = [
                    ("google_id", "VARCHAR(255)"),
                    ("auth_provider", "VARCHAR(50) DEFAULT 'local'"),
                    ("is_verified", "BOOLEAN DEFAULT FALSE"),
                    ("verification_code_hash", "TEXT"),
                    ("verification_expires_at", "TEXT"),
                    ("verification_attempts", "INTEGER DEFAULT 0"),
                    ("verification_sent_at", "TEXT"),
                    ("reset_token_hash", "TEXT"),
                    ("reset_expires_at", "TEXT"),
                    ("reset_attempts", "INTEGER DEFAULT 0"),
                    ("session_revoked_at", "TEXT"),
                    ("failed_login_attempts", "INTEGER DEFAULT 0"),
                    ("locked_until", "TEXT"),
                    ("avatar_url", "TEXT"),
                    ("phone_number", "VARCHAR(32)"),
                    ("phone_verified", "BOOLEAN DEFAULT FALSE"),
                    ("phone_verified_at", "TIMESTAMPTZ"),
                    ("phone_verification_sent_at", "TIMESTAMPTZ"),
                    ("phone_verification_attempts", "INTEGER DEFAULT 0"),
                ]
                for col_name, col_type in pg_columns:
                    try:
                        conn.execute(text(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col_name} {col_type};"))
                        conn.commit()
                    except Exception as ex:
                        logger.debug(f"PostgreSQL column {col_name} notice: {ex}")
                
                finding_pg = [
                    ("verification_status", "VARCHAR(50)"),
                    ("owasp_category", "VARCHAR(100)"),
                    ("cwe_id", "VARCHAR(50)"),
                ]
                for col_name, col_type in finding_pg:
                    try:
                        conn.execute(text(f"ALTER TABLE findings ADD COLUMN IF NOT EXISTS {col_name} {col_type};"))
                        conn.commit()
                    except Exception as ex:
                        logger.debug(f"PostgreSQL findings column {col_name} notice: {ex}")
    except Exception as e:
        logger.debug(f"Schema upgrade notice: {e}")

# Run non-destructive column check
safe_upgrade_schema()

