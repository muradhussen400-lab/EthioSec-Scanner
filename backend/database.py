import os
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
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{SQLITE_DB_PATH}")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

def init_engine():
    global DATABASE_URL
    is_sqlite = DATABASE_URL.startswith("sqlite")
    
    try:
        eng = create_engine(
            DATABASE_URL,
            connect_args={"check_same_thread": False} if is_sqlite else {},
            pool_pre_ping=True
        )
        # Verify connection immediately
        with eng.connect() as conn:
            pass
        return eng
    except Exception as e:
        if ENVIRONMENT == "production":
            logger.critical(f"FATAL: Failed to connect to production database ({DATABASE_URL}): {e}")
            raise RuntimeError(
                f"FATAL: Production database connection failed ({e}). "
                "Silent fallback to SQLite in production is strictly prohibited."
            ) from e
        
        # Development / test mode fallback with explicit warning
        DATABASE_URL = f"sqlite:///{SQLITE_DB_PATH}"
        logger.warning(
            f"[DEV WARNING] Could not connect to default database ({e}). "
            f"In development mode, falling back to local SQLite at {DATABASE_URL}."
        )
        return create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

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
    Non-destructive schema migration: safely ensures new security columns
    exist on existing user tables without dropping or resetting any data.
    """
    try:
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
                ]
                
                for col_name, col_type in new_columns:
                    if col_name not in columns:
                        try:
                            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                            conn.connection.commit()
                            logger.info(f"Added column {col_name} to users table.")
                        except Exception as ex:
                            logger.debug(f"Column {col_name} check/add notice: {ex}")
    except Exception as e:
        logger.debug(f"Schema upgrade notice: {e}")

# Run non-destructive column check
safe_upgrade_schema()
