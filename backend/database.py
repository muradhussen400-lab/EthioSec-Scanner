import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Use PostgreSQL if provided, otherwise default to SQLite for local development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ethiosec.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

try:
    engine = create_engine(DATABASE_URL, connect_args=connect_args)
    if not DATABASE_URL.startswith("sqlite"):
        # Test connection immediately
        with engine.connect() as conn:
            pass
except Exception as e:
    import logging
    logging.warning(f"Could not connect to {DATABASE_URL} ({e}). Falling back to local SQLite.")
    DATABASE_URL = "sqlite:///./ethiosec.db"
    connect_args = {"check_same_thread": False}
    engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
