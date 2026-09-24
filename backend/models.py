from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
import uuid
import datetime
from database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    full_name = Column(String, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user")
    website = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"))
    url = Column(String, nullable=False)
    authorized = Column(Boolean, default=False)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"))
    target_url = Column(String, nullable=False)
    depth = Column(String, default="standard")
    status = Column(String, default="queued") # queued, running, completed, failed
    progress = Column(Integer, default=0)
    stage = Column(String, default="Queued")
    checks = Column(JSON, default=dict)
    security_score = Column(Integer, nullable=True)
    
    # Optional Auth Contexts (JSON, typically {"headers": {"Authorization": "Bearer..."}})
    auth_context_1 = Column(JSON, nullable=True)
    auth_context_2 = Column(JSON, nullable=True)
    
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    finished_at = Column(String, nullable=True)
    
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id"))
    target_id = Column(String, ForeignKey("scan_targets.id"), nullable=True)
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False) # critical, high, medium, low, info
    confidence = Column(String, default="high")
    status = Column(String, default="open") # open, passed
    url = Column(String, nullable=True)
    parameter = Column(String, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    http_method = Column(String, nullable=True)
    request = Column(Text, nullable=True)
    response_summary = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(JSON, default=list) # JSON list of strings
    owasp = Column(String, nullable=True)
    cwe = Column(String, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    scan = relationship("Scan", back_populates="findings")
    target = relationship("ScanTarget")
