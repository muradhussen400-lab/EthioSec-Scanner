from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from typing import Optional
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
    password_hash = Column(String, nullable=True)
    role = Column(String, default="user")
    website = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    
    # OAuth Identity Linking
    google_id = Column(String, unique=True, index=True, nullable=True)
    auth_provider = Column(String, default="local") # "local" or "google"
    
    # Email verification
    is_verified = Column(Boolean, default=True, nullable=False)
    verification_code_hash = Column(String, nullable=True)
    verification_expires_at = Column(String, nullable=True)
    verification_attempts = Column(Integer, default=0, nullable=False)
    verification_sent_at = Column(String, nullable=True)

    # Phone number verification (real SMS provider integration)
    phone_number = Column(String(32), unique=True, index=True, nullable=True)
    phone_verified = Column(Boolean, default=False, nullable=False)
    phone_verified_at = Column(String, nullable=True)
    phone_verification_sent_at = Column(String, nullable=True)
    phone_verification_attempts = Column(Integer, default=0, nullable=False)

    # Password reset
    reset_token_hash = Column(String, nullable=True)
    reset_expires_at = Column(String, nullable=True)
    reset_attempts = Column(Integer, default=0, nullable=False)

    # Session & Account Lockout
    session_revoked_at = Column(String, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(String, nullable=True)

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
    modules = Column(JSON, nullable=True)
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
    confidence = Column(String, default="HIGH") # HIGH, MEDIUM, LOW
    status = Column(String, default="NOT_DETECTED") # Backward-compatible status
    verification_status = Column(String, default=None, nullable=True)
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

    @property
    def owasp_category(self) -> Optional[str]:
        return self.owasp

    @owasp_category.setter
    def owasp_category(self, val: Optional[str]):
        self.owasp = val

    @property
    def cwe_id(self) -> Optional[str]:
        return self.cwe

    @cwe_id.setter
    def cwe_id(self, val: Optional[str]):
        self.cwe = val

    @property
    def location(self) -> Optional[str]:
        if self.evidence:
            ev_lower = self.evidence.lower()
            if "location: cookie" in ev_lower or "cookie parameter" in (self.title or "").lower():
                return "cookie"
            if "location: form" in ev_lower or "form parameter" in (self.title or "").lower():
                return "form"
            if "location: json" in ev_lower or "json parameter" in (self.title or "").lower():
                return "json"
            if "location: header" in ev_lower or "header parameter" in (self.title or "").lower():
                return "header"
            if "location: query" in ev_lower or "query parameter" in (self.title or "").lower():
                return "query"
        return "query" if self.parameter else None

class UserSettings(Base):
    __tablename__ = "user_settings"
    
    user_id = Column(String, ForeignKey("users.id"), primary_key=True, index=True)
    default_scan_depth = Column(String, default="standard")
    notif_scan_completed = Column(Boolean, default=True)
    notif_scan_failed = Column(Boolean, default=True)
    notif_security_findings = Column(Boolean, default=True)
    updated_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class ScanModule(Base):
    __tablename__ = "scan_modules"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    module_key = Column(String(50), nullable=False)
    module_name = Column(String(100), nullable=False)
    status = Column(String(50), default="pending")
    progress = Column(Integer, default=0)
    execution_order = Column(Integer, default=1)
    findings_count = Column(Integer, default=0)
    duration_ms = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    finished_at = Column(String, nullable=True)

class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    format = Column(String(20), default="pdf")
    storage_path = Column(Text, nullable=False)
    file_size_bytes = Column(Integer, default=0)
    is_expired = Column(Boolean, default=False)
    expires_at = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(50), default="system")
    title = Column(String(150), nullable=False)
    message = Column(Text, nullable=False)
    link = Column(Text, nullable=True)
    is_read = Column(Boolean, default=False, index=True)
    read_at = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(100), nullable=False)
    entity = Column(String(50), nullable=False)
    entity_id = Column(String, nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    changes = Column(JSON, default=dict)
    created_at = Column(String, default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

