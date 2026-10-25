import re
import json
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from typing import Optional, List, Dict, Any

class UserBase(BaseModel):
    email: str = Field(..., max_length=255)
    full_name: Optional[str] = Field(None, max_length=100)
    website: Optional[str] = Field(None, max_length=255)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Email address cannot be empty.")
        normalized = v.strip().lower()
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", normalized):
            raise ValueError("Invalid email address format.")
        return normalized

class UserRegister(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    newsletter: Optional[bool] = False

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if len(v) > 128:
            raise ValueError("Password cannot exceed 128 characters.")
        return v

class UserLogin(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_login_email(cls, v: str) -> str:
        return v.strip().lower()

class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(None, max_length=100)
    website: Optional[str] = Field(None, max_length=255)
    avatar_url: Optional[str] = Field(None, max_length=500)
    phone_number: Optional[str] = Field(None, max_length=32)

class UserOut(UserBase):
    id: str
    role: str
    is_verified: bool = False
    google_id: Optional[str] = None
    auth_provider: Optional[str] = "local"
    avatar_url: Optional[str] = None
    phone_number: Optional[str] = None
    phone_verified: bool = False
    phone_verified_at: Optional[str] = None
    created_at: str

    model_config = ConfigDict(from_attributes=True)

class TokenResponse(BaseModel):
    token: str
    user: UserOut

class GoogleExchangeRequest(BaseModel):
    code: str = Field(..., min_length=10, max_length=128)

class PhoneSendCodeRequest(BaseModel):
    phone_number: str = Field(..., min_length=7, max_length=32)

class PhoneVerifyCodeRequest(BaseModel):
    phone_number: str = Field(..., min_length=7, max_length=32)
    code: str = Field(..., min_length=4, max_length=10)

class PhoneStatusOut(BaseModel):
    phone_number: Optional[str] = None
    phone_verified: bool = False
    phone_verified_at: Optional[str] = None
    provider: Optional[str] = None
    is_real_provider: Optional[bool] = False


class VerifyEmailRequest(BaseModel):
    email: str = Field(..., max_length=255)
    code: str = Field(..., min_length=4, max_length=10)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("code")
    @classmethod
    def normalize_code(cls, v: str) -> str:
        return v.strip()

class ResendVerificationRequest(BaseModel):
    email: str = Field(..., max_length=255)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., max_length=255)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

class ResetPasswordRequest(BaseModel):
    email: str = Field(..., max_length=255)
    token: str = Field(..., min_length=10, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if len(v) > 128:
            raise ValueError("Password cannot exceed 128 characters.")
        return v

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if len(v) > 128:
            raise ValueError("Password cannot exceed 128 characters.")
        return v

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None
    email: Optional[str] = None
    is_verified: Optional[bool] = None

class TargetCreate(BaseModel):
    url: str = Field(..., max_length=500)

class TargetOut(BaseModel):
    id: str
    url: str
    authorized: bool
    created_at: str

    model_config = ConfigDict(from_attributes=True)

class ScanCreate(BaseModel):
    target_id: str
    depth: Optional[str] = "standard"
    modules: Optional[Dict[str, Any]] = {}
    authorized: bool
    auth_context_1: Optional[Dict[str, Any]] = None
    auth_context_2: Optional[Dict[str, Any]] = None

    @field_validator("depth")
    @classmethod
    def validate_depth(cls, v: Optional[str]) -> str:
        if not v:
            return "standard"
        raw = v.strip().lower().replace("_", " ")
        if raw in ("deep", "deep audit", "deep scan", "level 2"):
            return "deep"
        if raw in ("quick", "quick scan"):
            return "quick"
        if raw in ("standard", "standard scan", "level 1"):
            return "standard"
        allowed = {"quick", "standard", "deep"}
        if raw not in allowed:
            raise ValueError(f"Invalid scan profile '{v}'. Supported profiles are: standard, deep.")
        return raw

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, v: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("Modules must be a key-value dictionary.")
        valid_keys = {
            "sqli", "xss", "headers", "cookies", "cors", "https", "auth",
            "access_control", "exposed_files", "http_methods", "info_disclosure",
            "csrf", "ssrf", "xsrf", "anti-csrf", "ssrf_safe", "request_forgery",
            "misconfig", "tls", "ssl", "all"
        }
        unknown = set(v.keys()) - valid_keys
        if unknown:
            supported = ", ".join(sorted([
                "sqli", "xss", "headers", "cookies", "cors", "https", "auth",
                "access_control", "exposed_files", "http_methods", "info_disclosure",
                "csrf", "ssrf"
            ]))
            raise ValueError(f"Unknown module(s): {', '.join(sorted(unknown))}. Supported modules are: {supported}.")
        return v

class ChecksOut(BaseModel):
    headers: bool = False
    ssl: bool = False
    dns: bool = False
    meta: bool = False
    owasp: bool = False
    ai: bool = False

class ScanStatusOut(BaseModel):
    scan_id: str
    target: str
    status: str
    progress: int
    stage: str
    depth: str
    checks: Dict[str, Any]
    completed_checks: Optional[Dict[str, bool]] = None
    modules: Optional[Dict[str, Any]] = None
    module_details: Optional[Dict[str, Any]] = None
    timeline: Optional[List[Dict[str, Any]]] = None
    pipeline_stages: Optional[List[Dict[str, Any]]] = None
    findings_count: Optional[Dict[str, int]] = None
    inventory: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    finished_at: Optional[str] = None

class FindingOut(BaseModel):
    id: str
    type: str
    severity: str
    confidence: Optional[str] = "HIGH"
    status: Optional[str] = "NOT_DETECTED"
    verification_status: Optional[str] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    location: Optional[str] = None
    title: str
    description: str
    evidence: Optional[str] = None
    http_method: Optional[str] = None
    request: Optional[str] = None
    response_summary: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[List[str]] = []
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    ai_explanation: Optional[str] = None
    created_at: str

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="after")
    def populate_verification_status(self):
        if not self.verification_status:
            st = (self.status or "").upper()
            if st in ("SCANNER_ERROR", "ERROR"):
                self.verification_status = "ERROR"
            elif st == "NOT_DETECTED":
                self.verification_status = "NOT_DETECTED"
            elif st == "INCONCLUSIVE":
                self.verification_status = "INCONCLUSIVE"
            elif st in ("BLOCKED", "SKIPPED", "NOT_TESTED", "POTENTIAL", "CONFIRMED"):
                self.verification_status = st
            elif st in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if (self.confidence or "").upper() == "LOW" or "potential" in (self.title or "").lower():
                    self.verification_status = "POTENTIAL"
                else:
                    self.verification_status = "CONFIRMED"
            else:
                self.verification_status = "POTENTIAL"
        else:
            self.verification_status = self.verification_status.upper()
            if self.verification_status == "SCANNER_ERROR":
                self.verification_status = "ERROR"
        if not self.location:
            if self.evidence and "location: cookie" in self.evidence.lower():
                self.location = "cookie"
            elif self.evidence and "location: form" in self.evidence.lower():
                self.location = "form"
            elif self.evidence and "location: json" in self.evidence.lower():
                self.location = "json"
            elif self.evidence and "location: header" in self.evidence.lower():
                self.location = "header"
            elif self.evidence and "location: query" in self.evidence.lower():
                self.location = "query"
            elif self.parameter:
                self.location = "query"
        return self

    @field_validator("remediation", mode="before")
    @classmethod
    def parse_remediation(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            v_str = v.strip()
            if v_str.startswith("[") and v_str.endswith("]"):
                try:
                    parsed = json.loads(v_str)
                    if isinstance(parsed, list):
                        return [str(x) for x in parsed]
                except Exception:
                    pass
            return [line.strip() for line in v.splitlines() if line.strip()]
        return []

class ScanCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    not_detected: int = 0
    scanner_error: int = 0
    inconclusive: int = 0
    confirmed: int = 0
    potential: int = 0
    blocked: int = 0
    skipped: int = 0
    not_tested: int = 0
    total: int = 0

class ScanResultOut(BaseModel):
    scan_id: str
    target: str
    depth: str
    status: Optional[str] = "completed"
    scanned_at: str
    security_score: Optional[int] = None
    counts: ScanCounts
    findings: List[FindingOut]
    module_details: Optional[Dict[str, Any]] = None
    inventory: Optional[Dict[str, Any]] = None

class DashboardTrend(BaseModel):
    labels: List[str]
    mine: List[int]
    all: List[int]
    trendLabels: List[str]
    trend: List[int]
    websites: int
    requests: int
    response: int

class DashboardSummaryOut(BaseModel):
    security_score: int
    last_scan: Optional[str] = None
    last_target: Optional[str] = None
    vulnerabilities: int
    warnings: int
    passed_checks: int
    issues: int
    total_scans: int
    breakdown: Dict[str, int]
    range: DashboardTrend

class AIRequest(BaseModel):
    message: str = Field(..., max_length=2000)
    finding_id: Optional[str] = None
    scan_id: Optional[str] = None
    history: Optional[List[Dict[str, Any]]] = None

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Message cannot be empty or contain only whitespace.")
        return v.strip()

class AIResponse(BaseModel):
    reply: str
    scan_id: Optional[str] = None
    finding_id: Optional[str] = None

class AIAssistantRequestNew(BaseModel):
    cwe_id: str = Field(..., max_length=50)
    severity: str = Field(..., max_length=50)
    target_endpoint: str = Field(..., max_length=500)
    response_snippet: str = Field(..., max_length=4000)

class UserSettingsUpdate(BaseModel):
    default_scan_depth: Optional[str] = None
    notif_scan_completed: Optional[bool] = None
    notif_scan_failed: Optional[bool] = None
    notif_security_findings: Optional[bool] = None

    @field_validator("default_scan_depth")
    @classmethod
    def validate_scan_depth(cls, v: Optional[str]) -> Optional[str]:
        if v and v.lower() not in {"quick", "standard", "deep"}:
            return "standard"
        return v.lower() if v else None

class UserSettingsOut(BaseModel):
    user_id: str
    default_scan_depth: str
    notif_scan_completed: bool
    notif_scan_failed: bool
    notif_security_findings: bool
    updated_at: str

    model_config = ConfigDict(from_attributes=True)
