from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any

class UserBase(BaseModel):
    email: str
    full_name: Optional[str] = None
    website: Optional[str] = None

class UserRegister(UserBase):
    password: str
    newsletter: Optional[bool] = False

class UserLogin(BaseModel):
    email: str
    password: str

class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    website: Optional[str] = None

class UserOut(UserBase):
    id: str
    role: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)

class TokenResponse(BaseModel):
    token: str
    user: UserOut

class TargetCreate(BaseModel):
    url: str

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
    depth: Optional[str] = "standard"
    checks: Dict[str, Any]

class FindingOut(BaseModel):
    id: str
    scan_id: str
    type: str
    severity: str
    confidence: str
    status: str
    url: Optional[str] = None
    parameter: Optional[str] = None
    title: str
    description: str
    evidence: Optional[str] = None
    http_method: Optional[str] = None
    request: Optional[str] = None
    response_summary: Optional[str] = None
    impact: Optional[str] = None
    remediation: List[str]
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    ai_explanation: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class ScanCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int
    not_detected: int
    scanner_error: int
    total: int

class ScanResultOut(BaseModel):
    scan_id: str
    target: str
    depth: str
    scanned_at: str
    security_score: int
    counts: ScanCounts
    findings: List[FindingOut]

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
    last_scan: Optional[str]
    last_target: Optional[str]
    vulnerabilities: int
    warnings: int
    passed_checks: int
    issues: int
    total_scans: int
    breakdown: Dict[str, int]
    range: DashboardTrend

class AIRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000, description="The user's question or message for the AI assistant.")
    scan_id: Optional[str] = Field(None, description="Optional ID of the scan to focus the question on.")
    finding_id: Optional[str] = Field(None, description="Optional ID of the finding to focus the question on.")
    history: Optional[List[Dict[str, Any]]] = Field(None, description="Optional recent conversation history.")

class AIAssistantRequestNew(BaseModel):
    cwe_id: str = Field(..., description="CWE ID of the vulnerability")
    severity: str = Field(..., description="Severity of the vulnerability")
    target_endpoint: str = Field(..., description="Target endpoint where the vulnerability was found")
    response_snippet: str = Field(..., description="HTTP response snippet containing evidence of the vulnerability")

class AIResponse(BaseModel):
    reply: str
    scan_id: Optional[str] = None
    finding_id: Optional[str] = None

class UserSettingsUpdate(BaseModel):
    default_scan_depth: Optional[str] = None
    notif_scan_completed: Optional[bool] = None
    notif_scan_failed: Optional[bool] = None
    notif_security_findings: Optional[bool] = None

class UserSettingsOut(BaseModel):
    default_scan_depth: str
    notif_scan_completed: bool
    notif_scan_failed: bool
    notif_security_findings: bool
    updated_at: str

    model_config = ConfigDict(from_attributes=True)
