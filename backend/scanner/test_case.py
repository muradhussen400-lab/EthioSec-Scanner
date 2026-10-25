from pydantic import BaseModel, Field
from typing import Optional, Any, Dict, List

class Observation(BaseModel):
    signal_type: str
    description: str
    is_suspicious: bool = False
    is_strong_evidence: bool = False
    technique: Optional[str] = None
    payload: Optional[str] = None
    confidence: Optional[str] = None

class TestCaseResult(BaseModel):
    __test__ = False
    category: str
    target_endpoint: str
    http_method: str
    parameter: Optional[str] = None
    location: Optional[str] = "query" # "query", "form", "cookie", "header", "json"
    
    baseline_request: Optional[Dict[str, Any]] = None
    baseline_response: Optional[Dict[str, Any]] = None
    
    test_request: Optional[Dict[str, Any]] = None
    test_response: Optional[Dict[str, Any]] = None
    
    observations: List[Observation] = Field(default_factory=list)
    
    status: str = "NOT_DETECTED" # HIGH, MEDIUM, LOW, NOT_DETECTED, SCANNER_ERROR, INCONCLUSIVE
    verification_status: Optional[str] = None # CONFIRMED, POTENTIAL, NOT_DETECTED, INCONCLUSIVE, BLOCKED, SKIPPED, NOT_TESTED, ERROR
    severity: str = "info"
    confidence: str = "HIGH" # HIGH, MEDIUM, LOW
    
    title: str = ""
    description: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: List[str] = []
    owasp: Optional[str] = None
    cwe: Optional[str] = None

    def add_observation(
        self, 
        signal_type: str, 
        description: str, 
        is_suspicious: bool = False, 
        is_strong_evidence: bool = False,
        technique: Optional[str] = None,
        payload: Optional[str] = None,
        confidence: Optional[str] = None
    ):
        self.observations.append(Observation(
            signal_type=signal_type, 
            description=description, 
            is_suspicious=is_suspicious, 
            is_strong_evidence=is_strong_evidence,
            technique=technique,
            payload=payload,
            confidence=confidence
        ))

    def evaluate(self):
        # 1. Handle explicit non-vulnerability technical states
        if self.verification_status in ("ERROR", "SCANNER_ERROR", "INCONCLUSIVE", "BLOCKED", "SKIPPED", "NOT_TESTED"):
            if self.verification_status == "SCANNER_ERROR":
                self.verification_status = "ERROR"
            self.status = "SCANNER_ERROR" if self.verification_status == "ERROR" else self.verification_status
            evidence_lines = [f"[-] {obs.description}" for obs in self.observations]
            if evidence_lines:
                self.evidence = "\n".join(evidence_lines)
            return

        if self.status in ("SCANNER_ERROR", "INCONCLUSIVE", "BLOCKED", "SKIPPED", "NOT_TESTED"):
            self.verification_status = "ERROR" if self.status == "SCANNER_ERROR" else self.status
            evidence_lines = [f"[-] {obs.description}" for obs in self.observations]
            if evidence_lines:
                self.evidence = "\n".join(evidence_lines)
            return

        strong_evidence_count = sum(1 for obs in self.observations if obs.is_strong_evidence)
        suspicious_count = sum(1 for obs in self.observations if obs.is_suspicious)

        if strong_evidence_count > 0:
            if not self.status or self.status == "NOT_DETECTED":
                sev = (self.severity or "high").upper()
                self.status = sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH"
            if not self.verification_status:
                self.verification_status = "CONFIRMED"
            if not self.confidence or self.confidence == "LOW":
                self.confidence = "HIGH"
        elif suspicious_count > 0:
            if not self.status or self.status == "NOT_DETECTED":
                self.status = "LOW"
            self.severity = self.severity if self.severity in ("critical", "high", "medium", "low") else "low"
            if not self.verification_status:
                self.verification_status = "POTENTIAL"
            if not self.confidence or self.confidence == "HIGH":
                self.confidence = "LOW"
        else:
            self.status = "NOT_DETECTED"
            self.verification_status = "NOT_DETECTED"
            self.confidence = "HIGH"

        evidence_lines = []
        for obs in self.observations:
            prefix = "[!]" if obs.is_strong_evidence else ("[~]" if obs.is_suspicious else "[+]")
            tech_tag = f" [{obs.technique}]" if obs.technique else ""
            evidence_lines.append(f"{prefix}{tech_tag} {obs.description}")
        self.evidence = "\n".join(evidence_lines)
