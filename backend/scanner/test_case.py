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
    
    baseline_request: Optional[Dict[str, Any]] = None
    baseline_response: Optional[Dict[str, Any]] = None
    
    test_request: Optional[Dict[str, Any]] = None
    test_response: Optional[Dict[str, Any]] = None
    
    observations: List[Observation] = Field(default_factory=list)
    
    status: str = "NOT_DETECTED" # HIGH, MEDIUM, LOW, NOT_DETECTED, SCANNER_ERROR, INCONCLUSIVE
    severity: str = "info"
    confidence: str = "HIGH" # HIGH, MEDIUM, LOW
    
    title: str = ""
    description: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: List[str] = []
    owasp: Optional[str] = None

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
        if self.status in ("SCANNER_ERROR", "INCONCLUSIVE"):
            evidence_lines = [f"[-] {obs.description}" for obs in self.observations]
            if evidence_lines:
                self.evidence = "\n".join(evidence_lines)
            return

        strong_evidence_count = sum(1 for obs in self.observations if obs.is_strong_evidence)
        suspicious_count = sum(1 for obs in self.observations if obs.is_suspicious)

        if strong_evidence_count > 0:
            sev = (self.severity or "high").upper()
            if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                self.status = sev
            else:
                self.status = "HIGH"
            self.confidence = "HIGH"
        elif suspicious_count > 0:
            self.status = "LOW"
            self.severity = "low"
            self.confidence = "LOW"
        else:
            self.status = "NOT_DETECTED"
            self.confidence = "HIGH"

        evidence_lines = []
        for obs in self.observations:
            prefix = "[!]" if obs.is_strong_evidence else ("[~]" if obs.is_suspicious else "[+]")
            tech_tag = f" [{obs.technique}]" if obs.technique else ""
            evidence_lines.append(f"{prefix}{tech_tag} {obs.description}")
        self.evidence = "\n".join(evidence_lines)
