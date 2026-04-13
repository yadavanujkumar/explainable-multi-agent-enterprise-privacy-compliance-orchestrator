from __future__ import annotations

import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceFramework(str, Enum):
    GDPR = "GDPR"
    CCPA = "CCPA"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"
    SOX = "SOX"


class AlertStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    AUTO_REMEDIATED = "AUTO_REMEDIATED"
    ESCALATED = "ESCALATED"


class DataEvent(BaseModel):
    event_id: str
    source_system: str
    payload: str
    timestamp: str
    data_classification: str = "INTERNAL"
    environment: str = "production"
    tenant_id: Optional[str] = None
    metadata: Dict[str, str] = Field(default_factory=dict)


class PIIFinding(BaseModel):
    entity_type: str
    start_idx: int
    end_idx: int
    risk_score: float
    severity: RiskSeverity = RiskSeverity.MEDIUM
    redacted_value: str = "[REDACTED]"
    compliance_frameworks: List[ComplianceFramework] = Field(default_factory=list)
    detection_method: str = "REGEX"
    confidence: float = 1.0

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"risk_score must be between 0.0 and 1.0, got {v}")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {v}")
        return v


class RedactionPolicy(BaseModel):
    policy_id: str
    policy_name: str
    entities_to_redact: List[str]
    redaction_method: str = "MASK"
    simulation_passed: bool = False
    downstream_impact_score: float = 0.0

    @field_validator("downstream_impact_score")
    @classmethod
    def validate_impact_score(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"downstream_impact_score must be between 0.0 and 1.0, got {v}")
        return v


class AuditEntry(BaseModel):
    audit_id: str
    event_id: str
    action: str
    actor: str = "agent-engine"
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z"
    )
    details: Dict[str, str] = Field(default_factory=dict)


class ComplianceAlert(BaseModel):
    alert_id: str
    event_id: str
    source_system: str = ""
    findings: List[PIIFinding]
    xai_explanation: str
    proposed_redaction_policy: str
    redaction_policy_detail: Optional[RedactionPolicy] = None
    status: AlertStatus = AlertStatus.PENDING_APPROVAL
    severity: RiskSeverity = RiskSeverity.MEDIUM
    triggered_frameworks: List[ComplianceFramework] = Field(default_factory=list)
    breach_notification_required: bool = False
    remediation_guidance: Dict[str, str] = Field(default_factory=dict)
    created_at: str = Field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z"
    )
    tenant_id: Optional[str] = None
    audit_trail: List[AuditEntry] = Field(default_factory=list)