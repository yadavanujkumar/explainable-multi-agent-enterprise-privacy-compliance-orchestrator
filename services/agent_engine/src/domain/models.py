from pydantic import BaseModel
from typing import List, Optional

class DataEvent(BaseModel):
    event_id: str
    source_system: str
    payload: str
    timestamp: str

class PIIFinding(BaseModel):
    entity_type: str
    start_idx: int
    end_idx: int
    risk_score: float

class ComplianceAlert(BaseModel):
    alert_id: str
    event_id: str
    findings: List[PIIFinding]
    xai_explanation: str
    proposed_redaction_policy: str
    status: str = 'PENDING_APPROVAL'