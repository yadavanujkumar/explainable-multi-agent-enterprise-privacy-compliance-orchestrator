import re
from typing import List
from domain.models import DataEvent, PIIFinding

class PIIDetectorAgent:
    """
    Detects PII in text using Regex and heuristic models.
    In a production enterprise system, this is replaced by Presidio or an LLM.
    """
    def __init__(self):
        # Mock SSN regex for demonstration
        self.ssn_pattern = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    def scan_payload(self, event: DataEvent) -> List[PIIFinding]:
        findings = []
        for match in self.ssn_pattern.finditer(event.payload):
            findings.append(PIIFinding(entity_type='SSN', start_idx=match.start(), end_idx=match.end(), risk_score=0.99))
        for match in self.email_pattern.finditer(event.payload):
            findings.append(PIIFinding(entity_type='EMAIL', start_idx=match.start(), end_idx=match.end(), risk_score=0.75))
        return findings

    def generate_redaction_policy(self, findings: List[PIIFinding]) -> str:
        if not findings:
            return 'NO_ACTION_REQUIRED'
        entities = set([f.entity_type for f in findings])
        return f"REDACT_ENTITIES:{','.join(entities)}"