import pytest
from src.domain.models import DataEvent
from src.agents.pii_detector import PIIDetectorAgent
from src.agents.xai_explainer import XAIExplainerAgent

def test_pii_detector():
    detector = PIIDetectorAgent()
    event = DataEvent(
        event_id="123",
        source_system="CRM",
        payload="User email is john.doe@example.com and SSN is 123-45-6789.",
        timestamp="2023-01-01T00:00:00Z"
    )
    findings = detector.scan_payload(event)
    assert len(findings) == 2
    entity_types = [f.entity_type for f in findings]
    assert "SSN" in entity_types
    assert "EMAIL" in entity_types

def test_redaction_policy_generation():
    detector = PIIDetectorAgent()
    event = DataEvent(
        event_id="123",
        source_system="CRM",
        payload="Email: test@test.com",
        timestamp="2023-01-01T00:00:00Z"
    )
    findings = detector.scan_payload(event)
    policy = detector.generate_redaction_policy(findings)
    assert "REDACT_ENTITIES:EMAIL" in policy

def test_xai_explainer():
    detector = PIIDetectorAgent()
    explainer = XAIExplainerAgent()
    event = DataEvent(
        event_id="123",
        source_system="CRM",
        payload="SSN 123-45-6789",
        timestamp="2023-01-01T00:00:00Z"
    )
    findings = detector.scan_payload(event)
    explanation = explainer.generate_explanation(findings)
    assert "HIGH RISK" in explanation
    assert "sandbox simulation" in explanation