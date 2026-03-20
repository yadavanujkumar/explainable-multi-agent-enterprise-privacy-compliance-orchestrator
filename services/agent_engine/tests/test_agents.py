"""
Enterprise-grade test suite for the Agent Engine.
"""
from __future__ import annotations

import pytest
from src.domain.models import (
    ComplianceFramework,
    DataEvent,
    RiskSeverity,
)
from src.agents.pii_detector import PIIDetectorAgent
from src.agents.xai_explainer import XAIExplainerAgent
from src.agents.compliance_engine import ComplianceEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def detector() -> PIIDetectorAgent:
    return PIIDetectorAgent()


@pytest.fixture
def explainer() -> XAIExplainerAgent:
    return XAIExplainerAgent()


@pytest.fixture
def compliance_engine() -> ComplianceEngine:
    return ComplianceEngine()


def _make_event(payload: str, event_id: str = "test-001") -> DataEvent:
    return DataEvent(
        event_id=event_id,
        source_system="CRM",
        payload=payload,
        timestamp="2024-01-01T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# PII Detector – basic patterns
# ---------------------------------------------------------------------------
class TestPIIDetectorBasicPatterns:
    def test_detects_ssn(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        types = [f.entity_type for f in findings]
        assert "SSN" in types

    def test_detects_email(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("Contact john.doe@example.com"))
        types = [f.entity_type for f in findings]
        assert "EMAIL" in types

    def test_detects_credit_card(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("Card 4111111111111111"))
        types = [f.entity_type for f in findings]
        assert "CREDIT_CARD" in types

    def test_detects_phone_number(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("Call us at 555-867-5309"))
        types = [f.entity_type for f in findings]
        assert "PHONE_NUMBER" in types

    def test_detects_ip_address(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("Source IP: 192.168.1.100"))
        types = [f.entity_type for f in findings]
        assert "IP_ADDRESS" in types

    def test_detects_date_of_birth(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("DOB: 01/15/1990"))
        types = [f.entity_type for f in findings]
        assert "DATE_OF_BIRTH" in types

    def test_detects_iban(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("Bank: GB29NWBK60161331926819"))
        types = [f.entity_type for f in findings]
        assert "IBAN" in types

    def test_detects_medical_record_number(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("Patient MRN-123456"))
        types = [f.entity_type for f in findings]
        assert "MEDICAL_RECORD_NUMBER" in types

    def test_detects_drivers_license(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("DL-ABC1234567"))
        types = [f.entity_type for f in findings]
        assert "DRIVERS_LICENSE" in types

    def test_no_findings_clean_text(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("The weather is nice today."))
        assert findings == []

    def test_multiple_entity_types_detected(self, detector: PIIDetectorAgent) -> None:
        payload = "User email is john.doe@example.com and SSN is 123-45-6789."
        findings = detector.scan_payload(_make_event(payload))
        assert len(findings) == 2
        types = [f.entity_type for f in findings]
        assert "SSN" in types
        assert "EMAIL" in types


# ---------------------------------------------------------------------------
# PII Detector – severity & compliance framework enrichment
# ---------------------------------------------------------------------------
class TestPIIDetectorEnrichment:
    def test_ssn_has_critical_severity(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        ssn = next(f for f in findings if f.entity_type == "SSN")
        assert ssn.severity == RiskSeverity.CRITICAL

    def test_ssn_triggers_gdpr_ccpa_hipaa(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        ssn = next(f for f in findings if f.entity_type == "SSN")
        frameworks = ssn.compliance_frameworks
        assert ComplianceFramework.GDPR in frameworks
        assert ComplianceFramework.CCPA in frameworks
        assert ComplianceFramework.HIPAA in frameworks

    def test_credit_card_triggers_pci_dss(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("CC 4111111111111111"))
        cc = next(f for f in findings if f.entity_type == "CREDIT_CARD")
        assert ComplianceFramework.PCI_DSS in cc.compliance_frameworks

    def test_email_has_high_severity(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("user@example.org"))
        email = next(f for f in findings if f.entity_type == "EMAIL")
        assert email.severity == RiskSeverity.HIGH

    def test_redacted_value_set(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        ssn = next(f for f in findings if f.entity_type == "SSN")
        assert ssn.redacted_value == "***-**-****"


# ---------------------------------------------------------------------------
# PII Detector – redaction policy
# ---------------------------------------------------------------------------
class TestPIIDetectorRedactionPolicy:
    def test_no_action_when_no_findings(self, detector: PIIDetectorAgent) -> None:
        assert detector.generate_redaction_policy([]) == "NO_ACTION_REQUIRED"

    def test_policy_contains_email(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("user@example.com"))
        policy = detector.generate_redaction_policy(findings)
        assert "REDACT_ENTITIES" in policy
        assert "EMAIL" in policy

    def test_policy_detail_simulation_passed(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        detail = detector.generate_redaction_policy_detail(findings)
        assert detail.simulation_passed is True
        assert "SSN" in detail.entities_to_redact

    def test_triggered_frameworks_deduped(self, detector: PIIDetectorAgent) -> None:
        payload = "SSN 123-45-6789 and user@example.com"
        findings = detector.scan_payload(_make_event(payload))
        frameworks = detector.triggered_frameworks(findings)
        # No duplicates
        assert len(frameworks) == len(set(frameworks))


# ---------------------------------------------------------------------------
# XAI Explainer
# ---------------------------------------------------------------------------
class TestXAIExplainer:
    def test_no_findings_explanation(self, explainer: XAIExplainerAgent) -> None:
        result = explainer.generate_explanation([])
        assert "No PII" in result or "compliant" in result.lower()

    def test_explanation_mentions_severity(self, explainer: XAIExplainerAgent) -> None:
        detector = PIIDetectorAgent()
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        result = explainer.generate_explanation(findings)
        assert "CRITICAL" in result

    def test_explanation_mentions_sandbox(self, explainer: XAIExplainerAgent) -> None:
        detector = PIIDetectorAgent()
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        result = explainer.generate_explanation(findings)
        assert "Sandbox" in result or "sandbox" in result

    def test_structured_explanation_shape(self, explainer: XAIExplainerAgent) -> None:
        detector = PIIDetectorAgent()
        findings = detector.scan_payload(_make_event("user@example.com"))
        structured = explainer.generate_structured_explanation(findings)
        assert "total_findings" in structured
        assert "severity_breakdown" in structured
        assert "triggered_frameworks" in structured
        assert "simulation_result" in structured
        assert structured["simulation_result"] == "PASSED"


# ---------------------------------------------------------------------------
# Compliance Engine
# ---------------------------------------------------------------------------
class TestComplianceEngine:
    def test_no_findings_returns_info(self, compliance_engine: ComplianceEngine) -> None:
        _, severity, breach = compliance_engine.evaluate([])
        assert severity == RiskSeverity.INFO
        assert breach is False

    def test_ssn_triggers_critical_and_breach(
        self, compliance_engine: ComplianceEngine, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        rules, severity, breach = compliance_engine.evaluate(findings)
        assert severity == RiskSeverity.CRITICAL
        assert breach is True

    def test_credit_card_triggers_pci_rule(
        self, compliance_engine: ComplianceEngine, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("CC 4111111111111111"))
        rules, _, _ = compliance_engine.evaluate(findings)
        rule_ids = [r.rule_id for r in rules]
        assert "PCI-001" in rule_ids

    def test_remediation_guidance_populated(
        self, compliance_engine: ComplianceEngine, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        triggered, _, _ = compliance_engine.evaluate(findings)
        guidance = compliance_engine.get_remediation_guidance(triggered)
        assert len(guidance) > 0
        for key, value in guidance.items():
            assert len(value) > 0

    def test_mrn_triggers_hipaa_rule(
        self, compliance_engine: ComplianceEngine, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("Patient MRN-123456"))
        rules, _, _ = compliance_engine.evaluate(findings)
        rule_ids = [r.rule_id for r in rules]
        assert "HIPAA-001" in rule_ids