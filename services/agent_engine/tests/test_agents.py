"""
Enterprise-grade test suite for the Agent Engine.
"""
from __future__ import annotations

import math

import pytest
from src.domain.models import (
    ComplianceFramework,
    DataEvent,
    PIIFinding,
    RiskSeverity,
)
from src.agents.pii_detector import PIIDetectorAgent
from src.agents.xai_explainer import XAIExplainerAgent
from src.agents.compliance_engine import ComplianceEngine
from src.federated.fl_client import DifferentialPrivacyMechanism, FederatedLearningClient


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
# PII Detector – improved redaction for all entity types
# ---------------------------------------------------------------------------
class TestPIIDetectorRedaction:
    def test_email_redaction_masks_local_part(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("user@example.com"))
        email = next(f for f in findings if f.entity_type == "EMAIL")
        assert email.redacted_value.endswith("@example.com")
        assert "*" in email.redacted_value

    def test_phone_redaction_preserves_last_four(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("Call 555-867-5309"))
        phone = next(f for f in findings if f.entity_type == "PHONE_NUMBER")
        assert "5309" in phone.redacted_value

    def test_ip_redaction_masks_last_two_octets(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("IP 192.168.1.100"))
        ip = next(f for f in findings if f.entity_type == "IP_ADDRESS")
        assert ip.redacted_value == "192.168.*.*"

    def test_dob_redaction_preserves_year(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("DOB: 01/15/1990"))
        dob = next(f for f in findings if f.entity_type == "DATE_OF_BIRTH")
        assert "1990" in dob.redacted_value
        assert dob.redacted_value.startswith("**/**/")

    def test_mrn_redaction_preserves_prefix(self, detector: PIIDetectorAgent) -> None:
        findings = detector.scan_payload(_make_event("Patient MRN-123456"))
        mrn = next(f for f in findings if f.entity_type == "MEDICAL_RECORD_NUMBER")
        assert mrn.redacted_value.upper().startswith("MRN")
        assert "*" in mrn.redacted_value

    def test_drivers_license_redaction_preserves_prefix(
        self, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("DL-ABC1234567"))
        dl = next(f for f in findings if f.entity_type == "DRIVERS_LICENSE")
        assert dl.redacted_value.upper().startswith("DL")
        assert "*" in dl.redacted_value

    def test_passport_redaction_preserves_first_two_chars(
        self, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("Passport AB1234567"))
        passport = next(f for f in findings if f.entity_type == "PASSPORT_NUMBER")
        assert passport.redacted_value[:2] == "AB"
        assert "*" in passport.redacted_value


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
# Domain model validators
# ---------------------------------------------------------------------------
class TestModelValidators:
    def test_pii_finding_risk_score_valid(self) -> None:
        finding = PIIFinding(
            entity_type="EMAIL",
            start_idx=0,
            end_idx=10,
            risk_score=0.75,
        )
        assert finding.risk_score == 0.75

    def test_pii_finding_risk_score_out_of_range_raises(self) -> None:
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            PIIFinding(
                entity_type="EMAIL",
                start_idx=0,
                end_idx=10,
                risk_score=1.5,
            )

    def test_pii_finding_confidence_out_of_range_raises(self) -> None:
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            PIIFinding(
                entity_type="EMAIL",
                start_idx=0,
                end_idx=10,
                risk_score=0.5,
                confidence=-0.1,
            )


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

    def test_ssn_triggers_sox_rule(
        self, compliance_engine: ComplianceEngine, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("SSN 123-45-6789"))
        rules, _, _ = compliance_engine.evaluate(findings)
        rule_ids = [r.rule_id for r in rules]
        assert "SOX-001" in rule_ids or "SOX-002" in rule_ids

    def test_passport_triggers_gdpr_rule(
        self, compliance_engine: ComplianceEngine, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("Passport AB1234567"))
        rules, _, _ = compliance_engine.evaluate(findings)
        rule_ids = [r.rule_id for r in rules]
        assert "GDPR-001" in rule_ids

    def test_passport_triggers_ccpa_rule(
        self, compliance_engine: ComplianceEngine, detector: PIIDetectorAgent
    ) -> None:
        findings = detector.scan_payload(_make_event("Passport AB1234567"))
        rules, _, _ = compliance_engine.evaluate(findings)
        rule_ids = [r.rule_id for r in rules]
        assert "CCPA-001" in rule_ids


# ---------------------------------------------------------------------------
# Federated Learning Client – Differential Privacy
# ---------------------------------------------------------------------------
class TestDifferentialPrivacyMechanism:
    def test_noise_is_applied(self) -> None:
        dp = DifferentialPrivacyMechanism(noise_scale=1.0, clip_norm=1.0)
        gradient = [1.0] * 128
        noised = dp.clip_and_noise(gradient)
        # With noise_scale=1.0 the noised gradient should differ from the original
        assert noised != gradient

    def test_clipping_reduces_large_gradients(self) -> None:
        dp = DifferentialPrivacyMechanism(noise_scale=0.0, clip_norm=1.0)
        # Very large gradient; L2 norm >> clip_norm
        gradient = [100.0] * 128
        clipped = dp.clip_and_noise(gradient)
        l2 = math.sqrt(sum(g * g for g in clipped))
        assert l2 <= dp.clip_norm + 1e-6

    def test_small_gradient_not_upscaled(self) -> None:
        dp = DifferentialPrivacyMechanism(noise_scale=0.0, clip_norm=10.0)
        gradient = [0.1] * 4
        clipped = dp.clip_and_noise(gradient)
        # L2 norm of [0.1, 0.1, 0.1, 0.1] = 0.2, well below clip_norm=10
        # Gradient should NOT be upscaled
        for orig, clp in zip(gradient, clipped):
            assert abs(clp - orig) < 1e-9

    def test_empty_gradient_returns_empty(self) -> None:
        dp = DifferentialPrivacyMechanism()
        assert dp.clip_and_noise([]) == []

    def test_fl_client_gradient_has_dp_config(self) -> None:
        client = FederatedLearningClient(client_id="test-client")
        payload = client.compute_local_gradient([{"sample": "data"}])
        assert "dp_config" in payload
        assert "noise_scale" in payload["dp_config"]
        assert "clip_norm" in payload["dp_config"]

    def test_fl_client_health_includes_clip_norm(self) -> None:
        client = FederatedLearningClient(client_id="test-client")
        health = client.get_health()
        assert "dp_clip_norm" in health
        assert "max_rounds" in health


# ---------------------------------------------------------------------------
# Health / Metrics HTTP endpoint
# ---------------------------------------------------------------------------
import sys
import threading
import types
from http.server import HTTPServer
from unittest.mock import MagicMock


def _import_health_handler():
    """Import HealthHandler from src.main with Kafka mocked out."""
    kafka_mock = types.ModuleType("kafka")
    kafka_mock.KafkaConsumer = MagicMock()
    kafka_mock.KafkaProducer = MagicMock()
    errors_mock = types.ModuleType("kafka.errors")
    errors_mock.KafkaError = Exception
    errors_mock.NoBrokersAvailable = Exception
    kafka_mock.errors = errors_mock

    sys.modules.setdefault("kafka", kafka_mock)
    sys.modules.setdefault("kafka.errors", errors_mock)

    if "src.main" in sys.modules:
        mod = sys.modules["src.main"]
    else:
        import importlib
        mod = importlib.import_module("src.main")
    return mod.HealthHandler, mod._health_state


class TestHealthEndpoint:
    """Spin up the in-process HTTP server and exercise all paths."""

    @pytest.fixture(autouse=True)
    def _server(self):
        HealthHandler, self.health_state = _import_health_handler()
        server = HTTPServer(("127.0.0.1", 0), HealthHandler)
        self.port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        yield
        server.shutdown()

    def _get(self, path: str):
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
            return r.status, r.read().decode()

    def _get_status(self, path: str) -> int:
        import urllib.error
        import urllib.request
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_healthz_returns_200_when_running(self) -> None:
        original = self.health_state["status"]
        self.health_state["status"] = "running"
        try:
            status, _ = self._get("/healthz")
            assert status == 200
        finally:
            self.health_state["status"] = original

    def test_healthz_returns_503_when_not_running(self) -> None:
        original = self.health_state["status"]
        self.health_state["status"] = "starting"
        try:
            code = self._get_status("/healthz")
            assert code == 503
        finally:
            self.health_state["status"] = original

    def test_metrics_endpoint_returns_prometheus_text(self) -> None:
        self.health_state["status"] = "running"
        status, body = self._get("/metrics")
        assert status == 200
        assert "agent_engine_messages_processed_total" in body
        assert "agent_engine_alerts_generated_total" in body
        assert "agent_engine_errors_total" in body
        assert "agent_engine_kafka_connected" in body

    def test_unknown_path_returns_404(self) -> None:
        code = self._get_status("/unknown")
        assert code == 404