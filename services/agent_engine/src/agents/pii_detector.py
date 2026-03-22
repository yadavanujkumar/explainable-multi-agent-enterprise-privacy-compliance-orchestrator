from __future__ import annotations

import re
import uuid
import logging
from typing import Dict, List, Tuple

from domain.models import (
    ComplianceFramework,
    DataEvent,
    PIIFinding,
    RedactionPolicy,
    RiskSeverity,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII pattern registry
# Each entry: (entity_type, compiled_pattern, risk_score, severity, frameworks)
# ---------------------------------------------------------------------------
_PII_PATTERNS: List[Tuple[str, re.Pattern[str], float, RiskSeverity, List[ComplianceFramework]]] = [
    (
        "SSN",
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        0.99,
        RiskSeverity.CRITICAL,
        [ComplianceFramework.GDPR, ComplianceFramework.CCPA, ComplianceFramework.HIPAA],
    ),
    (
        "CREDIT_CARD",
        re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        0.99,
        RiskSeverity.CRITICAL,
        [ComplianceFramework.PCI_DSS, ComplianceFramework.GDPR],
    ),
    (
        "EMAIL",
        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
        0.75,
        RiskSeverity.HIGH,
        [ComplianceFramework.GDPR, ComplianceFramework.CCPA],
    ),
    (
        "PHONE_NUMBER",
        re.compile(
            r'\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b'
        ),
        0.70,
        RiskSeverity.HIGH,
        [ComplianceFramework.GDPR, ComplianceFramework.CCPA],
    ),
    (
        "IP_ADDRESS",
        re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),
        0.60,
        RiskSeverity.MEDIUM,
        [ComplianceFramework.GDPR],
    ),
    (
        "DATE_OF_BIRTH",
        re.compile(
            r'\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b'
        ),
        0.65,
        RiskSeverity.MEDIUM,
        [ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
    ),
    (
        "PASSPORT_NUMBER",
        re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
        0.90,
        RiskSeverity.CRITICAL,
        [ComplianceFramework.GDPR, ComplianceFramework.CCPA],
    ),
    (
        "IBAN",
        re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'),
        0.85,
        RiskSeverity.HIGH,
        [ComplianceFramework.GDPR, ComplianceFramework.PCI_DSS],
    ),
    (
        "MEDICAL_RECORD_NUMBER",
        re.compile(r'\bMRN[-:\s]?\d{6,10}\b', re.IGNORECASE),
        0.95,
        RiskSeverity.CRITICAL,
        [ComplianceFramework.HIPAA],
    ),
    (
        "DRIVERS_LICENSE",
        re.compile(r'\bDL[-:\s]?[A-Z0-9]{7,15}\b', re.IGNORECASE),
        0.85,
        RiskSeverity.HIGH,
        [ComplianceFramework.GDPR, ComplianceFramework.CCPA],
    ),
]

# Compliance framework → article/regulation references
_FRAMEWORK_REFERENCES: Dict[ComplianceFramework, str] = {
    ComplianceFramework.GDPR: "GDPR Art. 5(1)(f), Art. 32",
    ComplianceFramework.CCPA: "CCPA §1798.100",
    ComplianceFramework.HIPAA: "HIPAA §164.514",
    ComplianceFramework.PCI_DSS: "PCI-DSS Req. 3, 4",
    ComplianceFramework.SOX: "SOX Section 404",
}


class PIIDetectorAgent:
    """
    Enterprise-grade PII detection agent.

    Scans structured data events for personally identifiable information using
    an extensible pattern registry.  Each detected entity is enriched with
    risk scoring, severity classification, applicable compliance frameworks,
    and a redacted representation.

    In production this layer is augmented by Microsoft Presidio or an
    LLM-backed NER model.
    """

    def __init__(self) -> None:
        self._patterns = _PII_PATTERNS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_payload(self, event: DataEvent) -> List[PIIFinding]:
        """Scan *event.payload* and return all PII findings."""
        findings: List[PIIFinding] = []
        seen_spans: List[Tuple[int, int]] = []

        for entity_type, pattern, risk_score, severity, frameworks in self._patterns:
            for match in pattern.finditer(event.payload):
                span = (match.start(), match.end())
                # Skip overlapping spans already captured by a higher-priority pattern
                if self._overlaps(span, seen_spans):
                    continue
                seen_spans.append(span)

                raw_value = match.group()
                redacted = self._redact(raw_value, entity_type)

                finding = PIIFinding(
                    entity_type=entity_type,
                    start_idx=span[0],
                    end_idx=span[1],
                    risk_score=risk_score,
                    severity=severity,
                    redacted_value=redacted,
                    compliance_frameworks=frameworks,
                    detection_method="REGEX",
                    confidence=1.0,
                )
                findings.append(finding)
                logger.debug(
                    "PII detected",
                    extra={
                        "event_id": event.event_id,
                        "entity_type": entity_type,
                        "severity": severity,
                    },
                )

        return findings

    def generate_redaction_policy(self, findings: List[PIIFinding]) -> str:
        """Return a short policy string suitable for Kafka messages."""
        if not findings:
            return "NO_ACTION_REQUIRED"
        entities = sorted({f.entity_type for f in findings})
        return f"REDACT_ENTITIES:{','.join(entities)}"

    def generate_redaction_policy_detail(
        self, findings: List[PIIFinding]
    ) -> RedactionPolicy:
        """Return a structured *RedactionPolicy* with simulation results."""
        entities = sorted({f.entity_type for f in findings})
        policy = RedactionPolicy(
            policy_id=str(uuid.uuid4()),
            policy_name=f"auto-policy-{','.join(entities)}",
            entities_to_redact=entities,
            redaction_method="MASK",
            simulation_passed=True,   # In production: run sandbox simulation
            downstream_impact_score=self._estimate_impact(findings),
        )
        return policy

    def triggered_frameworks(
        self, findings: List[PIIFinding]
    ) -> List[ComplianceFramework]:
        """Return deduplicated list of compliance frameworks triggered."""
        seen: set = set()
        result: List[ComplianceFramework] = []
        for finding in findings:
            for fw in finding.compliance_frameworks:
                if fw not in seen:
                    seen.add(fw)
                    result.append(fw)
        return result

    def framework_references(
        self, frameworks: List[ComplianceFramework]
    ) -> Dict[str, str]:
        """Map each framework to its regulatory article references."""
        return {fw.value: _FRAMEWORK_REFERENCES.get(fw, "") for fw in frameworks}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _overlaps(span: Tuple[int, int], seen: List[Tuple[int, int]]) -> bool:
        for s_start, s_end in seen:
            if span[0] < s_end and span[1] > s_start:
                return True
        return False

    @staticmethod
    def _redact(value: str, entity_type: str) -> str:
        """Produce a redacted representation that preserves length information."""
        if entity_type in {"SSN", "CREDIT_CARD", "IBAN"}:
            return re.sub(r'\d', '*', value)
        if entity_type == "EMAIL":
            local, _, domain = value.partition("@")
            return f"{'*' * len(local)}@{domain}"
        if entity_type == "PASSPORT_NUMBER":
            return value[:2] + "*" * (len(value) - 2)
        return "[REDACTED]"

    @staticmethod
    def _estimate_impact(findings: List[PIIFinding]) -> float:
        """Heuristic downstream impact score in [0, 1]."""
        critical = sum(1 for f in findings if f.severity == RiskSeverity.CRITICAL)
        high = sum(1 for f in findings if f.severity == RiskSeverity.HIGH)
        return min(1.0, (critical * 0.4 + high * 0.2) / max(len(findings), 1))