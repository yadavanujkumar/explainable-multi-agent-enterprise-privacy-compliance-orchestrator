from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from domain.models import ComplianceFramework, PIIFinding, RiskSeverity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GDPR Article 9 – special-category data entity types
# ---------------------------------------------------------------------------
_SPECIAL_CATEGORY_ENTITIES = {
    "MEDICAL_RECORD_NUMBER",
    "DATE_OF_BIRTH",
    "BIOMETRIC_DATA",
    "GENETIC_DATA",
}

# Minimum severity threshold that triggers a breach notification obligation
_BREACH_NOTIFICATION_THRESHOLD = RiskSeverity.HIGH

_SEVERITY_SCORE: Dict[RiskSeverity, int] = {
    RiskSeverity.CRITICAL: 10,
    RiskSeverity.HIGH: 7,
    RiskSeverity.MEDIUM: 4,
    RiskSeverity.LOW: 2,
    RiskSeverity.INFO: 1,
}


class ComplianceRule:
    """Represents a single regulatory compliance rule."""

    def __init__(
        self,
        rule_id: str,
        framework: ComplianceFramework,
        description: str,
        article: str,
        triggered_by: Optional[List[str]] = None,
    ) -> None:
        self.rule_id = rule_id
        self.framework = framework
        self.description = description
        self.article = article
        self.triggered_by = triggered_by or []

    def is_triggered(self, findings: List[PIIFinding]) -> bool:
        entity_types = {f.entity_type for f in findings}
        if self.triggered_by:
            return bool(entity_types.intersection(self.triggered_by))
        # Rule with no entity filter triggers on any finding
        return len(findings) > 0


# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------
_RULES: List[ComplianceRule] = [
    ComplianceRule(
        rule_id="GDPR-001",
        framework=ComplianceFramework.GDPR,
        description="Personal data must be protected with appropriate technical measures.",
        article="Art. 32",
        triggered_by=[
            "EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH", "IP_ADDRESS",
            "PASSPORT_NUMBER", "DRIVERS_LICENSE",
        ],
    ),
    ComplianceRule(
        rule_id="GDPR-002",
        framework=ComplianceFramework.GDPR,
        description="Special-category data requires explicit consent and heightened protection.",
        article="Art. 9",
        triggered_by=["MEDICAL_RECORD_NUMBER", "DATE_OF_BIRTH"],
    ),
    ComplianceRule(
        rule_id="GDPR-003",
        framework=ComplianceFramework.GDPR,
        description="Data minimisation: only data necessary for the purpose may be processed.",
        article="Art. 5(1)(c)",
    ),
    ComplianceRule(
        rule_id="CCPA-001",
        framework=ComplianceFramework.CCPA,
        description="Consumers have the right to know what personal information is collected.",
        article="§1798.100",
        triggered_by=[
            "EMAIL", "PHONE_NUMBER", "SSN", "DRIVERS_LICENSE", "PASSPORT_NUMBER",
        ],
    ),
    ComplianceRule(
        rule_id="CCPA-002",
        framework=ComplianceFramework.CCPA,
        description="Sale or sharing of personal information without opt-out is prohibited.",
        article="§1798.120",
        triggered_by=["EMAIL", "PHONE_NUMBER"],
    ),
    ComplianceRule(
        rule_id="HIPAA-001",
        framework=ComplianceFramework.HIPAA,
        description="Protected Health Information (PHI) must be de-identified before sharing.",
        article="§164.514",
        triggered_by=["MEDICAL_RECORD_NUMBER", "DATE_OF_BIRTH"],
    ),
    ComplianceRule(
        rule_id="PCI-001",
        framework=ComplianceFramework.PCI_DSS,
        description="Primary Account Numbers must be rendered unreadable in storage.",
        article="Req. 3.4",
        triggered_by=["CREDIT_CARD", "IBAN"],
    ),
    ComplianceRule(
        rule_id="PCI-002",
        framework=ComplianceFramework.PCI_DSS,
        description="Cardholder data must be protected during transmission over open networks.",
        article="Req. 4.1",
        triggered_by=["CREDIT_CARD"],
    ),
    ComplianceRule(
        rule_id="SOX-001",
        framework=ComplianceFramework.SOX,
        description=(
            "Financial records containing personally identifiable information must be "
            "access-controlled and audit-logged to ensure integrity and traceability."
        ),
        article="Section 302",
        triggered_by=["SSN", "CREDIT_CARD", "IBAN"],
    ),
    ComplianceRule(
        rule_id="SOX-002",
        framework=ComplianceFramework.SOX,
        description=(
            "Internal controls over financial reporting must protect employee and "
            "customer PII from unauthorised disclosure."
        ),
        article="Section 404",
        triggered_by=["EMAIL", "PHONE_NUMBER", "SSN"],
    ),
]


class ComplianceEngine:
    """
    Enterprise compliance rules engine.

    Evaluates a set of PIIFindings against a catalogue of regulatory rules
    (GDPR, CCPA, HIPAA, PCI-DSS, SOX) and returns triggered violations with
    remediation guidance.
    """

    def __init__(self) -> None:
        self._rules = _RULES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self, findings: List[PIIFinding]
    ) -> Tuple[List[ComplianceRule], RiskSeverity, bool]:
        """
        Evaluate findings against all rules.

        Returns:
            Tuple of (triggered_rules, overall_severity, breach_notification_required).
        """
        triggered: List[ComplianceRule] = [
            rule for rule in self._rules if rule.is_triggered(findings)
        ]
        overall_severity = self._compute_severity(findings)
        breach_required = self._requires_breach_notification(findings, overall_severity)

        logger.info(
            "Compliance evaluation complete",
            extra={
                "triggered_rules": len(triggered),
                "overall_severity": overall_severity,
                "breach_notification_required": breach_required,
            },
        )
        return triggered, overall_severity, breach_required

    def get_remediation_guidance(
        self, triggered_rules: List[ComplianceRule]
    ) -> Dict[str, str]:
        """Return a mapping of rule_id → remediation action."""
        guidance: Dict[str, str] = {}
        for rule in triggered_rules:
            guidance[rule.rule_id] = (
                f"[{rule.framework.value} {rule.article}] {rule.description} "
                "— Apply automated redaction policy and notify DPO."
            )
        return guidance

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_severity(findings: List[PIIFinding]) -> RiskSeverity:
        if not findings:
            return RiskSeverity.INFO
        max_score = max(_SEVERITY_SCORE.get(f.severity, 1) for f in findings)
        for sev, score in sorted(_SEVERITY_SCORE.items(), key=lambda x: -x[1]):
            if max_score >= score:
                return sev
        return RiskSeverity.INFO

    @staticmethod
    def _requires_breach_notification(
        findings: List[PIIFinding], overall_severity: RiskSeverity
    ) -> bool:
        has_special_category = any(
            f.entity_type in _SPECIAL_CATEGORY_ENTITIES for f in findings
        )
        threshold_met = (
            _SEVERITY_SCORE.get(overall_severity, 0)
            >= _SEVERITY_SCORE.get(_BREACH_NOTIFICATION_THRESHOLD, 7)
        )
        return has_special_category or threshold_met
