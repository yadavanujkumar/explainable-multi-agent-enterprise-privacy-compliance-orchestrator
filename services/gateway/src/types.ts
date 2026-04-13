/**
 * Shared domain types for the Privacy Compliance Orchestrator gateway.
 *
 * These types mirror the Pydantic models in the Python agent engine and
 * must be kept in sync with `services/agent_engine/src/domain/models.py`.
 */

export type RiskSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AlertStatus =
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'REJECTED'
  | 'AUTO_REMEDIATED'
  | 'ESCALATED';

export type ComplianceFrameworkValue = 'GDPR' | 'CCPA' | 'HIPAA' | 'PCI_DSS' | 'SOX';

export interface PIIFinding {
  entity_type: string;
  start_idx: number;
  end_idx: number;
  risk_score: number;
  severity: RiskSeverity;
  redacted_value: string;
  compliance_frameworks: ComplianceFrameworkValue[];
  detection_method: string;
  confidence: number;
}

export interface RedactionPolicy {
  policy_id: string;
  policy_name: string;
  entities_to_redact: string[];
  redaction_method: string;
  simulation_passed: boolean;
  downstream_impact_score: number;
}

export interface AuditEntry {
  audit_id: string;
  event_id: string;
  action: string;
  actor: string;
  timestamp: string;
  details: Record<string, string>;
}

export interface ComplianceAlert {
  alert_id: string;
  event_id: string;
  source_system?: string;
  findings?: PIIFinding[];
  xai_explanation: string;
  proposed_redaction_policy: string;
  redaction_policy_detail?: RedactionPolicy;
  status?: AlertStatus;
  severity?: RiskSeverity;
  triggered_frameworks?: ComplianceFrameworkValue[];
  breach_notification_required?: boolean;
  remediation_guidance?: Record<string, string>;
  created_at?: string;
  tenant_id?: string;
  audit_trail?: AuditEntry[];
}
