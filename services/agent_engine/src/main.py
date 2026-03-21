from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable

from agents.compliance_engine import ComplianceEngine
from agents.pii_detector import PIIDetectorAgent
from agents.xai_explainer import XAIExplainerAgent
from domain.models import AlertStatus, AuditEntry, ComplianceAlert, DataEvent
from federated.fl_client import FederatedLearningClient

# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("agent-engine")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
DATA_TOPIC = os.getenv("DATA_TOPIC", "enterprise_data_stream")
ALERT_TOPIC = os.getenv("ALERT_TOPIC", "compliance_alerts")
AUDIT_TOPIC = os.getenv("AUDIT_TOPIC", "audit_trail")
HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8080"))
KAFKA_MAX_RETRIES = int(os.getenv("KAFKA_MAX_RETRIES", "10"))
KAFKA_RETRY_BACKOFF_S = int(os.getenv("KAFKA_RETRY_BACKOFF_S", "5"))

# ---------------------------------------------------------------------------
# Global state for health-check endpoint
# ---------------------------------------------------------------------------
_health_state: Dict[str, Any] = {
    "status": "starting",
    "kafka_connected": False,
    "messages_processed": 0,
    "alerts_generated": 0,
    "errors": 0,
}


# ---------------------------------------------------------------------------
# Health-check HTTP server
# ---------------------------------------------------------------------------
class HealthHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for liveness / readiness probes."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/health", "/healthz", "/readyz"):
            code = 200 if _health_state["status"] == "running" else 503
            body = json.dumps(_health_state).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/metrics":
            lines = [
                "# HELP agent_engine_messages_processed_total Total Kafka messages processed",
                "# TYPE agent_engine_messages_processed_total counter",
                f"agent_engine_messages_processed_total {_health_state['messages_processed']}",
                "# HELP agent_engine_alerts_generated_total Total compliance alerts generated",
                "# TYPE agent_engine_alerts_generated_total counter",
                f"agent_engine_alerts_generated_total {_health_state['alerts_generated']}",
                "# HELP agent_engine_errors_total Total processing errors",
                "# TYPE agent_engine_errors_total counter",
                f"agent_engine_errors_total {_health_state['errors']}",
                "# HELP agent_engine_kafka_connected Whether the engine is connected to Kafka (1=yes, 0=no)",
                "# TYPE agent_engine_kafka_connected gauge",
                f"agent_engine_kafka_connected {1 if _health_state['kafka_connected'] else 0}",
                "",
            ]
            body = "\n".join(lines).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args: Any) -> None:  # suppress access logs
        pass


def _start_health_server() -> None:
    server = HTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    logger.info(f"Health-check server listening on :{HEALTH_PORT}")


# ---------------------------------------------------------------------------
# Kafka helpers with retry / back-off
# ---------------------------------------------------------------------------
def _create_consumer() -> KafkaConsumer:
    for attempt in range(1, KAFKA_MAX_RETRIES + 1):
        try:
            consumer = KafkaConsumer(
                DATA_TOPIC,
                bootstrap_servers=[KAFKA_BROKER],
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                auto_offset_reset="earliest",
                group_id="agent-engine-group",
                enable_auto_commit=True,
                session_timeout_ms=30_000,
                heartbeat_interval_ms=10_000,
            )
            logger.info(f"Kafka consumer connected (attempt {attempt})")
            return consumer
        except NoBrokersAvailable:
            logger.warning(
                f"Kafka not available (attempt {attempt}/{KAFKA_MAX_RETRIES}). "
                f"Retrying in {KAFKA_RETRY_BACKOFF_S}s..."
            )
            time.sleep(KAFKA_RETRY_BACKOFF_S)
    raise RuntimeError(f"Could not connect to Kafka after {KAFKA_MAX_RETRIES} attempts.")


def _create_producer() -> KafkaProducer:
    for attempt in range(1, KAFKA_MAX_RETRIES + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=[KAFKA_BROKER],
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                retries=5,
                acks="all",
            )
            logger.info(f"Kafka producer connected (attempt {attempt})")
            return producer
        except NoBrokersAvailable:
            logger.warning(
                f"Kafka producer not available (attempt {attempt}/{KAFKA_MAX_RETRIES}). "
                f"Retrying in {KAFKA_RETRY_BACKOFF_S}s..."
            )
            time.sleep(KAFKA_RETRY_BACKOFF_S)
    raise RuntimeError(f"Could not connect Kafka producer after {KAFKA_MAX_RETRIES} attempts.")


# ---------------------------------------------------------------------------
# Event processing
# ---------------------------------------------------------------------------
def process_event(
    event: DataEvent,
    producer: KafkaProducer,
    detector: PIIDetectorAgent,
    explainer: XAIExplainerAgent,
    compliance_engine: ComplianceEngine,
) -> None:
    """Process a single data event through the full multi-agent pipeline."""
    logger.info(
        f"Processing event",
        extra={"event_id": event.event_id, "source": event.source_system},
    )

    # 1. PII Detection
    findings = detector.scan_payload(event)

    if not findings:
        logger.info(f"No PII found in event {event.event_id}")
        return

    _health_state["alerts_generated"] += 1

    # 2. Compliance evaluation
    triggered_rules, overall_severity, breach_required = compliance_engine.evaluate(findings)

    # 3. XAI explanation
    explanation = explainer.generate_explanation(findings)

    # 4. Redaction policy
    policy_str = detector.generate_redaction_policy(findings)
    policy_detail = detector.generate_redaction_policy_detail(findings)
    frameworks = detector.triggered_frameworks(findings)

    # 5. Build compliance alert
    audit_entry = AuditEntry(
        audit_id=str(uuid.uuid4()),
        event_id=event.event_id,
        action="PII_DETECTED",
        details={
            "findings_count": str(len(findings)),
            "severity": overall_severity.value,
            "breach_notification_required": str(breach_required),
            "triggered_rules": ",".join(r.rule_id for r in triggered_rules),
        },
    )

    alert = ComplianceAlert(
        alert_id=str(uuid.uuid4()),
        event_id=event.event_id,
        source_system=event.source_system,
        findings=findings,
        xai_explanation=explanation,
        proposed_redaction_policy=policy_str,
        redaction_policy_detail=policy_detail,
        status=AlertStatus.PENDING_APPROVAL,
        severity=overall_severity,
        triggered_frameworks=frameworks,
        tenant_id=event.tenant_id,
        audit_trail=[audit_entry],
    )

    # 6. Publish alert to Kafka (with acks=all for durability)
    try:
        future = producer.send(ALERT_TOPIC, alert.model_dump())
        future.get(timeout=10)
        logger.info(
            f"Compliance alert published",
            extra={
                "alert_id": alert.alert_id,
                "severity": overall_severity.value,
                "breach_notification_required": breach_required,
            },
        )
    except KafkaError as e:
        logger.error(f"Failed to publish alert {alert.alert_id}: {e}")
        _health_state["errors"] += 1
        raise

    # 7. Publish audit entry
    try:
        producer.send(AUDIT_TOPIC, audit_entry.model_dump())
    except KafkaError as e:
        logger.warning(f"Failed to publish audit entry: {e}")


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
_shutdown_event = threading.Event()


def _handle_signal(sig: int, frame: Any) -> None:
    logger.info(f"Received signal {sig}. Initiating graceful shutdown…")
    _health_state["status"] = "shutting_down"
    _shutdown_event.set()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _start_health_server()

    logger.info(
        f"Agent Engine starting",
        extra={"kafka_broker": KAFKA_BROKER, "log_level": LOG_LEVEL},
    )

    try:
        consumer = _create_consumer()
        producer = _create_producer()
    except RuntimeError as e:
        logger.critical(f"Startup failed: {e}")
        _health_state["status"] = "failed"
        sys.exit(1)

    _health_state["kafka_connected"] = True
    _health_state["status"] = "running"

    detector = PIIDetectorAgent()
    explainer = XAIExplainerAgent()
    compliance_engine = ComplianceEngine()
    fl_client = FederatedLearningClient()

    logger.info(
        "All agents initialised. Listening for data streams…",
        extra={"topic": DATA_TOPIC},
    )

    for message in consumer:
        if _shutdown_event.is_set():
            break
        try:
            data = message.value
            event = DataEvent(**data)
            process_event(event, producer, detector, explainer, compliance_engine)
            _health_state["messages_processed"] += 1
        except Exception as e:
            logger.error(
                f"Error processing message: {e}",
                extra={"offset": message.offset, "partition": message.partition},
            )
            _health_state["errors"] += 1

    logger.info("Agent Engine shut down cleanly.")
    consumer.close()
    producer.flush()
    producer.close()


if __name__ == "__main__":
    main()