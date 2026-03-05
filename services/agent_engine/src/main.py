import os
import json
import uuid
import logging
import time
from kafka import KafkaConsumer, KafkaProducer
from domain.models import DataEvent, ComplianceAlert
from agents.pii_detector import PIIDetectorAgent
from agents.xai_explainer import XAIExplainerAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

KAFKA_BROKER = os.getenv('KAFKA_BROKER', 'localhost:9092')
DATA_TOPIC = 'enterprise_data_stream'
ALERT_TOPIC = 'compliance_alerts'

def main():
    logger.info(f"Starting Agent Engine. Connecting to {KAFKA_BROKER}")
    
    # Wait for Kafka to be ready
    time.sleep(10)
    
    try:
        consumer = KafkaConsumer(
            DATA_TOPIC,
            bootstrap_servers=[KAFKA_BROKER],
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='earliest',
            group_id='agent-engine-group'
        )
        producer = KafkaProducer(
            bootstrap_servers=[KAFKA_BROKER],
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
    except Exception as e:
        logger.error(f"Failed to connect to Kafka: {e}")
        return

    detector = PIIDetectorAgent()
    explainer = XAIExplainerAgent()

    logger.info("Agent Engine running and listening for data streams...")
    for message in consumer:
        try:
            data = message.value
            event = DataEvent(**data)
            
            # Multi-Agent Workflow
            findings = detector.scan_payload(event)
            if findings:
                logger.info(f"PII Detected in event {event.event_id}")
                policy = detector.generate_redaction_policy(findings)
                explanation = explainer.generate_explanation(findings)
                
                alert = ComplianceAlert(
                    alert_id=str(uuid.uuid4()),
                    event_id=event.event_id,
                    findings=findings,
                    xai_explanation=explanation,
                    proposed_redaction_policy=policy
                )
                
                producer.send(ALERT_TOPIC, alert.model_dump())
                logger.info(f"Sent compliance alert {alert.alert_id} to {ALERT_TOPIC}")
        except Exception as e:
            logger.error(f"Error processing message: {e}")

if __name__ == '__main__':
    main()