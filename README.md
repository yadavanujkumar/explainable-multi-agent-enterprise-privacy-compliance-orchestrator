# Explainable Multi-Agent Enterprise Privacy Compliance Orchestrator

A zero-trust multi-agent system that continuously audits enterprise data pipelines for PII leaks and compliance violations. It utilizes advanced LangChain/AutoGen workflows to scan Kafka data streams, auto-generates redaction policies, simulates them in ephemeral environments, and generates XAI-powered, human-readable risk summaries. Approvals for remediation are facilitated via a 1-click Slack/Teams integration.

## Architecture
- **Agent Engine (Python):** Contains Domain-Driven models for Data Events, PII Detection Agents, and XAI Explainers. Uses Federated Learning concepts to update local detection models without sharing raw data.
- **API Gateway (TypeScript/Node.js):** Connects the internal Kafka event bus to external webhooks (Slack/Teams). Validates inputs and handles the 1-click remediation approvals securely.
- **Kafka:** Decouples the scanning engine from the notification gateway, ensuring fault tolerance and continuous stream auditing.

## Setup
1. Ensure Docker and Docker Compose are installed.
2. Run `docker-compose up --build` to start Zookeeper, Kafka, the Python Agent Engine, and the Node.js API Gateway.
3. The Node.js API Gateway will be available at `http://localhost:3000`.

## API Documentation
- `POST /webhook/slack`: Receives interactive payload from Slack when a DPO clicks 'Approve Remediation' or 'Reject'.
  - Payload: standard Slack interactive message JSON.
  - Action: Publishes a `remediation_approved` event to Kafka.