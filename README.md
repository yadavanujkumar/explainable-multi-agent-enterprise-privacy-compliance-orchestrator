# Explainable Multi-Agent Enterprise Privacy Compliance Orchestrator

A **zero-trust, multi-agent system** that continuously audits enterprise data pipelines for PII leaks and compliance violations.  It uses an extensible agent architecture to scan Kafka data streams, evaluates violations against GDPR / CCPA / HIPAA / PCI-DSS rules, auto-generates redaction policies, simulates them in ephemeral environments, and delivers XAI-powered risk summaries to DPOs via Slack Block Kit and Microsoft Teams Adaptive Cards—with one-click approve / reject actions.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Kafka Event Bus                            │
│  enterprise_data_stream  ──►  compliance_alerts  ──►       │
│                               remediation_actions          │
│                               audit_trail                  │
└──────────┬──────────────────────────┬───────────────────────┘
           │                          │
  ┌────────▼──────────┐    ┌──────────▼──────────────────────┐
  │   Agent Engine     │    │        API Gateway              │
  │   (Python 3.10)    │    │   (Node.js 18 / TypeScript)     │
  │                    │    │                                  │
  │  PIIDetectorAgent  │    │  POST /webhook/slack             │
  │  XAIExplainerAgent │    │  POST /webhook/teams             │
  │  ComplianceEngine  │    │  GET  /health                    │
  │  FLClient (DP)     │    │  GET  /readyz                    │
  │  Health :8080      │    │  Rate-limit + HMAC auth          │
  └────────────────────┘    └──────────────────────────────────┘
```

### Services

| Service | Language | Responsibility |
|---|---|---|
| **Agent Engine** | Python 3.10 | PII scanning, compliance evaluation, XAI explanations, federated learning |
| **API Gateway** | TypeScript / Node.js 18 | Slack & Teams integrations, signature verification, rate-limiting, Kafka fan-out |
| **Kafka** | Confluent Platform 7.5 | Decoupled event streaming with replay, partitioned topics, persistent storage |

---

## Enterprise Features

### Security (Zero-Trust)
- **Slack HMAC-SHA256 signature verification** – every inbound interactive payload is cryptographically verified; replay attacks are blocked by a 5-minute timestamp window.
- **Non-root Docker containers** – both services run as dedicated non-root OS users.
- **Multi-stage Docker builds** – production images contain only compiled artefacts and production `node_modules`.
- **Kafka `acks=all`** – compliance alerts are durably committed before processing continues.

### PII Detection (10 Entity Types)
| Entity | Severity | Frameworks |
|---|---|---|
| SSN | CRITICAL | GDPR, CCPA, HIPAA |
| Credit Card | CRITICAL | PCI-DSS, GDPR |
| Medical Record Number | CRITICAL | HIPAA |
| Passport Number | CRITICAL | GDPR, CCPA |
| Email | HIGH | GDPR, CCPA |
| Phone Number | HIGH | GDPR, CCPA |
| IBAN | HIGH | GDPR, PCI-DSS |
| Driver's License | HIGH | GDPR, CCPA |
| Date of Birth | MEDIUM | GDPR, HIPAA |
| IP Address | MEDIUM | GDPR |

### Compliance Rules Engine
Built-in rule catalogue covering:
- **GDPR** – Art. 5 (minimisation), Art. 9 (special-category), Art. 32 (technical measures)
- **CCPA** – §1798.100 (right to know), §1798.120 (opt-out of sale)
- **HIPAA** – §164.514 (de-identification of PHI)
- **PCI-DSS** – Req. 3.4 (PAN rendering), Req. 4.1 (transmission security)

### Observability
- **Structured JSON logging** via Winston (gateway) and Python `logging` with JSON formatter (agent engine)
- **Audit trail topic** – every detection event is published to `audit_trail` for tamper-evident record-keeping
- **Health / readiness endpoints** – `GET /health`, `GET /readyz` (gateway), `GET /healthz` (agent engine on :8080)
- **Docker health checks** – all services include `HEALTHCHECK` directives; `depends_on: condition: service_healthy` ensures correct startup order

### Reliability
- **Kafka retry with exponential back-off** – both services retry Kafka connections up to 15 times
- **Graceful shutdown** – `SIGTERM` / `SIGINT` handlers flush producers and close consumers cleanly
- **Restart policies** – `unless-stopped` on all containers
- **Resource limits** – CPU and memory caps on every container

### Integrations
- **Slack Block Kit** – rich interactive messages with severity emoji, entity breakdown, and approve / reject buttons
- **Microsoft Teams Adaptive Cards** – full Adaptive Card 1.4 payload with colour-coded severity and submit actions
- **Express rate-limiting** – 120 req/min global, 30 req/min on webhook endpoints

### Federated Learning
- **Differential Privacy** – Gaussian mechanism stub; integrates with Google DP or TensorFlow Privacy
- **Audit hashing** – SHA-256 weight hash logged on every FL round for tamper detection
- **Zero-data transmission** – gradients only; raw PII never leaves the local enclave

---

## Quick Start

### Prerequisites
- Docker ≥ 24 and Docker Compose V2
- `make` (optional)

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in SLACK_BOT_TOKEN, SLACK_SIGNING_SECRET, TEAMS_WEBHOOK_URL
```

### 2. Start all services

```bash
docker compose up --build
```

Services start in dependency order (Zookeeper → Kafka → Agent Engine + Gateway).

### 3. Verify health

```bash
# Gateway
curl http://localhost:3000/health

# Agent Engine
curl http://localhost:8080/healthz
```

### 4. Publish a test event

```bash
# Install kafkacat / kcat
echo '{"event_id":"test-001","source_system":"CRM","payload":"SSN 123-45-6789 and email admin@example.com","timestamp":"2024-01-01T00:00:00Z"}' \
  | kcat -P -b localhost:9092 -t enterprise_data_stream
```

---

## API Reference

### `POST /webhook/slack`
Receives Slack Block Kit interaction payloads (approve / reject).

**Headers**
| Header | Required | Description |
|---|---|---|
| `X-Slack-Request-Timestamp` | Yes | Unix epoch timestamp |
| `X-Slack-Signature` | Yes | `v0=<HMAC-SHA256>` |

**Body** – Standard Slack Block Kit `block_actions` payload.

**Responses**
| Code | Meaning |
|---|---|
| 200 | Action acknowledged |
| 400 | Invalid payload schema |
| 401 | Missing or invalid signature |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

### `POST /webhook/teams`
Receives Microsoft Teams Adaptive Card submit actions.

**Body**
```json
{ "alertId": "<uuid>", "action": "approve_remediation" | "reject" }
```

**Responses** – same as `/webhook/slack`.

---

### `GET /health`
Returns service health and Kafka connectivity status.

```json
{ "status": "ok", "kafka_ready": true, "uptime_seconds": 3600 }
```

### `GET /readyz`
Kubernetes readiness probe.  Returns 503 until Kafka is connected.

---

## Development

### Agent Engine (Python)
```bash
cd services/agent_engine
pip install -r requirements.txt
pytest
```

### API Gateway (TypeScript)
```bash
cd services/gateway
npm install
npm test
npm run lint   # TypeScript type-check
npm run build
```

---

## Environment Variables

See [`.env.example`](.env.example) for the full reference.

| Variable | Service | Default | Description |
|---|---|---|---|
| `KAFKA_BROKER` | Both | `kafka:29092` | Kafka bootstrap server |
| `LOG_LEVEL` | Both | `INFO` / `info` | Log verbosity |
| `SLACK_BOT_TOKEN` | Gateway | — | Slack Bot OAuth token |
| `SLACK_SIGNING_SECRET` | Gateway | — | Slack HMAC signing secret |
| `SLACK_CHANNEL_ID` | Gateway | `#compliance-alerts` | Target Slack channel |
| `TEAMS_WEBHOOK_URL` | Gateway | — | Teams Incoming Webhook URL |
| `FL_DP_NOISE_SCALE` | Agent | `0.1` | Differential privacy noise scale |
| `HEALTH_PORT` | Agent | `8080` | Health check HTTP port |

---

## Security Considerations

- Store `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, and `TEAMS_WEBHOOK_URL` in a secrets manager (AWS Secrets Manager, HashiCorp Vault) and inject them at runtime—never commit to source control.
- In production, front the gateway with a TLS-terminating reverse proxy (nginx / ALB).
- Enable Kafka TLS + SASL authentication for inter-service communication.
- Review the `FL_DP_NOISE_SCALE` parameter with your data science team; higher values provide stronger privacy guarantees at the cost of model accuracy.
