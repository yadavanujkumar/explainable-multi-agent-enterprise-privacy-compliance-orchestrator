/**
 * Enterprise API Gateway – Privacy Compliance Orchestrator
 *
 * Features:
 *  - Slack Block Kit + Microsoft Teams Adaptive Card integrations
 *  - HMAC-SHA256 Slack signature verification
 *  - Express rate-limiting (per-IP)
 *  - Structured Winston logging + audit trail middleware
 *  - /health and /readyz probes for Kubernetes
 *  - Zod request validation
 *  - Graceful shutdown (SIGTERM / SIGINT)
 *  - Kafka consumer / producer with retry and acks=all
 *  - Circuit-breaker for Kafka producer calls
 */
import crypto from 'crypto';
import express, { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { Kafka, logLevel as kafkaLogLevel } from 'kafkajs';
import { z } from 'zod';

import { SlackIntegration } from './application/SlackIntegration';
import { TeamsIntegration } from './application/TeamsIntegration';
import { CircuitBreaker, CircuitOpenError } from './infrastructure/circuitBreaker';
import { logger } from './infrastructure/logger';
import { auditLogger } from './middleware/auditLogger';
import { verifySlackSignature } from './middleware/slackVerification';
import type { ComplianceAlert } from './types';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT ?? 3000);
const BROKER = process.env.KAFKA_BROKER ?? 'localhost:9092';
const REMEDIATION_TOPIC = process.env.REMEDIATION_TOPIC ?? 'remediation_actions';
const ALERT_TOPIC = process.env.ALERT_TOPIC ?? 'compliance_alerts';

// ---------------------------------------------------------------------------
// Zod schemas for inbound request validation
// ---------------------------------------------------------------------------
const SlackInteractionSchema = z.object({
  type: z.string(),
  actions: z
    .array(
      z.object({
        action_id: z.string().optional(),
        value: z.string(),
        block_id: z.string().optional(),
      })
    )
    .min(1),
  user: z.object({ id: z.string(), name: z.string() }).optional(),
  // Block Kit uses block_id; legacy Interactive Messages use callback_id
  callback_id: z.string().optional(),
});

const TeamsActionSchema = z.object({
  alertId: z.string(),
  action: z.enum(['approve_remediation', 'reject']),
});

// ---------------------------------------------------------------------------
// Express application
// ---------------------------------------------------------------------------
const app = express();

// Capture raw body for Slack HMAC verification before JSON parsing
app.use(
  (req: Request & { rawBody?: Buffer }, _res: Response, next: NextFunction) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      req.rawBody = Buffer.concat(chunks);
      next();
    });
    req.on('error', next);
  }
);

app.use(express.json());
app.use(auditLogger);

// Security headers
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// Global rate limiter: 120 req / min per IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use(globalLimiter);

// Strict rate limiter for webhook endpoints: 30 req / min
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Webhook rate limit exceeded.' },
});

// ---------------------------------------------------------------------------
// Health / readiness probes + Prometheus metrics
// ---------------------------------------------------------------------------
let kafkaReady = false;

// Simple in-process metrics counters (Prometheus text format)
const metrics = {
  http_requests_total: 0,
  webhook_slack_total: 0,
  webhook_teams_total: 0,
  kafka_messages_sent_total: 0,
  kafka_circuit_open_total: 0,
};

app.get('/health', (_req, res) => {
  metrics.http_requests_total++;
  res.status(200).json({
    status: 'ok',
    kafka_ready: kafkaReady,
    kafka_circuit: producerCircuit.currentState,
    uptime_seconds: Math.floor(process.uptime()),
  });
});

app.get('/readyz', (_req, res) => {
  metrics.http_requests_total++;
  if (!kafkaReady) {
    return res.status(503).json({ status: 'not_ready', reason: 'kafka_not_connected' });
  }
  res.status(200).json({ status: 'ready' });
});

/** Prometheus-compatible text exposition endpoint */
app.get('/metrics', (_req, res) => {
  const lines = [
    '# HELP http_requests_total Total HTTP requests handled by this gateway',
    '# TYPE http_requests_total counter',
    `http_requests_total ${metrics.http_requests_total}`,
    '# HELP webhook_slack_total Total Slack webhook events received',
    '# TYPE webhook_slack_total counter',
    `webhook_slack_total ${metrics.webhook_slack_total}`,
    '# HELP webhook_teams_total Total Microsoft Teams webhook events received',
    '# TYPE webhook_teams_total counter',
    `webhook_teams_total ${metrics.webhook_teams_total}`,
    '# HELP kafka_messages_sent_total Total Kafka messages successfully sent by the producer',
    '# TYPE kafka_messages_sent_total counter',
    `kafka_messages_sent_total ${metrics.kafka_messages_sent_total}`,
    '# HELP kafka_circuit_open_total Total times the Kafka producer circuit was tripped open',
    '# TYPE kafka_circuit_open_total counter',
    `kafka_circuit_open_total ${metrics.kafka_circuit_open_total}`,
    '# HELP process_uptime_seconds Gateway process uptime in seconds',
    '# TYPE process_uptime_seconds gauge',
    `process_uptime_seconds ${Math.floor(process.uptime())}`,
    '',
  ];
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(lines.join('\n'));
});

// ---------------------------------------------------------------------------
// Kafka
// ---------------------------------------------------------------------------
const kafka = new Kafka({
  clientId: 'gateway-service',
  brokers: [BROKER],
  logLevel: kafkaLogLevel.WARN,
  retry: { retries: 10, initialRetryTime: 1000 },
});

const consumer = kafka.consumer({ groupId: 'gateway-group' });
const producer = kafka.producer({ allowAutoTopicCreation: true });

// ---------------------------------------------------------------------------
// Circuit breaker – wraps all producer.send() calls
// ---------------------------------------------------------------------------
const producerCircuit = new CircuitBreaker({
  name: 'kafka-producer',
  failureThreshold: 5,
  resetTimeoutMs: 30_000,
});

// ---------------------------------------------------------------------------
// Integrations
// ---------------------------------------------------------------------------
const slackIntegration = new SlackIntegration();
const teamsIntegration = new TeamsIntegration();

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/**
 * POST /webhook/slack
 *
 * Receives Slack Block Kit interaction payloads (approve / reject).
 * Verifies the Slack signing secret and publishes a remediation action to Kafka.
 */
app.post(
  '/webhook/slack',
  webhookLimiter,
  verifySlackSignature,
  async (req: Request, res: Response) => {
    metrics.http_requests_total++;
    metrics.webhook_slack_total++;
    try {
      const parsed = SlackInteractionSchema.safeParse(req.body);
      if (!parsed.success) {
        logger.warn('Invalid Slack payload', { errors: parsed.error.format() });
        return res.status(400).json({ error: 'Invalid payload', details: parsed.error.format() });
      }

      const payload = parsed.data;
      const action = payload.actions[0];
      const alertId = action.block_id ?? payload.callback_id ?? 'unknown';
      const actor = payload.user?.name ?? 'unknown';

      if (action.value === 'approve_remediation') {
        await producerCircuit.execute(() =>
          producer.send({
            topic: REMEDIATION_TOPIC,
            messages: [
              {
                value: JSON.stringify({
                  alertId,
                  status: 'APPROVED',
                  actor,
                  timestamp: new Date().toISOString(),
                }),
              },
            ],
          })
        );
        metrics.kafka_messages_sent_total++;
        logger.info('Remediation approved via Slack', { alertId, actor });
        return res.status(200).json({ message: 'Remediation approved and queued.' });
      }

      if (action.value === 'reject') {
        await producerCircuit.execute(() =>
          producer.send({
            topic: REMEDIATION_TOPIC,
            messages: [
              {
                value: JSON.stringify({
                  alertId,
                  status: 'REJECTED',
                  actor,
                  timestamp: new Date().toISOString(),
                }),
              },
            ],
          })
        );
        metrics.kafka_messages_sent_total++;
        logger.info('Remediation rejected via Slack', { alertId, actor });
        return res.status(200).json({ message: 'Remediation rejected.' });
      }

      res.status(200).json({ message: 'Action acknowledged.' });
    } catch (error) {
      if (error instanceof CircuitOpenError) {
        metrics.kafka_circuit_open_total++;
        logger.warn('Kafka producer circuit open – Slack action queued for retry', { error: error.message });
        return res.status(503).json({ error: 'Service temporarily unavailable. Please retry shortly.' });
      }
      logger.error('Slack webhook processing error', { error });
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * POST /webhook/teams
 *
 * Receives Microsoft Teams Adaptive Card submit actions (approve / reject).
 */
app.post('/webhook/teams', webhookLimiter, async (req: Request, res: Response) => {
  metrics.http_requests_total++;
  metrics.webhook_teams_total++;
  try {
    const parsed = TeamsActionSchema.safeParse(req.body);
    if (!parsed.success) {
      logger.warn('Invalid Teams payload', { errors: parsed.error.format() });
      return res.status(400).json({ error: 'Invalid payload', details: parsed.error.format() });
    }

    const { alertId, action } = parsed.data;
    const status = action === 'approve_remediation' ? 'APPROVED' : 'REJECTED';

    await producerCircuit.execute(() =>
      producer.send({
        topic: REMEDIATION_TOPIC,
        messages: [
          {
            value: JSON.stringify({
              alertId,
              status,
              actor: 'teams-user',
              timestamp: new Date().toISOString(),
            }),
          },
        ],
      })
    );

    metrics.kafka_messages_sent_total++;
    logger.info(`Remediation ${status} via Teams`, { alertId });
    res.status(200).json({ message: `Remediation ${status.toLowerCase()}.` });
  } catch (error) {
    if (error instanceof CircuitOpenError) {
      metrics.kafka_circuit_open_total++;
      logger.warn('Kafka producer circuit open – Teams action queued for retry', { error: error.message });
      return res.status(503).json({ error: 'Service temporarily unavailable. Please retry shortly.' });
    }
    logger.error('Teams webhook processing error', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Kafka consumer + server startup
// ---------------------------------------------------------------------------
async function start(): Promise<void> {
  await producer.connect();
  await consumer.connect();
  await consumer.subscribe({ topic: ALERT_TOPIC, fromBeginning: false });

  kafkaReady = true;
  logger.info('Gateway connected to Kafka', { broker: BROKER });

  await consumer.run({
    eachMessage: async ({ message }) => {
      if (!message.value) return;
      try {
        const alert = JSON.parse(message.value.toString()) as ComplianceAlert;
        logger.info('Received compliance alert', {
          alert_id: alert.alert_id,
          severity: alert.severity,
          breach_notification_required: alert.breach_notification_required,
        });

        // Fan-out to both Slack and Teams
        await Promise.allSettled([
          slackIntegration.sendApprovalRequest(alert),
          teamsIntegration.sendApprovalRequest(alert),
        ]);
      } catch (err) {
        logger.error('Failed to process compliance alert', { error: err });
      }
    },
  });

  const server = app.listen(PORT, () => {
    logger.info('Gateway listening', { port: PORT });
  });

  // ---------------------------------------------------------------------------
  // Graceful shutdown
  // ---------------------------------------------------------------------------
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal} – shutting down gracefully…`);
    kafkaReady = false;

    server.close(async () => {
      try {
        await consumer.disconnect();
        await producer.disconnect();
        logger.info('Gateway shut down cleanly.');
        process.exit(0);
      } catch (err) {
        logger.error('Error during shutdown', { error: err });
        process.exit(1);
      }
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch((err) => {
  logger.error('Fatal startup error', { error: err });
  process.exit(1);
});