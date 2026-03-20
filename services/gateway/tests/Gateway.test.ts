/**
 * Enterprise test suite for the API Gateway.
 */
import crypto from 'crypto';
import { Request, Response } from 'express';
import { SlackIntegration } from '../src/application/SlackIntegration';
import { TeamsIntegration } from '../src/application/TeamsIntegration';

// ---------------------------------------------------------------------------
// Mock logger so tests don't emit output
// ---------------------------------------------------------------------------
jest.mock('../src/infrastructure/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const mockAlert = {
  alert_id: 'abc-123',
  event_id: 'event-999',
  source_system: 'CRM',
  xai_explanation: '🔴 CRITICAL PII detected: SSN found.',
  proposed_redaction_policy: 'REDACT_ENTITIES:SSN,EMAIL',
  severity: 'CRITICAL',
  triggered_frameworks: ['GDPR', 'CCPA', 'HIPAA'],
};

// ---------------------------------------------------------------------------
// SlackIntegration tests
// ---------------------------------------------------------------------------
describe('SlackIntegration', () => {
  let slack: SlackIntegration;

  beforeEach(() => {
    slack = new SlackIntegration('#test-channel');
  });

  it('should log the Block Kit payload when no token is configured', async () => {
    const { logger } = require('../src/infrastructure/logger');
    delete process.env.SLACK_BOT_TOKEN;

    await slack.sendApprovalRequest(mockAlert);

    expect(logger.info).toHaveBeenCalledWith(
      expect.stringContaining('[Slack]'),
      expect.objectContaining({ alert_id: 'abc-123' })
    );
  });

  it('payload should contain the alert ID', async () => {
    const { logger } = require('../src/infrastructure/logger');
    (logger.info as jest.Mock).mockClear();

    await slack.sendApprovalRequest(mockAlert);

    const infoCall = (logger.info as jest.Mock).mock.calls[0];
    expect(JSON.stringify(infoCall)).toContain('abc-123');
  });

  it('payload should contain approve_remediation action', async () => {
    const { logger } = require('../src/infrastructure/logger');
    (logger.info as jest.Mock).mockClear();

    await slack.sendApprovalRequest(mockAlert);

    const infoCall = (logger.info as jest.Mock).mock.calls[0];
    expect(JSON.stringify(infoCall)).toContain('approve_remediation');
  });

  it('payload should reference proposed policy', async () => {
    const { logger } = require('../src/infrastructure/logger');
    (logger.info as jest.Mock).mockClear();

    await slack.sendApprovalRequest(mockAlert);

    const infoCall = (logger.info as jest.Mock).mock.calls[0];
    expect(JSON.stringify(infoCall)).toContain('REDACT_ENTITIES:SSN,EMAIL');
  });

  it('should include CRITICAL severity emoji in payload', async () => {
    const { logger } = require('../src/infrastructure/logger');
    (logger.info as jest.Mock).mockClear();

    await slack.sendApprovalRequest(mockAlert);

    const infoCall = (logger.info as jest.Mock).mock.calls[0];
    expect(JSON.stringify(infoCall)).toContain('🔴');
  });
});

// ---------------------------------------------------------------------------
// TeamsIntegration tests
// ---------------------------------------------------------------------------
describe('TeamsIntegration', () => {
  let teams: TeamsIntegration;

  beforeEach(() => {
    // No webhook URL → falls back to logger
    teams = new TeamsIntegration(undefined);
    delete process.env.TEAMS_WEBHOOK_URL;
  });

  it('should log the Adaptive Card payload when no webhook URL is set', async () => {
    const { logger } = require('../src/infrastructure/logger');
    (logger.info as jest.Mock).mockClear();

    await teams.sendApprovalRequest(mockAlert);

    expect(logger.info).toHaveBeenCalledWith(
      expect.stringContaining('[Teams]'),
      expect.objectContaining({ alert_id: 'abc-123' })
    );
  });

  it('Adaptive Card should contain the alert ID', async () => {
    const { logger } = require('../src/infrastructure/logger');
    (logger.info as jest.Mock).mockClear();

    await teams.sendApprovalRequest(mockAlert);

    const call = (logger.info as jest.Mock).mock.calls[0];
    expect(JSON.stringify(call)).toContain('abc-123');
  });

  it('Adaptive Card should include both approve and reject actions', async () => {
    const { logger } = require('../src/infrastructure/logger');
    (logger.info as jest.Mock).mockClear();

    await teams.sendApprovalRequest(mockAlert);

    const call = (logger.info as jest.Mock).mock.calls[0];
    const payload = JSON.stringify(call);
    expect(payload).toContain('approve_remediation');
    expect(payload).toContain('reject');
  });

  it('Adaptive Card should contain triggered frameworks', async () => {
    const { logger } = require('../src/infrastructure/logger');
    (logger.info as jest.Mock).mockClear();

    await teams.sendApprovalRequest(mockAlert);

    const call = (logger.info as jest.Mock).mock.calls[0];
    expect(JSON.stringify(call)).toContain('GDPR');
  });
});

// ---------------------------------------------------------------------------
// Slack signature verification unit tests
// ---------------------------------------------------------------------------
describe('verifySlackSignature middleware', () => {
  const signingSecret = 'test-signing-secret';

  function buildRequest(
    body: string,
    timestamp: string,
    signature: string
  ): Partial<Request> & { rawBody: Buffer } {
    const rawBody = Buffer.from(body, 'utf8');
    return {
      rawBody,
      body: JSON.parse(body),
      path: '/webhook/slack',
      ip: '127.0.0.1',
      headers: {
        'x-slack-request-timestamp': timestamp,
        'x-slack-signature': signature,
      },
    } as unknown as Partial<Request> & { rawBody: Buffer };
  }

  function buildValidSignature(body: string, timestamp: string): string {
    const sigBase = `v0:${timestamp}:${body}`;
    const hmac = crypto
      .createHmac('sha256', signingSecret)
      .update(sigBase, 'utf8')
      .digest('hex');
    return `v0=${hmac}`;
  }

  it('should call next() when signature is valid', async () => {
    process.env.SLACK_SIGNING_SECRET = signingSecret;
    const { verifySlackSignature } = require('../src/middleware/slackVerification');

    const body = JSON.stringify({ type: 'block_actions' });
    const timestamp = String(Math.floor(Date.now() / 1000));
    const sig = buildValidSignature(body, timestamp);

    const req = buildRequest(body, timestamp, sig);
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as unknown as Response;
    const next = jest.fn();

    verifySlackSignature(req as Request, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();

    delete process.env.SLACK_SIGNING_SECRET;
  });

  it('should return 401 when signature is invalid', async () => {
    process.env.SLACK_SIGNING_SECRET = signingSecret;
    const { verifySlackSignature } = require('../src/middleware/slackVerification');

    const body = JSON.stringify({ type: 'block_actions' });
    const timestamp = String(Math.floor(Date.now() / 1000));
    // Craft a wrong signature with the correct length (v0= + 64 hex chars)
    const wrongSignature = 'v0=' + '0'.repeat(64);
    const req = buildRequest(body, timestamp, wrongSignature);

    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as unknown as Response;
    const next = jest.fn();

    verifySlackSignature(req as Request, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();

    delete process.env.SLACK_SIGNING_SECRET;
  });

  it('should return 401 when timestamp is stale', () => {
    process.env.SLACK_SIGNING_SECRET = signingSecret;
    const { verifySlackSignature } = require('../src/middleware/slackVerification');

    const body = JSON.stringify({ type: 'block_actions' });
    // 10 minutes in the past
    const staleTimestamp = String(Math.floor(Date.now() / 1000) - 600);
    const sig = buildValidSignature(body, staleTimestamp);
    const req = buildRequest(body, staleTimestamp, sig);

    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as unknown as Response;
    const next = jest.fn();

    verifySlackSignature(req as Request, res, next);
    expect(res.status).toHaveBeenCalledWith(401);

    delete process.env.SLACK_SIGNING_SECRET;
  });

  it('should skip verification and call next() when no signing secret is configured', () => {
    delete process.env.SLACK_SIGNING_SECRET;
    // Re-import with no secret
    jest.resetModules();
    const { verifySlackSignature } = require('../src/middleware/slackVerification');

    const body = '{}';
    const timestamp = String(Math.floor(Date.now() / 1000));
    const req = buildRequest(body, timestamp, 'v0=anythinghere');

    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as unknown as Response;
    const next = jest.fn();

    verifySlackSignature(req as Request, res, next);
    expect(next).toHaveBeenCalled();
  });
});