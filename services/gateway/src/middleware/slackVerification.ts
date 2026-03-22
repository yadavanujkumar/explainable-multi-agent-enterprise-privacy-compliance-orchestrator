/**
 * Slack request-signature verification middleware.
 *
 * Validates HMAC-SHA256 signatures on inbound Slack interactive payloads to
 * prevent replay attacks and spoofed requests.
 *
 * @see https://api.slack.com/authentication/verifying-requests-from-slack
 */
import crypto from 'crypto';
import { NextFunction, Request, Response } from 'express';
import { logger } from '../infrastructure/logger';

const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET || '';
const SLACK_VERSION = 'v0';
const MAX_REQUEST_AGE_SECONDS = 300; // 5 minutes

export function verifySlackSignature(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // In production the signing secret is mandatory
  if (!SLACK_SIGNING_SECRET) {
    if (process.env.NODE_ENV === 'production') {
      logger.error(
        'SLACK_SIGNING_SECRET is not set in production – rejecting all Slack requests'
      );
      res.status(503).json({
        error: 'Service misconfigured: SLACK_SIGNING_SECRET must be set in production',
      });
      return;
    }
    logger.warn('SLACK_SIGNING_SECRET not set – skipping signature verification (non-production only)');
    next();
    return;
  }

  const timestamp = req.headers['x-slack-request-timestamp'];
  const slackSignature = req.headers['x-slack-signature'];

  if (!timestamp || !slackSignature) {
    logger.warn('Missing Slack signature headers', {
      path: req.path,
      ip: req.ip,
    });
    res.status(401).json({ error: 'Missing Slack signature headers' });
    return;
  }

  // Protect against replay attacks
  const requestAge = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (requestAge > MAX_REQUEST_AGE_SECONDS) {
    logger.warn('Slack request timestamp too old – possible replay attack', {
      age_seconds: requestAge,
      ip: req.ip,
    });
    res.status(401).json({ error: 'Request timestamp too old' });
    return;
  }

  // Compute expected signature
  const rawBody = (req as Request & { rawBody?: Buffer }).rawBody;
  const sigBaseString = `${SLACK_VERSION}:${timestamp}:${rawBody?.toString() ?? ''}`;
  const hmac = crypto
    .createHmac('sha256', SLACK_SIGNING_SECRET)
    .update(sigBaseString, 'utf8')
    .digest('hex');
  const computedSignature = `${SLACK_VERSION}=${hmac}`;

  const isValid =
    computedSignature.length === String(slackSignature).length &&
    crypto.timingSafeEqual(
      Buffer.from(computedSignature, 'utf8'),
      Buffer.from(String(slackSignature), 'utf8')
    );

  if (!isValid) {
    logger.warn('Invalid Slack signature', { ip: req.ip });
    res.status(401).json({ error: 'Invalid signature' });
    return;
  }

  next();
}
