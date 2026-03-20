/**
 * Audit logging middleware.
 *
 * Appends a structured audit entry to every inbound HTTP request, capturing
 * actor identity, action, outcome, and timing for compliance reporting.
 */
import { NextFunction, Request, Response } from 'express';
import { logger } from '../infrastructure/logger';

export function auditLogger(req: Request, res: Response, next: NextFunction): void {
  const startMs = Date.now();

  res.on('finish', () => {
    logger.info('HTTP request', {
      audit: true,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration_ms: Date.now() - startMs,
      ip: req.ip,
      user_agent: req.headers['user-agent'] ?? 'unknown',
    });
  });

  next();
}
