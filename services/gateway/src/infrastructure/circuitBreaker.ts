/**
 * Circuit Breaker for Kafka producer calls.
 *
 * States:
 *  CLOSED   – normal operation; failures are counted.
 *  OPEN     – producer calls fail fast; a reset timer is running.
 *  HALF_OPEN – one probe call is allowed; success → CLOSED, failure → OPEN.
 */

import { logger } from './logger';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
  /** Number of consecutive failures that trip the circuit. Default: 5 */
  failureThreshold?: number;
  /** Milliseconds to wait in OPEN state before entering HALF_OPEN. Default: 30_000 */
  resetTimeoutMs?: number;
  /** Name used in log output. Default: 'kafka-producer' */
  name?: string;
}

export class CircuitBreaker {
  private state: CircuitState = 'CLOSED';
  private failureCount = 0;
  private nextAttemptAt = 0;

  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly name: string;

  constructor(opts: CircuitBreakerOptions = {}) {
    this.failureThreshold = opts.failureThreshold ?? 5;
    this.resetTimeoutMs = opts.resetTimeoutMs ?? 30_000;
    this.name = opts.name ?? 'kafka-producer';
  }

  get currentState(): CircuitState {
    return this.state;
  }

  /**
   * Execute `fn` through the circuit breaker.
   * Throws `CircuitOpenError` when the circuit is OPEN (fast-fail).
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttemptAt) {
        throw new CircuitOpenError(
          `Circuit [${this.name}] is OPEN – retry after ${new Date(this.nextAttemptAt).toISOString()}`
        );
      }
      // Transition to HALF_OPEN to allow one probe
      this.state = 'HALF_OPEN';
      logger.info(`Circuit [${this.name}] entering HALF_OPEN state`);
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure(err);
      throw err;
    }
  }

  private onSuccess(): void {
    if (this.state !== 'CLOSED') {
      logger.info(`Circuit [${this.name}] closed after successful probe`);
    }
    this.failureCount = 0;
    this.state = 'CLOSED';
  }

  private onFailure(err: unknown): void {
    this.failureCount += 1;
    const errMsg = err instanceof Error ? err.message : String(err);

    if (this.state === 'HALF_OPEN' || this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttemptAt = Date.now() + this.resetTimeoutMs;
      logger.error(
        `Circuit [${this.name}] tripped OPEN after ${this.failureCount} failure(s). ` +
          `Next attempt at ${new Date(this.nextAttemptAt).toISOString()}`,
        { error: errMsg }
      );
    } else {
      logger.warn(
        `Circuit [${this.name}] failure ${this.failureCount}/${this.failureThreshold}`,
        { error: errMsg }
      );
    }
  }
}

export class CircuitOpenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CircuitOpenError';
  }
}
