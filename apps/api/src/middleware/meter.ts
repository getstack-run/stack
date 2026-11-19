import type { FastifyInstance, FastifyRequest } from 'fastify';
import { safeErrorSummary } from '@stack/shared';
import type { Services } from '../config/wiring/services-type.js';
import {
  actionHandedBack,
  type IdempotentMeterOptions,
  type MeterDenialContext,
  type MeterPeek,
  type MeterRollback,
  type RecordCheckResult,
} from '../lib/action-meter.js';
import { onRequestEnd } from './request-end.js';

/**
 * The meter, called the way routes have always called it. Each function forwards
 * to the deployment's `services.actionMeter`, so a route changes only the path
 * it imports from: nothing here knows whether an action is priced, counted or
 * free.
 */
type Meters = Pick<Services, 'actionMeter'>;

/** One recorded action of the request's caller; the rollback is registered on the request. */
export function meterAction(
  services: Meters,
  request: FastifyRequest,
  denialContext?: MeterDenialContext,
  idempotencyKey?: string,
  /** The acting agent when the route verified it itself (a passport in the body); else the request's agent. */
  actingAgentId: string | null | undefined = request.agentId,
  /** Whose action it is when the caller acts for another operator (a partner for one of its accounts); else the request's. */
  operatorId?: string,
): Promise<void> {
  return services.actionMeter.meterAction(request, denialContext, idempotencyKey, actingAgentId, operatorId);
}

/** One recorded action for an operator the route resolved itself (no request to read it from). */
export function enforceOverage(
  services: Meters,
  operatorId: string,
  meter: 'action',
  denialContext?: MeterDenialContext,
  onCounted?: (rollback: MeterRollback) => void,
  idempotency?: IdempotentMeterOptions,
): Promise<void> {
  return services.actionMeter.enforce(operatorId, meter, denialContext, onCounted, idempotency);
}

/** What `enforceOverage` would do for one more action, without counting it. */
export function peekOverage(services: Meters, operatorId: string, meter: 'action'): Promise<MeterPeek> {
  return services.actionMeter.peek(operatorId, meter);
}

/** Hosted control checks, charged once per batch the decision engine decided. */
export function recordCheck(services: Meters, operatorId: string, count: number): Promise<RecordCheckResult> {
  return services.actionMeter.recordCheck(operatorId, count);
}

/** Decisions the customer's own control server made, charged once per batch the decision engine decided. */
export function recordDecision(services: Meters, operatorId: string, count: number): Promise<RecordCheckResult> {
  return services.actionMeter.recordDecision(operatorId, count);
}

/** Issuing and refreshing an account agent's passport is upkeep, never an action. */
export function meterPassportUpkeep(services: Meters, request: FastifyRequest, agentId: string): Promise<void> {
  return services.actionMeter.passportUpkeep(request, agentId);
}

/**
 * At the end of the request rather than in the error handler, because many
 * denials are `return reply.status(...).send(...)`, which never throws; here
 * the status code is final and every path is covered. "The end" includes a
 * client that hung up (see `onRequestEnd`): a counted action whose client left
 * and which then failed as a client mistake is handed back like any other, and
 * one that ran stays counted. Fire-and-forget: the client already has its
 * response, or has gone.
 *
 * A request that counted nothing has no rollback and is left alone, so a
 * deployment with no meter registers this at no cost.
 */
export function registerMeterRefund(app: FastifyInstance): void {
  onRequestEnd(app, (request, statusCode) => {
    const rollback = request.meterRollback;
    if (!rollback) return;
    request.meterRollback = undefined as never;
    if (!actionHandedBack(statusCode, request.stackSideUnavailable === true, request.refundAction === true)) return;
    void rollback().catch((err: unknown) => {
      console.error('[overage] meter rollback failed', safeErrorSummary(err));
    });
  });
}
