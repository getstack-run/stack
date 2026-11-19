import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { ZodError } from 'zod';
import {
  ControlLimitExceededError,
  MissionPausedError,
  StackError,
  SpendRefusedError,
  CmekRevokedError,
  NotConfiguredError,
  ServiceUnavailableError,
  SERVICE_UNAVAILABLE_RETRY_AFTER_SECONDS,
  isRedisUnavailableError,
  safeErrorSummary,
  safeRouteTemplate,
} from '@stack/shared';
import * as Sentry from '@sentry/node';

/**
 * Dependencies the error handler needs beyond the raw error. Today only
 * `cmek.recordRevoked` — called fire-and-forget when a `CmekRevokedError`
 * bubbles through, to flip the operator's `cmek_status` to `revoked` and
 * publish the cache-invalidation event so other machines drop their stale
 * `active`/`migrating` cached state. Without this wiring the 503 response
 * still fires (KmsService rethrows + cache evicts on this machine), but
 * the DB status stays `active` and every subsequent request still hits
 * KMS (`AccessDeniedException`) before falling out the same way — wasted
 * KMS spend + a dashboard that misreports the operator state.
 *
 * `cmek` is optional so tests + dev paths that don't construct a CmekService
 * still build a working handler.
 */
export interface ErrorHandlerDeps {
  cmek?: {
    recordRevoked(operatorId: string, keyArn?: string): Promise<void>;
  };
  /**
   * A Mission's money cap refused a spend at the budget ledger's counter, wherever the spend was reserved: its cap
   * behaviour follows here, the one place every such refusal reaches. `pause` (the default) pauses the Mission for its
   * owner's review and the agent reads MISSION_PAUSED; `end_mission` ends it; `refuse_action` only refuses the spend.
   */
  missions?: {
    spendCapReached(missionId: string): Promise<'pause' | 'refuse_action' | 'end_mission' | null>;
  };
}

export function createErrorHandler(deps: ErrorHandlerDeps = {}) {
  return async function errorHandler(
    error: FastifyError | StackError | Error,
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    if (error instanceof ControlLimitExceededError && error.missionId && deps.missions) {
      let behavior: Awaited<ReturnType<NonNullable<ErrorHandlerDeps['missions']>['spendCapReached']>> = null;
      try {
        behavior = await deps.missions.spendCapReached(error.missionId);
      } catch (capError) {
        console.error('A Mission cap behaviour failed during error handling', safeErrorSummary(capError));
      }
      if (behavior === 'pause') {
        // The spend never ran: the action is handed back, as for any limit that refused it.
        request.refundAction = true;
        return handleError(new MissionPausedError(error.missionId, 'coverage_cap_cents'), request, reply);
      }
    }
    // CmekRevokedError handling — fire-and-forget the status flip so the
    // response latency stays bounded by what the client experiences. If
    // recordRevoked fails (DB hiccup), log and move on — the 503 still
    // fires correctly because the contract is "every operator-scoped
    // decrypt fails closed after revoke", which is enforced at the KMS
    // layer regardless of whether the DB status is in sync.
    if (error instanceof CmekRevokedError && deps.cmek) {
      const details = (error as CmekRevokedError).details as
        | { operator_id?: string; key_arn?: string }
        | undefined;
      const operatorId = details?.operator_id;
      const keyArn = details?.key_arn;
      if (operatorId) {
        void deps.cmek.recordRevoked(operatorId, keyArn).catch((recordErr) => {
          console.error('CmekService.recordRevoked failed during error handling', safeErrorSummary(recordErr));
        });
      }
    }
    return handleError(error, request, reply);
  };
}

/**
 * Back-compat export. Prefer `createErrorHandler(services)` so the CMEK
 * status-flip wiring fires. This export keeps existing direct-import call
 * sites (none in production today, but kept for surface stability) and
 * tests that do not need the CMEK wiring.
 */
export function errorHandler(
  error: FastifyError | StackError | Error,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  return handleError(error, request, reply);
}

function handleError(
  thrown: FastifyError | StackError | Error,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  let error = thrown;
  const isRateLimitError = 'statusCode' in error && error.statusCode === 429;
  // Send unexpected errors to Sentry. Skip StackErrors, Fastify
  // validation errors, Fastify body/parser errors (FST_ERR_*), and
  // ZodError — those are all 4xx user-input outcomes the api raises
  // intentionally and pollute Sentry as system errors when they're
  // really client bugs. The 4xx response we return to the client is
  // the actionable signal; the Sentry capture would be duplicate.
  const isExpected = error instanceof StackError
    || error instanceof ZodError
    || isRateLimitError
    || ('validation' in error && error.validation)
    || ('code' in error && typeof error.code === 'string' && error.code.startsWith('FST_ERR_'));
  // the route TEMPLATE (never request.url) and validated codes are
  // the only request context that reaches logs and Sentry.
  const route = safeRouteTemplate(request.routeOptions?.url);
  if (!isExpected && process.env['SENTRY_DSN']) {
    const { pg_code: pgCode } = safeErrorSummary(error);
    Sentry.withScope((scope) => {
      scope.setTag('method', request.method);
      scope.setTag('source', 'api.error-handler');
      if (route) scope.setTag('route', route);
      if (pgCode) scope.setTag('pg_code', pgCode);
      Sentry.captureException(error);
    });
  }

  // Redis unreachable on a path with no handler of its own (the meter, a
  // revocation or replay flag, a cache): the call fails closed but is
  // retriable, so the caller reads an outage and not a broken request.
  if (isRedisUnavailableError(thrown)) {
    console.error('Redis unavailable', { ...safeErrorSummary(thrown), ...(route ? { route } : {}) });
    error = new ServiceUnavailableError();
    // STACK's own dependency failed, not the request: a metered action already counted
    // (the counter lives in Redis, and a later Redis step is what timed out) is handed back,
    // like the other STACK-side refusals. A generic 503 keeps its action counted.
    request.stackSideUnavailable = true;
  }

  // A refusal to spend (not enough credit, a frozen wallet) answers with what its
  // class fixed when it was raised, never with fields a catch block may have rewritten. A spend whose
  // settlement is still pending (SpendSettlementPendingError) is an ordinary StackError: 503.
  if (error instanceof SpendRefusedError) {
    const { code, message, details } = error.refusal;
    return reply.status(402).send({ error: { code, message, ...(details ? { details } : {}) } });
  }

  if (error instanceof StackError) {
    if (error.statusCode === 503 && error.code === 'SERVICE_UNAVAILABLE') {
      const wait = error.details?.['retry_after_seconds'];
      reply.header(
        'Retry-After',
        String(typeof wait === 'number' && Number.isSafeInteger(wait) && wait > 0 ? wait : SERVICE_UNAVAILABLE_RETRY_AFTER_SECONDS),
      );
    }
    // A throttle that says how long to wait says it in the header too.
    if (error.statusCode === 429) {
      const wait = error.details?.['retry_after_seconds'];
      if (typeof wait === 'number' && Number.isSafeInteger(wait) && wait > 0) reply.header('Retry-After', String(wait));
    }
    // The meter refund (meter.ts) hands the action back for these.
    if (error.stackSide) request.stackSideUnavailable = true;
    // A 501 that names the vault service whose credential is missing is counted by the deployment (never on the wire).
    if (error instanceof NotConfiguredError && error.service) request.notConfiguredService = error.service;
    // A spend limit of the customer's policy refused the action while it was being paid for: it never ran.
    if (error.code === 'CONTROL_LIMIT_EXCEEDED') request.refundAction = true;
    return reply.status(error.statusCode).send({
      error: {
        code: error.code,
        message: error.message,
        details: error.details,
      },
    });
  }

  // @fastify/rate-limit throws a plain Error carrying statusCode=429. Keep
  // that client-visible outcome instead of turning an expected throttle into
  // a 500, while still replacing the plugin's timing detail with a stable
  // response that discloses nothing about the backing limiter.
  if (isRateLimitError) {
    return reply.status(429).send({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
      },
    });
  }

  // Fastify validation errors
  if ('validation' in error && error.validation) {
    return reply.status(400).send({
      error: {
        code: 'VALIDATION_ERROR',
        message: error.message,
      },
    });
  }

  // Fastify JSON parse errors and other known codes
  if ('code' in error && typeof error.code === 'string') {
    if (error.code === 'FST_ERR_CTP_INVALID_JSON_BODY') {
      return reply.status(400).send({
        error: {
          code: 'INVALID_JSON',
          message: 'Request body is not valid JSON',
        },
      });
    }
    if (error.code === 'FST_ERR_CTP_EMPTY_JSON_BODY') {
      return reply.status(400).send({
        error: {
          code: 'EMPTY_BODY',
          message: 'Request body must not be empty',
        },
      });
    }
    if (error.code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE') {
      return reply.status(415).send({
        error: {
          code: 'UNSUPPORTED_MEDIA_TYPE',
          message: 'Content-Type must be application/json',
        },
      });
    }
    if (error.code === 'FST_ERR_CTP_INVALID_CONTENT_LENGTH') {
      // UTF-8 chars in body sometimes cause Content-Length mismatch when
      // clients compute it incorrectly. Surface as 400 with a hint instead
      // of leaking a generic 500 + "An unexpected error occurred".
      return reply.status(400).send({
        error: {
          code: 'INVALID_CONTENT_LENGTH',
          message: 'Request Content-Length did not match received body size. If you are sending UTF-8 (em-dashes, accented chars), let your HTTP client compute Content-Length from the byte-length of the encoded body.',
        },
      });
    }
    // Any other Fastify content-type-parser error (codes start with FST_ERR_CTP_)
    // is by definition a 4xx malformed-request error — surface as 400 instead
    // of letting it fall through to the generic 500.
    if (error.code.startsWith('FST_ERR_CTP_')) {
      return reply.status(400).send({
        error: {
          code: 'INVALID_REQUEST',
          message: error.message,
        },
      });
    }
  }

  // Zod validation errors
  if (error instanceof ZodError) {
    return reply.status(400).send({
      error: {
        code: 'VALIDATION_ERROR',
        message: error.message,
      },
    });
  }

  // Unexpected errors — don't leak internals
  console.error('Unhandled error', { ...safeErrorSummary(error), ...(route ? { route } : {}) });
  return reply.status(500).send({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
    },
  });
}
