import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  StackError,
  ids,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { meterAction } from '../middleware/meter.js';
import { actionPoolSnapshot } from '../lib/action-pool.js';
import { scanForPromptInjectionAsync } from '../detectors/prompt-injection.js';

/**
 * POST /v1/scan — content-scanning endpoint for retrieved data.
 *
 * The most common production prompt-injection vector is INDIRECT —
 * an agent retrieves a doc/email/webpage/calendar invite, the
 * retrieved content carries an injection payload, the agent feeds
 * it to its LLM. /v1/scan gives agents a way to scan retrieved
 * content BEFORE feeding it to the model. Agents call /v1/scan,
 * receive a verdict, and decide whether to proceed.
 *
 * Reuses the same detector chain as /v1/proxy and /v1/skills/:id/invoke
 * (L1 regex + L2 encoding-aware normalization). Same scanForPromptInjection
 * function — keeping detection logic in one place.
 *
 * Auth: same model as /v1/proxy. Operator API key, OAuth, or dashboard
 * session. Optional X-Passport-Token header for attribution to
 * a specific agent context.
 *
 * Metering: each scan counts as one action. Cheap but non-zero, so the
 * endpoint is not an open abuse surface.
 */

const ScanRequestInput = z.object({
  /** The content to scan. Strings are scanned directly; objects are
   * walked one level deep, same as proxy bodies. */
  content: z.union([z.string(), z.record(z.unknown())]),
  /** Optional human-readable context tag. Recorded in security event
   * metadata so operators can filter by retrieval source. */
  context: z.enum(['email', 'document', 'webpage', 'chat_log', 'api_response', 'calendar', 'other']).optional(),
  /** Optional source identifier (URL / sender / filename). Recorded
   * in security event metadata. NEVER reproduced in logs at full
   * length — truncated to 256 chars. */
  source: z.string().max(2048).optional(),
});

export function registerScanRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.post(
    '/v1/scan',
    { preHandler: auth },
    async (request, reply) => {
      const start = Date.now();

      // 1. Parse + validate input.
      const parsed = ScanRequestInput.safeParse(request.body);
      if (!parsed.success) {
        throw new StackError(
          parsed.error.errors.map((e) => e.message).join(', '),
          'INVALID_REQUEST',
          400,
        );
      }
      const { content, context, source } = parsed.data;

      // 2. Tier metering — every scan is one recorded action against the
      //    operator's monthly allowance. Above it, debits the wallet at
      //    OVERAGE_PRICES_CENTS.action. Empty wallet → 402.
      await meterAction(services, request);

      // 3. Optional passport attribution. If a passport token is
      //    present in the X-Passport-Token header, verify it with the
      //    full freshness check. A stale passport (revoked agent,
      //    deactivated connection, expired identity claim) means the
      //    attribution would be wrong anyway — fail loud rather than
      //    record a misattributed scan.
      const passportToken = request.headers['x-passport-token'] as string | undefined;
      let agentId: string | null = null;
      let passportJti: string | null = null;
      if (passportToken) {
        const claims = await services.passport.verify(passportToken);
        agentId = claims.stk.agent_id ?? null;
        passportJti = claims.jti ?? null;
      }

      // 4. Scan with the full L1+L2+L3 chain. L3 (LLM funnel) only
      //    fires when the heuristic gate fires AND a classifier is available;
      //    otherwise this falls through to L1+L2 only.
      //
      //    L7 — fetch operator's per-detector overrides. Cache-fronted
      //    so this is typically a single Redis GET. When no row exists
      //    the detector runs its built-in defaults unchanged.
      const overrideRow = await services.operatorDetectorConfig.getForDetector(
        request.operatorId,
        'prompt_injection',
      );
      // when the passport names an eval-traffic agent, skip the
      // L3 spend (scan is not a hot path - one indexed lookup).
      let scanEvalTraffic = false;
      if (agentId) {
        try {
          const scanAgent = await services.agent.getById(agentId, request.operatorId);
          scanEvalTraffic = scanAgent.eval_traffic === true;
        } catch {
          scanEvalTraffic = false; // unknown agent - full-strength scan
        }
      }
      const { match, llm, verdict: chainVerdict } = await scanForPromptInjectionAsync(
        content,
        'content',
        {
          // The deployment's own classifier, which carries its own budget, or STACK's network
          // classifier on an install that chose it.
          l3: services.l3Classifier?.({ operatorId: request.operatorId, agentId, passportJti }) ?? null,
          ...(services.networkClient?.rules?.current().length ? { extraPatterns: services.networkClient.rules.current() } : {}),
          ...(scanEvalTraffic ? { skipL3: true } : {}),
          ...(overrideRow ? { overrides: {
            enabled: overrideRow.enabled,
            custom_patterns: overrideRow.custom_patterns,
            whitelist_patterns: overrideRow.whitelist_patterns,
            severity_overrides: overrideRow.severity_overrides,
          } } : {}),
        },
      );

      // 5. Map merged verdict → response shape + record events.
      const scanId = ids.session();
      const durationMs = Date.now() - start;

      const verdict =
        chainVerdict === 'critical' ? 'critical'
        : chainVerdict === 'warning' ? 'suspicious'
        : 'clean';

      // Record a security event whenever the chain fired (L1/L2 match
      // OR L3 caught something). Clean scans don't add noise. If L3
      // degraded gracefully, also record a detector_degraded event so
      // operators see when L3 isn't contributing.
      if (llm?.degraded) {
        await services.securityEvent.record({
          operatorId: request.operatorId,
          agentId: agentId ?? '',
          passportJti: passportJti ?? undefined,
          signalType: 'prompt_injection',
          severity: 'info',
          message: `L3 LLM classifier degraded: ${llm.reasoning}`,
          // dedup: degraded-L3 is operational telemetry — one
          // event per agent per hour, not one per affected call
          dedupKey: `l3_degraded:${agentId ?? 'none'}`,
          dedupWindowSeconds: 3600,
          metadata: {
            scan_id: scanId,
            l3_degraded: true,
            l3_duration_ms: llm.duration_ms,
            l3_model: llm.model,
          },
        });
      }
      if (match || (llm && !llm.degraded && llm.verdict !== 'clean')) {
        const severity = chainVerdict === 'critical' ? 'critical' : 'warning';
        const causeBits: string[] = [];
        if (match) causeBits.push(`L1/L2 ${match.pattern_id}@${match.field_path}${match.encoding ? '/' + match.encoding : ''}`);
        if (llm && !llm.degraded && llm.verdict !== 'clean') {
          causeBits.push(`L3 ${llm.verdict}@${llm.confidence}`);
        }
        await services.securityEvent.record({
          operatorId: request.operatorId,
          agentId: agentId ?? '',
          passportJti: passportJti ?? undefined,
          signalType: 'prompt_injection',
          severity,
          message: `Scan caught injection: ${causeBits.join(' + ')}`,
          metadata: {
            scan_id: scanId,
            ...(match ? {
              pattern_id: match.pattern_id,
              field_path: match.field_path,
              matched_excerpt: match.matched_text,
              ...(match.encoding ? { encoding: match.encoding } : {}),
            } : {}),
            ...(llm && !llm.degraded ? {
              l3_verdict: llm.verdict,
              l3_confidence: llm.confidence,
              l3_reasoning: llm.reasoning,
              l3_cost_cents: llm.cost_cents,
              l3_duration_ms: llm.duration_ms,
              l3_model: llm.model,
            } : {}),
            ...(context ? { scan_context: context } : {}),
            ...(source ? { scan_source: source.slice(0, 256) } : {}),
          },
        });
      }

      // Always write an audit row — every scan is a metered op and
      // shows up in the chain regardless of outcome.
      await services.audit.write({
        ctx: auditCtx(request, {
          ...(agentId ? { agent_id: agentId } : {}),
          ...(passportJti ? { passport_jti: passportJti } : {}),
        }),
        layer: 'vault',
        action: 'content.scan',
        outcome: verdict === 'critical' ? 'failure' : 'success',
        duration_ms: durationMs,
        ...(match ? {
          error: {
            code: verdict === 'critical' ? 'PROMPT_INJECTION_DETECTED' : 'SUSPICIOUS_CONTENT',
            message: `${match.pattern_id} on ${match.field_path}`,
          },
        } : {}),
      });

      // 6. Response — stable shape for SDKs and the MCP wrapper. The
      //    L3 LLM result is exposed when present so callers can see
      //    why a verdict went the way it did (e.g. "L3 said suspicious
      //    even though regex was clean").
      return reply.status(200).send({
        verdict,
        scan_id: scanId,
        duration_ms: durationMs,
        match: match
          ? {
              pattern_id: match.pattern_id,
              severity: match.severity,
              field_path: match.field_path,
              matched_excerpt: match.matched_text,
              ...(match.encoding ? { encoding: match.encoding } : {}),
            }
          : null,
        llm: llm && !llm.degraded
          ? {
              verdict: llm.verdict,
              confidence: llm.confidence,
              reasoning: llm.reasoning,
              model: llm.model,
            }
          : null,
        // When L3 ran but degraded (timeout / network / parse error),
        // surface that fact so callers know the verdict is L1+L2-only,
        // not the full chain. Useful for trust models that escalate
        // when they don't have a complete signal.
        l3_degraded: llm?.degraded === true ? { reason: llm.reasoning, duration_ms: llm.duration_ms } : null,
      });
    },
  );

  // Per-operator usage stats — symmetric with /v1/proxy/usage. Lets
  // dashboards show the scan quota gauge.
  app.get('/v1/scan/usage', { preHandler: auth }, async (request) => {
    const now = new Date();
    // Same correction as /v1/proxy/usage: this read the retired `scan` key and
    // has reported zero since the meters collapsed. `used` is the shared
    // recorded-actions pool the scan spends from — for the
    // accounts of a partner on a negotiated hard cap, the partner's pool; the endpoint folds into /v1/usage
    // with the rest of the wire-shape change.
    return actionPoolSnapshot(services, request.operatorId, now);
  });
}
