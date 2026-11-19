import type { FastifyInstance, FastifyRequest } from 'fastify';
import { denyAgentContexts } from '../middleware/require-platform.js';
import { requireControls } from '../middleware/require-controls.js';
import { CheckpointInput, CheckoutInput, ReviewDecisionInput, NotificationChannelInput, AddDeliveryMethodInput, CreateNotificationRuleInput, UpdateNotificationRuleInput, ForbiddenError, ids, passportClaims, passportCheckpoints } from '@stack/shared';
import { and, eq, gt, desc } from 'drizzle-orm';
import { z } from 'zod';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { enforceGovernanceStepUp } from '../middleware/governance-stepup.js';
import { auditCtx } from '../middleware/audit.js';
import { requireRole } from '../middleware/require-role.js';

/** Verification code submitted to confirm a delivery method or a rule. */
const VerifyCodeBody = z.object({ code: z.string().min(1) });

/**
 * An integer query value clamped into [min, max]. An empty string counts as
 * absent, a value that is not a number is rejected, and a fractional value is
 * truncated.
 */
const clampedIntQuery = (min: number, max: number) =>
  z
    .preprocess((value) => (value === '' ? undefined : value), z.coerce.number().finite().optional())
    .transform((value) => (value === undefined ? undefined : Math.min(max, Math.max(min, Math.trunc(value)))));

const ReviewQueueQuery = z.object({
  status: z.string().optional(),
  page: clampedIntQuery(1, Number.MAX_SAFE_INTEGER),
  limit: clampedIntQuery(1, 100),
});

/**
 * Create-rule body. Which shape it is (destination-based or inline channel)
 * is decided from the keys present, and each shape is then parsed against its
 * own shared schema.
 */
const NotificationRuleRequestBody = z.record(z.string(), z.unknown());

/**
 * Decide whether a new delivery method starts out verified.
 *
 * There is exactly one case: the operator's own registered email, which is
 * already proven because that address is how they sign in.
 *
 * A webhook used to be trusted the moment it was named, which made "verified"
 * meaningless for the one channel type that points at an arbitrary URL and the
 * one that carries security events off our network. Nominating a URL is a
 * claim about an endpoint; it is now proven the same way email and SMS are, by
 * reading a code STACK delivers to the endpoint itself.
 *
 * Pinned here as a pure function so the rule is testable and so a second
 * create path cannot quietly grow a different answer.
 */
export function resolveDestinationAutoVerify(args: {
  channelType: string;
  destination: string;
  operatorEmail: string | null;
}): boolean {
  if (args.channelType !== 'email') return false;
  if (!args.operatorEmail) return false;
  return args.operatorEmail.toLowerCase() === args.destination.toLowerCase();
}

function redactNotificationSecret<T extends Record<string, unknown>>(
  row: T,
): Omit<T, 'webhook_secret_encrypted' | 'webhook_secret_previous_encrypted'> {
  const safe = { ...row };
  delete safe['webhook_secret_encrypted'];
  delete safe['webhook_secret_previous_encrypted'];
  return safe;
}

/**
 * A rule as every answer shows it: the stored row (`active` as stored), its resolved `delivery_methods` and `delivers`, the
 * one derived state (`NotificationService.describeRule`): true only when the rule is active and dispatch would send to a
 * verified delivery method of it. Nothing that shows a rule as On may read anything but `delivers`.
 */
async function ruleView(services: Services, channel: Parameters<Services['notification']['describeRule']>[0] & Record<string, unknown>) {
  const { methods, delivers } = await services.notification.describeRule(channel);
  return {
    ...redactNotificationSecret(channel as Record<string, unknown>),
    delivery_methods: methods.map((method) => redactNotificationSecret(method as unknown as Record<string, unknown>)),
    delivers,
  };
}

async function requireNotificationMutation(
  services: Services,
  request: FastifyRequest,
  resourceId: string,
  payload: unknown,
  summary: string,
): Promise<void> {
  requireRole(request, 'admin');
  await enforceGovernanceStepUp(services, request, {
    action: 'notification_config_mutate',
    resourceId,
    payload,
    summary,
  });
}

export function registerAccountabilityRoutes(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  // ─── Checkpoint ─────────────────────────────────────────────────────

  app.post<{ Params: { jti: string } }>(
    '/v1/passports/:jti/checkpoint',
    { preHandler: auth },
    async (request, reply) => {
      requireRole(request, 'standard');
      const input = CheckpointInput.parse(request.body);
      const start = Date.now();
      const jti = request.params.jti;

      // checkpoint dual-write producer.
      // Each successful checkpoint POST also emits a task_complete
      // intent_claim + matching intent_outcome into the claim
      // registry. The legacy checkpoints table keeps populating
      // unchanged (TTL extension + checkpoint_silence detector still
      // read from the endpoint cadence, NOT from the claim emission).
      // Per ADR: do NOT add a parallel agent_heartbeat_silence
      // detector — checkpoint_silence stays canonical. Skipped
      // cleanly when the passport row can't be resolved (operator
      // mismatch, expired, etc. — submitCheckpoint will throw and
      // we don't emit a half-record).
      let intentClaimId: string | null = null;
      let passportAgentId: string | null = null;
      try {
        const passportRow = await services.passport.findByJti(jti);
        if (passportRow && passportRow.operator_id === request.operatorId) {
          passportAgentId = passportRow.agent_id ?? null;
        }
      } catch {
        // findByJti errors are non-fatal here — claim emission is
        // best-effort and the legacy path runs regardless.
      }

      if (passportAgentId) {
        try {
          const intentResult = await services.claimRegistry.registerClaim({
            operatorId: request.operatorId,
            passportJti: jti,
            claimType: 'intent_claim',
            payload: {
              type: 'intent_claim',
              intent_type: 'task_complete',
              agent_id: passportAgentId,
              named_intent: 'stack:passport:checkpoint',
              target: `passport:${jti}`,
              action: 'submit_checkpoint',
              parameters: {
                services_used_count: input.services_used.length,
                actions_count: input.actions_count,
                has_summary: Boolean(input.summary),
                tool_calls_count: input.tool_calls?.length ?? 0,
                delegated_to_count: input.delegated_to?.length ?? 0,
              },
              estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
              accountability: 'standard',
              reason: input.summary ?? null,
              requires: [],
              user_subject: request.memberId ? `mem:${request.memberId}` : null,
              mission_ref: null,
              submitted_at: Date.now(),
            },
          });
          intentClaimId = intentResult.claimId;
        } catch (err) {
          console.error('intent_claim emission failed:', safeErrorSummary(err));
        }
      }

      let result: Awaited<ReturnType<typeof services.accountability.submitCheckpoint>>;
      try {
        result = await services.accountability.submitCheckpoint(
          jti,
          request.operatorId,
          input,
        );
      } catch (err) {
        // Failure-path Outcome — pair the Intent so a verifier sees
        // the attempted checkpoint + the rejection.
        if (intentClaimId && passportAgentId) {
          try {
            await services.claimRegistry.registerClaim({
              operatorId: request.operatorId,
              passportJti: jti,
              claimType: 'intent_outcome',
              payload: {
                type: 'intent_outcome',
                intent_claim_ref: intentClaimId,
                status: 'failed',
                duration_ms: Date.now() - start,
                cost_actual: { wallet_cents: 0, tokens: null, gas_gwei: null },
                recorded_at: Date.now(),
                outcome_type: 'task_complete',
              },
            });
          } catch (outcomeErr) {
            console.error('failure-path intent_outcome emission failed:', safeErrorSummary(outcomeErr));
          }
        }
        throw err;
      }

      // Success-path Outcome — task_complete is informational only,
      // so it just records the duration + standard fields.
      if (intentClaimId && passportAgentId) {
        try {
          await services.claimRegistry.registerClaim({
            operatorId: request.operatorId,
            passportJti: jti,
            claimType: 'intent_outcome',
            payload: {
              type: 'intent_outcome',
              intent_claim_ref: intentClaimId,
              status: 'succeeded',
              duration_ms: Date.now() - start,
              cost_actual: { wallet_cents: 0, tokens: null, gas_gwei: null },
              recorded_at: Date.now(),
              outcome_type: 'task_complete',
            },
          });
        } catch (err) {
          console.error('success-path intent_outcome emission failed:', safeErrorSummary(err));
        }
      }

      // composability bonus — checkpoint_self_report_divergence
      // detector. Compares the just-submitted checkpoint's self-reported
      // services_used + actions_count against the verified intent_claim
      // emissions on this passport since the previous checkpoint (or
      // passport start). A divergent self-report against signed Intent
      // history fires the detector. Substrate-enabled answer to "agent
      // lying in its own checkpoint summary." Best-effort: divergence-
      // check failures log + swallow so checkpoint flow stays resilient.
      try {
        // Window start: previous checkpoint's submitted_at, or passport
        // issued_at if this is the first checkpoint.
        const prevCheckpoints = await services.db
          .select()
          .from(passportCheckpoints)
          .where(eq(passportCheckpoints.passport_jti, jti))
          .orderBy(desc(passportCheckpoints.submitted_at))
          .limit(2);
        // [0] is the checkpoint we just wrote; [1] is the previous one if any.
        const windowStart =
          prevCheckpoints[1]?.submitted_at ??
          (await services.passport.findByJti(jti))?.issued_at ??
          new Date(0);
        const windowStartMs = windowStart.getTime();

        // Pull all intent_claim rows since the window started, on this
        // passport. Filter out task_complete (the checkpoint itself
        // emits task_complete; don't count it as an "action").
        const intentClaims = await services.db
          .select()
          .from(passportClaims)
          .where(
            and(
              eq(passportClaims.passport_id, jti),
              eq(passportClaims.type, 'intent_claim'),
              gt(passportClaims.issued_at_ms, windowStartMs),
            ),
          );

        const verifiedActions = intentClaims.filter(
          (c) => (c.body_json as { intent_type?: string }).intent_type !== 'task_complete',
        );
        const verifiedActionsCount = verifiedActions.length;
        const verifiedServices = new Set<string>();
        for (const c of verifiedActions) {
          const target = (c.body_json as { target?: string }).target;
          if (target) verifiedServices.add(target);
        }

        // Reported values from the checkpoint payload.
        const reportedActionsCount = input.actions_count;
        const reportedServices = new Set(input.services_used);

        // Divergence rules (v1, deliberately strict — refine with data):
        //   1. verifiedActionsCount > reportedActionsCount (agent under-
        //      reported how many actions it took).
        //   2. A service appears in verifiedServices but NOT in
        //      reportedServices (agent under-reported which services
        //      it touched).
        const missingServices: string[] = [];
        for (const svc of verifiedServices) {
          if (!reportedServices.has(svc)) missingServices.push(svc);
        }
        const actionsUnderReported = verifiedActionsCount > reportedActionsCount;
        const servicesUnderReported = missingServices.length > 0;

        if (passportAgentId && (actionsUnderReported || servicesUnderReported)) {
          const causes: string[] = [];
          if (actionsUnderReported) {
            causes.push(`actions_count under-reported: reported ${reportedActionsCount}, verified ${verifiedActionsCount}`);
          }
          if (servicesUnderReported) {
            causes.push(`services_used missing: ${missingServices.join(', ')}`);
          }
          await services.securityEvent.record({
            operatorId: request.operatorId,
            agentId: passportAgentId,
            passportJti: jti,
            signalType: 'checkpoint_self_report_divergence',
            severity: 'warning',
            message: `Checkpoint self-report diverges from verified Intent emissions: ${causes.join('; ')}`,
            metadata: {
              reported_actions_count: reportedActionsCount,
              verified_actions_count: verifiedActionsCount,
              reported_services: Array.from(reportedServices),
              verified_services: Array.from(verifiedServices),
              missing_services: missingServices,
              window_start_ms: windowStartMs,
            },
            pipeline: 'heuristic',
          });
        }
      } catch (err) {
        // Divergence-check failures must NOT break checkpoint flow.
        // Log via the regular sentry pipeline; the legacy + claim paths
        // already ran successfully above.
        console.error('divergence check failed:', safeErrorSummary(err));
      }

      await services.audit.write({
        ctx: auditCtx(request, { passport_jti: jti }),
        layer: 'vault',
        action: 'passport.checkpoint',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.status(201).send(result);
    },
  );

  // ─── Checkout ───────────────────────────────────────────────────────

  app.post<{ Params: { jti: string } }>(
    '/v1/passports/:jti/checkout',
    { preHandler: auth },
    async (request, reply) => {
      requireRole(request, 'standard');
      const input = CheckoutInput.parse(request.body);
      const start = Date.now();

      const result = await services.accountability.submitCheckout(
        request.params.jti,
        request.operatorId,
        input,
      );

      await services.audit.write({
        ctx: auditCtx(request, { passport_jti: request.params.jti }),
        layer: 'vault',
        action: 'passport.checkout',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return reply.send(result);
    },
  );

  // ─── Report ─────────────────────────────────────────────────────────

  // A passport report reads the record: a controls feature (402 CONTROLS_REQUIRED without controls).
  app.get<{ Params: { jti: string } }>(
    '/v1/passports/:jti/report',
    { preHandler: [auth, requireControls(services)] },
    async (request) => {
      return services.accountability.getReport(request.params.jti, request.operatorId);
    },
  );

  // ─── Review Queue ───────────────────────────────────────────────────

  app.get('/v1/passports/reviews', { preHandler: auth }, async (request) => {
    const { status, page, limit } = ReviewQueueQuery.parse(request.query);
    return services.accountability.getReviewQueue(request.operatorId, { status, page, limit });
  });

  // ─── Review Decision ────────────────────────────────────────────────

  app.post<{ Params: { checkoutId: string } }>(
    '/v1/passports/reviews/:checkoutId/decide',
    { preHandler: [auth, denyAgentContexts] },
    async (request) => {
      requireRole(request, 'standard');
      const input = ReviewDecisionInput.parse(request.body);

      // APPROVING a held checkout is scope-expanding (releases
      // the hold) — Bearer-credential contexts (incl. agentic MCP
      // sessions) need a human-approved governance approval. BLOCKING is
      // tightening and stays frictionless from anywhere.
      if (input.decision === 'approved') {
        await enforceGovernanceStepUp(services, request, {
          action: 'review_decide_approve',
          resourceId: request.params.checkoutId,
          payload: { checkout_id: request.params.checkoutId, decision: input.decision },
          summary: `Approve held checkout ${request.params.checkoutId}`,
        });
      }

      const start = Date.now();

      const result = await services.accountability.submitDecision(
        request.params.checkoutId,
        request.operatorId,
        input,
        { decider_agent_id: request.agentId },
      );

      await services.audit.write({
        ctx: auditCtx(request, { agent_id: result.agent_id }),
        layer: 'vault',
        action: 'passport.review_decide',
        outcome: 'success',
        duration_ms: Date.now() - start,
      });

      return result;
    },
  );

  // ─── Notification Destinations (Delivery Methods) ──────────────────

  app.post('/v1/notifications/destinations', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    const input = AddDeliveryMethodInput.parse(request.body);

    const existing = await services.notificationDestination.findByOperatorAndTypeAndDest(
      request.operatorId, input.channel_type, input.destination,
    );
    if (existing) {
      return reply.status(409).send({ error: { message: 'Delivery method already exists' } });
    }

    await requireNotificationMutation(
      services,
      request,
      `${input.channel_type}:${input.destination}`,
      input,
      `Add ${input.channel_type} notification destination ${input.destination}`,
    );

    const operator = input.channel_type === 'email'
      ? await services.operator.getById(request.operatorId)
      : null;
    const autoVerified = resolveDestinationAutoVerify({
      channelType: input.channel_type,
      destination: input.destination,
      operatorEmail: operator?.email ?? null,
    });

    const destinationId = ids.notificationDestination();
    const webhook = input.channel_type === 'webhook'
      ? await services.notification.createWebhookSecret(
          request.operatorId,
          destinationId,
          'notification_destination_webhook_secret',
        )
      : null;
    const dest = await services.notificationDestination.create({
      id: destinationId,
      operator_id: request.operatorId,
      channel_type: input.channel_type,
      destination: input.destination,
      verified: autoVerified,
      webhook_secret_encrypted: webhook?.encrypted ?? null,
    });

    return reply.status(201).send({
      ...redactNotificationSecret(dest as unknown as Record<string, unknown>),
      ...(webhook ? { webhook_secret: webhook.secret } : {}),
    });
  });

  app.get('/v1/notifications/destinations', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    requireRole(request, 'admin');
    const rows = await services.notificationDestination.findByOperator(request.operatorId);
    return rows.map((row) => redactNotificationSecret(row as unknown as Record<string, unknown>));
  });

  app.delete<{ Params: { id: string } }>(
    '/v1/notifications/destinations/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const dest = await services.notificationDestination.findById(request.params.id);
      if (!dest || dest.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Delivery method not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { destination_id: request.params.id },
        'Delete a notification destination',
      );
      await services.notificationDestination.delete(request.params.id);
      return { deleted: true };
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/notifications/destinations/:id/rotate-secret',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const dest = await services.notificationDestination.findById(request.params.id);
      if (!dest || dest.operator_id !== request.operatorId || dest.channel_type !== 'webhook') {
        return reply.status(404).send({ error: { message: 'Webhook delivery method not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { destination_id: request.params.id, operation: 'rotate_webhook_secret' },
        'Rotate a notification webhook signing secret',
      );
      const webhook = await services.notification.createWebhookSecret(
        request.operatorId,
        dest.id,
        'notification_destination_webhook_secret',
      );
      // The secret this replaces keeps signing beside the new one for 24 hours.
      const updated = await services.notificationDestination.update(dest.id, {
        webhook_secret_encrypted: webhook.encrypted,
        webhook_secret_previous_encrypted: dest.webhook_secret_encrypted,
        webhook_secret_rotated_at: new Date(),
      });
      return {
        ...redactNotificationSecret(updated as unknown as Record<string, unknown>),
        webhook_secret: webhook.secret,
      };
    },
  );

  // ─── Destination Verification ──────────────────────────────────────

  app.post<{ Params: { id: string } }>(
    '/v1/notifications/destinations/:id/send-code',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const destination = await services.notificationDestination.findById(request.params.id);
      if (!destination || destination.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Delivery method not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { destination_id: request.params.id, operation: 'send_verification_code' },
        'Send a notification destination verification code',
      );
      return services.notification.sendDestinationVerificationCode(request.params.id, request.operatorId);
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/notifications/destinations/:id/verify',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const { code } = VerifyCodeBody.parse(request.body);
      const destination =await services.notificationDestination.findById(request.params.id);
      if (!destination || destination.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Delivery method not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { destination_id: request.params.id, operation: 'verify' },
        'Verify a notification destination',
      );
      const result = await services.notification.verifyDestinationCode(request.params.id, request.operatorId, code);
      if (!result.verified) {
        return reply.status(400).send({ error: { message: result.error } });
      }
      return result;
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/notifications/destinations/:id/test',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const destination = await services.notificationDestination.findById(request.params.id);
      if (!destination || destination.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Delivery method not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { destination_id: request.params.id, operation: 'send_test' },
        'Send a test notification',
      );
      const result = await services.notification.testDestination(request.params.id, request.operatorId);
      if (!result.sent) {
        return reply.status(400).send({ error: { message: result.error } });
      }
      return result;
    },
  );

  // ─── Notification Channels (Rules) ─────────────────────────────────

  app.post('/v1/notifications/channels', { preHandler: [auth, denyAgentContexts] }, async (request, reply) => {
    const body = NotificationRuleRequestBody.parse(request.body);

    // New-style: destination-based rule (single or multi)
    if (body.destination_id || body.destination_ids) {
      const input = CreateNotificationRuleInput.parse(body);
      const destIds = input.destination_ids ?? (input.destination_id ? [input.destination_id] : []);

      if (destIds.length === 0) {
        return reply.status(400).send({ error: { message: 'At least one delivery method is required' } });
      }

      // Verify all destinations exist, belong to operator, and are verified
      for (const destId of destIds) {
        const dest = await services.notificationDestination.findById(destId);
        if (!dest || dest.operator_id !== request.operatorId) {
          return reply.status(404).send({ error: { message: `Delivery method ${destId} not found` } });
        }
        if (!dest.verified) {
          return reply.status(400).send({ error: { message: 'All delivery methods must be verified before creating rules' } });
        }
      }

      await requireNotificationMutation(
        services,
        request,
        destIds.join(','),
        input,
        'Create a notification rule',
      );

      // Use first destination for legacy fields
      const firstDest = await services.notificationDestination.findById(destIds[0]!);

      const channel = await services.notificationChannel.create({
        id: ids.notificationChannel(),
        operator_id: request.operatorId,
        destination_id: destIds[0],
        destination_ids: destIds,
        channel_type: firstDest!.channel_type,
        destination: firstDest!.destination,
        events: input.events,
        min_severity: input.min_severity ?? 'warning',
        verified: true,
        active: true,
      });

      return reply.status(201).send(await ruleView(services, channel));
    }

    // Inline channel_type + destination.
    const input = NotificationChannelInput.parse(body);
    await requireNotificationMutation(
      services,
      request,
      `${input.channel_type}:${input.destination}`,
      input,
      'Create a notification rule',
    );

    // A webhook cannot be named inline: this path would mark it verified on
    // the spot, the same open door the destinations endpoint closed. Refused
    // rather than stored and then quietly never delivered.
    if (input.channel_type === 'webhook') {
      throw new ForbiddenError(
        'Webhook channels must be created via POST /v1/notifications/destinations, ' +
          'which verifies that you control the URL before anything is delivered to it.',
      );
    }

    const allEvents = [
      'passport.flagged',
      'passport.blocked',
      'agent.blocked',
      'passport.missed_checkout',
    ];

    // An inline address is a delivery method named in the rule. It becomes one: found if the account already has it,
    // otherwise created exactly as POST /v1/notifications/destinations creates it (verified at once only when it is the
    // account's own sign-in address) and attached to the rule, so the one verification flow of delivery methods can make
    // it deliverable. A method made here has its verification message sent once; a method that already existed is not
    // mailed again.
    let destination = await services.notificationDestination.findByOperatorAndTypeAndDest(
      request.operatorId, input.channel_type, input.destination,
    );
    let created = false;
    if (!destination) {
      const operator = input.channel_type === 'email' ? await services.operator.getById(request.operatorId) : null;
      try {
        destination = await services.notificationDestination.create({
          id: ids.notificationDestination(),
          operator_id: request.operatorId,
          channel_type: input.channel_type,
          destination: input.destination,
          verified: resolveDestinationAutoVerify({
            channelType: input.channel_type,
            destination: input.destination,
            operatorEmail: operator?.email ?? null,
          }),
          webhook_secret_encrypted: null,
        });
        created = true;
      } catch (error) {
        // A second request for the same address won the unique index: use its row.
        destination = await services.notificationDestination.findByOperatorAndTypeAndDest(
          request.operatorId, input.channel_type, input.destination,
        );
        if (!destination) throw error;
      }
    }

    const channel = await services.notificationChannel.create({
      id: ids.notificationChannel(),
      operator_id: request.operatorId,
      destination_id: destination.id,
      destination_ids: [destination.id],
      channel_type: destination.channel_type,
      destination: destination.destination,
      events: input.events ?? allEvents,
      min_severity: input.min_severity ?? 'warning',
      verified: destination.verified,
    });

    if (created && !destination.verified) {
      try {
        await services.notification.sendDestinationVerificationCode(destination.id, request.operatorId);
      } catch (error) {
        // The rule exists and says it does not deliver; the code can be sent again from the delivery method.
        request.log.warn({ err: safeErrorSummary(error), destination_id: destination.id }, 'notification verification code not sent');
      }
    }

    return reply.status(201).send(await ruleView(services, channel));
  });

  app.get('/v1/notifications/channels', { preHandler: [auth, denyAgentContexts] }, async (request) => {
    requireRole(request, 'admin');
    const channels = await services.notificationChannel.findByOperator(request.operatorId);

    return Promise.all(channels.map((ch) => ruleView(services, ch)));
  });

  app.delete<{ Params: { id: string } }>(
    '/v1/notifications/channels/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const channel = await services.notificationChannel.findById(request.params.id);
      if (!channel || channel.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Notification channel not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { channel_id: request.params.id, operation: 'delete' },
        'Delete a notification rule',
      );
      await services.notificationChannel.delete(request.params.id);
      return { deleted: true };
    },
  );

  app.patch<{ Params: { id: string } }>(
    '/v1/notifications/channels/:id',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const channel = await services.notificationChannel.findById(request.params.id);
      if (!channel || channel.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Notification channel not found' } });
      }

      const input = UpdateNotificationRuleInput.parse(request.body);
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        input,
        'Update a notification rule',
      );
      const updates: Record<string, unknown> = {};

      if (input.events) updates.events = input.events;
      if (input.min_severity) updates.min_severity = input.min_severity;
      // `!== undefined`, not truthiness — `active: false` is the whole
      // point of the field and a truthy check would silently drop it.
      if (input.active !== undefined) updates.active = input.active;

      if (input.destination_ids && input.destination_ids.length > 0) {
        // Verify all destinations
        for (const destId of input.destination_ids) {
          const dest = await services.notificationDestination.findById(destId);
          if (!dest || dest.operator_id !== request.operatorId) {
            return reply.status(404).send({ error: { message: `Delivery method ${destId} not found` } });
          }
          if (!dest.verified) {
            return reply.status(400).send({ error: { message: 'All delivery methods must be verified' } });
          }
        }
        updates.destination_ids = input.destination_ids;
        updates.destination_id = input.destination_ids[0]; // legacy
        const firstDest = await services.notificationDestination.findById(input.destination_ids[0]!);
        if (firstDest) {
          updates.channel_type = firstDest.channel_type;
          updates.destination = firstDest.destination;
        }
      }

      const updated = await services.notificationChannel.update(request.params.id, updates);
      return ruleView(services, updated!);
    },
  );

  // ─── Legacy Channel Verification (kept for backward compat) ────────

  app.post<{ Params: { id: string } }>(
    '/v1/notifications/channels/:id/send-code',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const channel = await services.notificationChannel.findById(request.params.id);
      if (!channel || channel.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Notification channel not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { channel_id: request.params.id, operation: 'send_verification_code' },
        'Send a notification-channel verification code',
      );
      return services.notification.sendVerificationCode(request.params.id, request.operatorId);
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/notifications/channels/:id/verify',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const { code } = VerifyCodeBody.parse(request.body);
      const channel =await services.notificationChannel.findById(request.params.id);
      if (!channel || channel.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Notification channel not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { channel_id: request.params.id, operation: 'verify' },
        'Verify a notification channel',
      );
      const result = await services.notification.verifyCode(request.params.id, request.operatorId, code);
      if (!result.verified) {
        return reply.status(400).send({ error: { message: result.error } });
      }
      return result;
    },
  );

  app.post<{ Params: { id: string } }>(
    '/v1/notifications/channels/:id/test',
    { preHandler: [auth, denyAgentContexts] },
    async (request, reply) => {
      const channel = await services.notificationChannel.findById(request.params.id);
      if (!channel || channel.operator_id !== request.operatorId) {
        return reply.status(404).send({ error: { message: 'Notification channel not found' } });
      }
      await requireNotificationMutation(
        services,
        request,
        request.params.id,
        { channel_id: request.params.id, operation: 'send_test' },
        'Send a test notification',
      );
      const result = await services.notification.testChannel(request.params.id, request.operatorId);
      if (!result.sent) {
        return reply.status(400).send({ error: { message: result.error } });
      }
      return result;
    },
  );
}
import { safeErrorSummary } from '@stack/shared';
