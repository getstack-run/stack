import type { Redis } from 'ioredis';
import { safeErrorSummary } from '@stack/shared';
import {
  ids,
  resolveMissionRef,
  type CheckpointInput,
  type CheckoutInput,
  type ReviewDecisionInput,
  type ReviewFlag,
  NotFoundError,
  PassportExpiredError,
  PassportRevokedError,
  CheckpointNotAvailableError,
  CHECKPOINT_DEFAULT_INTERVAL_SECONDS,
  ForbiddenError,
} from '@stack/shared';
import { CheckpointRepository } from '../repositories/checkpoint-repo.js';
import { CheckoutRepository } from '../repositories/checkout-repo.js';
import { ReviewRepository } from '../repositories/review-repo.js';
import { PassportRepository } from '../repositories/passport-repo.js';
import { AgentRepository } from '../repositories/agent-repo.js';
import { SecurityEventRepository } from '../repositories/security-event-repo.js';
import { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import { signDetectorSignalClaim } from './detector-signal-claim.js';
import type { BehavioralGenomeService } from './behavioral-genome-service.js';
import type { PassportService } from './passport-service.js';
import { projectOutcomeClaim, projectSimulationClaim } from './accountability/claim-projection.js';
import { NO_INTENT_DEVIATION_GRADER, type IntentDeviationGrader } from './accountability/intent-deviation.js';
import {
  behavioralAnomalyFlags,
  checkpointGapFlags,
  credentialUnreportedFlags,
  determineReviewStatus,
  durationExceededFlags,
  highActionVolumeFlags,
  missingCheckpointFlags,
  scopeEscalationPatternFlags,
  undeclaredDelegationFlags,
  undeclaredServiceFlags,
  type ReviewAgent,
  type ReviewCheckpoint,
  type ReviewPassport,
} from './accountability/review-rules.js';

export type { IntentDeviationGrader, IntentDeviationInput } from './accountability/intent-deviation.js';

export class AccountabilityService {
  private intentDeviation: IntentDeviationGrader = NO_INTENT_DEVIATION_GRADER;
  /**
   * late-wired claim registry. When set
   * submitCheckpoint dual-writes a signed checkpoint_approval claim
   * alongside the legacy passport_checkpoints row. Mirror of
   * SecurityEventService.setClaimRegistryService.
   */
  private claimRegistry?: ClaimRegistryService;

  /**
   * late-wired behavioral genome producer. When set
   * submitCheckpoint fires a fire-and-forget genome emit per checkpoint
   * (window: last_checkpoint_at → now, or issued_at → now on first
   * checkpoint). Tier-gated downstream at the claim registry —
   * non-enterprise operators silently no-op via ForbiddenError caught
   * in the .catch() handler.
   */
  private behavioralGenome?: BehavioralGenomeService;
  private agentBlocker?: Pick<PassportService, 'blockAgent'>;

  constructor(
    private checkpointRepo: CheckpointRepository,
    private checkoutRepo: CheckoutRepository,
    private reviewRepo: ReviewRepository,
    private passportRepo: PassportRepository,
    private agentRepo: AgentRepository,
    private redis?: Redis,
    private securityEventRepo?: SecurityEventRepository,
    /**
     * optional, used by `getReport`
     * to surface attached intent_simulation + intent_outcome claims so
     * the dashboard /reviews detail can render simulated-vs-actual.
     * Tests that don't care about that surface omit it; production
     * services.ts wires it.
     */
    private passportClaimsRepo?: PassportClaimsRepository,
  ) {}

  /**
   * Inject the grader of the Intent Deviation detector. Optional — if not set,
   * the detector raises nothing and checkout proceeds.
   */
  setIntentDeviationGrader(grader: IntentDeviationGrader) {
    this.intentDeviation = grader;
  }

  setAgentBlocker(agentBlocker: Pick<PassportService, 'blockAgent'>) {
    this.agentBlocker = agentBlocker;
  }

  /**
   * wire the claim registry late (post-construction)
   * so submitCheckpoint can dual-write a checkpoint_approval claim. Mirror
   * of SecurityEventService.setClaimRegistryService.
   */
  setClaimRegistryService(claimRegistry: ClaimRegistryService) {
    this.claimRegistry = claimRegistry;
  }

  /**
   * wire the behavioral genome producer so submitCheckpoint
   * emits a passport-scoped behavioral_genome claim per checkpoint. Mirror
   * of setClaimRegistryService. Optional dep: if unset, checkpoint flow
   * silently skips the genome emit (legacy path unchanged).
   */
  setBehavioralGenomeService(behavioralGenome: BehavioralGenomeService) {
    this.behavioralGenome = behavioralGenome;
  }

  // ─── Checkpoint ─────────────────────────────────────────────────────

  async submitCheckpoint(passportJti: string, operatorId: string, input: CheckpointInput) {
    const passport = await this.passportRepo.findByJti(passportJti);
    if (!passport) throw new NotFoundError('Passport', passportJti);
    if (passport.operator_id !== operatorId) throw new NotFoundError('Passport', passportJti);
    if (passport.revoked_at) throw new PassportRevokedError();
    const agent = await this.agentRepo.findById(passport.agent_id);
    if (!agent) throw new NotFoundError('Agent', passport.agent_id);

    // Standard mode passports don't support checkpoints
    if (agent.accountability_mode === 'standard') {
      throw new CheckpointNotAvailableError();
    }

    // Check if passport is expired (allow recently expired for grace)
    const now = new Date();
    if (passport.expires_at < now) {
      throw new PassportExpiredError();
    }

    // Get previous checkpoints for running totals
    const prevCheckpoints = await this.checkpointRepo.findByPassport(passportJti);
    const lastCheckpoint = prevCheckpoints[prevCheckpoints.length - 1];
    const prevTotalActions = lastCheckpoint?.total_actions ?? 0;
    const prevTotalServices = new Set<string>(lastCheckpoint?.total_services ?? []);
    for (const svc of input.services_used) prevTotalServices.add(svc);

    const checkpoint = await this.checkpointRepo.create({
      id: ids.checkpoint(),
      passport_jti: passportJti,
      operator_id: operatorId,
      services_used: input.services_used,
      tool_calls: input.tool_calls ?? null,
      actions_count: input.actions_count,
      delegations: input.delegated_to ?? null,
      summary: input.summary ?? null,
      total_actions: prevTotalActions + input.actions_count,
      total_services: Array.from(prevTotalServices),
    });

    // dual-write checkpoint_approval claim.
    // Best-effort: claim emission never fails the legacy write. Mirror
    // of SecurityEventService.record ( +
    // back-reference linkage from 1.22). The claim is the cryptographic
    // substrate; the legacy row stays the user-facing record.
    if (this.claimRegistry) {
      try {
        // 5.0.4 — auto-resolve mission_ref from the passport's mission_ids
        // (loaded above at line 101 — row carries the denormalized list).
        const missionRef = resolveMissionRef(passport.mission_ids ?? undefined);
        const result = await this.claimRegistry.registerClaim({
          operatorId,
          passportJti,
          claimType: 'checkpoint_approval',
          payload: {
            type: 'checkpoint_approval',
            checkpoint_id: checkpoint.id,
            interval_seconds:
              agent.accountability_mode === 'enforced'
                ? passport.checkpoint_interval_seconds ?? CHECKPOINT_DEFAULT_INTERVAL_SECONDS
                : null,
            services_used: input.services_used,
            actions_count: input.actions_count,
            has_summary: Boolean(input.summary),
            delegated_to: input.delegated_to ?? [],
            submitted_by: operatorId,
            submitted_at: Date.now(),
            ...(missionRef ? { mission_ref: missionRef } : {}),
          },
        });
        try {
          await this.checkpointRepo.linkClaim(checkpoint.id, result.claimId);
        } catch (linkErr) {
          console.error('checkpoint_approval linkClaim failed:', safeErrorSummary(linkErr));
        }
      } catch (err) {
        console.error('checkpoint_approval emission failed:', safeErrorSummary(err));
      }
    }

    // Update passport checkpoint tracking
    const newCount = (passport.checkpoint_count ?? 0) + 1;
    await this.passportRepo.updateCheckpoint(passportJti, now, newCount);

    // Enforced mode: extend passport expiry
    let newExpiresAt: Date | undefined;
    if (agent.accountability_mode === 'enforced') {
      const interval = passport.checkpoint_interval_seconds ?? CHECKPOINT_DEFAULT_INTERVAL_SECONDS;
      newExpiresAt = new Date(now.getTime() + interval * 1000);
      await this.passportRepo.extendExpiry(passportJti, newExpiresAt);
    }

    // fire-and-forget behavioral_genome emit. Captures
    // the activity window since the previous checkpoint, or since
    // issuance on first checkpoint. NO `await`: the HTTP response must
    // not block on genome computation (~50-200ms). `.catch()` is
    // mandatory to prevent unhandled rejection. Tier-gate at the
    // claim registry filters non-enterprise operators (ForbiddenError
    // logged + swallowed; legacy checkpoint flow unaffected).
    if (this.behavioralGenome) {
      const windowStartMs =
        passport.last_checkpoint_at?.getTime() ?? passport.issued_at.getTime();
      const windowEndMs = now.getTime();
      this.behavioralGenome
        .emitForWindow(operatorId, passportJti, windowStartMs, windowEndMs)
        .catch((err) => {
          console.error('[behavioral_genome] checkpoint hook failed:', safeErrorSummary(err));
        });
    }

    // Check for immediate flags (undeclared services)
    const flags: string[] = [];
    if (passport.intent_services && input.services_used.length > 0) {
      const declaredServices = new Set(passport.intent_services);
      for (const svc of input.services_used) {
        if (!declaredServices.has(svc)) {
          flags.push(`Undeclared service: ${svc}`);
        }
      }
    }

    return {
      checkpoint_id: checkpoint.id,
      passport_jti: passportJti,
      new_expires_at: newExpiresAt?.toISOString(),
      flags: flags.length > 0 ? flags : undefined,
    };
  }

  // ─── Checkout ───────────────────────────────────────────────────────

  async submitCheckout(passportJti: string, operatorId: string, input: CheckoutInput) {
    const passport = await this.passportRepo.findByJti(passportJti);
    if (!passport) throw new NotFoundError('Passport', passportJti);
    if (passport.operator_id !== operatorId) throw new NotFoundError('Passport', passportJti);
    if (passport.revoked_at) throw new PassportRevokedError();

    const agent = await this.agentRepo.findById(passport.agent_id);
    if (!agent) throw new NotFoundError('Agent', passport.agent_id);

    if (agent.accountability_mode === 'standard') {
      throw new CheckpointNotAvailableError();
    }

    // Allow checkout on recently expired passports (same grace as refresh)
    const now = new Date();
    const expiredMs = now.getTime() - passport.expires_at.getTime();
    if (expiredMs > 24 * 60 * 60 * 1000) {
      throw new PassportExpiredError();
    }

    // Check if already checked out
    const existing = await this.checkoutRepo.findByPassport(passportJti);
    if (existing) {
      return {
        checkout_id: existing.id,
        passport_jti: passportJti,
        review_status: existing.review_status as 'clean' | 'flagged' | 'blocked',
        flags: existing.review_flags as ReviewFlag[] | undefined,
      };
    }

    // Get checkpoint history for review
    const checkpoints = await this.checkpointRepo.findByPassport(passportJti);

    // Run review engine
    const reviewResult = await this.runReviewEngine(passport, agent, checkpoints, input);
    const missionId = resolveMissionRef(passport.mission_ids ?? undefined);

    // Create checkout record
    const checkout = await this.checkoutRepo.create({
      id: ids.checkout(),
      passport_jti: passportJti,
      operator_id: operatorId,
      mission_id: missionId,
      services_used: input.services_used,
      tool_calls: input.tool_calls ?? null,
      actions_count: input.actions_count,
      delegations: input.delegated_to ?? null,
      summary: input.summary ?? null,
      review_status: reviewResult.status,
      review_flags: reviewResult.flags.length > 0 ? reviewResult.flags : null,
      reviewed_at: new Date(),
    });

    // Update passport
    await this.passportRepo.updateCheckout(passportJti, now, reviewResult.status, reviewResult.flags);

    // If blocked, block the agent from future passport issuance
    if (reviewResult.status === 'blocked') {
      if (!this.agentBlocker) throw new Error('AccountabilityService agent blocker is not wired');
      await this.agentBlocker.blockAgent(
        operatorId,
        passport.agent_id,
        `Blocked by review: ${reviewResult.flags.map((f) => f.message).join('; ')}`,
        now,
      );
    }

    return {
      checkout_id: checkout.id,
      passport_jti: passportJti,
      review_status: reviewResult.status as 'clean' | 'flagged' | 'blocked',
      flags: reviewResult.flags.length > 0 ? reviewResult.flags : undefined,
    };
  }

  // ─── Review Engine ──────────────────────────────────────────────────
  //
  // The rules themselves are pure functions in ./accountability/review-rules.ts
  // and the grader of declared-versus-observed behaviour is the interface in
  // ./accountability/intent-deviation.ts, which a deployment fills. This
  // method reads what they need, applies them in order, filters by accountability
  // mode, bridges flags into security events and decides the status.

  private async runReviewEngine(
    passport: ReviewPassport,
    agent: ReviewAgent,
    checkpoints: ReviewCheckpoint[],
    checkout: CheckoutInput,
  ): Promise<{ status: 'clean' | 'flagged' | 'blocked'; flags: ReviewFlag[] }> {
    const flags: ReviewFlag[] = [];
    const missionId = resolveMissionRef(passport.mission_ids ?? undefined);

    // Merge real-time security events (Signals 1-5) into flags
    if (this.securityEventRepo) {
      const securityEvents = await this.securityEventRepo.findByPassport(passport.jti);
      for (const evt of securityEvents) {
        flags.push({
          type: evt.signal_type as ReviewFlag['type'],
          severity: evt.severity as ReviewFlag['severity'],
          message: evt.message,
        });
      }
    }

    // Only run full review for enforced mode; logged mode only flags critical
    const isEnforced = agent.accountability_mode === 'enforced';

    flags.push(
      ...undeclaredServiceFlags(passport, checkout),
      ...undeclaredDelegationFlags(passport, checkout),
      ...durationExceededFlags(passport),
      ...missingCheckpointFlags(isEnforced, checkpoints),
      ...checkpointGapFlags(isEnforced, passport, checkpoints),
      ...highActionVolumeFlags(checkout),
    );

    // Signal 8: scope_escalation_pattern
    try {
      flags.push(
        ...scopeEscalationPatternFlags(await this.passportRepo.findRecentByAgent(agent.id, 10)),
      );
    } catch {
      // Non-critical, don't fail checkout
    }

    // Signal 9: credential_unreported (credentials retrieved but not reported)
    if (this.redis) {
      try {
        const accessedProviders = await this.redis.smembers(`cred_accessed:${passport.jti}`);
        flags.push(...credentialUnreportedFlags(accessedProviders, checkpoints, checkout));
        // Clean up the Redis set
        await this.redis.del(`cred_accessed:${passport.jti}`);
      } catch {
        // Non-critical
      }
    }

    // Signal 11: behavioral_anomaly against the agent's own recent checkouts.
    try {
      flags.push(
        ...behavioralAnomalyFlags(
          passport,
          checkout,
          await this.checkoutRepo.findRecentByAgent(agent.id, 20),
        ),
      );
    } catch {
      // Non-critical: baseline lookup failures don't block checkout.
    }

    // Signal 10: intent_deviation, on every checkout (the grader decides whether the account has it).
    flags.push(
      ...(await this.intentDeviation.grade({
        passport,
        agent,
        checkpoints,
        checkout,
        missionId,
      })),
    );

    // For logged mode, only keep critical flags
    const effectiveFlags = agent.accountability_mode === 'logged'
      ? flags.filter((f) => f.severity === 'critical')
      : flags;

    // Bridge: emit review-engine flags into the security_events stream so the
    // real-time dashboard view and the review page share a single signal list.
    // Flags sourced from the real-time stream are already persisted; skip those.
    if (this.securityEventRepo) {
      for (const flag of effectiveFlags) {
        if (flag.severity === 'info') continue; // info flags stay review-only
        try {
          const exists = await this.securityEventRepo.existsForPassport(passport.jti, flag.type);
          if (exists) continue;
          // Claim-first, like SecurityEventService.record, so the Console's
          // signed Mission decision can act on the row. Only the signing is
          // shared: a checkout flag does not notify or auto-block here, the
          // review status decides that at checkout.
          const claimId = await signDetectorSignalClaim(this.claimRegistry, {
            operatorId: passport.operator_id,
            passportJti: passport.jti,
            agentId: passport.agent_id,
            signalType: flag.type,
            severity: flag.severity,
            metadata: {},
            missionRef: missionId,
          });
          await this.securityEventRepo.create({
            id: ids.securityEvent(),
            operator_id: passport.operator_id,
            agent_id: passport.agent_id,
            passport_jti: passport.jti,
            mission_id: missionId,
            signal_type: flag.type,
            severity: flag.severity,
            message: flag.message,
            metadata: {},
            claim_id: claimId,
            resolved: false,
          });
        } catch {
          // Best-effort bridge: don't fail checkout if security_events insert fails
        }
      }
    }

    // Determine status based on flags + agent escalation config
    const status = determineReviewStatus(effectiveFlags, agent);

    return { status, flags: effectiveFlags };
  }

  // ─── Report ─────────────────────────────────────────────────────────

  async getReport(passportJti: string, operatorId: string) {
    const passport = await this.passportRepo.findByJti(passportJti);
    if (!passport) throw new NotFoundError('Passport', passportJti);
    if (passport.operator_id !== operatorId) throw new NotFoundError('Passport', passportJti);

    const agent = await this.agentRepo.findById(passport.agent_id);
    const checkpoints = await this.checkpointRepo.findByPassport(passportJti);
    const checkout = await this.checkoutRepo.findByPassport(passportJti);
    const review = checkout ? await this.reviewRepo.findByCheckout(checkout.id) : null;

    // attach intent_simulation + intent_outcome claims
    // so the dashboard /reviews detail can render simulated-vs-actual.
    // Skipped when passportClaimsRepo isn't wired (mostly tests).
    let simulations: ReturnType<typeof projectSimulationClaim>[] = [];
    let outcomes: ReturnType<typeof projectOutcomeClaim>[] = [];
    if (this.passportClaimsRepo) {
      const claims = await this.passportClaimsRepo.findActiveByPassportId(passportJti);
      simulations = claims
        .filter((c) => c.type === 'intent_simulation')
        .map(projectSimulationClaim)
        .sort((a, b) => b.issued_at_ms - a.issued_at_ms);
      outcomes = claims
        .filter((c) => c.type === 'intent_outcome')
        .map(projectOutcomeClaim)
        .sort((a, b) => b.issued_at_ms - a.issued_at_ms);
    }

    return {
      passport: {
        jti: passport.jti,
        agent_id: passport.agent_id,
        agent_name: agent?.name ?? 'unknown',
        accountability_mode: agent?.accountability_mode ?? 'standard',
        issued_at: passport.issued_at.toISOString(),
        expires_at: passport.expires_at.toISOString(),
        checked_out_at: passport.checked_out_at?.toISOString() ?? null,
      },
      intent: passport.intent_summary
        ? {
            summary: passport.intent_summary,
            services: passport.intent_services ?? [],
            will_delegate: passport.intent_delegates,
            estimated_duration_seconds: passport.estimated_duration_seconds ?? null,
          }
        : null,
      checkpoints: checkpoints.map((c) => ({
        id: c.id,
        submitted_at: c.submitted_at.toISOString(),
        services_used: c.services_used ?? [],
        actions_count: c.actions_count,
        summary: c.summary,
      })),
      checkout: checkout
        ? {
            id: checkout.id,
            submitted_at: checkout.submitted_at.toISOString(),
            services_used: checkout.services_used ?? [],
            actions_count: checkout.actions_count,
            summary: checkout.summary,
            review_status: checkout.review_status,
            flags: (checkout.review_flags as ReviewFlag[]) ?? [],
          }
        : null,
      review: review
        ? {
            id: review.id,
            decision: review.decision,
            notes: review.notes,
            decided_at: review.decided_at.toISOString(),
          }
        : null,
      simulations,
      outcomes,
    };
  }

  // ─── Review Queue ───────────────────────────────────────────────────

  async getReviewQueue(operatorId: string, filters?: { status?: string; page?: number; limit?: number }) {
    const limit = filters?.limit ?? 20;
    const page = filters?.page ?? 1;
    const offset = (page - 1) * limit;
    const status = filters?.status ?? 'flagged';

    const items = await this.checkoutRepo.findByOperator(operatorId, {
      review_status: status,
      limit,
      offset,
    });

    const total = await this.checkoutRepo.countByOperator(operatorId, status);

    // Enrich with agent info
    const enriched = await Promise.all(
      items.map(async (item) => {
        const passport = await this.passportRepo.findByJti(item.passport_jti);
        const agent = passport ? await this.agentRepo.findById(passport.agent_id) : null;
        return {
          checkout_id: item.id,
          passport_jti: item.passport_jti,
          mission_id: item.mission_id,
          agent_id: passport?.agent_id ?? 'unknown',
          agent_name: agent?.name ?? 'unknown',
          intent_summary: passport?.intent_summary ?? '',
          review_status: item.review_status,
          flags: (item.review_flags as ReviewFlag[]) ?? [],
          submitted_at: item.submitted_at.toISOString(),
        };
      }),
    );

    return { items: enriched, total };
  }

  // ─── Operator Decision ──────────────────────────────────────────────

  async submitDecision(
    checkoutId: string,
    operatorId: string,
    input: ReviewDecisionInput,
    opts?: { decider_agent_id?: string },
  ) {
    // defense-in-depth: a review decision is governance. The
    // route layer already denies agent-bearing contexts; this guard
    // makes the service refuse them too, so no future caller (worker,
    // MCP, new route) can re-open the no-self-authorization hole.
    if (opts?.decider_agent_id) {
      throw new ForbiddenError('review decisions require a non-agent principal');
    }
    const checkout = await this.checkoutRepo.findById(checkoutId);
    if (!checkout) throw new NotFoundError('Checkout', checkoutId);
    if (checkout.operator_id !== operatorId) throw new NotFoundError('Checkout', checkoutId);

    const passport = await this.passportRepo.findByJti(checkout.passport_jti);
    if (!passport) throw new NotFoundError('Passport', checkout.passport_jti);

    // Create review record
    const review = await this.reviewRepo.create({
      id: ids.review(),
      checkout_id: checkoutId,
      operator_id: operatorId,
      agent_id: passport.agent_id,
      decision: input.decision,
      notes: input.notes ?? null,
      block_future: input.block_future ?? false,
    });

    // Update checkout status based on decision
    const newStatus = input.decision === 'approved' ? 'clean' : 'blocked';
    await this.checkoutRepo.updateReviewStatus(checkoutId, newStatus, checkout.review_flags as ReviewFlag[] | undefined);

    // Handle blocking/unblocking
    if (input.decision === 'blocked' || input.block_future) {
      if (!this.agentBlocker) throw new Error('AccountabilityService agent blocker is not wired');
      await this.agentBlocker.blockAgent(
        operatorId,
        passport.agent_id,
        `Blocked by operator review: ${input.notes ?? 'No reason given'}`,
      );
    } else if (input.decision === 'approved') {
      // If approved, unblock the agent if it was blocked by this checkout
      const agent = await this.agentRepo.findById(passport.agent_id);
      if (agent?.passport_blocked) {
        await this.agentRepo.update(passport.agent_id, {
          passport_blocked: false,
          passport_blocked_reason: null,
          passport_blocked_at: null,
        });
      }
    }

    return {
      review_id: review.id,
      agent_id: passport.agent_id,
      decision: input.decision,
      passport_blocked: input.decision === 'blocked' || (input.block_future ?? false),
    };
  }

  // ─── Agent Unblock ──────────────────────────────────────────────────

  async unblockAgent(agentId: string, operatorId: string) {
    const agent = await this.agentRepo.findById(agentId);
    if (!agent) throw new NotFoundError('Agent', agentId);
    if (agent.operator_id !== operatorId) throw new NotFoundError('Agent', agentId);

    await this.agentRepo.update(agentId, {
      passport_blocked: false,
      passport_blocked_reason: null,
      passport_blocked_at: null,
    });

    return { unblocked: true, agent_id: agentId };
  }
}
