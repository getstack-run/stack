import { ids, resolveMissionRef } from '@stack/shared';
import { safeErrorSummary } from '@stack/shared';
import { SecurityEventRepository } from '../repositories/security-event-repo.js';
import { AgentRepository } from '../repositories/agent-repo.js';
import type { NotificationService } from './notification-service.js';
import type { ClaimRegistryService } from './claim-registry-service.js';
import { signDetectorSignalClaim } from './detector-signal-claim.js';
import type { PassportService } from './passport-service.js';

export type SignalType =
  // Real-time detectors (pipeline 1)
  | 'credential_outside_scope' // synchronous hard scope-rule deny (L1/L2)
  | 'scope_drift' // behavioral L3: cumulative drift-from-intent scoring
  | 'credential_after_checkout'
  | 'credential_burst'
  | 'delegation_without_intent'
  | 'delegation_downgrade'
  | 'checkpoint_silence'
  | 'checkpoint_self_report_divergence' // 1.20 composability bonus: agent self-report vs verified Intent emissions
  | 'simulation_divergence' // 2.3: paired intent_simulation prediction disagrees with intent_outcome result
  | 'undeclared_target' // Decision 2: review flag — a live proxy call reached a counterparty this passport never dealt with and the operator did not pre-declare. Was simulation-only before; now fires on the live path. Flag, never a block.
  | 'expired_no_checkout'
  | 'upstream_not_found' // informational: upstream returned 404, possible bad or hallucinated endpoint
  | 'prompt_injection' // pattern-scan of proxied request body for known injection markers
  | 'prompt_injection_output' // L6: output-side scan — leaked credential / system-prompt / compliance language in upstream response
  | 'behavior_drift' // L6: per-passport cross-call entropy/length z-score outlier (3σ) — catches agents acting on a successful earlier injection
  // Post-hoc review-engine detectors (pipeline 2, bridged into this table at checkout)
  | 'undeclared_service'
  | 'undeclared_delegation'
  | 'duration_exceeded'
  | 'no_checkpoints'
  | 'checkpoint_gap'
  | 'high_action_volume'
  | 'scope_escalation_pattern'
  | 'credential_unreported'
  | 'intent_deviation'
  | 'behavioral_anomaly'
  // passport-scoped genome drift. Distinct from
  // `behavior_drift` above (per-call L6 entropy outlier) and
  // `behavioral_anomaly` (checkout-time mission-vs-baseline). This
  // one fires post-persist on every behavioral_genome claim when
  // computeDiff vs prior_genome_ref breaches threshold.
  | 'genome_drift'
  // 2026-08-05 — NOT a detector, and deliberately absent from the DETECTORS
  // catalog in @stack/shared: adding it there would inflate the detector
  // count every marketing surface renders, and this signal detects nothing.
  // It is the PII scanner reporting its own uncertainty — text that passed a
  // country's check digit but scored under the redaction threshold, so was
  // forwarded intact. The operator's cue to scope redaction to their
  // countries and lower the threshold. Info severity, deduped hourly.
  | 'pii_below_threshold'
  // Skill access control
  | 'unauthorized_skill_access'
  // OAuth 2.1
  | 'oauth_refresh_reuse' // critical: a refresh token already replaced was presented again — token family revoked
  | 'oauth_invalid_pkce' // warning: PKCE verifier did not match the stored challenge at /oauth/token
  | 'oauth_unknown_client' // info: /authorize or /token referenced a client_id with no row
  | 'oauth_redirect_uri_mismatch' // warning: redirect_uri presented at /authorize doesn't match registered set
  // Connect with STACK (platform-abuse signal, oauth_* precedent:
  // not a behavioral detector, so NOT in the detector catalog)
  | 'partner_connect_burst' // warning: kept for events recorded before partner connect was removed; nothing raises it now
  // Platform-integrity alarm: an evidence-critical action was denied because
  // its passport claim set could not be bound into audit hash v2. This is not
  // a behavioral detector and is deliberately absent from the public catalog.
  | 'audit_claim_binding_failure'
  // posture warning raised at passport-issue time, not a behavioral
  // detector (nothing was observed and nothing was scored: it reports the
  // shape of the grant itself), so the oauth_* / partner_connect_burst
  // precedent applies and it is NOT in the detector catalog.
  | 'unconstrained_scope'; // warning: a passport was issued with a service scope carrying no constraints

export type Severity = 'info' | 'warning' | 'critical';

export interface RecordEventInput {
  operatorId: string;
  agentId: string;
  passportJti?: string;
  signalType: SignalType;
  severity: Severity;
  message: string;
  metadata?: Record<string, unknown>;
  // producer-migration hints. Both optional
  // defaults are safe for legacy call sites that don't supply them.
  pipeline?: 'heuristic' | 'llm' | 'detection-chain';
  intentClaimRef?: string;
  /**
   * mission attribution. Callers that hold
   * the passport JWT pass the passport's `mission_ids` claim here;
   * resolveMissionRef picks the single active one (or null when zero /
   * multiple). Worker-side callers that only have the passportJti pass
   * undefined and the detector_signal ends up unattributed — fine for
   * the legacy behavior; dashboard replay just won't filter those by
   * mission until a follow-up wires the worker-side lookup.
   */
  missionIds?: readonly string[];
  /**
   * dedup for REPEATED IDENTICAL signals. When set, a Redis
   * SETNX gate (`stack:sec_event_dedup:<operator>:<dedupKey>`, TTL
   * dedupWindowSeconds, default 3600) runs BEFORE anything else: the
   * first occurrence in the window records normally; repeats create no
   * claim, no row and no notification (a burst of identical warnings
   * once produced one e-mail per event). A repeat
   * raises `metadata.repeat_count` on the event the first occurrence made,
   * so the owner still sees how often it happened. A critical repeat is
   * counted too, and still goes through the agent's on_critical block.
   * Opt-in per call site. Redis outage fails OPEN (record rather than lose signal).
   */
  dedupKey?: string;
  dedupWindowSeconds?: number;
  /**
   * The signal is about content a third party sent to the agent (inbound
   * mail, SMS, a transcript), not about anything the agent did. A critical
   * signal is still recorded and notified, but the agent's on_critical
   * auto-block does not fire: otherwise anyone who knows the agent's address
   * could block it by sending it a known injection.
   */
  skipAgentAutoBlock?: boolean;
}

/**
 * Minimal Redis surface for the dedup gate and the dismissal window (matches ioredis). `get` is optional: a store
 * without it still suppresses repeats, it just cannot count them or honour a dismissal.
 */
export interface DedupStore {
  set(key: string, value: string, ex: 'EX', seconds: number, nx?: 'NX'): Promise<unknown>;
  get?(key: string): Promise<string | null>;
}

/** How long a dismissal also covers new events of the same signal type for the same agent. */
export const DISMISSAL_SUPPRESS_SECONDS = 24 * 60 * 60;

/** Severities a dismissal covers. A critical is never silenced by one. */
export const DISMISSIBLE_SEVERITIES = ['info', 'warning'] as const;

const dedupGateKey = (operatorId: string, dedupKey: string) => `stack:sec_event_dedup:${operatorId}:${dedupKey}`;
const dismissedKey = (operatorId: string, agentId: string, signalType: string) =>
  `stack:sec_event_dismissed:${operatorId}:${agentId}:${signalType}`;

export class SecurityEventService {
  private notification: NotificationService | null = null;
  private claimRegistry: ClaimRegistryService | null = null;
  private dedupStore: DedupStore | null = null;
  private agentBlocker: Pick<PassportService, 'blockAgent'> | null = null;

  constructor(
    private securityEventRepo: SecurityEventRepository,
    private agentRepo: AgentRepository,
  ) {}

  /**
   * Wire the Redis-backed dedup gate. Optional — without it
   * dedupKey inputs record every occurrence as before.
   */
  setDedupStore(store: DedupStore): void {
    this.dedupStore = store;
  }

  /**
   * Wire the notification dispatcher so detector fires can route to the
   * operator's configured delivery methods (email, SMS, webhook). Optional —
   * if not set, security events are still recorded and surfaced via API/MCP,
   * just without push notifications.
   */
  setNotificationService(notification: NotificationService): void {
    this.notification = notification;
  }

  /**
   * Wire the claim registry so every detector fire dual-writes a signed
   * detector_signal claim alongside the legacy security_events row.
   * producer migration. Optional — if not set
   * the legacy table populates as before with no claim emission.
   */
  setClaimRegistryService(claimRegistry: ClaimRegistryService): void {
    this.claimRegistry = claimRegistry;
  }

  setAgentBlocker(agentBlocker: Pick<PassportService, 'blockAgent'>): void {
    this.agentBlocker = agentBlocker;
  }

  async record(input: RecordEventInput) {
    // the dedup gate runs FIRST, ahead of claim emission, the
    // row insert, auto-block, and notification dispatch: a suppressed
    // repeat produces nothing at all. First-in-window records normally.
    // A dismissal of this agent's warnings also covers new ones of the same signal type for a day, so what the
    // owner just cleared does not come straight back. A critical is never covered.
    if (input.severity !== 'critical' && (await this.dismissedRecently(input))) return null;

    if (input.dedupKey && this.dedupStore) {
      try {
        const first = await this.dedupStore.set(
          dedupGateKey(input.operatorId, input.dedupKey),
          '1',
          'EX',
          input.dedupWindowSeconds ?? 3600,
          'NX',
        );
        if (!first) {
          // repeat within the window — suppressed, but counted on the event the first one made
          await this.countRepeat(input);
          return null;
        }
      } catch {
        // Redis down: fail OPEN — record rather than lose the signal.
      }
    }

    // claim-first ordering. The signed
    // detector_signal claim becomes the source of truth; the legacy
    // security_events row is a denormalised projection populated with
    // claim_id at INSERT time (no separate linkClaim UPDATE). When
    // claim emission fails, fall back to legacy-only with claim_id =
    // null — preserves availability during the transition window.
    //
    // originally wired this as legacy-first
    // dual-write with post-hoc linkClaim. Inversion happens here so
    // the four producers (this, accountability, invocation
    // identity) all share the claim-first shape — consistent mental
    // model + one ordering for future readers.
    // A security signal must still be recorded when attribution is ambiguous.
    // This is evidence only. Admission producers use the strict resolver.
    const evidenceMissionIds = [...new Set(input.missionIds ?? [])];
    const missionRef = evidenceMissionIds.length === 1 ? resolveMissionRef(evidenceMissionIds) : null;
    const claimId = input.passportJti
      ? await signDetectorSignalClaim(this.claimRegistry, {
          operatorId: input.operatorId,
          passportJti: input.passportJti,
          agentId: input.agentId,
          signalType: input.signalType,
          severity: input.severity,
          pipeline: input.pipeline,
          intentClaimRef: input.intentClaimRef,
          metadata: input.metadata,
          // Stamp only unambiguous evidence attribution.
          missionRef,
        })
      : null;

    // eval-traffic quiet routing, applied at THIS choke point so
    // every producer (DetectorService, scan.ts inline, skills, proxy)
    // inherits it. Detection stays fully ON and the row still lands —
    // but on an eval_traffic agent, severity ≤ warning inserts
    // pre-resolved and skips notification dispatch. Criticals stay
    // completely live (an eval agent's real incident still surfaces).
    // Agent lookup failure fails OPEN to normal loud recording.
    let evalAgent: Awaited<ReturnType<typeof this.agentRepo.findById>> | null = null;
    try {
      evalAgent = await this.agentRepo.findById(input.agentId);
    } catch (err) {
      console.error('[SECURITY_EVENT] agent lookup failed - recording un-quieted:', safeErrorSummary(err));
    }
    const autoResolveEval = evalAgent?.eval_traffic === true && input.severity !== 'critical';

    const event = await this.securityEventRepo.create({
      id: ids.securityEvent(),
      operator_id: input.operatorId,
      agent_id: input.agentId,
      passport_jti: input.passportJti ?? null,
      mission_id: missionRef,
      signal_type: input.signalType,
      severity: input.severity,
      message: input.message,
      metadata: input.metadata ?? null,
      claim_id: claimId,
      ...(autoResolveEval
        ? { resolved: true, resolved_by: 'auto:eval_traffic', resolved_at: new Date() }
        : {}),
    });

    // Remember which event this window's repeats are counted on.
    if (input.dedupKey && this.dedupStore) {
      await this.dedupStore
        .set(dedupGateKey(input.operatorId, input.dedupKey), event.id, 'EX', input.dedupWindowSeconds ?? 3600)
        .catch(() => undefined);
    }

    await this.autoBlockIfConfigured(input, evalAgent);

    // Fire-and-forget notification dispatch. Event type is per-signal —
    // 'security.${signal_type}' — so operators can subscribe at the
    // per-detector grain in the dashboard (Account → Notifications → Add
    // rule). Both the event subscription list and min_severity gate apply:
    // a channel receives the notification only if it is subscribed to
    // this specific signal's event_type AND the severity passes the
    // channel's min_severity floor.
    if (this.notification && !autoResolveEval) {
      this.notification
        .publishEvent({
          operatorId: input.operatorId,
          eventType: `security.${input.signalType}`,
          severity: input.severity,
          payload: {
            event_id: event.id,
            signal_type: input.signalType,
            agent_id: input.agentId,
            passport_jti: input.passportJti ?? undefined,
            occurred_at: event.created_at.toISOString(),
            message: input.message,
          },
        })
        .catch((err) => {
          // Notification failures must never break detector flow.
          console.error('[SECURITY_EVENT] Notification dispatch failed:', safeErrorSummary(err));
        });
    }

    return event;
  }

  /** Auto-block on a critical signal when the agent is configured for it. */
  private async autoBlockIfConfigured(
    input: RecordEventInput,
    known?: Awaited<ReturnType<AgentRepository['findById']>> | null,
  ): Promise<void> {
    if (input.severity !== 'critical' || input.skipAgentAutoBlock === true) return;
    const agent = known ?? (await this.agentRepo.findById(input.agentId));
    if (agent && agent.on_critical === 'block') {
      if (!this.agentBlocker) {
        throw new Error('SecurityEventService agent blocker is not wired');
      }
      await this.agentBlocker.blockAgent(
        input.operatorId,
        input.agentId,
        `Auto-blocked: ${input.signalType} — ${input.message}`,
      );
    }
  }

  /** A repeat of a deduplicated signal: raise the count on the event the window's first occurrence made. */
  private async countRepeat(input: RecordEventInput): Promise<void> {
    if (!input.dedupKey || !this.dedupStore?.get) return;
    try {
      const eventId = await this.dedupStore.get(dedupGateKey(input.operatorId, input.dedupKey));
      if (eventId && eventId !== '1') await this.securityEventRepo.addRepeat(eventId, input.operatorId);
    } catch (err) {
      console.error('[SECURITY_EVENT] counting a repeat failed:', safeErrorSummary(err));
    }
    // A repeated critical is still a critical: the agent's own block setting applies to it as it did to the first.
    await this.autoBlockIfConfigured(input);
  }

  private async dismissedRecently(input: RecordEventInput): Promise<boolean> {
    if (!this.dedupStore?.get) return false;
    try {
      return (await this.dedupStore.get(dismissedKey(input.operatorId, input.agentId, input.signalType))) !== null;
    } catch {
      return false; // Redis down: fail open, record the signal
    }
  }

  /**
   * The owner dismissed an agent's open warnings: new events of the same signal types for that agent are not
   * recorded for the next day (a critical is never covered).
   */
  async suppressRepeats(
    operatorId: string,
    agentId: string,
    signalTypes: readonly string[],
    seconds: number = DISMISSAL_SUPPRESS_SECONDS,
  ): Promise<void> {
    if (!this.dedupStore) return;
    await Promise.all(
      [...new Set(signalTypes)].map((signalType) =>
        this.dedupStore!.set(dismissedKey(operatorId, agentId, signalType), '1', 'EX', seconds).catch(() => undefined),
      ),
    );
  }

  /**
   * Resolve every open warning and info event of one agent in one statement, and keep new ones of the same signal
   * types from coming back for a day. Criticals are left open. Returns what was resolved.
   */
  async dismissOpenForAgent(operatorId: string, agentId: string, resolvedBy: string) {
    const resolved = await this.securityEventRepo.resolveOpenForAgent(operatorId, agentId, resolvedBy, DISMISSIBLE_SEVERITIES);
    await this.suppressRepeats(operatorId, agentId, resolved.map((row) => row.signal_type));
    return resolved;
  }

  async getForPassport(jti: string) {
    return this.securityEventRepo.findByPassport(jti);
  }

  async getUnresolved(
    operatorId: string,
    opts?: { agentId?: string; page?: number; limit?: number; excludeSynthetic?: boolean },
  ) {
    const limit = opts?.limit ?? 50;
    const page = opts?.page ?? 1;
    const offset = (page - 1) * limit;
    return this.securityEventRepo.findByOperator(operatorId, {
      resolved: false,
      agentId: opts?.agentId,
      limit,
      offset,
      excludeSynthetic: opts?.excludeSynthetic,
    });
  }

  async getById(id: string) {
    return this.securityEventRepo.findById(id);
  }

  async resolveEvent(id: string, operatorId: string) {
    const event = await this.securityEventRepo.findById(id);
    if (!event || event.operator_id !== operatorId) return null;
    return this.securityEventRepo.resolve(id, operatorId);
  }

  async countUnresolved(operatorId: string, opts?: { excludeSynthetic?: boolean }) {
    return this.securityEventRepo.countUnresolved(operatorId, opts);
  }

  async existsForPassport(jti: string, signalType: string) {
    return this.securityEventRepo.existsForPassport(jti, signalType);
  }

  async existsForOperator(operatorId: string, signalType: string) {
    return this.securityEventRepo.existsUnresolvedForOperator(operatorId, signalType);
  }
}
