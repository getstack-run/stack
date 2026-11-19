// IntentSimulationService.
//
// Pre-execution dry-run producer. Runs the proxy's policy chain
// statically against a candidate IntentClaim + passport, returns a
// deterministic verdict, and emits a signed `intent_simulation` claim
// attached to the passport.
//
// **Why JWT-in-hand and not JTI lookup.** The passports DB row stores
// only `intent_services` (text[]). The full `services: ServiceScope[]`
// array — with per-service `constraints` and `service_name` — lives
// only in the signed JWT. Therefore the simulator must take the token
// as input. The proxy.ts hot path takes it the same way (X-Passport-
// Token header), so we mirror.
//
// **What's deferred.** Two of the six denial reasons in the schema
// enum are not checked in v1:
//   - `detector_block`  — needs DetectorService.scanInput to support a
//     dryRun flag (today it unconditionally records security_events).
//     Lands with (`undeclared_target` detector +
//     DetectorService refactor amortised).
//   - `requires_unmet`  — no runtime enforcement of `Intent.requires[]`
//     exists anywhere yet. Build it for actual execution first, mirror
//     in the simulator later. Backlog P2.
//
// `tier_limit` IS covered in v1. Caller supplies a `peekOverage`
// function (mirrors `enforceOverage` semantics — cap + wallet headroom)
// and a `resolveOperatorTier` function. Both are optional deps so the
// service still works in dashboard-only / unit-test contexts where
// metering isn't wired; when either is absent, tier_limit is silently
// skipped.
// `predicted_detector_fires` is `[]` in v1 (schema's `.default([])` accepts).
// `projected_http` is omitted in v1 (cannot honestly project upstream
// status without calling).

import {
  extractEntities,
  observedKnowsEntity,
  ForbiddenError,
  findFailingConstraint,
  normalizeRequest,
  subjectForPassport,
  isServiceInScope,
  type IntentClaim,
  type IntentSimulationClaim,
  type NormalizedRequest,
  type OperatorTier,
  type ProxyRequestInput,
  type ServiceScope,
} from '@stack/shared';
import type { ClaimRegistryService } from './claim-registry-service.js';
import type { PassportService } from './passport-service.js';
import { enforceRequires } from './requires-enforcer.js';

/**
 * The meters the simulator can predict tier_limit denial for. Other
 * intent_types (mcp_tool, onchain_tx, task_complete) don't meter today;
 * if metering lands for them, extend `INTENT_TYPE_TO_METER` below.
 */
// One meter. Proxy calls and free-skill invocations were separate
// allowances; both are metered actions now, so a simulated denial can
// only ever be against the single actions pool.
export type SimulableMeter = 'action';

/** Snapshot of the overage state for one (operator, meter) pair. */
export interface OveragePeekSnapshot {
  used: number;
  cap: number;
  walletBalanceCents: number;
  overagePriceCents: number;
  /** True iff `enforceOverage` would throw 402 for the next unit. */
  wouldDeny: boolean;
}

export interface IntentSimulationDeps {
  passportService: PassportService;
  claimRegistry: ClaimRegistryService;
  /**
   * Resolve operator → tier. Required for tier_limit checks. Omit in
   * unit tests that don't exercise tier_limit. Same shape as the
   * resolver `ClaimRegistryService` already takes.
   */
  resolveOperatorTier?: (operatorId: string) => Promise<OperatorTier>;
  /**
   * Read-only overage peek (no counter mutation, no wallet debit).
   * Production wiring uses `peekOverage` from
   * the action meter (`apps/api/src/middleware/meter.ts`); unit tests can stub. Omit
   * to disable tier_limit entirely.
   */
  peekOverage?: (
    operatorId: string,
    tier: OperatorTier,
    meter: SimulableMeter,
  ) => Promise<OveragePeekSnapshot>;
  /**
   * optional DetectorService dep. When wired, the
   * simulator runs the prompt-injection scanner in dryRun mode
   * (no security_event side effects) and projects the result onto
   * `predicted_detector_fires`. A `critical` verdict also adds
   * `detector_block` to denialReasons. Omit to skip the check
   * entirely (predicted_detector_fires stays empty as in v1).
   */
  detector?: {
    scanInput: (args: {
      ctx: { operatorId: string; agentId: string; passportJti?: string; mode?: string; tier: string };
      body: unknown;
      fieldPath?: string;
      dryRun?: boolean;
    }) => Promise<{ verdict: 'clean' | 'warning' | 'critical' }>;
  };
  /**
   * optional repo dep for the `undeclared_target`
   * detector. The simulator queries the passport's prior
   * `entity_observation` claims and compares the union of observed
   * entities against entities extracted from the candidate Intent.
   *
   * extended with `findActiveOutcomesByClaimIdsAndSessionId`
   * for the `requires_unmet` section 2g check. Same dep object so a
   * single repo wire-up covers both sections. Both methods are
   * required when the repo is present.
   */
  passportClaimsRepo?: {
    findActiveByPassportId: (passportJti: string) => Promise<Array<{
      type: string;
      body_json: unknown;
    }>>;
    findActiveOutcomesByClaimIdsAndSessionId: (
      claimIds: string[],
      sessionId: string,
    ) => Promise<Array<{ claim_id: string; type: string; body_json: unknown }>>;
  };
  /**
   * #6 — optional mission lookup so the simulator can seed the bound
   * mission's `expected_counterparties` into the observed-entity set. This is
   * what makes pre-declaring a counterparty actually suppress the first-touch
   * `undeclared_target` flag (previously the field was inert). Shape matches
   * `MissionService.findById`. Omit to skip (pre-declaration then has no effect,
   * the pre-fix behavior) — graceful, same pattern as the other optional deps.
   */
  missionLookup?: {
    findById: (missionId: string) => Promise<{ expected_counterparties: string[] } | null>;
  };
}

/** intent_type → overage meter. Intents not in this map skip the tier_limit check. */
const INTENT_TYPE_TO_METER: Partial<Record<IntentClaim['intent_type'], SimulableMeter>> = {
  http_call: 'action',
  skill_invocation: 'action',
};

export interface SimulateInput {
  /**
   * Passport JWT to simulate against. Verified by `PassportService.verify`
   * — signature + revocation + freshness checks all run. Callers are
   * responsible for providing a fresh token; simulation on a revoked or
   * expired passport throws (`PassportRevokedError` / `PassportExpiredError`)
   * before any check runs.
   */
  passportToken: string;
  /**
   * Candidate IntentClaim. May or may not already be registered as a
   * claim — both shapes are accepted. When already registered, pass
   * `intentClaimRef` so the resulting simulation claim links to it.
   */
  intent: IntentClaim;
  /**
   * Pre-registered Intent claim id (claim_*). Optional. Sets the
   * resulting simulation claim's `intent_claim_ref` field.
   */
  intentClaimRef?: string;
  /**
   * Skip the claim registration when false. Default true. Dashboard
   * "what-if" callers pass false to inspect the result without
   * polluting the registry; pre-execution hot-path callers pass true.
   */
  persist?: boolean;
}

/**
 * #5 — does this `target` value look like a URL rather than a service
 * slug? A slug is a bare token ('stripe'); a URL has a scheme+host. We treat
 * anything with an http(s):// scheme, or a bare host with a dot + slash/colon,
 * as URL-shaped. Deliberately conservative: a false negative just means no
 * extra hint (the scope_mismatch still fires), never a wrong allow/deny.
 */
export function targetLooksLikeUrl(target: string): boolean {
  const t = target.trim();
  if (/^https?:\/\//i.test(t)) return true;
  // bare host forms like "api.stripe.com/v1" or "api.stripe.com:443"
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/:?]|$)/i.test(t) && (t.includes('/') || t.includes(':') || t.includes('.'))) {
    // require a dot to avoid flagging plain slugs; but a plain slug has no dot,
    // so a value with a dot + a TLD-looking suffix is URL-shaped.
    return /\.[a-z]{2,}(\b|[/:?])/i.test(t);
  }
  return false;
}

export interface SimulateDiagnostics {
  /**
   * entities the simulator extracted from the
   * candidate Intent that aren't in the passport's observed-entity-set.
   * Surfaced when the `undeclared_target` detector fires (flag-not-block).
   */
  undeclaredEntities?: Array<{ entity: string; entity_type: string }>;
  failedConstraint?: { path: string; op: string };
  scopeMissingService?: string;
  /**
   * Set when the Passport holds several scopes of the intent's service and the intent names none of them (its
   * `parameters.connection` is a connection id): the constraints to judge it by are not known, so it is refused
   * rather than judged against whichever scope comes first.
   */
  connectionAmbiguousService?: string;
  /**
   * #5 — set true when a scope_mismatch's `target` looks like a URL
   * rather than a service slug. The scope check string-equals `target` against
   * granted provider slugs, so a URL in `target` always misses. This flag lets
   * the UI/agent surface "you put a URL where a slug goes — move it to
   * parameters.url" instead of the misleading "this service isn't in scope".
   */
  targetLooksLikeUrl?: boolean;
  accountabilityPassport?: 'enforced' | 'logged' | 'standard';
  accountabilityIntent?: 'enforced' | 'logged' | 'standard';
  /**
   * Set when tier_limit denied. `meter` is the gating dimension,
   * `cap` the monthly allowance, `used` the current counter, and
   * `walletBalanceCents` / `overagePriceCents` let the UI render the
   * overage shortfall ("you need $0.001 in wallet to cover one more
   * proxy call").
   */
  tierLimit?: {
    meter: SimulableMeter;
    cap: number;
    used: number;
    walletBalanceCents: number;
    overagePriceCents: number;
  };
  /**
   * pc_* outcome ids from intent.requires that were
   * NOT satisfied on this delegation chain. Surfaced when the
   * `requires_unmet` denial fires (section 2g). Each entry is either
   * (a) absent from passport_claims, (b) revoked, (c) on a different
   * session_id, or (d) has body_json.status !== 'succeeded'.
   */
  failingRequires?: string[];
}

export interface SimulateResult {
  allowed: boolean;
  denialReasons: IntentSimulationClaim['denial_reasons'];
  simulatedCost: IntentSimulationClaim['simulated_cost'];
  /** Always [] in v1 — detector simulation lands with. */
  predictedDetectorFires: IntentSimulationClaim['predicted_detector_fires'];
  simulatedAt: number;
  /** Present iff persist !== false. Subject is the passport URI per `subjectForPassport`. */
  claimId?: string;
  /**
   * Diagnostic surface — NOT signed into the claim. Lets the REST/MCP
   * caller render *why* a denial happened in the UI without re-deriving.
   */
  diagnostics: SimulateDiagnostics;
}

type AccountabilityMode = 'enforced' | 'logged' | 'standard';

const ACCOUNTABILITY_RANK: Record<AccountabilityMode, number> = {
  enforced: 3,
  logged: 2,
  standard: 1,
};

export class IntentSimulationService {
  constructor(private deps: IntentSimulationDeps) {}

  async simulate(input: SimulateInput): Promise<SimulateResult> {
    if (input.intent.policy_decision) throw new ForbiddenError();
    // 1. Verify the passport token. Throws on signature / revocation / freshness fail.
    const claims = await this.deps.passportService.verify(input.passportToken);
    const operatorId = claims.stk.operator_id;
    const passportJti = claims.jti;

    // 2. Run checks in order, accumulating reasons. D7: do NOT short-
    //    circuit — operators want the full picture in the "what-if" UI.
    const denialReasons: IntentSimulationClaim['denial_reasons'] = [];
    const diagnostics: SimulateDiagnostics = {};

    // 2a. scope_mismatch — mirror the real gate (grant is the sole
    //     authority, intent may only narrow). Same isServiceInScope helper
    //     the proxy/llm/credentials routes use, so the what-if prediction
    //     matches actual enforcement.
    const intentServices = (claims.stk.intent_services ?? []) as string[];
    const servicesArr = (claims.stk.services ?? []) as ServiceScope[];
    const grantedProviders = servicesArr.map((s) => s.service_name);
    const inScope = isServiceInScope(input.intent.target, grantedProviders, intentServices);
    if (!inScope) {
      denialReasons.push('scope_mismatch');
      diagnostics.scopeMissingService = input.intent.target;
      // #5 — a URL in `target` (common mistake) always misses the
      // slug-equality check. Flag it so the caller gets an actionable hint
      // instead of "this service isn't in scope".
      if (targetLooksLikeUrl(input.intent.target)) {
        diagnostics.targetLooksLikeUrl = true;
      }
    }

    // 2b. constraint_violation — mirror proxy.ts:115-178. Only for
    //     http_call intents that ship url + method in parameters. Run
    //     even when scope failed (D7 accumulate).
    if (input.intent.intent_type === 'http_call') {
      const scopesOfService = servicesArr.filter((s) => s.service_name === input.intent.target);
      const named = (input.intent.parameters as Record<string, unknown>)['connection'];
      let scopeEntry: ServiceScope | undefined;
      if (typeof named === 'string' && named.length > 0) {
        scopeEntry = scopesOfService.find((s) => s.connection_id === named);
        if (!scopeEntry && scopesOfService.length > 0) denialReasons.push('constraint_violation');
      } else if (scopesOfService.length > 1) {
        denialReasons.push('constraint_violation');
        diagnostics.connectionAmbiguousService = input.intent.target;
      } else {
        scopeEntry = scopesOfService[0];
      }
      if (scopeEntry?.constraints && scopeEntry.constraints.length > 0) {
        const normalized = this.buildNormalizedFromIntent(input.intent);
        if (normalized === null) {
          // http_call intent missing url/method — deny by default,
          // same posture as constraints.ts evaluator for unresolved paths.
          denialReasons.push('constraint_violation');
        } else {
          const failed = findFailingConstraint(scopeEntry.constraints, normalized);
          if (failed) {
            denialReasons.push('constraint_violation');
            diagnostics.failedConstraint = { path: failed.path, op: failed.op };
          }
        }
      }
    }

    // 2c. accountability_monotonicity — Intent.accountability cannot be
    //     weaker than the passport's session-level accountability.
    //     Strength: enforced > logged > standard.
    const passportMode = (claims.stk.accountability ?? 'standard') as AccountabilityMode;
    const intentMode = input.intent.accountability ?? 'standard';
    if (ACCOUNTABILITY_RANK[intentMode] < ACCOUNTABILITY_RANK[passportMode]) {
      denialReasons.push('accountability_monotonicity');
      diagnostics.accountabilityPassport = passportMode;
      diagnostics.accountabilityIntent = intentMode;
    }

    // 2d. tier_limit — would the runtime enforce-overage 402 on this
    //     intent's metered dimension? Requires both deps wired
    //     (graceful skip otherwise so unit tests don't have to mock).
    const meter = INTENT_TYPE_TO_METER[input.intent.intent_type];
    if (meter && this.deps.peekOverage && this.deps.resolveOperatorTier) {
      const tier = await this.deps.resolveOperatorTier(operatorId);
      const peek = await this.deps.peekOverage(operatorId, tier, meter);
      if (peek.wouldDeny) {
        denialReasons.push('tier_limit');
        diagnostics.tierLimit = {
          meter,
          cap: peek.cap,
          used: peek.used,
          walletBalanceCents: peek.walletBalanceCents,
          overagePriceCents: peek.overagePriceCents,
        };
      }
    }

    // 2e. detector_block — runs the prompt-injection scanner in dryRun
    //     mode (no security_event side effects). Only for http_call
    //     intents that carry a body in parameters. Graceful skip when
    //     the detector dep isn't wired (unit tests / minimal bootstrap).
    const predictedDetectorFires: IntentSimulationClaim['predicted_detector_fires'] = [];
    if (input.intent.intent_type === 'http_call' && this.deps.detector) {
      const params = input.intent.parameters as Record<string, unknown>;
      const scanBody = params['body'] ?? params;
      // The dry run still runs L3, so it still needs the plan that decides
      // whether L3 may run. Without the resolver wired the simulation falls
      // back to the base plan (L1+L2 only), which under-predicts what the real
      // call would catch. That is the honest direction for a PREDICTION: it
      // never promises a block the runtime would not make.
      const scanTier = this.deps.resolveOperatorTier
        ? await this.deps.resolveOperatorTier(operatorId).catch(() => 'free')
        : 'free';
      const scan = await this.deps.detector.scanInput({
        ctx: {
          operatorId,
          agentId: claims.stk.agent_id as string,
          passportJti,
          mode: passportMode,
          tier: scanTier,
        },
        body: scanBody,
        dryRun: true,
      });
      if (scan.verdict === 'critical') {
        denialReasons.push('detector_block');
        predictedDetectorFires.push({ detector_key: 'prompt_injection', severity: 'critical' });
      } else if (scan.verdict === 'warning') {
        predictedDetectorFires.push({ detector_key: 'prompt_injection', severity: 'medium' });
      }
    }

    // 2f. undeclared_target — flag (not denial) when the candidate
    //     Intent references entities absent from the passport's
    //     observed-entity-set from prior intent_outcomes. Skips
    //     gracefully when the claims repo isn't wired.
    if (this.deps.passportClaimsRepo) {
      const observations = await this.deps.passportClaimsRepo.findActiveByPassportId(passportJti);
      const observed = new Set<string>();
      for (const obs of observations) {
        if (obs.type !== 'entity_observation') continue;
        const body = obs.body_json as { entities?: unknown };
        const ents = Array.isArray(body.entities) ? body.entities : [];
        for (const e of ents) {
          if (typeof e === 'string') observed.add(e.toLowerCase());
        }
      }
      // #6 — seed the bound mission's pre-declared counterparties into
      // the observed set, so an operator who declares a counterparty up front
      // is NOT tripped by the first-touch undeclared_target flag. Best-effort:
      // needs the candidate intent's mission_ref + the missionLookup dep wired;
      // skips silently otherwise (pre-fix behavior).
      if (input.intent.mission_ref && this.deps.missionLookup) {
        try {
          const mission = await this.deps.missionLookup.findById(input.intent.mission_ref);
          for (const cp of mission?.expected_counterparties ?? []) {
            if (typeof cp === 'string') observed.add(cp.toLowerCase());
          }
        } catch {
          // mission unresolved / cross-tenant — treat as no pre-declaration.
        }
      }
      const candidates = extractEntities({
        target: input.intent.target,
        parameters: input.intent.parameters,
      });
      // An observation is kept as a one-way digest (or, if recorded before
      // that, as text): either form counts as dealt with.
      const undeclared = candidates.filter((c) => !observedKnowsEntity(observed, c.entity));
      if (undeclared.length > 0) {
        predictedDetectorFires.push({ detector_key: 'undeclared_target', severity: 'medium' });
        diagnostics.undeclaredEntities = undeclared.map((u) => ({
          entity: u.entity,
          entity_type: u.entity_type,
        }));
      }
    }

    // 2g. requires_unmet — runtime enforcement that each pc_* id in
    //     `intent.requires[]` resolves to an active intent_outcome with
    //     status='succeeded' on the SAME session_id (delegation chain).
    //     Mirrors the producer-side gate (ApprovalGateService.check)
    //     via the shared `enforceRequires` helper. Simulator and gate
    //     cannot drift — a passing simulation guarantees a passing
    //     runtime gate (for the same passport at the same instant).
    //
    //     Skips gracefully when the claims repo isn't wired (consistent
    //     with 2f). An IntentClaim with empty `requires` short-circuits
    //     inside the helper (no SQL).
    if (this.deps.passportClaimsRepo) {
      const sessionId = (claims.stk.session_id ?? '') as string;
      // Defensive: if session_id is somehow absent we skip rather than
      // pass an empty-string predicate that would match every row with
      // a NULL/empty session_id (the column is NOT NULL today, so this
      // is belt-and-braces).
      if (sessionId) {
        const reqResult = await enforceRequires(
          { passportClaimsRepo: this.deps.passportClaimsRepo },
          { sessionId, requires: input.intent.requires ?? [] },
        );
        if (!reqResult.allowed) {
          denialReasons.push('requires_unmet');
          diagnostics.failingRequires = reqResult.failingRequires;
        }
      }
    }

    // 3. Compose payload. 5.0.4 — simulation inherits the candidate
    // intent's mission_ref so the simulation claim filters by mission
    // the same way the eventual intent_outcome will.
    const allowed = denialReasons.length === 0;
    const simulatedAt = Date.now();
    const payload: IntentSimulationClaim = {
      type: 'intent_simulation',
      ...(input.intentClaimRef !== undefined ? { intent_claim_ref: input.intentClaimRef } : {}),
      allowed,
      denial_reasons: denialReasons,
      simulated_cost: input.intent.estimated_cost,
      predicted_detector_fires: predictedDetectorFires,
      simulated_at: simulatedAt,
      ...(input.intent.mission_ref ? { mission_ref: input.intent.mission_ref } : {}),
    };

    // 4. Persist via ClaimRegistryService.registerClaim (or skip).
    let claimId: string | undefined;
    if (input.persist !== false) {
      const result = await this.deps.claimRegistry.registerClaim({
        operatorId,
        passportJti,
        claimType: 'intent_simulation',
        payload,
      });
      claimId = result.claimId;
    }

    // Subject helper is imported so callers can correlate the claim
    // back to a passport URI without re-deriving the format. Not
    // returned today (the claim_id is enough) but used in tests for
    // the envelope round-trip assertion.
    void subjectForPassport;

    return {
      allowed,
      denialReasons,
      simulatedCost: payload.simulated_cost,
      predictedDetectorFires,
      simulatedAt,
      ...(claimId !== undefined ? { claimId } : {}),
      diagnostics,
    };
  }

  /**
   * Construct a NormalizedRequest from an IntentClaim's parameters.
   * Returns null when the intent claims to be http_call but parameters
   * lack `url` or `method` — caller treats that as a constraint denial
   * (deny-by-default).
   *
   * Reuses `normalizeRequest()` from `@stack/shared` so URL parsing
   * + lowercasing + trailing-slash stripping all match the runtime
   * proxy evaluator byte-for-byte.
   */
  private buildNormalizedFromIntent(intent: IntentClaim): NormalizedRequest | null {
    const params = intent.parameters as Record<string, unknown>;
    const url = typeof params['url'] === 'string' ? (params['url'] as string) : null;
    const method = typeof params['method'] === 'string' ? (params['method'] as string) : null;
    if (!url || !method) return null;

    const normalizedMethod = method.toUpperCase();
    const allowedMethods: ProxyRequestInput['method'][] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
    if (!allowedMethods.includes(normalizedMethod as ProxyRequestInput['method'])) {
      return null;
    }

    try {
      return normalizeRequest({
        service: intent.target,
        url,
        method: normalizedMethod as ProxyRequestInput['method'],
        body: params['body'],
        query: (params['query'] as Record<string, string> | undefined) ?? undefined,
        headers: (params['headers'] as Record<string, string> | undefined) ?? undefined,
      });
    } catch {
      // Malformed url — same deny-by-default posture as missing fields.
      return null;
    }
  }
}
