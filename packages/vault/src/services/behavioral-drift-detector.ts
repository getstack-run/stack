// behavioral drift detector (wire-key: `genome_drift`).
//
// Post-persist hook for `behavioral_genome` claims. When a genome lands,
// this detector reads the prior genome via the chain pointer
// (`prior_genome_ref` on the current payload), runs
// BehavioralGenomeService.computeDiff(currentClaimId, priorClaimId), and
// on threshold breach emits a `genome_drift` security event + paired
// `detector_signal` claim via SecurityEventService.record
// inverted write ordering: claim emitted first, legacy row second with
// claim_id linked).
//
// Wire-key naming: the SignalType emitted is `genome_drift` (NOT
// `behavior_drift` — that key is taken by the L6 per-call entropy
// detector; NOT `behavioral_anomaly` — that key is taken by the
// checkout-time mission baseline detector). The class name + file
// name keep "behavioral drift" as descriptive; only the wire-key is
// `genome_drift` to avoid collision.
//
// Distinct from `behavioral_anomaly` (the checkout-time detector at
// accountability-service.ts:494-544 which compares a single checkout's
// metrics against the agent's rolling 20-checkout baseline). Same
// conceptual family — both surface unusual behavior — but different
// firing path, different inputs, different metadata shape. Keeping the
// detector keys distinct prevents dashboard-filter collisions.
//
// Thresholds (hardcoded constants below):
//   - Z_MAX_THRESHOLD = 3.0: any single dimension at 3σ from prior fires
//   - L2_NORM_THRESHOLD = 5.0: composite drift across scalar dims fires
//   - MIN_PRIOR_CALL_COUNT = 5: skip on small-sample baselines (noisy
//     stddev produces spurious z-scores; matches cross-call-drift
//     COLD_START_N precedent)
//   - FIRE_ONCE_TTL_SECONDS = 86_400: 24h alert-fatigue guard per
//     passport. Without this, an agent that legitimately shifts baseline
//     would page the operator on every subsequent genome (cron daily +
//     checkpoint every 5 min on enforced agents = 200+ fires/day worst
//     case). With it, one fire per passport per day; operator still
//     sees all historical signals via the /v1/security-events export.
//
// v1.1 threshold-override path: OperatorDetectorConfigService can grow
// an additive `threshold_overrides: Record<string, number>` field if
// customer feedback shows demand for per-operator tuning. Not built in
// v1 — no production data yet to calibrate against.
//
// Detector metadata shape (locked here for 5.1.6 smoke + UI):
//   - current_genome_id: claim_id of the just-emitted genome
//   - prior_genome_id:   claim_id of the genome being compared against
//   - max_z:             max absolute z-score across scalar dimensions
//   - l2_norm:           L2 norm of scalar z-scores
//   - per_dimension:     full per-dimension breakdown from computeDiff
//   - breached_dimensions: array of dim names that crossed Z_MAX_THRESHOLD
//   - z_threshold:       the configured Z_MAX_THRESHOLD (for caller context)
//   - l2_threshold:      the configured L2_NORM_THRESHOLD
//
// Cold-start (prior_genome_ref === null): silent skip. Matches
// cross-call-drift precedent — first observation establishes baseline,
// doesn't fire.

import type { Redis } from 'ioredis';
import type { BehavioralGenomeClaim } from '@stack/shared';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { PassportRepository } from '../repositories/passport-repo.js';
import type { SecurityEventService } from './security-event-service.js';
import type { BehavioralGenomeService } from './behavioral-genome-service.js';
import type { BehavioralDriftHook } from './claim-registry-service.js';

export const BEHAVIORAL_DRIFT_Z_MAX_THRESHOLD = 3.0;
export const BEHAVIORAL_DRIFT_L2_NORM_THRESHOLD = 5.0;
export const BEHAVIORAL_DRIFT_MIN_PRIOR_CALL_COUNT = 5;
export const BEHAVIORAL_DRIFT_FIRE_ONCE_TTL_SECONDS = 86_400;

export interface BehavioralDriftDetectorDeps {
  passportClaimsRepo: PassportClaimsRepository;
  passportRepo: PassportRepository;
  securityEvent: SecurityEventService;
  behavioralGenome: BehavioralGenomeService;
  redis: Redis;
}

export class BehavioralDriftDetector implements BehavioralDriftHook {
  constructor(private readonly deps: BehavioralDriftDetectorDeps) {}

  async check(args: {
    operatorId: string;
    passportJti: string;
    claimId: string;
  }): Promise<void> {
    // 1. Load the just-persisted genome claim.
    const currentRow = await this.deps.passportClaimsRepo.findByClaimId(args.claimId);
    if (!currentRow || currentRow.type !== 'behavioral_genome') return;

    const currentBody = currentRow.body_json as BehavioralGenomeClaim;
    const priorRef = currentBody.prior_genome_ref;

    // 2. Cold-start: no prior → skip silently. First observation just
    //    establishes a baseline for the next genome to diff against.
    if (!priorRef) return;

    // 3. Load prior claim. Missing prior (e.g. pruned by retention,
    //    revoked) → skip silently. The next genome will pick up a new
    //    prior_genome_ref (the just-emitted one) and resume normal flow.
    const priorRow = await this.deps.passportClaimsRepo.findByClaimId(priorRef);
    if (!priorRow) return;
    const priorBody = priorRow.body_json as BehavioralGenomeClaim;

    // 4. Small-sample guard: prior had < MIN_PRIOR_CALL_COUNT calls →
    //    stddev estimates are noisy → z-scores spurious. Skip until the
    //    baseline stabilises. Matches cross-call-drift COLD_START_N = 5.
    if (priorBody.call_count < BEHAVIORAL_DRIFT_MIN_PRIOR_CALL_COUNT) return;

    // 5. Fire-once guard: if we already paged the operator within the
    //    24h window on this passport, skip. Prevents alert fatigue when
    //    an agent legitimately shifts baseline and every subsequent
    //    genome breaches the OLD baseline. The 5.1.5 mission_open path
    //    will clear this key when a new mission starts (new baseline
    //    expected); for now the TTL expires naturally.
    const fireKey = `genome_drift_fired:${args.passportJti}`;
    const alreadyFired = await this.deps.redis.get(fireKey);
    if (alreadyFired) return;

    // 6. Compute drift via the existing 5.1.2 helper.
    const diff = await this.deps.behavioralGenome.computeDiff(args.claimId, priorRef);
    const breached =
      diff.max_z >= BEHAVIORAL_DRIFT_Z_MAX_THRESHOLD ||
      diff.l2_norm >= BEHAVIORAL_DRIFT_L2_NORM_THRESHOLD;
    if (!breached) return;

    // 7. Resolve agent_id for the security_events row (column is NOT NULL).
    //    Behavioral genome payload does NOT carry agent_id (passport-scoped
    //    fingerprint, agent identity is on the passport row). Look it up.
    const passport = await this.deps.passportRepo.findByJti(args.passportJti);
    if (!passport) {
      // The passport was revoked + pruned between genome emit and detector
      // run — defensive skip. Won't happen in practice; here as a guard.
      console.warn(
        '[BehavioralDriftDetector] passport not found for drift event:', args.passportJti,
      );
      return;
    }

    // 8. Identify which dimensions breached, for metadata + message.
    const breachedDims = Object.entries(diff.per_dimension)
      .filter(([, v]) => Math.abs(v) >= BEHAVIORAL_DRIFT_Z_MAX_THRESHOLD)
      .map(([k]) => k);

    // 9. Fire the security event. SecurityEventService.record() inverts
    //    the write: signed detector_signal
    //    claim emitted first, legacy security_events row second with
    //    claim_id linked.
    await this.deps.securityEvent.record({
      operatorId: args.operatorId,
      agentId: passport.agent_id,
      passportJti: args.passportJti,
      signalType: 'genome_drift',
      severity: 'warning',
      message:
        `Behavioral drift detected: max_z=${diff.max_z.toFixed(2)} ` +
        `l2=${diff.l2_norm.toFixed(2)} on ${breachedDims.length} dimension(s)` +
        (breachedDims.length > 0 ? `: ${breachedDims.join(', ')}` : ''),
      pipeline: 'heuristic',
      metadata: {
        current_genome_id: args.claimId,
        prior_genome_id: priorRef,
        max_z: diff.max_z,
        l2_norm: diff.l2_norm,
        per_dimension: diff.per_dimension,
        breached_dimensions: breachedDims,
        z_threshold: BEHAVIORAL_DRIFT_Z_MAX_THRESHOLD,
        l2_threshold: BEHAVIORAL_DRIFT_L2_NORM_THRESHOLD,
      },
    });

    // 10. Set fire-once flag. After this, subsequent genome emissions on
    //     the same passport will short-circuit at step 5 until the TTL
    //     expires (or 5.1.5 mission_open clears the key).
    await this.deps.redis.set(
      fireKey,
      '1',
      'EX',
      BEHAVIORAL_DRIFT_FIRE_ONCE_TTL_SECONDS,
    );
  }
}
