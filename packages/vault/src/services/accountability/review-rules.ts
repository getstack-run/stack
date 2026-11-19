import { CHECKPOINT_DEFAULT_INTERVAL_SECONDS, type CheckoutInput, type ReviewFlag } from '@stack/shared';
import type { AgentRepository } from '../../repositories/agent-repo.js';
import type { CheckpointRepository } from '../../repositories/checkpoint-repo.js';
import type { CheckoutRepository } from '../../repositories/checkout-repo.js';
import type { PassportRepository } from '../../repositories/passport-repo.js';

export type ReviewPassport = NonNullable<Awaited<ReturnType<PassportRepository['findByJti']>>>;
export type ReviewAgent = NonNullable<Awaited<ReturnType<AgentRepository['findById']>>>;
export type ReviewCheckpoint = Awaited<ReturnType<CheckpointRepository['findByPassport']>>[number];
type RecentPassport = Awaited<ReturnType<PassportRepository['findRecentByAgent']>>[number];
type RecentCheckout = Awaited<ReturnType<CheckoutRepository['findRecentByAgent']>>[number];

// The review rules below turn what a mission declared and what it did into
// flags. Each one is a pure function of rows already read, so a rule can be
// tested without a service. The order in which the service applies them is the
// order of the review; it is not significant to any one rule.

/** Rule 1: services used that the passport's declared intent did not name. */
export function undeclaredServiceFlags(
  passport: ReviewPassport,
  checkout: CheckoutInput,
): ReviewFlag[] {
  const flags: ReviewFlag[] = [];
  if (passport.intent_services && checkout.services_used.length > 0) {
    const declared = new Set(passport.intent_services);
    for (const svc of checkout.services_used) {
      if (!declared.has(svc)) {
        flags.push({
          type: 'undeclared_service',
          severity: 'warning',
          message: `Accessed ${svc} (not in declared intent)`,
        });
      }
    }
  }
  return flags;
}

/** Rule 2: delegation the passport's declared intent did not allow. */
export function undeclaredDelegationFlags(
  passport: ReviewPassport,
  checkout: CheckoutInput,
): ReviewFlag[] {
  if (checkout.delegated_to && checkout.delegated_to.length > 0 && !passport.intent_delegates) {
    return [
      {
        type: 'undeclared_delegation',
        severity: 'critical',
        message: `Delegated to ${checkout.delegated_to.length} agent(s) without declaring delegation intent`,
      },
    ];
  }
  return [];
}

/** Rule 3: the mission ran far longer than its declared estimate. */
export function durationExceededFlags(passport: ReviewPassport): ReviewFlag[] {
  if (passport.estimated_duration_seconds && passport.checked_out_at === null) {
    const actualDuration = (Date.now() - passport.issued_at.getTime()) / 1000;
    const estimated = passport.estimated_duration_seconds;
    if (actualDuration > estimated * 5) {
      return [
        {
          type: 'duration_exceeded',
          severity: 'warning',
          message: `Mission took ${Math.round(actualDuration / 60)}m, estimated ${Math.round(estimated / 60)}m (5x over)`,
        },
      ];
    } else if (actualDuration > estimated * 2) {
      return [
        {
          type: 'duration_exceeded',
          severity: 'info',
          message: `Mission took ${Math.round(actualDuration / 60)}m, estimated ${Math.round(estimated / 60)}m (2x over)`,
        },
      ];
    }
  }
  return [];
}

/** Rule 4: an enforced mission that never checked in. */
export function missingCheckpointFlags(
  isEnforced: boolean,
  checkpoints: readonly ReviewCheckpoint[],
): ReviewFlag[] {
  if (isEnforced && checkpoints.length === 0) {
    return [
      {
        type: 'no_checkpoints',
        severity: 'warning',
        message: 'No checkpoints submitted during enforced mission',
      },
    ];
  }
  return [];
}

/** Rule 5: an enforced mission that went quiet for more than three intervals. */
export function checkpointGapFlags(
  isEnforced: boolean,
  passport: ReviewPassport,
  checkpoints: readonly ReviewCheckpoint[],
): ReviewFlag[] {
  const flags: ReviewFlag[] = [];
  if (isEnforced && checkpoints.length > 1) {
    const interval = passport.checkpoint_interval_seconds ?? CHECKPOINT_DEFAULT_INTERVAL_SECONDS;
    for (let i = 1; i < checkpoints.length; i++) {
      const gap =
        (checkpoints[i]!.submitted_at.getTime() - checkpoints[i - 1]!.submitted_at.getTime()) / 1000;
      if (gap > interval * 3) {
        flags.push({
          type: 'checkpoint_gap',
          severity: 'info',
          message: `${Math.round(gap / 60)}m gap between checkpoints ${i} and ${i + 1}`,
        });
      }
    }
  }
  return flags;
}

/** Rule 6: an unusually large number of actions in one mission. */
export function highActionVolumeFlags(checkout: CheckoutInput): ReviewFlag[] {
  if (checkout.actions_count > 500) {
    return [
      {
        type: 'high_action_volume',
        severity: 'warning',
        message: `${checkout.actions_count} actions in single mission`,
      },
    ];
  } else if (checkout.actions_count > 100) {
    return [
      {
        type: 'high_action_volume',
        severity: 'info',
        message: `${checkout.actions_count} actions in single mission`,
      },
    ];
  }
  return [];
}

/**
 * Signal 8, scope_escalation_pattern: monotonic growth in intent_services
 * across the agent's recent passports (newest first, as the repository returns them).
 */
export function scopeEscalationPatternFlags(recentPassports: readonly RecentPassport[]): ReviewFlag[] {
  if (recentPassports.length >= 3) {
    const serviceCounts = recentPassports
      .filter((p) => p.intent_services && p.intent_services.length > 0)
      .map((p) => p.intent_services!.length);
    if (serviceCounts.length >= 3) {
      let monotonic = true;
      for (let i = 1; i < serviceCounts.length; i++) {
        if (serviceCounts[i]! < serviceCounts[i - 1]!) {
          monotonic = false;
          break;
        }
      }
      const first = serviceCounts[0]!;
      const last = serviceCounts[serviceCounts.length - 1]!;
      if (monotonic && first > 0 && last > first * 2) {
        return [
          {
            type: 'scope_escalation_pattern',
            severity: 'warning',
            message: `Intent services grew from ${first} to ${last} across last ${serviceCounts.length} passports`,
          },
        ];
      }
    }
  }
  return [];
}

/**
 * Signal 9, credential_unreported: providers whose credentials the agent
 * retrieved but never listed in a checkpoint or the checkout. Connection-based
 * accesses (prefixed "conn:") are not provider names and are ignored.
 */
export function credentialUnreportedFlags(
  accessedProviders: readonly string[],
  checkpoints: readonly ReviewCheckpoint[],
  checkout: CheckoutInput,
): ReviewFlag[] {
  if (accessedProviders.length === 0) return [];
  // Collect all reported services from checkpoints + checkout
  const reportedServices = new Set<string>();
  for (const cp of checkpoints) {
    if (cp.services_used) {
      for (const svc of cp.services_used) reportedServices.add(svc);
    }
  }
  for (const svc of checkout.services_used) reportedServices.add(svc);

  const unreported = accessedProviders.filter(
    (p) => !p.startsWith('conn:') && !reportedServices.has(p),
  );
  if (unreported.length === 0) return [];
  return [
    {
      type: 'credential_unreported',
      severity: 'warning',
      message: `Credentials retrieved but not reported: ${unreported.join(', ')}`,
    },
  ];
}

/**
 * Signal 11, behavioral_anomaly: per-agent statistical baseline.
 * Takes the agent's last completed checkouts (this mission's own checkout
 * excluded), computes mean and stddev on three dimensions (actions, services,
 * duration) and compares this mission's numbers. Fires at 3 sigma or 3x the
 * mean, whichever is stricter. Skips entirely when fewer than five baseline
 * checkouts exist: not enough history to be meaningful.
 */
export function behavioralAnomalyFlags(
  passport: ReviewPassport,
  checkout: CheckoutInput,
  history: readonly RecentCheckout[],
): ReviewFlag[] {
  // Skip the current checkout from baseline (it was just written).
  const baseline = history.filter((h) => h.passport_jti !== passport.jti);
  if (baseline.length < 5) return [];

  // The review runs BEFORE the checkout record is persisted, so use now as the
  // submission timestamp.
  const issuedAt = passport.issued_at.getTime();
  const currentDuration = Math.max(1, (Date.now() - issuedAt) / 1000);

  const currentActions = checkout.actions_count;
  const currentServices = checkout.services_used.length;

  const durations = baseline.map((b) =>
    Math.max(1, (b.submitted_at.getTime() - b.issued_at.getTime()) / 1000),
  );
  const actions = baseline.map((b) => b.actions_count);
  const services = baseline.map((b) => (b.services_used ?? []).length);

  const anomalies: string[] = [];
  const checkDim = (name: string, current: number, sample: number[]) => {
    const mean = sample.reduce((a, b) => a + b, 0) / sample.length;
    const variance = sample.reduce((a, b) => a + (b - mean) ** 2, 0) / sample.length;
    const stddev = Math.sqrt(variance);
    // Dual threshold: 3σ OR 3× mean (protects against low-variance
    // baselines where even modest absolute jumps are very σ-high).
    const sigmaOver = stddev > 0 && current > mean + 3 * stddev;
    const ratioOver = mean > 0 && current > mean * 3;
    if (sigmaOver || ratioOver) {
      anomalies.push(
        `${name}=${current.toFixed(0)} (baseline μ=${mean.toFixed(1)}, σ=${stddev.toFixed(1)}, n=${sample.length})`,
      );
    }
  };
  checkDim('actions', currentActions, actions);
  checkDim('services', currentServices, services);
  checkDim('duration_s', currentDuration, durations);

  if (anomalies.length === 0) return [];
  return [
    {
      type: 'behavioral_anomaly',
      severity: anomalies.length >= 2 ? 'warning' : 'info',
      message: `Behavioral anomaly vs agent baseline: ${anomalies.join('; ')}`,
    },
  ];
}

/** Whether the flags, under the agent's escalation settings, block, flag or pass the mission. */
export function determineReviewStatus(
  flags: ReviewFlag[],
  agent: { on_warning: string; on_critical: string },
): 'clean' | 'flagged' | 'blocked' {
  if (flags.length === 0) return 'clean';

  const hasWarning = flags.some((f) => f.severity === 'warning');
  const hasCritical = flags.some((f) => f.severity === 'critical');
  const onlyInfo = flags.every((f) => f.severity === 'info');

  if (onlyInfo) return 'clean';

  if (hasCritical && agent.on_critical === 'block') return 'blocked';
  if (hasWarning && agent.on_warning === 'block') return 'blocked';

  return 'flagged';
}
