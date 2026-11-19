// simulation_divergence detector.
//
// When an intent_outcome claim lands, we check whether the same
// passport carried a paired intent_simulation (linked by
// intent_claim_ref). If the simulation's prediction disagrees with
// the observed outcome — predicted-allowed vs failed, predicted-
// denied vs succeeded, or cost variance over 50% — we emit a
// `detector_signal` claim with `detector_key='simulation_divergence'`
// via SecurityEventService.record (which dual-writes the legacy
// security_events row + the signed claim wiring).
//
// Mirror of the `checkpoint_self_report_divergence` pattern from
// the dashboard already renders the visual signal
// (amber border on /reviews), this commit ships the signed-claim
// audit-trail counterpart.

import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';
import type { SecurityEventService } from './security-event-service.js';

export interface SimulationDivergenceDetectorDeps {
  repo: PassportClaimsRepository;
  securityEvent: SecurityEventService;
}

export class SimulationDivergenceDetector {
  constructor(private readonly deps: SimulationDivergenceDetectorDeps) {}

  async check(args: {
    operatorId: string;
    passportJti: string;
    outcomeClaimId: string;
  }): Promise<void> {
    const outcomeRow = await this.deps.repo.findByClaimId(args.outcomeClaimId);
    if (!outcomeRow || outcomeRow.type !== 'intent_outcome') return;

    const outcomeBody = outcomeRow.body_json as {
      intent_claim_ref?: string;
      status?: string;
      cost_actual?: { wallet_cents?: number | null; tokens?: number | null; gas_gwei?: number | null };
    };
    const intentClaimRef = outcomeBody.intent_claim_ref;
    if (!intentClaimRef) return;
    const outcomeStatus = outcomeBody.status;
    if (outcomeStatus !== 'succeeded' && outcomeStatus !== 'failed') return;

    // Find the paired simulation + the original intent_claim on this
    // passport. Multiple sims can exist for the same intent_claim_ref
    // (re-simulations); use the newest one (largest issued_at_ms).
    // The intent_claim carries the agent_id we need for the detector_signal.
    const passportClaims = await this.deps.repo.findActiveByPassportId(args.passportJti);
    let pairedSim: { body_json: unknown; issued_at_ms?: number | null } | null = null;
    let agentId: string | null = null;
    for (const claim of passportClaims) {
      if (claim.type === 'intent_simulation') {
        const body = claim.body_json as { intent_claim_ref?: string };
        if (body.intent_claim_ref !== intentClaimRef) continue;
        const issued = (claim as { issued_at_ms?: number | null }).issued_at_ms ?? 0;
        if (!pairedSim || (issued > (pairedSim.issued_at_ms ?? 0))) {
          pairedSim = { body_json: claim.body_json, issued_at_ms: issued };
        }
      } else if (claim.type === 'intent_claim' && claim.claim_id === intentClaimRef) {
        const body = claim.body_json as { agent_id?: string };
        if (typeof body.agent_id === 'string') agentId = body.agent_id;
      }
    }
    if (!pairedSim) return;
    if (!agentId) return;

    const simBody = pairedSim.body_json as {
      allowed?: boolean;
      simulated_cost?: { wallet_cents?: number | null; tokens?: number | null };
    };

    const divergences: string[] = [];

    // 1. Verdict disagreement: predicted allowed vs actual failed,
    //    or predicted denied vs actual succeeded.
    if (simBody.allowed === true && outcomeStatus === 'failed') {
      divergences.push('predicted_allowed_but_failed');
    } else if (simBody.allowed === false && outcomeStatus === 'succeeded') {
      divergences.push('predicted_denied_but_succeeded');
    }

    // 2. Cost variance > 50% (wallet_cents only — tokens/gas vary
    //    enough at the per-call layer that 50% gates on them would
    //    be too noisy in v1).
    const simCost = simBody.simulated_cost?.wallet_cents;
    const actualCost = outcomeBody.cost_actual?.wallet_cents;
    if (
      typeof simCost === 'number' &&
      simCost > 0 &&
      typeof actualCost === 'number' &&
      Math.abs(actualCost - simCost) / simCost > 0.5
    ) {
      divergences.push('cost_variance_over_50pct');
    }

    if (divergences.length === 0) return;

    // Fire the detector — securityEvent.record dual-writes the signed
    // detector_signal claim.
    await this.deps.securityEvent.record({
      operatorId: args.operatorId,
      agentId,
      passportJti: args.passportJti,
      signalType: 'simulation_divergence',
      severity: 'warning',
      message: `Outcome diverges from simulation: ${divergences.join(', ')}`,
      metadata: {
        intent_claim_ref: intentClaimRef,
        outcome_claim_id: args.outcomeClaimId,
        divergences,
        predicted_allowed: simBody.allowed,
        actual_status: outcomeStatus,
        simulated_cost_cents: simCost ?? null,
        actual_cost_cents: actualCost ?? null,
      },
    });
  }
}
