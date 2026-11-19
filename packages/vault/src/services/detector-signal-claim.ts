import { safeErrorSummary } from '@stack/shared';
import type { ClaimRegistryService } from './claim-registry-service.js';

export type DetectorSignalSeverity = 'info' | 'warning' | 'critical';

/**
 * Map the 3-level security-event severity to the 4-level detector_signal
 * claim schema enum. The schema is more granular but the producers only emit
 * 3 levels today; 'warning' splits into 'medium' vs 'high' if a future
 * producer needs the finer grain.
 */
export function toClaimSeverity(s: DetectorSignalSeverity): 'low' | 'medium' | 'high' | 'critical' {
  if (s === 'critical') return 'critical';
  if (s === 'warning') return 'medium';
  return 'low'; // 'info'
}

export interface DetectorSignalClaimInput {
  operatorId: string;
  passportJti: string;
  agentId?: string;
  signalType: string;
  severity: DetectorSignalSeverity;
  pipeline?: 'heuristic' | 'llm' | 'detection-chain';
  intentClaimRef?: string;
  metadata?: Record<string, unknown>;
  /** The one unambiguous Mission the signal belongs to, or null. */
  missionRef?: string | null;
}

/**
 * Sign the detector_signal claim for one security event and return its id, or
 * null when the registry is not wired or signing failed (the caller then
 * records the row without a claim, as the legacy path always did). This is
 * the single place a security event's claim is built: the real-time producers
 * (`SecurityEventService.record`) and the checkout review bridge both call it,
 * so the Console's signed Mission decision can act on either.
 */
export async function signDetectorSignalClaim(
  claimRegistry: ClaimRegistryService | null | undefined,
  input: DetectorSignalClaimInput,
): Promise<string | null> {
  if (!claimRegistry) return null;
  try {
    const result = await claimRegistry.registerClaim({
      operatorId: input.operatorId,
      passportJti: input.passportJti,
      claimType: 'detector_signal',
      payload: {
        type: 'detector_signal',
        detector_key: input.signalType,
        severity: toClaimSeverity(input.severity),
        pipeline: input.pipeline ?? 'heuristic',
        ...(input.intentClaimRef ? { intent_claim_ref: input.intentClaimRef } : {}),
        ...(input.agentId ? { agent_id: input.agentId } : {}),
        metadata: input.metadata ?? {},
        detected_at: Date.now(),
        ...(input.missionRef ? { mission_ref: input.missionRef } : {}),
      },
    });
    return result.claimId;
  } catch (err) {
    console.error('detector_signal emission failed:', safeErrorSummary(err));
    return null;
  }
}
