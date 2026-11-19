// ReplayService.
//
// Interpretation layer over a mission's signed claim set, NOT evidence
// (per the 5.4.0 ADR Design decision 1). Two entry points:
//
//   - reconstructMissionTimeline(missionId, operatorId): live DB read
//     path. Walks PassportClaimsRepository.findInMissionScope (5.4.4
//     substrate) and feeds the rows into the shared
//     reconstructTimeline helper.
//
//   - reconstructFromClaims(missionId, operatorId, decodedClaims):
//     from-pack path. The verifier package (5.4.8, no @stack/vault
//     dep) COSE-decodes each manifest envelope and passes the parsed
//     bodies here. Both paths converge on the same shared helper, so
//     the live dashboard timeline and the offline verifier output are
//     byte-identical for the same underlying claim set.
//
// The live path verifies each immutable claim envelope before it
// reconstructs activity. The from-pack path accepts claims that its
// caller has already verified.

import { createHash } from 'node:crypto';
import {
  NotFoundError,
  SchemaValidationError,
  reconstructTimeline,
  type ReplayedTimeline,
  type ReconstructClaimInput,
} from '@stack/shared';
import type { ClaimVerifyResult } from '../crypto/claim-signer.js';
import type { PassportClaimsRepository } from '../repositories/passport-claims-repo.js';

// ─── Public types ───────────────────────────────────────────────────

export interface ReplayServiceDeps {
  passportClaimsRepo: PassportClaimsRepository;
  missionRepo: ReplayMissionLookup;
  claimVerifier: {
    verifyClaim(claimId: string): Promise<ClaimVerifyResult>;
  };
}

export interface ReplayMissionLookup {
  findById(missionId: string): Promise<{
    mission_id: string;
    operator_id: string;
    started_at: Date;
    completed_at: Date | null;
    revoked_at: Date | null;
  } | null | undefined>;
}

// ─── Service ────────────────────────────────────────────────────────

export class ReplayService {
  constructor(private deps: ReplayServiceDeps) {}

  /**
   * Live-mission timeline reconstruction. Walks the operator's claim
   * set for `missionId` via the mission-scope repo method (which UNIONs
   * `body_json->>'mission_ref' = missionId` AND
   * `body_json->>'mission_id' = missionId` so MissionClaim itself is
   * included alongside every intent_*, detector_signal, dossier,
   * twin_divergence, etc.).
   *
   * The mission lookup fixes the same half-open mission bounds used
   * by EvidencePackService. Unknown and foreign missions fail before
   * any claim query runs.
   */
  async reconstructMissionTimeline(
    missionId: string,
    operatorId: string,
  ): Promise<ReplayedTimeline> {
    const mission = await this.deps.missionRepo.findById(missionId);
    if (!mission || mission.operator_id !== operatorId) {
      throw new NotFoundError('mission', missionId);
    }
    const t0Ms = mission.started_at.getTime();
    const t1Ms = (mission.revoked_at ?? mission.completed_at)?.getTime() ?? Date.now();
    if (t1Ms <= t0Ms) {
      throw new SchemaValidationError({
        message: `mission ${missionId} has invalid activity time bounds`,
        claim_type: 'mission',
      });
    }
    const rows = await this.deps.passportClaimsRepo.findInMissionScope(
      missionId,
      operatorId,
      t0Ms,
      t1Ms,
    );

    const claims = await this.verifyRows(rows, operatorId);
    return reconstructTimeline(missionId, operatorId, claims);
  }

  /** Paginated verified records, deliberately not a partial reconstruction. */
  async listMissionClaimPage(missionId: string, operatorId: string, pagination: { page: number; limit: number }) {
    const mission = await this.deps.missionRepo.findById(missionId);
    if (!mission || mission.operator_id !== operatorId) throw new NotFoundError('mission', missionId);
    const t0Ms = mission.started_at.getTime();
    const t1Ms = (mission.revoked_at ?? mission.completed_at)?.getTime() ?? Date.now();
    if (t1Ms <= t0Ms) throw new SchemaValidationError({ message: `mission ${missionId} has invalid activity time bounds`, claim_type: 'mission' });
    const rows = await this.deps.passportClaimsRepo.findInMissionScope(missionId, operatorId, t0Ms, t1Ms, pagination);
    const claims = await this.verifyRows(rows.slice(0, pagination.limit), operatorId);
    return {
      view: 'claim_page' as const,
      events: claims.map((claim) => ({
        kind: claim.type, at_ms: claim.issued_at_ms, claim_id: claim.claim_id,
        claim_hash: claim.claim_hash, body: claim.body,
      })),
      ...pagination,
      has_more: rows.length > pagination.limit,
    };
  }

  private async verifyRows(
    rows: Awaited<ReturnType<PassportClaimsRepository['findInMissionScope']>>,
    operatorId: string,
  ): Promise<ReconstructClaimInput[]> {
    return Promise.all(rows.map(async (row) => {
      if (!row.envelope_cose) {
        throw new Error(`mission activity claim ${row.claim_id} has no immutable envelope`);
      }
      const envelopeHash = createHash('sha256')
        .update(Buffer.from(row.envelope_cose, 'base64url'))
        .digest('hex');
      if (envelopeHash !== row.claim_hash) {
        throw new Error(`mission activity claim ${row.claim_id} has a hash mismatch`);
      }
      const verified = await this.deps.claimVerifier.verifyClaim(row.claim_id);
      if (!verified.valid || !verified.envelope) {
        throw new Error(
          `mission activity claim ${row.claim_id} failed verification: ${verified.error ?? 'invalid envelope'}`,
        );
      }
      const envelope = verified.envelope;
      if (envelope.issuer !== operatorId) {
        throw new Error(`mission activity claim ${row.claim_id} has a foreign issuer`);
      }
      if (envelope.claim_type !== row.type) {
        throw new Error(`mission activity claim ${row.claim_id} has a type mismatch`);
      }
      if (!envelope.payload || typeof envelope.payload !== 'object' || Array.isArray(envelope.payload)) {
        throw new Error(`mission activity claim ${row.claim_id} has an invalid payload`);
      }
      return {
        type: envelope.claim_type,
        body: envelope.payload as Record<string, unknown>,
        issued_at_ms: envelope.issued_at,
        claim_id: row.claim_id,
        claim_hash: envelopeHash,
      };
    }));

  }

  /**
   * From-pack timeline reconstruction. Caller (typically the verifier
   * in @getstackrun/verify) has already COSE-decoded each envelope
   * from the pack manifest's `claims[]`, validated signatures, and
   * extracted the payload body. Passes the decoded list here.
   *
   * The verifier package CANNOT import @stack/vault (per 5.4.8 ADR —
   * standalone, no STACK runtime deps); for that surface it calls
   * `reconstructTimeline` from @stack/shared directly. This method is
   * for callers INSIDE the STACK runtime that already have parsed
   * bodies in hand (e.g. dashboard reconstructing from an uploaded
   * pack without going through the full verifier package).
   */
  reconstructFromClaims(
    missionId: string,
    operatorId: string,
    decodedClaims: readonly ReconstructClaimInput[],
  ): ReplayedTimeline {
    return reconstructTimeline(missionId, operatorId, decodedClaims);
  }
}
