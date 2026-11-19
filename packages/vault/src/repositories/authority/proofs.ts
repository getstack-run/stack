import { and, desc, eq, gt, inArray, isNull } from 'drizzle-orm';
import {
  authorityProofDependencies,
  authorityProofs,
  identityClaims,
  identityProviders,
  passportClaims,
} from '@stack/shared';
import type {
  AuthorityProofRecord,
  AuthorityProofStatus,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { proofRow } from './rows.js';

/** Proof records, their sources, and the legacy identity-claim facades. */
export class AuthorityProofRepository extends AuthorityAggregateRepository {
  async insertProof(row: AuthorityProofRecord) {
    if (!this.transaction) return this.atomic((repo) => repo.insertProof(row));
    await this.lockOperatorAuthorityGraph(row.operator_id);
    const [created] = await this.db.insert(authorityProofs).values({
      ...row,
      last_status_checked_at: row.last_status_checked_at,
    }).returning();
    return proofRow(created!);
  }

  async findLegacyIdentityClaim(operatorId: string, claimId: string) {
    const [row] = await this.db.select({
      claim: identityClaims,
      provider_active: identityProviders.active,
      signed_claim_hash: passportClaims.claim_hash,
    }).from(identityClaims)
      .innerJoin(identityProviders, eq(identityClaims.provider_id, identityProviders.id))
      .innerJoin(passportClaims, eq(identityClaims.claim_id, passportClaims.claim_id))
      .where(and(eq(identityClaims.operator_id, operatorId), eq(identityClaims.id, claimId),
        isNull(identityClaims.revoked_at), gt(identityClaims.expires_at, new Date()),
        eq(identityProviders.active, true), isNull(passportClaims.revoked_at))).limit(1);
    if (!row || !row.claim.claim_id) return null;
    return {
      id: row.claim.id,
      operator_id: row.claim.operator_id,
      provider_key: row.claim.provider_key,
      layer: row.claim.layer,
      claim_type: row.claim.claim_type,
      assurance_level: row.claim.assurance_level,
      verified_at: row.claim.verified_at,
      expires_at: row.claim.expires_at,
      signed_claim_id: row.claim.claim_id,
      signed_claim_hash: `sha256:${row.signed_claim_hash}`,
    };
  }

  async findLegacyProofFacade(operatorId: string, legacyClaimId: string, subjectPrincipalId: string,
    profileVersionId: string) {
    const [row] = await this.db.select().from(authorityProofs).where(and(
      eq(authorityProofs.operator_id, operatorId), eq(authorityProofs.source_kind, 'legacy_identity_claim'),
      eq(authorityProofs.legacy_identity_claim_id, legacyClaimId),
      eq(authorityProofs.subject_principal_id, subjectPrincipalId),
      eq(authorityProofs.profile_version_id, profileVersionId),
    )).orderBy(desc(authorityProofs.version)).limit(1);
    return row ? proofRow(row) : null;
  }

  async listLegacyProofFacades(operatorId: string, legacyClaimId: string) {
    return (await this.db.select().from(authorityProofs).where(and(
      eq(authorityProofs.operator_id, operatorId), eq(authorityProofs.source_kind, 'legacy_identity_claim'),
      eq(authorityProofs.legacy_identity_claim_id, legacyClaimId),
      inArray(authorityProofs.status, ['pending', 'active', 'suspended']),
    ))).map(proofRow);
  }

  async listProofs(operatorId: string) {
    return (await this.db.select().from(authorityProofs).where(eq(authorityProofs.operator_id, operatorId))
      .orderBy(desc(authorityProofs.created_at))).map(proofRow);
  }

  async findProof(operatorId: string, proofId: string, version?: number) {
    const conditions = [eq(authorityProofs.operator_id, operatorId), eq(authorityProofs.id, proofId)];
    if (version !== undefined) conditions.push(eq(authorityProofs.version, version));
    const [row] = await this.db.select().from(authorityProofs).where(and(...conditions))
      .orderBy(desc(authorityProofs.version)).limit(1);
    return row ? proofRow(row) : null;
  }

  async listProofSources(operatorId: string, proofId: string, version: number) {
    const rows = await this.db.select({ proof: authorityProofs }).from(authorityProofDependencies)
      .innerJoin(authorityProofs, and(
        eq(authorityProofs.operator_id, authorityProofDependencies.operator_id),
        eq(authorityProofs.id, authorityProofDependencies.source_proof_id),
        eq(authorityProofs.version, authorityProofDependencies.source_proof_version),
      )).where(and(eq(authorityProofDependencies.operator_id, operatorId),
        eq(authorityProofDependencies.derived_proof_id, proofId),
        eq(authorityProofDependencies.derived_proof_version, version)))
      .orderBy(authorityProofs.id, authorityProofs.version);
    return rows.map((row) => proofRow(row.proof));
  }

  async transitionProof(input: {
    operatorId: string; proofId: string; from: AuthorityProofStatus[]; to: AuthorityProofStatus;
    now: Date; reason?: string; erase?: { tombstoneHash: string; tombstoneClaimId: string };
  }) {
    const [row] = await this.db.update(authorityProofs).set({
      status: input.to,
      ...(input.to === 'revoked' ? { revoked_at: input.now, revoked_reason: input.reason ?? 'revoked' } : {}),
      ...(input.erase ? {
        native_evidence_encrypted: null, normalized_facts_encrypted: null,
        erased_at: input.now, tombstone_hash: input.erase.tombstoneHash,
        tombstone_claim_id: input.erase.tombstoneClaimId,
      } : {}),
    }).where(and(eq(authorityProofs.operator_id, input.operatorId), eq(authorityProofs.id, input.proofId),
      inArray(authorityProofs.status, input.from))).returning();
    return row ? proofRow(row) : null;
  }
}
