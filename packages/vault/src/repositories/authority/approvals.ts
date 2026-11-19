import { and, desc, eq, gt, inArray, isNull, or, sql } from 'drizzle-orm';
import {
  ConflictError,
  authorityApprovalDecisions,
  authorityApprovalRequests,
  authorityBindingProofs,
  authorityBindings,
  authorityPrincipals,
  authorityProofs,
  canonicalize,
  generateId,
  passportClaims,
} from '@stack/shared';
import type { ResolvedAuthorityApprovalDecision } from '../../services/authority/approval-verifier.js';
import { sha256 as digest } from '../../services/authority/digest.js';
import type {
  AuthorityApprovalRequestRecord,
  AuthorityDbTransaction,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';

/** Approval requests, the verifier candidates for them, and signed approval decisions. */
export class AuthorityApprovalRepository extends AuthorityAggregateRepository {
  async hasUnsatisfiedApprovals(operatorId: string, bindingId: string, version: number, requestHash?: string) {
    const conditions = [eq(authorityApprovalRequests.operator_id, operatorId), eq(authorityApprovalRequests.binding_id, bindingId),
      eq(authorityApprovalRequests.binding_version, version), inArray(authorityApprovalRequests.status, ['pending', 'expired', 'rejected'])];
    if (requestHash) conditions.push(eq(authorityApprovalRequests.request_hash, requestHash));
    const [row] = await this.db.select({ id: authorityApprovalRequests.id }).from(authorityApprovalRequests)
      .where(and(...conditions)).limit(1);
    return Boolean(row);
  }

  async consumeSatisfiedApprovals(input: {
    operatorId: string; bindingId: string; bindingVersion: number;
    phase: 'activation' | 'action' | 'presentation'; requestHash: string; now: Date;
  }) {
    await this.db.update(authorityApprovalRequests).set({ status: 'consumed', consumed_at: input.now }).where(and(
      eq(authorityApprovalRequests.operator_id, input.operatorId),
      eq(authorityApprovalRequests.binding_id, input.bindingId),
      eq(authorityApprovalRequests.binding_version, input.bindingVersion),
      eq(authorityApprovalRequests.phase, input.phase),
      eq(authorityApprovalRequests.request_hash, input.requestHash),
      eq(authorityApprovalRequests.status, 'satisfied'),
    ));
  }

  async ensureApprovalRequest(input: {
    operatorId: string; bindingId: string; bindingVersion: number; authorityUseId?: string;
    phase: 'activation' | 'action' | 'presentation'; groupKey: string; requestHash: string;
    challengeHash: string; requiredWeight: number; rejectMode: 'any_reject' | 'threshold_reject'; expiresAt: Date;
  }) {
    await this.db.insert(authorityApprovalRequests).values({
      id: generateId('apr'), operator_id: input.operatorId, binding_id: input.bindingId,
      binding_version: input.bindingVersion, authority_use_id: input.authorityUseId ?? null,
      phase: input.phase, group_key: input.groupKey, request_hash: input.requestHash,
      challenge_hash: input.challengeHash, required_weight: input.requiredWeight,
      collected_weight: 0, reject_mode: input.rejectMode, status: 'pending', expires_at: input.expiresAt,
    }).onConflictDoNothing();
  }

  async listApprovalRequests(operatorId: string, bindingId: string) {
    return (await this.db.select().from(authorityApprovalRequests).where(and(
      eq(authorityApprovalRequests.operator_id, operatorId), eq(authorityApprovalRequests.binding_id, bindingId),
    )).orderBy(desc(authorityApprovalRequests.created_at))).map((row) => ({
      ...row,
      phase: row.phase as AuthorityApprovalRequestRecord['phase'],
      reject_mode: row.reject_mode as AuthorityApprovalRequestRecord['reject_mode'],
      status: row.status as AuthorityApprovalRequestRecord['status'],
    }));
  }

  async listApprovalVerifierCandidates(operatorId: string, requestId: string, now: Date) {
    const [request] = await this.db.select().from(authorityApprovalRequests).where(and(
      eq(authorityApprovalRequests.operator_id, operatorId), eq(authorityApprovalRequests.id, requestId),
      eq(authorityApprovalRequests.status, 'pending'), gt(authorityApprovalRequests.expires_at, now),
    )).limit(1);
    if (!request) return [];
    const identities = await this.db.select().from(authorityBindingProofs).where(and(
      eq(authorityBindingProofs.operator_id, operatorId), eq(authorityBindingProofs.binding_id, request.binding_id),
      eq(authorityBindingProofs.binding_version, request.binding_version), eq(authorityBindingProofs.group_key, request.group_key),
      eq(authorityBindingProofs.role, 'authoriser_identity'),
    ));
    const candidates = [];
    for (const identityLink of identities) {
      if (!identityLink.authoriser_principal_id) continue;
      const identityProof = await this.repo.findProof(operatorId, identityLink.proof_id, identityLink.proof_version);
      if (!identityProof || identityProof.status !== 'active'
        || (identityProof.expires_at && identityProof.expires_at <= now)) continue;
      const profile = await this.repo.findProofProfileVersion(operatorId, identityProof.profile_version_id);
      if (!profile || profile.status !== 'active') continue;
      const capacityLinks = await this.db.select().from(authorityBindingProofs).where(and(
        eq(authorityBindingProofs.operator_id, operatorId), eq(authorityBindingProofs.binding_id, request.binding_id),
        eq(authorityBindingProofs.binding_version, request.binding_version), eq(authorityBindingProofs.group_key, request.group_key),
        eq(authorityBindingProofs.role, 'authoriser_capacity'),
        eq(authorityBindingProofs.authoriser_principal_id, identityLink.authoriser_principal_id),
      ));
      const capacityProof = capacityLinks[0]
        ? await this.repo.findProof(operatorId, capacityLinks[0].proof_id, capacityLinks[0].proof_version) : null;
      if (capacityProof && (capacityProof.status !== 'active'
        || (capacityProof.expires_at && capacityProof.expires_at <= now))) continue;
      candidates.push({
        authoriserPrincipalId: identityLink.authoriser_principal_id,
        identityProof,
        ...(capacityProof ? { capacityProof } : {}),
        profile,
        requestHash: request.request_hash,
      });
    }
    return candidates;
  }

  async validateApprovalDecision(input: {
    operatorId: string; requestId: string; authenticatedAuthor: unknown;
    decision: { request_id: string; decision: 'approve' | 'reject'; request_hash: string; signed_decision: string };
    resolved: ResolvedAuthorityApprovalDecision; now: Date;
  }) {
    if (this.transaction) {
      await this.transaction.execute(sql`select id from ${authorityApprovalRequests} where
        operator_id=${input.operatorId} and id=${input.requestId} for update`);
    }
    const [request] = await this.db.select().from(authorityApprovalRequests).where(and(
      eq(authorityApprovalRequests.operator_id, input.operatorId), eq(authorityApprovalRequests.id, input.requestId),
      eq(authorityApprovalRequests.status, 'pending'), gt(authorityApprovalRequests.expires_at, input.now),
      eq(authorityApprovalRequests.request_hash, input.decision.request_hash),
    )).limit(1);
    if (!request || input.decision.request_id !== request.id) return null;
    const assignments = await this.repo.listBindingProofs(input.operatorId, request.binding_id, request.binding_version);
    const identity = assignments.find((item) => item.group_key === request.group_key
      && item.role === 'authoriser_identity' && item.authoriser_principal_id === input.resolved.authoriserPrincipalId
      && item.proof_id === input.resolved.identityProofId && item.proof_version === input.resolved.identityProofVersion);
    if (!identity) return null;
    const [binding] = await this.db.select({ kind: authorityPrincipals.kind }).from(authorityBindings)
      .innerJoin(authorityPrincipals, and(eq(authorityBindings.principal_id, authorityPrincipals.id),
        eq(authorityBindings.operator_id, authorityPrincipals.operator_id)))
      .where(and(eq(authorityBindings.operator_id, input.operatorId), eq(authorityBindings.id, request.binding_id),
        eq(authorityBindings.version, request.binding_version))).limit(1);
    const capacity = assignments.find((item) => item.group_key === request.group_key
      && item.role === 'authoriser_capacity' && item.authoriser_principal_id === input.resolved.authoriserPrincipalId
      && item.proof_id === input.resolved.capacityProofId && item.proof_version === input.resolved.capacityProofVersion);
    if (binding?.kind === 'organisation' && !capacity) return null;
    if (binding?.kind !== 'organisation' && (input.resolved.capacityProofId !== undefined) !== Boolean(capacity)) return null;
    const [decisionProof] = await this.db.select().from(authorityProofs).where(and(
      eq(authorityProofs.operator_id, input.operatorId), eq(authorityProofs.id, input.resolved.decisionProofId),
      eq(authorityProofs.version, input.resolved.decisionProofVersion), eq(authorityProofs.status, 'active'),
      eq(authorityProofs.subject_principal_id, input.resolved.authoriserPrincipalId),
      inArray(authorityProofs.proof_kind, ['signature', 'consent']),
    )).limit(1);
    if (!decisionProof) return null;
    return {
      request_id: request.id,
      binding_id: request.binding_id,
      binding_version: request.binding_version,
      authority_use_id: request.authority_use_id,
      authoriser_principal_id: input.resolved.authoriserPrincipalId,
      identity_proof_id: input.resolved.identityProofId,
      identity_proof_version: input.resolved.identityProofVersion,
      capacity_proof_id: input.resolved.capacityProofId ?? null,
      capacity_proof_version: input.resolved.capacityProofVersion ?? null,
      decision_proof_id: input.resolved.decisionProofId,
      decision_proof_version: input.resolved.decisionProofVersion,
      decision: input.decision.decision,
      weight: identity.weight,
      request_hash: request.request_hash,
      phase: request.phase as AuthorityApprovalRequestRecord['phase'],
      group_key_hash: digest(request.group_key),
      approval_requirement_hash: digest(canonicalize({
        phase: request.phase,
        group_key: request.group_key,
        required_weight: request.required_weight,
        reject_mode: request.reject_mode,
      })),
      expires_at: request.expires_at,
    };
  }

  async listSatisfiedApprovalClaimRefs(input: {
    operatorId: string; bindingId: string; bindingVersion: number; authorityUseId: string;
  }) {
    const requestRows = await this.db.execute(sql<{
      id: string; phase: AuthorityApprovalRequestRecord['phase']; group_key: string;
      required_weight: number; collected_weight: number;
      reject_mode: AuthorityApprovalRequestRecord['reject_mode']; request_hash: string;
      status: AuthorityApprovalRequestRecord['status'];
    }>`select req.id, req.phase, req.group_key, req.required_weight, req.collected_weight,
        req.reject_mode, req.request_hash, req.status
      from ${authorityApprovalRequests} req
      where req.operator_id=${input.operatorId}
        and req.binding_id=${input.bindingId} and req.binding_version=${input.bindingVersion}
        and req.status in ('satisfied','consumed')
        and (req.phase='activation' or req.authority_use_id=${input.authorityUseId})
      order by req.phase, req.group_key, req.id`);
    const claimRows = await this.db.execute(sql<{
      request_id: string; claim_id: string; claim_hash: string;
      phase: AuthorityApprovalRequestRecord['phase'];
    }>`select distinct pc.claim_id, pc.claim_hash, req.phase
      from ${authorityApprovalRequests} req
      join ${authorityApprovalDecisions} decision
        on decision.operator_id=req.operator_id and decision.request_id=req.id and decision.revoked_at is null
      join ${passportClaims} pc
        on pc.operator_id=req.operator_id and pc.type='authority_approval'
        and pc.body_json->>'decision_id'=decision.id and pc.revoked_at is null
      where req.operator_id=${input.operatorId}
        and req.binding_id=${input.bindingId} and req.binding_version=${input.bindingVersion}
        and req.status in ('satisfied','consumed')
        and (req.phase='activation' or req.authority_use_id=${input.authorityUseId})
      order by req.phase, pc.claim_id`);
    const claimRefs = Array.from(claimRows).map((row) => ({
      claim_id: String(row.claim_id),
      claim_hash: String(row.claim_hash).startsWith('sha256:')
        ? String(row.claim_hash)
        : `sha256:${String(row.claim_hash)}`,
      phase: row.phase as AuthorityApprovalRequestRecord['phase'],
    }));
    const decisionRows = await this.db.execute(sql<{
      request_id: string; claim_id: string; claim_hash: string;
    }>`select distinct req.id as request_id, pc.claim_id, pc.claim_hash
      from ${authorityApprovalRequests} req
      join ${authorityApprovalDecisions} decision
        on decision.operator_id=req.operator_id and decision.request_id=req.id and decision.revoked_at is null
      join ${passportClaims} pc
        on pc.operator_id=req.operator_id and pc.type='authority_approval'
        and pc.body_json->>'decision_id'=decision.id and pc.revoked_at is null
      where req.operator_id=${input.operatorId}
        and req.binding_id=${input.bindingId} and req.binding_version=${input.bindingVersion}
        and req.status in ('satisfied','consumed')
        and (req.phase='activation' or req.authority_use_id=${input.authorityUseId})
      order by req.id, pc.claim_id`);
    const decisionsByRequest = new Map<string, Array<{ claim_id: string; claim_hash: string }>>();
    for (const row of Array.from(decisionRows)) {
      const refs = decisionsByRequest.get(String(row.request_id)) ?? [];
      refs.push({ claim_id: String(row.claim_id), claim_hash: String(row.claim_hash).startsWith('sha256:')
        ? String(row.claim_hash) : `sha256:${String(row.claim_hash)}` });
      decisionsByRequest.set(String(row.request_id), refs);
    }
    const requirements = Array.from(requestRows).map((request) => ({
      phase: request.phase as AuthorityApprovalRequestRecord['phase'],
      group_key_hash: digest(String(request.group_key)),
      required_weight: Number(request.required_weight),
      collected_weight: Number(request.collected_weight),
      reject_mode: request.reject_mode as AuthorityApprovalRequestRecord['reject_mode'],
      request_hash: String(request.request_hash),
      approval_requirement_hash: digest(canonicalize({
        phase: request.phase,
        group_key: request.group_key,
        required_weight: Number(request.required_weight),
        reject_mode: request.reject_mode,
      })),
      status: request.status as AuthorityApprovalRequestRecord['status'],
      decision_claim_refs: decisionsByRequest.get(String(request.id)) ?? [],
    }));
    return { claimRefs, requirements };
  }

  async decideApproval(input: {
    operatorId: string; requestId: string; authenticatedAuthor: unknown;
    decision: { request_id: string; decision: 'approve' | 'reject'; request_hash: string; signed_decision: string };
    resolved: ResolvedAuthorityApprovalDecision; decisionId: string; now: Date;
  }) {
    const decide = async (tx: AuthorityDbTransaction) => {
      await tx.execute(sql`select id from ${authorityApprovalRequests} where
        operator_id=${input.operatorId} and id=${input.requestId} for update`);
      const [request] = await tx.select().from(authorityApprovalRequests).where(and(
        eq(authorityApprovalRequests.operator_id, input.operatorId), eq(authorityApprovalRequests.id, input.requestId),
        eq(authorityApprovalRequests.status, 'pending'), gt(authorityApprovalRequests.expires_at, input.now),
        eq(authorityApprovalRequests.request_hash, input.decision.request_hash),
      )).limit(1);
      if (!request) return null;
      const assignments = await tx.select().from(authorityBindingProofs).where(and(
        eq(authorityBindingProofs.operator_id, input.operatorId), eq(authorityBindingProofs.binding_id, request.binding_id),
        eq(authorityBindingProofs.binding_version, request.binding_version), eq(authorityBindingProofs.group_key, request.group_key),
        eq(authorityBindingProofs.role, 'authoriser_identity'),
        eq(authorityBindingProofs.authoriser_principal_id, input.resolved.authoriserPrincipalId),
        eq(authorityBindingProofs.proof_id, input.resolved.identityProofId),
        eq(authorityBindingProofs.proof_version, input.resolved.identityProofVersion),
      ));
      const assignment = assignments[0];
      if (!assignment) return null;
      const [bindingPrincipal] = await tx.select({ kind: authorityPrincipals.kind }).from(authorityBindings)
        .innerJoin(authorityPrincipals, and(eq(authorityBindings.principal_id, authorityPrincipals.id),
          eq(authorityBindings.operator_id, authorityPrincipals.operator_id)))
        .where(and(eq(authorityBindings.operator_id, input.operatorId),
          eq(authorityBindings.id, request.binding_id), eq(authorityBindings.version, request.binding_version))).limit(1);
      const requiredProofPredicates = [
        and(eq(authorityProofs.id, input.resolved.identityProofId),
          eq(authorityProofs.version, input.resolved.identityProofVersion)),
        and(eq(authorityProofs.id, input.resolved.decisionProofId),
          eq(authorityProofs.version, input.resolved.decisionProofVersion)),
        ...(input.resolved.capacityProofId && input.resolved.capacityProofVersion
          ? [and(eq(authorityProofs.id, input.resolved.capacityProofId),
              eq(authorityProofs.version, input.resolved.capacityProofVersion))]
          : []),
      ];
      const activeProofRows = await tx.select().from(authorityProofs).where(and(
        eq(authorityProofs.operator_id, input.operatorId), eq(authorityProofs.status, 'active'),
        eq(authorityProofs.subject_principal_id, input.resolved.authoriserPrincipalId),
        or(...requiredProofPredicates),
        or(isNull(authorityProofs.expires_at), gt(authorityProofs.expires_at, input.now)),
      ));
      const hasActive = (id: string, version: number) => activeProofRows.some((proof) => proof.id === id && proof.version === version);
      if (!hasActive(input.resolved.identityProofId, input.resolved.identityProofVersion)
        || !hasActive(input.resolved.decisionProofId, input.resolved.decisionProofVersion)) return null;
      const capacityAssignment = await tx.select().from(authorityBindingProofs).where(and(
        eq(authorityBindingProofs.operator_id, input.operatorId), eq(authorityBindingProofs.binding_id, request.binding_id),
        eq(authorityBindingProofs.binding_version, request.binding_version), eq(authorityBindingProofs.group_key, request.group_key),
        eq(authorityBindingProofs.role, 'authoriser_capacity'),
        eq(authorityBindingProofs.authoriser_principal_id, input.resolved.authoriserPrincipalId),
        ...(input.resolved.capacityProofId && input.resolved.capacityProofVersion ? [
          eq(authorityBindingProofs.proof_id, input.resolved.capacityProofId),
          eq(authorityBindingProofs.proof_version, input.resolved.capacityProofVersion),
        ] : []),
      ));
      if (bindingPrincipal?.kind === 'organisation'
        && (!input.resolved.capacityProofId || !input.resolved.capacityProofVersion
          || capacityAssignment.length !== 1
          || !hasActive(input.resolved.capacityProofId, input.resolved.capacityProofVersion))) return null;
      const decisionProof = activeProofRows.find((proof) => proof.id === input.resolved.decisionProofId
        && proof.version === input.resolved.decisionProofVersion);
      if (!decisionProof || !['signature', 'consent'].includes(decisionProof.proof_kind)) return null;
      const [created] = await tx.insert(authorityApprovalDecisions).values({
        id: input.decisionId, operator_id: input.operatorId, request_id: request.id,
        authoriser_principal_id: input.resolved.authoriserPrincipalId,
        identity_proof_id: input.resolved.identityProofId, identity_proof_version: input.resolved.identityProofVersion,
        capacity_proof_id: input.resolved.capacityProofId ?? null,
        capacity_proof_version: input.resolved.capacityProofVersion ?? null,
        decision_proof_id: input.resolved.decisionProofId, decision_proof_version: input.resolved.decisionProofVersion,
        decision: input.decision.decision, weight: assignment.weight, request_hash: request.request_hash,
        decided_at: input.now, expires_at: request.expires_at,
      }).onConflictDoNothing().returning();
      if (!created) return null;
      const [weights] = await tx.select({
        approve: sql<number>`coalesce(sum(case when ${authorityApprovalDecisions.decision}='approve' then ${authorityApprovalDecisions.weight} else 0 end),0)`,
        reject: sql<number>`coalesce(sum(case when ${authorityApprovalDecisions.decision}='reject' then ${authorityApprovalDecisions.weight} else 0 end),0)`,
      }).from(authorityApprovalDecisions).where(and(
        eq(authorityApprovalDecisions.operator_id, input.operatorId), eq(authorityApprovalDecisions.request_id, request.id),
        isNull(authorityApprovalDecisions.revoked_at),
        or(isNull(authorityApprovalDecisions.expires_at), gt(authorityApprovalDecisions.expires_at, input.now)),
      ));
      const approveWeight = Number(weights?.approve ?? 0);
      const rejectWeight = Number(weights?.reject ?? 0);
      const rejected = request.reject_mode === 'any_reject'
        ? rejectWeight > 0 : rejectWeight >= request.required_weight;
      const satisfied = !rejected && approveWeight >= request.required_weight;
      const [updated] = await tx.update(authorityApprovalRequests).set({
        collected_weight: approveWeight,
        status: rejected ? 'rejected' : satisfied ? 'satisfied' : 'pending',
        satisfied_at: satisfied ? input.now : null,
      }).where(and(eq(authorityApprovalRequests.id, request.id), eq(authorityApprovalRequests.status, 'pending'),
        eq(authorityApprovalRequests.collected_weight, request.collected_weight))).returning();
      if (!updated) throw new ConflictError('authority approval lost a concurrent decision race');
      return {
        request_id: updated.id, status: updated.status, collected_weight: updated.collected_weight,
        required_weight: updated.required_weight, decided_at: input.now.toISOString(),
      };
    };
    return this.transaction ? decide(this.transaction) : this.db.transaction(decide);
  }
}
