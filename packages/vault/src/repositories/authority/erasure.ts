import { and, eq, inArray, isNull, or, sql } from 'drizzle-orm';
import {
  authorityApprovalRequests,
  authorityBindingProofs,
  authorityBindings,
  authorityIdempotencyKeys,
  authorityPresentations,
  authorityPrincipals,
  authorityProofDependencies,
  authorityProofs,
  authorityUses,
  canonicalize,
  passportAuthorityBindings,
  passportClaims,
  passports,
  receiverTransactionReceipts,
} from '@stack/shared';
import { sha256 as digest } from '../../services/authority/digest.js';
import type {
  AuthorityErasureTarget,
  AuthorityErasureTombstone,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';

const ERASURE_KIND_ORDER: Record<AuthorityErasureTarget['target_kind'], number> = {
  receiver_transaction_receipt: 0,
  presentation: 1,
  binding: 2,
  proof: 3,
  principal: 4,
};

/** Erasure of one authority artefact and everything derived from it: lock the graph, then apply tombstones. */
export class AuthorityErasureRepository extends AuthorityAggregateRepository {
  async lockErasureGraph(input: {
    operatorId: string;
    targetKind: 'principal' | 'binding' | 'proof' | 'presentation';
    targetId: string;
  }): Promise<AuthorityErasureTarget[] | null> {
    if (!this.transaction) return this.atomic((repo) => repo.lockErasureGraph(input));
    const tx = this.transaction;
    await this.lockOperatorAuthorityGraph(input.operatorId);

    const rootExists = input.targetKind === 'principal'
      ? Boolean((await tx.select({ id: authorityPrincipals.id }).from(authorityPrincipals).where(and(
          eq(authorityPrincipals.operator_id, input.operatorId), eq(authorityPrincipals.id, input.targetId),
        )).limit(1))[0])
      : input.targetKind === 'binding'
        ? Boolean((await tx.select({ id: authorityBindings.id }).from(authorityBindings).where(and(
            eq(authorityBindings.operator_id, input.operatorId), eq(authorityBindings.id, input.targetId),
          )).limit(1))[0])
        : input.targetKind === 'proof'
          ? Boolean((await tx.select({ id: authorityProofs.id }).from(authorityProofs).where(and(
              eq(authorityProofs.operator_id, input.operatorId), eq(authorityProofs.id, input.targetId),
            )).limit(1))[0])
          : Boolean((await tx.select({ id: authorityPresentations.id }).from(authorityPresentations).where(and(
              eq(authorityPresentations.operator_id, input.operatorId), eq(authorityPresentations.id, input.targetId),
            )).limit(1))[0]);
    if (!rootExists) return null;

    const proofPairs = input.targetKind === 'proof' || input.targetKind === 'principal'
      ? Array.from(await tx.execute(sql<{ id: string; version: number }>`
          with recursive affected(id, version) as (
            select p.id, p.version from ${authorityProofs} p
            where p.operator_id=${input.operatorId}
              and ${input.targetKind === 'proof'
                ? sql`p.id=${input.targetId}`
                : sql`(p.subject_principal_id=${input.targetId} or p.represented_principal_id=${input.targetId})`}
            union
            select d.derived_proof_id, d.derived_proof_version
            from ${authorityProofDependencies} d join affected source
              on d.source_proof_id=source.id and d.source_proof_version=source.version
            where d.operator_id=${input.operatorId}
          ) select distinct id, version from affected order by id, version`))
      : [];
    const proofPredicate = proofPairs.length > 0
      ? sql`(${sql.join(proofPairs.map((pair) => sql`(
          ${authorityProofs.id}=${pair.id} and ${authorityProofs.version}=${pair.version}
        )`), sql` or `)})`
      : sql`false`;
    const linkProofPredicate = proofPairs.length > 0
      ? sql`(${sql.join(proofPairs.map((pair) => sql`(
          link.proof_id=${pair.id} and link.proof_version=${pair.version}
        )`), sql` or `)})`
      : sql`false`;
    const bindingPairs = input.targetKind === 'presentation'
      ? []
      : Array.from(await tx.execute(sql<{ id: string; version: number }>`
          with recursive directly_affected(id, version) as (
            select b.id, b.version from ${authorityBindings} b
            where b.operator_id=${input.operatorId} and (
              ${input.targetKind === 'binding' ? sql`b.id=${input.targetId}` : sql`false`}
              ${input.targetKind === 'principal' ? sql`or b.principal_id=${input.targetId}` : sql``}
            )
            union
            select distinct link.binding_id, link.binding_version
            from ${authorityBindingProofs} link
            where link.operator_id=${input.operatorId} and link.required=true and ${linkProofPredicate}
            ${input.targetKind === 'principal'
              ? sql`union select distinct link.binding_id, link.binding_version
                  from ${authorityBindingProofs} link
                  where link.operator_id=${input.operatorId}
                    and link.required=true and link.authoriser_principal_id=${input.targetId}`
              : sql``}
          ), affected(id, version) as (
            select id, version from directly_affected
            union
            select child.id, child.version from ${authorityBindings} child join affected parent
              on child.parent_binding_id=parent.id and child.parent_binding_version=parent.version
            where child.operator_id=${input.operatorId}
          ) select distinct id, version from affected order by id, version`));
    const bindingPredicate = bindingPairs.length > 0
      ? sql`(${sql.join(bindingPairs.map((pair) => sql`(
          ${authorityBindings.id}=${pair.id} and ${authorityBindings.version}=${pair.version}
        )`), sql` or `)})`
      : sql`false`;

    const principalRows = input.targetKind === 'principal'
      ? await tx.select().from(authorityPrincipals).where(and(
          eq(authorityPrincipals.operator_id, input.operatorId), eq(authorityPrincipals.id, input.targetId),
        )).orderBy(authorityPrincipals.id).for('update')
      : [];
    const proofRows = proofPairs.length > 0
      ? await tx.select().from(authorityProofs).where(and(eq(authorityProofs.operator_id, input.operatorId), proofPredicate))
          .orderBy(authorityProofs.id, authorityProofs.version).for('update')
      : [];
    const bindingRows = bindingPairs.length > 0
      ? await tx.select().from(authorityBindings).where(and(eq(authorityBindings.operator_id, input.operatorId), bindingPredicate))
          .orderBy(authorityBindings.id, authorityBindings.version).for('update')
      : [];
    const presentationRows = input.targetKind === 'presentation'
      ? await tx.select().from(authorityPresentations).where(and(
          eq(authorityPresentations.operator_id, input.operatorId), eq(authorityPresentations.id, input.targetId),
        )).orderBy(authorityPresentations.id).for('update')
      : bindingPairs.length > 0
        ? await tx.select().from(authorityPresentations).where(and(
            eq(authorityPresentations.operator_id, input.operatorId),
            sql`(${sql.join(bindingPairs.map((pair) => sql`(
              ${authorityPresentations.binding_id}=${pair.id}
              and ${authorityPresentations.binding_version}=${pair.version}
            )`), sql` or `)})`,
          )).orderBy(authorityPresentations.id).for('update')
        : [];
    const presentationIds = presentationRows.map((row) => row.id);
    const receiptRows = presentationIds.length > 0
      ? await tx.select().from(receiverTransactionReceipts).where(and(
          eq(receiverTransactionReceipts.operator_id, input.operatorId),
          inArray(receiverTransactionReceipts.presentation_id, presentationIds),
        )).orderBy(receiverTransactionReceipts.id).for('update')
      : [];

    const claimIds = [...proofRows.map((row) => row.claim_id), ...bindingRows.map((row) => row.claim_id),
      ...receiptRows.map((row) => row.claim_id)].filter((id): id is string => Boolean(id));
    const claimRows = claimIds.length > 0
      ? await tx.select({ id: passportClaims.claim_id, hash: passportClaims.claim_hash })
          .from(passportClaims).where(and(eq(passportClaims.operator_id, input.operatorId), inArray(passportClaims.claim_id, claimIds)))
      : [];
    const claimHashes = new Map(claimRows.map((row) => [row.id,
      String(row.hash).startsWith('sha256:') ? String(row.hash) : `sha256:${String(row.hash)}`]));
    const targets: AuthorityErasureTarget[] = [];
    for (const row of principalRows) {
      if (row.status === 'erased') continue;
      targets.push({ target_kind: 'principal', target_id: row.id, target_version: null,
        prior_artifact_digest: digest(canonicalize({ id: row.id, kind: row.kind,
          label_ciphertext_digest: row.label_encrypted ? digest(row.label_encrypted) : null,
          created_at: row.created_at.toISOString() })), prior_claim_digest: null });
    }
    for (const row of proofRows) {
      if (row.status === 'erased') continue;
      targets.push({ target_kind: 'proof', target_id: row.id, target_version: row.version,
        prior_artifact_digest: digest(canonicalize({ id: row.id, version: row.version,
          native_evidence_hash: row.native_evidence_hash, normalized_facts_hash: row.normalized_facts_hash,
          profile_version_id: row.profile_version_id })),
        prior_claim_digest: row.claim_id ? claimHashes.get(row.claim_id) ?? null : null });
    }
    for (const row of bindingRows) {
      if (row.status === 'erased') continue;
      targets.push({ target_kind: 'binding', target_id: row.id, target_version: row.version,
        prior_artifact_digest: digest(canonicalize({ id: row.id, version: row.version,
          purpose_hash: row.purpose_hash, scope_hash: row.scope_hash,
          approval_policy_hash: row.approval_policy_hash, disclosure_policy_hash: row.disclosure_policy_hash,
          delegation_policy_hash: row.delegation_policy_hash, proof_set_hash: row.proof_set_hash })),
        prior_claim_digest: row.claim_id ? claimHashes.get(row.claim_id) ?? null : null });
    }
    for (const row of presentationRows) {
      if (row.status === 'erased') continue;
      targets.push({ target_kind: 'presentation', target_id: row.id, target_version: null,
        prior_artifact_digest: digest(canonicalize({ id: row.id, authority_use_id: row.authority_use_id,
          signed_request_hash: row.signed_request_hash, payload_hash: row.payload_hash,
          presentation_jti_hash: row.presentation_jti_hash })), prior_claim_digest: null });
    }
    for (const row of receiptRows) {
      if (row.erased_at) continue;
      targets.push({ target_kind: 'receiver_transaction_receipt', target_id: row.id, target_version: null,
        prior_artifact_digest: row.receipt_hash,
        prior_claim_digest: row.claim_id ? claimHashes.get(row.claim_id) ?? null : null });
    }
    return targets.sort((left, right) => ERASURE_KIND_ORDER[left.target_kind] - ERASURE_KIND_ORDER[right.target_kind]
      || left.target_id.localeCompare(right.target_id) || (left.target_version ?? 0) - (right.target_version ?? 0));
  }

  async applyErasureGraph(input: {
    operatorId: string;
    targetKind: 'principal' | 'binding' | 'proof' | 'presentation';
    targetId: string;
    erasedAt: Date;
    tombstones: AuthorityErasureTombstone[];
  }): Promise<{ passportJtis: string[] }> {
    if (!this.transaction) return this.atomic((repo) => repo.applyErasureGraph(input));
    const tx = this.transaction;
    const byKind = <T extends AuthorityErasureTarget['target_kind']>(kind: T) =>
      input.tombstones.filter((target) => target.target_kind === kind);
    const principalTargets = byKind('principal');
    const proofTargets = byKind('proof');
    const bindingTargets = byKind('binding');
    const presentationTargets = byKind('presentation');
    const receiptTargets = byKind('receiver_transaction_receipt');
    const claimIds: string[] = [];
    const passportJtis = bindingTargets.length > 0
      ? [...new Set((await tx.select({ jti: passportAuthorityBindings.passport_jti })
          .from(passportAuthorityBindings).where(and(
            eq(passportAuthorityBindings.operator_id, input.operatorId),
            sql`(${sql.join(bindingTargets.map((target) => sql`(
              ${passportAuthorityBindings.binding_id}=${target.target_id}
              and ${passportAuthorityBindings.binding_version}=${target.target_version!}
            )`), sql` or `)})`,
          ))).map((row) => row.jti))]
      : [];

    for (const target of receiptTargets) {
      const [current] = await tx.select({ claimId: receiverTransactionReceipts.claim_id })
        .from(receiverTransactionReceipts).where(and(eq(receiverTransactionReceipts.operator_id, input.operatorId),
          eq(receiverTransactionReceipts.id, target.target_id))).limit(1);
      if (current?.claimId) claimIds.push(current.claimId);
      await tx.update(receiverTransactionReceipts).set({
        native_receipt_encrypted: null,
        erased_at: input.erasedAt,
        tombstone_hash: target.tombstone_digest,
        tombstone_claim_id: target.tombstone_claim_id,
      }).where(and(eq(receiverTransactionReceipts.operator_id, input.operatorId),
        eq(receiverTransactionReceipts.id, target.target_id), isNull(receiverTransactionReceipts.erased_at)));
    }
    for (const target of presentationTargets) {
      await tx.update(authorityPresentations).set({
        status: 'erased', request_payload_encrypted: null, erased_at: input.erasedAt,
        tombstone_hash: target.tombstone_digest, tombstone_claim_id: target.tombstone_claim_id,
      }).where(and(eq(authorityPresentations.operator_id, input.operatorId),
        eq(authorityPresentations.id, target.target_id), sql`${authorityPresentations.status}<>'erased'`));
    }
    for (const target of bindingTargets) {
      const [current] = await tx.select({ claimId: authorityBindings.claim_id }).from(authorityBindings).where(and(
        eq(authorityBindings.operator_id, input.operatorId), eq(authorityBindings.id, target.target_id),
        eq(authorityBindings.version, target.target_version!),
      )).limit(1);
      if (current?.claimId) claimIds.push(current.claimId);
      await tx.update(authorityBindings).set({
        status: 'erased', purpose_statement_encrypted: null, scope_encrypted: null,
        approval_policy_encrypted: null, disclosure_policy_encrypted: null,
        erased_at: input.erasedAt, tombstone_hash: target.tombstone_digest,
        tombstone_claim_id: target.tombstone_claim_id,
      }).where(and(eq(authorityBindings.operator_id, input.operatorId), eq(authorityBindings.id, target.target_id),
        eq(authorityBindings.version, target.target_version!), sql`${authorityBindings.status}<>'erased'`));
    }
    for (const target of proofTargets) {
      const [current] = await tx.select({ claimId: authorityProofs.claim_id }).from(authorityProofs).where(and(
        eq(authorityProofs.operator_id, input.operatorId), eq(authorityProofs.id, target.target_id),
        eq(authorityProofs.version, target.target_version!),
      )).limit(1);
      if (current?.claimId) claimIds.push(current.claimId);
      await tx.update(authorityProofs).set({
        status: 'erased', native_evidence_encrypted: null, normalized_facts_encrypted: null,
        erased_at: input.erasedAt, tombstone_hash: target.tombstone_digest,
        tombstone_claim_id: target.tombstone_claim_id,
      }).where(and(eq(authorityProofs.operator_id, input.operatorId), eq(authorityProofs.id, target.target_id),
        eq(authorityProofs.version, target.target_version!), sql`${authorityProofs.status}<>'erased'`));
    }
    for (const target of principalTargets) {
      await tx.update(authorityPrincipals).set({
        status: 'erased', label_encrypted: null, erased_at: input.erasedAt,
        tombstone_hash: target.tombstone_digest, tombstone_claim_id: target.tombstone_claim_id,
      }).where(and(eq(authorityPrincipals.operator_id, input.operatorId),
        eq(authorityPrincipals.id, target.target_id), sql`${authorityPrincipals.status}<>'erased'`));
    }

    if (bindingTargets.length > 0) {
      const bindingWhere = sql`(${sql.join(bindingTargets.map((target) => sql`(
        ${authorityUses.binding_id}=${target.target_id} and ${authorityUses.binding_version}=${target.target_version!}
      )`), sql` or `)})`;
      await tx.update(authorityApprovalRequests).set({ status: 'cancelled' }).where(and(
        eq(authorityApprovalRequests.operator_id, input.operatorId),
        sql`(${sql.join(bindingTargets.map((target) => sql`(
          ${authorityApprovalRequests.binding_id}=${target.target_id}
          and ${authorityApprovalRequests.binding_version}=${target.target_version!}
        )`), sql` or `)})`, inArray(authorityApprovalRequests.status, ['pending', 'satisfied']),
      ));
      await tx.update(authorityUses).set({ status: 'denied', denial_code: 'AUTHORITY_ERASED', completed_at: input.erasedAt })
        .where(and(eq(authorityUses.operator_id, input.operatorId), bindingWhere,
          inArray(authorityUses.status, ['pending', 'waiting_approval', 'authorized'])));
      // Dispatched rows intentionally remain dispatched: the external action may already have occurred.
    }
    if (passportJtis.length > 0) {
      await tx.update(passports).set({ revoked_at: input.erasedAt, revoked_reason: 'authority:erased' }).where(and(
        eq(passports.operator_id, input.operatorId), inArray(passports.jti, passportJtis), isNull(passports.revoked_at),
      ));
      await tx.update(passportClaims).set({ revoked_at: input.erasedAt, revoked_reason: 'authority:erased' }).where(and(
        eq(passportClaims.operator_id, input.operatorId), inArray(passportClaims.passport_id, passportJtis),
        isNull(passportClaims.revoked_at),
      ));
    }
    if (claimIds.length > 0) {
      await tx.update(passportClaims).set({ revoked_at: input.erasedAt, revoked_reason: 'authority:artifact_erased' })
        .where(and(eq(passportClaims.operator_id, input.operatorId), inArray(passportClaims.claim_id, claimIds),
          isNull(passportClaims.revoked_at)));
    }
    const targetIds = input.tombstones.map((target) => target.target_id);
    if (targetIds.length > 0) {
      await tx.update(authorityIdempotencyKeys).set({
        workflow_payload_encrypted: null,
        workflow_phase: sql`case when ${authorityIdempotencyKeys.workflow_phase} is null then null else 'erased' end`,
        lease_token_hash: null, lease_expires_at: null, state: 'completed',
        response_status: sql`coalesce(${authorityIdempotencyKeys.response_status}, 410)`,
        response_body: sql`coalesce(${authorityIdempotencyKeys.response_body}, '{}'::jsonb)`,
        updated_at: input.erasedAt,
      }).where(and(eq(authorityIdempotencyKeys.operator_id, input.operatorId), or(
        inArray(authorityIdempotencyKeys.resource_id, targetIds),
        inArray(sql<string>`${authorityIdempotencyKeys.response_body}->>'id'`, targetIds),
        inArray(sql<string>`${authorityIdempotencyKeys.response_body}#>>'{proof,id}'`, targetIds),
      )));
    }
    return { passportJtis };
  }
}
