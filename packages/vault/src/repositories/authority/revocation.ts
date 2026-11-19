import { and, desc, eq, inArray, isNull, sql } from 'drizzle-orm';
import {
  authorityApprovalRequests,
  authorityBindingProofs,
  authorityBindings,
  authorityPresentations,
  authorityProofDependencies,
  authorityProofs,
  authorityUses,
  passportAuthorityBindings,
  passportClaims,
  passports,
} from '@stack/shared';
import type { AuthorityDbTransaction } from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { bindingRow } from './rows.js';

/**
 * Revocation cascades: revoking a binding takes its descendants, Passports,
 * approvals, uses and presentations with it; invalidating a proof does the same
 * for every binding that requires it.
 */
export class AuthorityRevocationRepository extends AuthorityAggregateRepository {
  async cascadeProofInvalidation(operatorId: string, proofId: string, now: Date, reason: string) {
    const cascade = async (tx: AuthorityDbTransaction) => {
      const dependent = await tx.execute(sql<{ id: string; version: number }>`
        with recursive affected(id, version) as (
          select ${authorityProofs.id}, ${authorityProofs.version} from ${authorityProofs}
          where ${authorityProofs.operator_id}=${operatorId} and ${authorityProofs.id}=${proofId}
          union
          select d.derived_proof_id, d.derived_proof_version from ${authorityProofDependencies} d
          join affected a on d.source_proof_id=a.id and d.source_proof_version=a.version
          where d.operator_id=${operatorId}
        ) select distinct id, version from affected`);
      const proofPairs = Array.from(dependent);
      if (proofPairs.length === 0) return { passportJtis: [] };
      await tx.update(authorityProofs).set({ status: 'suspended' }).where(and(
        eq(authorityProofs.operator_id, operatorId),
        sql`(${sql.join(proofPairs.map((pair) => sql`(
          ${authorityProofs.id}=${pair.id} and ${authorityProofs.version}=${pair.version}
        )`), sql` or `)})`,
        eq(authorityProofs.status, 'active'),
      ));
      const bindingRows = await tx.execute(sql<{ id: string; version: number }>`
        with recursive directly_affected(id, version) as (
          select distinct link.binding_id, link.binding_version
          from ${authorityBindingProofs} link
          where link.operator_id=${operatorId} and link.required=true and (
            ${sql.join(proofPairs.map((pair) => sql`(
              link.proof_id=${pair.id} and link.proof_version=${pair.version}
            )`), sql` or `)}
          )
        ), affected_bindings(id, version) as (
          select id, version from directly_affected
          union
          select child.id, child.version from ${authorityBindings} child
          join affected_bindings parent
            on child.parent_binding_id=parent.id and child.parent_binding_version=parent.version
          where child.operator_id=${operatorId}
        ) select distinct id, version from affected_bindings`);
      const bindingPairs = Array.from(bindingRows);
      if (bindingPairs.length === 0) return { passportJtis: [] };
      await tx.execute(sql`select id from ${authorityBindings}
        where operator_id=${operatorId} and (${sql.join(bindingPairs.map((pair) => sql`(
          id=${pair.id} and version=${pair.version}
        )`), sql` or `)}) for update`);
      const passportRows = await tx.select({ jti: passportAuthorityBindings.passport_jti })
        .from(passportAuthorityBindings).where(and(
          eq(passportAuthorityBindings.operator_id, operatorId),
          sql`(${sql.join(bindingPairs.map((pair) => sql`(
            ${passportAuthorityBindings.binding_id}=${pair.id}
            and ${passportAuthorityBindings.binding_version}=${pair.version}
          )`), sql` or `)})`,
        ));
      const passportJtis = [...new Set(passportRows.map((row) => row.jti))];
      await tx.update(authorityBindings).set({ status: 'suspended', revoked_reason: reason }).where(and(
        eq(authorityBindings.operator_id, operatorId),
        sql`(${sql.join(bindingPairs.map((pair) => sql`(
          ${authorityBindings.id}=${pair.id} and ${authorityBindings.version}=${pair.version}
        )`), sql` or `)})`,
        inArray(authorityBindings.status, ['active', 'pending_approval']),
      ));
      if (passportJtis.length > 0) {
        await tx.update(passports).set({ revoked_at: now, revoked_reason: `authority:${reason}` }).where(and(
          eq(passports.operator_id, operatorId), inArray(passports.jti, passportJtis), isNull(passports.revoked_at),
        ));
        await tx.update(passportClaims).set({ revoked_at: now, revoked_reason: `authority:${reason}` }).where(and(
          eq(passportClaims.operator_id, operatorId), inArray(passportClaims.passport_id, passportJtis),
          isNull(passportClaims.revoked_at),
        ));
      }
      const bindingPairSql = <TId, TVersion>(idColumn: TId, versionColumn: TVersion) =>
        sql.join(bindingPairs.map((pair) => sql`(${idColumn}=${pair.id} and ${versionColumn}=${pair.version})`), sql` or `);
      await tx.update(authorityApprovalRequests).set({ status: 'cancelled' }).where(and(
        eq(authorityApprovalRequests.operator_id, operatorId),
        sql`(${bindingPairSql(authorityApprovalRequests.binding_id, authorityApprovalRequests.binding_version)})`,
        inArray(authorityApprovalRequests.status, ['pending', 'satisfied']),
      ));
      await tx.update(authorityUses).set({ status: 'denied', denial_code: 'AUTHORITY_PROOF_INVALID', completed_at: now }).where(and(
        eq(authorityUses.operator_id, operatorId),
        sql`(${bindingPairSql(authorityUses.binding_id, authorityUses.binding_version)})`,
        inArray(authorityUses.status, ['pending', 'waiting_approval', 'authorized']),
      ));
      await tx.update(authorityPresentations).set({ status: 'expired', last_error_code: 'AUTHORITY_PROOF_INVALID',
        request_payload_encrypted: null }).where(and(
        eq(authorityPresentations.operator_id, operatorId),
        sql`(${bindingPairSql(authorityPresentations.binding_id, authorityPresentations.binding_version)})`,
        inArray(authorityPresentations.status, ['pending', 'prepared', 'delivered']),
      ));
      return { passportJtis };
    };
    return this.transaction ? cascade(this.transaction) : this.db.transaction(cascade);
  }

  async revokeBindingCascade(operatorId: string, bindingId: string, now: Date, reason: string) {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`select id from ${authorityBindings}
        where operator_id=${operatorId} and id=${bindingId} for update`);
      const [target] = await tx.select().from(authorityBindings).where(and(
        eq(authorityBindings.operator_id, operatorId), eq(authorityBindings.id, bindingId),
      )).orderBy(desc(authorityBindings.version)).limit(1);
      if (!target) return null;

      const affected = await tx.execute(sql<{ id: string; version: number }>`
        with recursive affected(id, version) as (
          select id, version from ${authorityBindings}
          where operator_id=${operatorId} and id=${target.id} and version=${target.version}
          union all
          select child.id, child.version from ${authorityBindings} child
          join affected parent
            on child.parent_binding_id=parent.id and child.parent_binding_version=parent.version
          where child.operator_id=${operatorId}
        ) select id, version from affected`);
      const pairs = Array.from(affected);
      if (pairs.length === 0) return null;
      const pairPredicate = sql.join(pairs.map((pair) => sql`(
        ${authorityBindings.id}=${pair.id} and ${authorityBindings.version}=${pair.version}
      )`), sql` or `);

      const passportRows = await tx.select({ jti: passportAuthorityBindings.passport_jti })
        .from(passportAuthorityBindings).where(and(
          eq(passportAuthorityBindings.operator_id, operatorId),
          sql.join(pairs.map((pair) => sql`(
            ${passportAuthorityBindings.binding_id}=${pair.id}
            and ${passportAuthorityBindings.binding_version}=${pair.version}
          )`), sql` or `),
        ));
      const passportJtis = [...new Set(passportRows.map((row) => row.jti))];

      await tx.update(authorityBindings).set({ status: 'revoked', revoked_at: now, revoked_reason: reason })
        .where(and(eq(authorityBindings.operator_id, operatorId), sql`(${pairPredicate})`,
          inArray(authorityBindings.status, ['draft', 'pending_approval', 'active', 'suspended'])));
      if (passportJtis.length > 0) {
        await tx.update(passports).set({ revoked_at: now, revoked_reason: `authority:${reason}` }).where(and(
          eq(passports.operator_id, operatorId), inArray(passports.jti, passportJtis), isNull(passports.revoked_at),
        ));
        await tx.update(passportClaims).set({ revoked_at: now, revoked_reason: `authority:${reason}` }).where(and(
          eq(passportClaims.operator_id, operatorId), inArray(passportClaims.passport_id, passportJtis),
          isNull(passportClaims.revoked_at),
        ));
      }
      await tx.update(authorityApprovalRequests).set({ status: 'cancelled' }).where(and(
        eq(authorityApprovalRequests.operator_id, operatorId),
        sql`(${sql.join(pairs.map((pair) => sql`(
          ${authorityApprovalRequests.binding_id}=${pair.id}
          and ${authorityApprovalRequests.binding_version}=${pair.version}
        )`), sql` or `)})`,
        inArray(authorityApprovalRequests.status, ['pending', 'satisfied']),
      ));
      await tx.update(authorityUses).set({ status: 'denied', denial_code: 'AUTHORITY_REVOKED', completed_at: now }).where(and(
        eq(authorityUses.operator_id, operatorId),
        sql`(${sql.join(pairs.map((pair) => sql`(
          ${authorityUses.binding_id}=${pair.id} and ${authorityUses.binding_version}=${pair.version}
        )`), sql` or `)})`,
        inArray(authorityUses.status, ['pending', 'waiting_approval', 'authorized']),
      ));
      await tx.update(authorityPresentations).set({ status: 'expired', last_error_code: 'AUTHORITY_REVOKED',
        request_payload_encrypted: null }).where(and(
        eq(authorityPresentations.operator_id, operatorId),
        sql`(${sql.join(pairs.map((pair) => sql`(
          ${authorityPresentations.binding_id}=${pair.id}
          and ${authorityPresentations.binding_version}=${pair.version}
        )`), sql` or `)})`,
        inArray(authorityPresentations.status, ['pending', 'prepared', 'delivered']),
      ));
      const [revokedTarget] = await tx.select({ binding: authorityBindings, claim_hash: passportClaims.claim_hash })
        .from(authorityBindings).leftJoin(passportClaims, eq(authorityBindings.claim_id, passportClaims.claim_id))
        .where(and(eq(authorityBindings.operator_id, operatorId), eq(authorityBindings.id, target.id),
          eq(authorityBindings.version, target.version))).limit(1);
      return revokedTarget ? { binding: bindingRow({ ...revokedTarget.binding, claim_hash: revokedTarget.claim_hash }), passportJtis } : null;
    });
  }
}
