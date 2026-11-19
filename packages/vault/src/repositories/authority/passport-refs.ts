import { and, asc, eq, inArray, or, sql } from 'drizzle-orm';
import {
  ForbiddenError,
  authorityBindingProofs,
  authorityBindings,
  passportAuthorityBindings,
  passportClaims,
  type AuthorityReference,
} from '@stack/shared';
import { bindingDigest } from '../../services/authority/digest.js';
import type {
  AuthorityBindingProofRecord,
  AuthorityDbTransaction,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { bindingRow } from './rows.js';

/** The authority references a Passport carries, and the checks made before one is issued. */
export class AuthorityPassportRefRepository extends AuthorityAggregateRepository {
  async linkPassportRefs(input: { operatorId: string; passportJti: string; refs: AuthorityReference[] }, transaction?: AuthorityDbTransaction) {
    if (input.refs.length === 0) return;
    if (!transaction && !this.transaction) {
      await this.atomic((repo) => repo.linkPassportRefs(input, repo.currentTransaction()));
      return;
    }
    const executor = (transaction ?? this.transaction)!;
    const now = new Date();
    for (const ref of [...input.refs].sort((left, right) =>
      `${left.binding_id}:${left.binding_version}`.localeCompare(`${right.binding_id}:${right.binding_version}`))) {
      await executor.execute(sql`select id from ${authorityBindings}
        where operator_id=${input.operatorId} and id=${ref.binding_id} and version=${ref.binding_version} for share`);
      const [stored] = await executor.select({ binding: authorityBindings, claim_hash: passportClaims.claim_hash })
        .from(authorityBindings).leftJoin(passportClaims, eq(authorityBindings.claim_id, passportClaims.claim_id))
        .where(and(eq(authorityBindings.operator_id, input.operatorId), eq(authorityBindings.id, ref.binding_id),
          eq(authorityBindings.version, ref.binding_version))).limit(1);
      if (!stored) throw new ForbiddenError('authority reference is invalid');
      const binding = bindingRow({ ...stored.binding, claim_hash: stored.claim_hash });
      const proofs = (await executor.select().from(authorityBindingProofs).where(and(
        eq(authorityBindingProofs.operator_id, input.operatorId), eq(authorityBindingProofs.binding_id, binding.id),
        eq(authorityBindingProofs.binding_version, binding.version),
      )).orderBy(authorityBindingProofs.ordinal)) as AuthorityBindingProofRecord[];
      if (binding.status !== 'active' || binding.valid_from > now || binding.expires_at <= now
        || binding.claim_id !== ref.binding_claim_id || !binding.claim_hash
        || binding.receiver_id !== ref.receiver_id
        || binding.receiver_profile_version_id !== ref.receiver_profile_version_id
        || Math.floor(binding.expires_at.getTime() / 1000) !== ref.expires_at
        || bindingDigest(binding, proofs) !== ref.binding_digest) {
        throw new ForbiddenError('authority reference changed before Passport issuance');
      }
    }
    await executor.insert(passportAuthorityBindings).values(input.refs.map((ref) => ({
      passport_jti: input.passportJti, operator_id: input.operatorId, binding_id: ref.binding_id,
      binding_version: ref.binding_version, binding_claim_id: ref.binding_claim_id,
    }))).onConflictDoNothing();
  }

  async listPassportRefs(operatorId: string, passportJti: string) {
    const links = await this.db.select({ link: passportAuthorityBindings, binding: authorityBindings })
      .from(passportAuthorityBindings).innerJoin(authorityBindings, and(
        eq(passportAuthorityBindings.binding_id, authorityBindings.id),
        eq(passportAuthorityBindings.binding_version, authorityBindings.version),
        eq(passportAuthorityBindings.operator_id, authorityBindings.operator_id),
      )).where(and(eq(passportAuthorityBindings.operator_id, operatorId), eq(passportAuthorityBindings.passport_jti, passportJti)));
    const refs: AuthorityReference[] = [];
    for (const item of links) {
      const binding = bindingRow(item.binding);
      const proofs = await this.repo.listBindingProofs(operatorId, binding.id, binding.version);
      refs.push({
        binding_id: binding.id, binding_version: binding.version, binding_claim_id: item.link.binding_claim_id,
        binding_digest: bindingDigest(binding, proofs), receiver_id: binding.receiver_id,
        receiver_profile_version_id: binding.receiver_profile_version_id,
        expires_at: Math.floor(binding.expires_at.getTime() / 1000),
      });
    }
    return refs;
  }

  async listPassportRefsForPassports(operatorId: string, passportJtis: string[]) {
    const uniqueJtis = [...new Set(passportJtis)];
    const refsByPassport = new Map<string, AuthorityReference[]>(
      uniqueJtis.map((passportJti) => [passportJti, []]),
    );
    if (uniqueJtis.length === 0) return refsByPassport;

    const links = await this.db.select({ link: passportAuthorityBindings, binding: authorityBindings })
      .from(passportAuthorityBindings).innerJoin(authorityBindings, and(
        eq(passportAuthorityBindings.binding_id, authorityBindings.id),
        eq(passportAuthorityBindings.binding_version, authorityBindings.version),
        eq(passportAuthorityBindings.operator_id, authorityBindings.operator_id),
      )).where(and(
        eq(passportAuthorityBindings.operator_id, operatorId),
        inArray(passportAuthorityBindings.passport_jti, uniqueJtis),
      )).orderBy(
        asc(passportAuthorityBindings.passport_jti),
        asc(passportAuthorityBindings.binding_id),
        asc(passportAuthorityBindings.binding_version),
      );

    const bindingPairs = [...new Map(links.map(({ link }) => [
      `${link.binding_id}:${link.binding_version}`,
      { id: link.binding_id, version: link.binding_version },
    ])).values()];
    const proofRows = bindingPairs.length === 0 ? [] : await this.db.select()
      .from(authorityBindingProofs)
      .where(and(
        eq(authorityBindingProofs.operator_id, operatorId),
        or(...bindingPairs.map(({ id, version }) => and(
          eq(authorityBindingProofs.binding_id, id),
          eq(authorityBindingProofs.binding_version, version),
        ))),
      )).orderBy(
        asc(authorityBindingProofs.binding_id),
        asc(authorityBindingProofs.binding_version),
        asc(authorityBindingProofs.ordinal),
      ) as AuthorityBindingProofRecord[];
    const proofsByBinding = new Map<string, AuthorityBindingProofRecord[]>();
    for (const proof of proofRows) {
      const key = `${proof.binding_id}:${proof.binding_version}`;
      const proofs = proofsByBinding.get(key) ?? [];
      proofs.push(proof);
      proofsByBinding.set(key, proofs);
    }

    for (const item of links) {
      const binding = bindingRow(item.binding);
      const proofs = proofsByBinding.get(`${binding.id}:${binding.version}`) ?? [];
      refsByPassport.get(item.link.passport_jti)!.push({
        binding_id: binding.id,
        binding_version: binding.version,
        binding_claim_id: item.link.binding_claim_id,
        binding_digest: bindingDigest(binding, proofs),
        receiver_id: binding.receiver_id,
        receiver_profile_version_id: binding.receiver_profile_version_id,
        expires_at: Math.floor(binding.expires_at.getTime() / 1000),
      });
    }
    return refsByPassport;
  }
}
