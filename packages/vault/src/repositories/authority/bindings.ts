import { createHash } from 'node:crypto';
import { and, asc, desc, eq, gt, inArray, isNull, lte, or, sql } from 'drizzle-orm';
import {
  ConflictError,
  agents,
  authorityBindingProofs,
  authorityBindings,
  authorityPrincipals,
  authorityProofs,
  authorityReceivers,
  missions,
  passportAuthorityBindings,
  passportClaims,
  passports,
} from '@stack/shared';
import type {
  AuthorityBindingProofRecord,
  AuthorityBindingRecord,
  AuthorityPrincipalRecord,
} from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { bindingRow, proofRow, receiverRow } from './rows.js';

function agentThumbprint(jwk: { kty: string; crv: string; x: string }): string {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !/^[A-Za-z0-9_-]+$/.test(jwk.x)) {
    throw new ConflictError('authority agent has no valid public Ed25519 proof-of-possession key');
  }
  return `sha256:${createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest('hex')}`;
}

/** Authority bindings, their proof links, and the agent, mission and passport checks made against them. */
export class AuthorityBindingRepository extends AuthorityAggregateRepository {
  async lockBindingGraphForDisclosure(operatorId: string, bindingId: string, bindingVersion: number): Promise<void> {
    if (!this.transaction) {
      await this.atomic((repo) => repo.lockBindingGraphForDisclosure(operatorId, bindingId, bindingVersion));
      return;
    }
    await this.lockOperatorAuthorityGraph(operatorId);
    await this.transaction.execute(sql`select id from ${authorityBindings}
      where operator_id=${operatorId} and id=${bindingId} and version=${bindingVersion} for share`);
  }

  async listAccountRecordBindings(operatorId: string, kind: 'principals' | 'proofs' | 'receivers', recordId: string,
    version: number | undefined, page: number, limit: number) {
    // EXISTS keeps each binding version once even when multiple proof roles refer to the selected record.
    const linkedProof = (condition: ReturnType<typeof eq>) => sql`exists (
      select 1 from ${authorityBindingProofs}
      where ${authorityBindingProofs.operator_id} = ${operatorId}
        and ${authorityBindingProofs.binding_id} = ${authorityBindings.id}
        and ${authorityBindingProofs.binding_version} = ${authorityBindings.version}
        and ${condition})`;
    const association = kind === 'receivers' ? eq(authorityBindings.receiver_id, recordId)
      : kind === 'principals' ? or(eq(authorityBindings.principal_id, recordId),
        linkedProof(eq(authorityBindingProofs.authoriser_principal_id, recordId)))
      : linkedProof(and(eq(authorityBindingProofs.proof_id, recordId), eq(authorityBindingProofs.proof_version, version!))!);
    const rows = await this.db.select().from(authorityBindings)
      .where(and(eq(authorityBindings.operator_id, operatorId), association))
      .orderBy(desc(authorityBindings.created_at), asc(authorityBindings.id), desc(authorityBindings.version))
      .limit(limit + 1).offset((page - 1) * limit);
    return rows.map(bindingRow);
  }

  async resolveCurrentAgentKey(operatorId: string, agentId: string) {
    const [row] = await this.db.select({ pubkey: agents.pubkey, status: agents.status }).from(agents).where(and(
      eq(agents.operator_id, operatorId), eq(agents.id, agentId),
    )).limit(1);
    if (!row?.pubkey) return null;
    return { thumbprint: agentThumbprint(row.pubkey), active: row.status === 'active', publicJwk: row.pubkey };
  }

  async isMissionActive(operatorId: string, missionId: string) {
    const [row] = await this.db.select({ id: missions.mission_id }).from(missions).where(and(
      eq(missions.operator_id, operatorId), eq(missions.mission_id, missionId), isNull(missions.completed_at),
      isNull(missions.revoked_at), gt(missions.expires_at, new Date()),
    )).limit(1);
    return Boolean(row);
  }

  async insertBinding(row: AuthorityBindingRecord, proofs: AuthorityBindingProofRecord[]) {
    if (!this.transaction) return this.atomic((repo) => repo.insertBinding(row, proofs));
    await this.lockOperatorAuthorityGraph(row.operator_id);
    const [created] = await this.db.insert(authorityBindings).values({
      id: row.id, version: row.version, operator_id: row.operator_id, principal_id: row.principal_id,
      agent_id: row.agent_id, agent_key_thumbprint: row.agent_key_thumbprint, receiver_id: row.receiver_id,
      receiver_profile_version_id: row.receiver_profile_version_id, domain_profile_version_id: row.domain_profile_version_id,
      mission_ids: row.mission_ids, lineage_root_id: row.lineage_root_id, lineage_root_version: row.lineage_root_version,
      parent_binding_id: row.parent_binding_id, parent_binding_version: row.parent_binding_version,
      delegation_depth: row.delegation_depth, purpose_code: row.purpose_code,
      purpose_statement_encrypted: row.purpose_statement_encrypted, purpose_hash: row.purpose_hash,
      scope_encrypted: row.scope_encrypted, scope_hash: row.scope_hash,
      approval_policy_encrypted: row.approval_policy_encrypted, approval_policy_hash: row.approval_policy_hash,
      disclosure_policy_encrypted: row.disclosure_policy_encrypted, disclosure_policy_hash: row.disclosure_policy_hash,
      delegation_policy: row.delegation_policy, delegation_policy_hash: row.delegation_policy_hash,
      proof_set_hash: row.proof_set_hash, valid_from: row.valid_from, expires_at: row.expires_at,
      status: row.status, claim_id: row.claim_id, created_at: row.created_at, activated_at: row.activated_at,
      revoked_at: row.revoked_at, revoked_reason: row.revoked_reason,
      erased_at: row.erased_at, tombstone_hash: row.tombstone_hash,
      tombstone_claim_id: row.tombstone_claim_id,
    }).returning();
    if (proofs.length > 0) await this.db.insert(authorityBindingProofs).values(proofs.map((proof) => ({
      ...proof, operator_id: row.operator_id,
    })));
    return bindingRow(created!);
  }

  async listBindings(operatorId: string) {
    const rows = await this.db.select({ binding: authorityBindings, claim_hash: passportClaims.claim_hash })
      .from(authorityBindings).leftJoin(passportClaims, eq(authorityBindings.claim_id, passportClaims.claim_id))
      .where(eq(authorityBindings.operator_id, operatorId)).orderBy(desc(authorityBindings.created_at));
    return rows.map((row) => bindingRow({ ...row.binding, claim_hash: row.claim_hash }));
  }

  async listAgentBindings(operatorId: string, agentId: string, page: number, limit: number,
    binding?: { id: string; version: number }) {
    // Bindings carry their own agent association. Do not restrict this history to
    // live Passports or select an account-wide page before applying the agent filter.
    const conditions = [eq(authorityBindings.operator_id, operatorId), eq(authorityBindings.agent_id, agentId)];
    if (binding) conditions.push(eq(authorityBindings.id, binding.id), eq(authorityBindings.version, binding.version));
    const rows = await this.db.select({ binding: authorityBindings, claim_hash: passportClaims.claim_hash })
      .from(authorityBindings).leftJoin(passportClaims, and(
        eq(authorityBindings.claim_id, passportClaims.claim_id),
        eq(passportClaims.operator_id, operatorId),
      )).where(and(...conditions))
      .orderBy(desc(authorityBindings.created_at), asc(authorityBindings.id), desc(authorityBindings.version))
      .limit(limit + 1).offset((page - 1) * limit);
    const bindings = rows.slice(0, limit).map((row) => bindingRow({ ...row.binding, claim_hash: row.claim_hash }));
    if (bindings.length === 0) return { bindings, links: [], principals: [], receivers: [], proofs: [], has_more: false };
    const links = await this.db.select().from(authorityBindingProofs).where(and(
      eq(authorityBindingProofs.operator_id, operatorId),
      or(...bindings.map((binding) => and(eq(authorityBindingProofs.binding_id, binding.id),
        eq(authorityBindingProofs.binding_version, binding.version)))),
    )).orderBy(asc(authorityBindingProofs.ordinal));
    const principalIds = [...new Set([...bindings.map((binding) => binding.principal_id),
      ...links.flatMap((link) => link.authoriser_principal_id ? [link.authoriser_principal_id] : [])])];
    const [principalRows, receiverRows, proofRows] = await Promise.all([
      this.db.select().from(authorityPrincipals).where(and(eq(authorityPrincipals.operator_id, operatorId),
        inArray(authorityPrincipals.id, principalIds))),
      this.db.select().from(authorityReceivers).where(and(eq(authorityReceivers.managed_by_operator_id, operatorId),
        inArray(authorityReceivers.id, [...new Set(bindings.map((binding) => binding.receiver_id))]))),
      links.length === 0 ? Promise.resolve([]) : this.db.select().from(authorityProofs).where(and(
        eq(authorityProofs.operator_id, operatorId),
        or(...links.map((link) => and(eq(authorityProofs.id, link.proof_id), eq(authorityProofs.version, link.proof_version)))),
      )),
    ]);
    return {
      bindings, links: links as AuthorityBindingProofRecord[],
      principals: principalRows as AuthorityPrincipalRecord[],
      receivers: receiverRows.map(receiverRow), proofs: proofRows.map(proofRow), has_more: rows.length > limit,
    };
  }

  async findBinding(operatorId: string, bindingId: string, version?: number) {
    const conditions = [eq(authorityBindings.operator_id, operatorId), eq(authorityBindings.id, bindingId)];
    if (version !== undefined) conditions.push(eq(authorityBindings.version, version));
    const [row] = await this.db.select({ binding: authorityBindings, claim_hash: passportClaims.claim_hash })
      .from(authorityBindings).leftJoin(passportClaims, and(
        eq(authorityBindings.claim_id, passportClaims.claim_id),
        eq(passportClaims.operator_id, operatorId),
      )).where(and(...conditions)).orderBy(desc(authorityBindings.version)).limit(1);
    return row ? bindingRow({ ...row.binding, claim_hash: row.claim_hash }) : null;
  }

  async listBindingProofs(operatorId: string, bindingId: string, version: number) {
    return (await this.db.select().from(authorityBindingProofs).where(and(
      eq(authorityBindingProofs.operator_id, operatorId), eq(authorityBindingProofs.binding_id, bindingId),
      eq(authorityBindingProofs.binding_version, version),
    )).orderBy(authorityBindingProofs.ordinal)).map((row) => ({
      ...row,
    })) as AuthorityBindingProofRecord[];
  }

  async activateBinding(input: { operatorId: string; bindingId: string; version: number; claimId: string; claimHash: string; now: Date }) {
    const [row] = await this.db.update(authorityBindings).set({ status: 'active', claim_id: input.claimId, activated_at: input.now })
      .where(and(eq(authorityBindings.operator_id, input.operatorId), eq(authorityBindings.id, input.bindingId),
        eq(authorityBindings.version, input.version), inArray(authorityBindings.status, ['draft', 'pending_approval'])))
      .returning();
    return row ? bindingRow({ ...row, claim_hash: input.claimHash }) : null;
  }

  async isBindingInAgentChain(operatorId: string, bindingId: string, version: number, agentId: string) {
    const rows = await this.db.execute(sql<{ allowed: boolean }>`
      with recursive chain as (
        select * from ${authorityBindings} where operator_id=${operatorId} and id=${bindingId} and version=${version}
        union all
        select p.* from ${authorityBindings} p join chain c
          on p.id=c.parent_binding_id and p.version=c.parent_binding_version and p.operator_id=c.operator_id
      ) select exists(select 1 from chain where agent_id=${agentId}) as allowed`);
    return rows[0]?.allowed === true;
  }

  async isPassportAuthorizedForBinding(input: {
    operatorId: string; passportJti: string; agentId: string; bindingId: string; bindingVersion: number; now: Date;
  }) {
    const [row] = await this.db.select({ jti: passports.jti }).from(passports)
      .innerJoin(passportAuthorityBindings, and(
        eq(passportAuthorityBindings.passport_jti, passports.jti),
        eq(passportAuthorityBindings.operator_id, passports.operator_id),
      )).innerJoin(authorityBindings, and(
        eq(authorityBindings.operator_id, passportAuthorityBindings.operator_id),
        eq(authorityBindings.id, passportAuthorityBindings.binding_id),
        eq(authorityBindings.version, passportAuthorityBindings.binding_version),
        eq(authorityBindings.claim_id, passportAuthorityBindings.binding_claim_id),
      )).where(and(eq(passports.operator_id, input.operatorId), eq(passports.jti, input.passportJti),
        eq(passports.agent_id, input.agentId), isNull(passports.revoked_at), gt(passports.expires_at, input.now),
        eq(passportAuthorityBindings.binding_id, input.bindingId),
        eq(passportAuthorityBindings.binding_version, input.bindingVersion),
        eq(authorityBindings.status, 'active'), lte(authorityBindings.valid_from, input.now),
        gt(authorityBindings.expires_at, input.now))).limit(1);
    return Boolean(row);
  }
}
