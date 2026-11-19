import { and, eq, sql } from 'drizzle-orm';
import {
  ForbiddenError,
  agents,
  authorityApprovalDecisions,
  authorityApprovalRequests,
  authorityBindingProofs,
  authorityBindings,
  authorityPrincipals,
  authorityProfileVersions,
  authorityProofDependencies,
  authorityProofs,
  authorityPresentations,
  authorityReceivers,
  authorityUses,
  missions,
  passportAuthorityBindings,
  passportClaims,
  passports,
  receiverTransactionReceipts,
} from '@stack/shared';
import type { ReceiverTransactionReceiptRecord } from '../../services/authority/records.js';
import { AuthorityAggregateRepository } from './context.js';
import { receiptRow } from './rows.js';

/** Receiver transaction receipts, and the locks taken to finalise one against a still-valid authority graph. */
export class AuthorityReceiptRepository extends AuthorityAggregateRepository {
  async insertReceiverReceipt(row: ReceiverTransactionReceiptRecord) {
    const [created] = await this.db.insert(receiverTransactionReceipts).values(row).returning();
    return receiptRow(created!);
  }

  async findReceiverReceiptByPresentation(receiverId: string, presentationId: string) {
    const [row] = await this.db.select().from(receiverTransactionReceipts).where(and(
      eq(receiverTransactionReceipts.receiver_id, receiverId), eq(receiverTransactionReceipts.presentation_id, presentationId),
    )).limit(1);
    return row ? receiptRow(row) : null;
  }

  async lockReceiptAuthorityGraph(receiverId: string, presentationId: string, now: Date) {
    if (!this.transaction) return this.atomic((repo) => repo.lockReceiptAuthorityGraph(receiverId, presentationId, now));
    const tx = this.transaction;
    const [route] = await tx.select({ operatorId: authorityPresentations.operator_id })
      .from(authorityPresentations).where(and(eq(authorityPresentations.receiver_id, receiverId),
        eq(authorityPresentations.id, presentationId))).limit(1);
    if (!route) return null;
    await this.lockOperatorAuthorityGraph(route.operatorId);

    await tx.execute(sql`select id from ${authorityPresentations}
      where operator_id=${route.operatorId} and receiver_id=${receiverId} and id=${presentationId} for update`);
    const presentation = await this.repo.findPresentation(receiverId, presentationId);
    if (!presentation) return null;
    await tx.execute(sql`select id from ${authorityUses}
      where operator_id=${route.operatorId} and id=${presentation.authority_use_id} for update`);
    const use = await this.repo.findAuthorityUseById(receiverId, presentation.authority_use_id);
    if (!use) return null;
    await tx.execute(sql`select id from ${authorityBindings}
      where operator_id=${route.operatorId} and id=${use.binding_id} and version=${use.binding_version} for share`);
    const binding = await this.repo.findBinding(route.operatorId, use.binding_id, use.binding_version);
    if (!binding) return null;
    const nowIso = now.toISOString();
    const presentationExpiresAtIso = presentation.expires_at.toISOString();

    const invalid = await tx.execute(sql<{ invalid: boolean }>`
      with recursive ancestry as (
        select b.* from ${authorityBindings} b
        where b.operator_id=${route.operatorId} and b.id=${binding.id} and b.version=${binding.version}
        union all
        select parent.* from ${authorityBindings} parent join ancestry child
          on parent.operator_id=child.operator_id and parent.id=child.parent_binding_id
          and parent.version=child.parent_binding_version
      ), required_proofs as (
        select p.* from ancestry b join ${authorityBindingProofs} link
          on link.operator_id=b.operator_id and link.binding_id=b.id and link.binding_version=b.version
          and link.required=true
        join ${authorityProofs} p on p.operator_id=link.operator_id
          and p.id=link.proof_id and p.version=link.proof_version
      ), all_required_proofs as (
        select * from required_proofs
        union
        select source.* from ${authorityProofDependencies} dep join all_required_proofs derived
          on dep.operator_id=derived.operator_id and dep.derived_proof_id=derived.id
          and dep.derived_proof_version=derived.version
        join ${authorityProofs} source on source.operator_id=dep.operator_id
          and source.id=dep.source_proof_id and source.version=dep.source_proof_version
      )
      select (
        ${presentation.status}<>'delivered'
        or ${presentationExpiresAtIso}::timestamptz<=${nowIso}::timestamptz
        or ${presentation.request_payload_encrypted}::text is null
        or ${use.status}<>'dispatched'
        or exists(select 1 from ancestry b where b.status<>'active'
          or b.valid_from>${nowIso}::timestamptz or b.expires_at<=${nowIso}::timestamptz
          or b.erased_at is not null or b.claim_id is null)
        or exists(select 1 from ancestry b left join ${authorityPrincipals} principal
          on principal.operator_id=b.operator_id and principal.id=b.principal_id
          where principal.id is null or principal.status<>'active')
        or exists(select 1 from ancestry b left join ${agents} agent
          on agent.operator_id=b.operator_id and agent.id=b.agent_id
          where agent.id is null or agent.status<>'active')
        or exists(select 1 from ancestry b join unnest(b.mission_ids) as mission_ref(mission_id) on true
          left join ${missions} mission on mission.operator_id=b.operator_id
            and mission.mission_id=mission_ref.mission_id
          where mission.mission_id is null or mission.revoked_at is not null or mission.completed_at is not null
            or mission.expires_at<=${nowIso}::timestamptz)
        or exists(select 1 from all_required_proofs p where p.status<>'active'
          or p.valid_from>${nowIso}::timestamptz
          or (p.expires_at is not null and p.expires_at<=${nowIso}::timestamptz)
          or p.erased_at is not null or p.claim_id is null)
        or exists(select 1 from all_required_proofs p left join ${authorityPrincipals} subject
          on subject.operator_id=p.operator_id and subject.id=p.subject_principal_id
          where subject.id is null or subject.status<>'active')
        or exists(select 1 from ancestry b join ${authorityBindingProofs} link
          on link.operator_id=b.operator_id and link.binding_id=b.id and link.binding_version=b.version
          and link.required=true and link.authoriser_principal_id is not null
          left join ${authorityPrincipals} authoriser on authoriser.operator_id=link.operator_id
            and authoriser.id=link.authoriser_principal_id
          where authoriser.id is null or authoriser.status<>'active')
        or exists(select 1 from ancestry b left join ${passportClaims} claim
          on claim.operator_id=b.operator_id and claim.claim_id=b.claim_id and claim.type='authority_binding'
          where claim.claim_id is null or claim.revoked_at is not null
            or claim.body_json->>'binding_id'<>b.id
            or (claim.body_json->>'binding_version')::integer<>b.version
            or claim.body_json->>'status'<>'active')
        or exists(select 1 from all_required_proofs p left join ${passportClaims} claim
          on claim.operator_id=p.operator_id and claim.claim_id=p.claim_id and claim.type='external_proof_verification'
          where claim.claim_id is null or claim.revoked_at is not null
            or claim.body_json->>'proof_id'<>p.id
            or (claim.body_json->>'proof_version')::integer<>p.version
            or claim.body_json->>'status'<>'active')
        or not exists(select 1 from ${passportClaims} claim where claim.operator_id=${route.operatorId}
          and claim.type='authority_use' and claim.body_json->>'authority_use_id'=${use.id}
          and claim.body_json->>'binding_id'=${binding.id}
          and (claim.body_json->>'binding_version')::integer=${binding.version}
          and claim.body_json->>'request_hash'=${use.request_hash}
          and claim.body_json->>'action_uri'=${use.action_uri}
          and claim.body_json->>'status' in ('authorized','dispatched') and claim.revoked_at is null)
        or not exists(select 1 from ${passports} passport join ${passportAuthorityBindings} link
          on link.operator_id=passport.operator_id and link.passport_jti=passport.jti
          where passport.operator_id=${route.operatorId} and passport.jti=${use.passport_jti}
            and passport.agent_id=${use.agent_id} and passport.revoked_at is null
            and passport.expires_at>${nowIso}::timestamptz
            and link.binding_id=${binding.id} and link.binding_version=${binding.version})
        or not exists(select 1 from ${authorityReceivers} receiver where receiver.id=${receiverId}
          and receiver.managed_by_operator_id=${route.operatorId} and receiver.status='active'
          and receiver.current_profile_version_id=${binding.receiver_profile_version_id})
        or not exists(select 1 from ${authorityProfileVersions} profile
          where profile.id=${binding.receiver_profile_version_id} and profile.profile_kind='receiver'
            and profile.status='active' and (profile.owner_operator_id is null or profile.owner_operator_id=${route.operatorId}))
        or (${binding.domain_profile_version_id}::text is not null and not exists(select 1 from ${authorityProfileVersions} profile
          where profile.id=${binding.domain_profile_version_id} and profile.profile_kind='domain'
            and profile.status='active' and (profile.owner_operator_id is null or profile.owner_operator_id=${route.operatorId})))
        or exists(select 1 from all_required_proofs p left join ${authorityProfileVersions} profile
          on profile.id=p.profile_version_id and profile.profile_kind='proof'
          and (profile.owner_operator_id is null or profile.owner_operator_id=p.operator_id)
          where profile.id is null or profile.status<>'active')
        or exists(select 1 from ${authorityApprovalRequests} req
          where req.operator_id=${route.operatorId} and req.binding_id=${binding.id}
            and req.binding_version=${binding.version}
            and (req.phase='activation' or req.authority_use_id=${use.id})
            and (req.status not in ('satisfied','consumed') or req.collected_weight<req.required_weight
              or req.expires_at<=${nowIso}::timestamptz))
        or exists(select 1 from ${authorityApprovalDecisions} decision
          join ${authorityApprovalRequests} req on req.operator_id=decision.operator_id and req.id=decision.request_id
          left join ${passportClaims} claim on claim.operator_id=decision.operator_id
            and claim.type='authority_approval' and claim.body_json->>'decision_id'=decision.id
          where req.operator_id=${route.operatorId} and req.binding_id=${binding.id}
            and req.binding_version=${binding.version} and (req.phase='activation' or req.authority_use_id=${use.id})
            and (decision.revoked_at is not null
              or (decision.expires_at is not null and decision.expires_at<=${nowIso}::timestamptz)
              or claim.claim_id is null or claim.revoked_at is not null))
      ) as invalid`);
    if (invalid[0]?.invalid === true) throw new ForbiddenError('receiver receipt authority graph is no longer valid');
    return { presentation, use, binding };
  }

  async lockPresentationAndUseForReceipt(receiverId: string, presentationId: string) {
    if (!this.transaction) {
      return this.atomic((repo) => repo.lockPresentationAndUseForReceipt(receiverId, presentationId));
    }
    await this.transaction.execute(sql`select id from ${authorityPresentations}
      where receiver_id=${receiverId} and id=${presentationId} for update`);
    const presentation = await this.repo.findPresentation(receiverId, presentationId);
    if (!presentation) return null;
    await this.transaction.execute(sql`select id from ${authorityUses}
      where id=${presentation.authority_use_id} and receiver_id=${receiverId}
        and operator_id=${presentation.operator_id} for update`);
    const use = await this.repo.findAuthorityUseById(receiverId, presentation.authority_use_id);
    return use && use.operator_id === presentation.operator_id ? { presentation, use } : null;
  }
}
