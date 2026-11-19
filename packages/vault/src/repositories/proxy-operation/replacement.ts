// Replacement acknowledgements: the one-shot human authorization to repeat an unresolved external
// effect, and the guard that consumes it inside the replacement dispatch transaction.

import { and, eq, inArray, ne, or, sql } from 'drizzle-orm';
import { proxyOperationReplacementAcknowledgements, proxyOperations } from '@stack/shared';
import { governanceOperationIsCurrent, lockOperationByKey } from './internals.js';
import {
  type ProxyOperationTransaction,
  type ProxyOperationReplacementAcknowledgement,
} from './types.js';
import { operationHasUnresolvedEffect } from './internals.js';

export async function createReplacementAcknowledgement(input: {
  id: string;
  operatorId: string;
  originalOperationKeyHash: string;
  replacementOperationKeyHash: string;
  warningVersion: number;
  warningText: string;
  warningHash: string;
  humanAuthorKind: 'operator_owner' | 'team_member';
  humanAuthorId: string;
  dashboardSessionFamilyId: string;
  dashboardSessionTokenHash: string;
  acknowledgedAt?: Date;
}, transaction: ProxyOperationTransaction): Promise<{
  state: 'created' | 'existing' | 'conflict' | 'unavailable';
  acknowledgement?: ProxyOperationReplacementAcknowledgement;
}> {
  const original = await lockOperationByKey(
    transaction,
    input.operatorId,
    input.originalOperationKeyHash,
  );
  if (!original || !operationHasUnresolvedEffect(original)) {
    return { state: 'unavailable' };
  }
  if (!await governanceOperationIsCurrent(transaction, original)) {
    return { state: 'unavailable' };
  }
  const replacement = await lockOperationByKey(
    transaction,
    input.operatorId,
    input.replacementOperationKeyHash,
  );
  if (!replacement || replacement.delivery_state !== 'admitted'
    || replacement.replay_state !== 'none'
    || replacement.effect_correlation_hash !== original.effect_correlation_hash) {
    return { state: 'unavailable' };
  }
  const replacementRequestHash = replacement.request_hash;
  const existing = await transaction.query.proxyOperationReplacementAcknowledgements.findFirst({
    where: or(
      and(
        eq(proxyOperationReplacementAcknowledgements.operator_id, input.operatorId),
        eq(proxyOperationReplacementAcknowledgements.original_operation_id, original.id),
      ),
      and(
        eq(proxyOperationReplacementAcknowledgements.operator_id, input.operatorId),
        eq(proxyOperationReplacementAcknowledgements.replacement_operation_key_hash, input.replacementOperationKeyHash),
      ),
    ),
  });
  if (existing) {
    const same = existing.original_operation_id === original.id
      && existing.replacement_operation_key_hash === input.replacementOperationKeyHash
      && existing.replacement_request_hash === replacementRequestHash
      && existing.warning_version === input.warningVersion
      && existing.warning_text === input.warningText
      && existing.warning_hash === input.warningHash
      && existing.human_author_kind === input.humanAuthorKind
      && existing.human_author_id === input.humanAuthorId
      && existing.dashboard_session_family_id === input.dashboardSessionFamilyId
      && existing.dashboard_session_token_hash === input.dashboardSessionTokenHash;
    return { state: same ? 'existing' : 'conflict', acknowledgement: existing };
  }
  const [created] = await transaction.insert(proxyOperationReplacementAcknowledgements).values({
    id: input.id,
    operator_id: input.operatorId,
    original_operation_id: original.id,
    replacement_operation_key_hash: input.replacementOperationKeyHash,
    replacement_request_hash: replacementRequestHash,
    warning_version: input.warningVersion,
    warning_text: input.warningText,
    warning_hash: input.warningHash,
    human_author_kind: input.humanAuthorKind,
    human_author_id: input.humanAuthorId,
    dashboard_session_family_id: input.dashboardSessionFamilyId,
    dashboard_session_token_hash: input.dashboardSessionTokenHash,
    acknowledged_at: input.acknowledgedAt ?? new Date(),
  }).returning();
  return created ? { state: 'created', acknowledgement: created } : { state: 'conflict' };
}

/**
 * A fresh handle may not silently repeat an unresolved external effect. The
 * matching prior row and the one-shot human acknowledgement are locked and
 * checked in the same transaction that will claim the replacement dispatch.
 */
export async function guardAndConsumeReplacement(input: {
  operatorId: string;
  replacementOperationId: string;
  replacementOperationKeyHash: string;
  replacementRequestHash: string;
  effectCorrelationHash: string;
}, transaction: ProxyOperationTransaction): Promise<
  | { state: 'not_required' }
  | { state: 'consumed'; originalOperationId: string }
  | { state: 'authorization_required' }
  | { state: 'ambiguous' }
> {
  const prior = await transaction.select({ id: proxyOperations.id })
    .from(proxyOperations)
    .where(and(
      eq(proxyOperations.operator_id, input.operatorId),
      eq(proxyOperations.effect_correlation_hash, input.effectCorrelationHash),
      ne(proxyOperations.id, input.replacementOperationId),
      or(
        and(
          eq(proxyOperations.delivery_state, 'outcome_unknown'),
          or(
            ne(proxyOperations.reconciliation_state, 'confirmed'),
            inArray(proxyOperations.reconciliation_provider_status, ['pending', 'requires_action']),
          ),
          ne(proxyOperations.reconciliation_state, 'contradictory'),
        ),
        and(
          eq(proxyOperations.adapter_kind, 'stripe'),
          eq(proxyOperations.delivery_state, 'response_received'),
          or(
            inArray(proxyOperations.reconciliation_state, ['pending', 'not_found', 'expired']),
            and(
              eq(proxyOperations.reconciliation_state, 'confirmed'),
              inArray(proxyOperations.reconciliation_provider_status, ['pending', 'requires_action']),
            ),
          ),
        ),
      ),
    ))
    .for('update');
  if (prior.length === 0) return { state: 'not_required' };
  if (prior.length !== 1) return { state: 'ambiguous' };

  const [consumed] = await transaction.update(proxyOperationReplacementAcknowledgements).set({
    consumed_at: new Date(),
    consumed_by_operation_id: input.replacementOperationId,
  }).where(and(
    eq(proxyOperationReplacementAcknowledgements.operator_id, input.operatorId),
    eq(proxyOperationReplacementAcknowledgements.original_operation_id, prior[0]!.id),
    eq(proxyOperationReplacementAcknowledgements.replacement_operation_key_hash, input.replacementOperationKeyHash),
    eq(proxyOperationReplacementAcknowledgements.replacement_request_hash, input.replacementRequestHash),
    sql`${proxyOperationReplacementAcknowledgements.consumed_at} is null`,
    sql`${proxyOperationReplacementAcknowledgements.consumed_by_operation_id} is null`,
  )).returning({ originalOperationId: proxyOperationReplacementAcknowledgements.original_operation_id });
  return consumed
    ? { state: 'consumed', originalOperationId: consumed.originalOperationId }
    : { state: 'authorization_required' };
}

/** Consume only the exact request the human saw, in the replacement dispatch transaction. */
export async function consumeReplacementAcknowledgement(input: {
  operatorId: string;
  replacementOperationKeyHash: string;
  replacementRequestHash: string;
  replacementOperationId: string;
}, transaction: ProxyOperationTransaction): Promise<ProxyOperationReplacementAcknowledgement | null> {
  const [consumed] = await transaction.update(proxyOperationReplacementAcknowledgements).set({
    consumed_at: new Date(),
    consumed_by_operation_id: input.replacementOperationId,
  }).where(and(
    eq(proxyOperationReplacementAcknowledgements.operator_id, input.operatorId),
    eq(proxyOperationReplacementAcknowledgements.replacement_operation_key_hash, input.replacementOperationKeyHash),
    eq(proxyOperationReplacementAcknowledgements.replacement_request_hash, input.replacementRequestHash),
    sql`${proxyOperationReplacementAcknowledgements.consumed_at} is null`,
    sql`${proxyOperationReplacementAcknowledgements.consumed_by_operation_id} is null`,
  )).returning();
  return consumed ?? null;
}
