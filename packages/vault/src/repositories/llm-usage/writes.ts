// llm_usage writes. An insert is idempotent on its id. When the row owes a wallet fee, `afterInsert`
// (a deployment with a wallet credits its fee accumulator) runs in the same transaction, only for a
// row that was new.

import { llmUsage, type Database } from '@stack/shared';
import { type InsertLlmUsageInput, type LlmUsageTransaction } from './types.js';

export async function insert(
  db: Database,
  input: InsertLlmUsageInput,
  afterInsert: (tx: LlmUsageTransaction, input: InsertLlmUsageInput) => Promise<void>,
): Promise<void> {
  const walletFeeMicrocents = input.wallet_fee_microcents ?? null;
  if (
    walletFeeMicrocents !== null &&
    (!Number.isSafeInteger(walletFeeMicrocents) || walletFeeMicrocents < 0)
  ) {
    throw new Error(
      `LLM wallet fee must be a non-negative safe integer, got ${walletFeeMicrocents}`,
    );
  }
  if (((input.wallet_fee_kind ?? null) === null) !== (walletFeeMicrocents === null)) {
    throw new Error('LLM wallet fee kind and microcents must both be present or both be null');
  }

  await db.transaction(async (tx) => {
    const [inserted] = await tx
      .insert(llmUsage)
      .values({
        id: input.id,
        operator_id: input.operator_id,
        agent_id: input.agent_id,
        passport_jti: input.passport_jti,
        mission_id: input.mission_id,
        provider: input.provider,
        model: input.model,
        prompt_tokens: input.prompt_tokens,
        completion_tokens: input.completion_tokens,
        total_tokens: input.total_tokens,
        provider_cost_cents: input.provider_cost_cents,
        markup_cents: input.markup_cents,
        total_cost_cents: input.total_cost_cents,
        provider_cost_microcents: input.provider_cost_microcents,
        markup_microcents: input.markup_microcents,
        total_cost_microcents: input.total_cost_microcents,
        cost_basis: input.cost_basis,
        cached_prompt_tokens: input.cached_prompt_tokens,
        wallet_debited: input.wallet_debited,
        surface: input.surface,
        provider_payer: input.provider_payer,
        stack_fee_payer: input.stack_fee_payer,
        wallet_hold_id: input.wallet_hold_id,
        wallet_fee_kind: input.wallet_fee_kind ?? null,
        wallet_fee_microcents: walletFeeMicrocents,
        wallet_fee_microcents_remaining: walletFeeMicrocents,
        skill_id: input.skill_id ?? null,
        invocation_id: input.invocation_id ?? null,
        sealed_step_index: input.sealed_step_index ?? null,
        streaming: input.streaming,
      })
      .onConflictDoNothing({ target: llmUsage.id })
      .returning({ id: llmUsage.id });
    if (!inserted) return;
    if (input.wallet_fee_kind && walletFeeMicrocents !== null) await afterInsert(tx, input);
  });
}
