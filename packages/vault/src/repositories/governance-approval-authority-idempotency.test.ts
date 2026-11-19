import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  createDb,
  governanceApprovals,
  operators,
  sha256,
  type Database,
} from '@stack/shared';
import { GovernanceApprovalRepository } from './governance-approval-repo.js';

const DATABASE_URL = process.env.DATABASE_URL ?? process.env.STACK_TEST_DATABASE_URL;
const RUN = Date.now().toString(36);
const OPERATOR_ID = `op_gvr_authority_${RUN}`;
const APPROVAL_ID = `gvr_authority_${RUN}`;
const PAYLOAD_HASH = sha256('{"reason_code":"principal_request"}');
const KEY_HASH = sha256('erase-operation-one');

describe.skipIf(!DATABASE_URL)('GovernanceApprovalRepository authority idempotent consume', () => {
  let db: Database;
  let repo: GovernanceApprovalRepository;

  beforeAll(async () => {
    db = createDb(DATABASE_URL!);
    repo = new GovernanceApprovalRepository(db);
    await db.insert(operators).values({
      id: OPERATOR_ID,
      email: `${OPERATOR_ID}@example.invalid`,
      api_key_hash: `hash-${RUN}`,
    });
    await db.insert(governanceApprovals).values({
      id: APPROVAL_ID,
      operator_id: OPERATOR_ID,
      member_id: null,
      action: 'authority_proof_erase',
      resource_id: 'prf_one',
      payload_hash: PAYLOAD_HASH,
      summary: 'Erase proof',
      requested_via: 'operator_key',
      status: 'approved',
      expires_at: new Date(Date.now() + 60_000),
      decided_at: new Date(),
    });
  });

  afterAll(async () => {
    await db.delete(governanceApprovals).where(eq(governanceApprovals.operator_id, OPERATOR_ID));
    await db.delete(operators).where(eq(operators.id, OPERATOR_ID));
  });

  it('has exactly one CAS winner and returns the committed row to the exact concurrent retry', async () => {
    const input = {
      id: APPROVAL_ID,
      operatorId: OPERATOR_ID,
      action: 'authority_proof_erase',
      resourceId: 'prf_one',
      payloadHash: PAYLOAD_HASH,
      idempotencyKeyHash: KEY_HASH,
      now: new Date(),
    };
    const results = await Promise.all([
      repo.consumeAuthorityIdempotently(input),
      repo.consumeAuthorityIdempotently(input),
    ]);
    expect(results.filter((result) => result?.consumedNow)).toHaveLength(1);
    expect(results.filter((result) => result && !result.consumedNow)).toHaveLength(1);
    expect(results.every((result) => result?.row.status === 'consumed')).toBe(true);
    expect(results.every(
      (result) => result?.row.consumed_idempotency_key_hash === KEY_HASH,
    )).toBe(true);
  });

  it('does not consume on a different action, resource, payload, or key commitment', async () => {
    for (const mismatch of [
      { action: 'authority_binding_erase' },
      { resourceId: 'prf_other' },
      { payloadHash: sha256('different') },
      { idempotencyKeyHash: sha256('different-key') },
    ]) {
      const result = await repo.consumeAuthorityIdempotently({
        id: APPROVAL_ID,
        operatorId: OPERATOR_ID,
        action: 'authority_proof_erase',
        resourceId: 'prf_one',
        payloadHash: PAYLOAD_HASH,
        idempotencyKeyHash: KEY_HASH,
        now: new Date(),
        ...mismatch,
      });
      expect(result?.consumedNow).toBe(false);
      expect(result?.row.consumed_idempotency_key_hash).toBe(KEY_HASH);
    }
  });
});
