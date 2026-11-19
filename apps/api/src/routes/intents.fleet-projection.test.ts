import { describe, expect, it } from 'vitest';
import { rowForWire } from './intents.js';

describe('fleet intent approval projection', () => {
  it('exposes scope identifiers without encrypted request custody or raw request data', () => {
    const row = { id: 'ia_review', operator_id: 'op_one', agent_id: 'agt_one', passport_jti: 'ppt_one',
      intent_claim_id: 'clm_one', simulated_claim_id: null, status: 'pending', requested_at: new Date(),
      expires_at: new Date(Date.now() + 60_000), decided_at: null, decided_by_member_id: null, notes: null,
      block_future: false, fleet_policy_id: 'flp_one', fleet_policy_revision: 3, fleet_mission_id: 'ms_one',
      fleet_request_hash: 'a'.repeat(64), fleet_review_key: 'b'.repeat(64),
      fleet_review_encrypted: 'PRIVATE_CIPHERTEXT', fleet_review_key_ref: 'PRIVATE_KMS_REF',
      fleet_request: { body: { secret: 'PRIVATE_REQUEST' } } };
    const result = rowForWire(row);
    expect(result).toMatchObject({ fleet_policy_id: 'flp_one', fleet_policy_revision: 3, fleet_mission_id: 'ms_one' });
    for (const key of ['fleet_request_hash', 'fleet_review_key', 'fleet_review_encrypted', 'fleet_review_key_ref', 'fleet_request']) expect(result).not.toHaveProperty(key);
    expect(JSON.stringify(result)).not.toContain('PRIVATE_');
  });
});
