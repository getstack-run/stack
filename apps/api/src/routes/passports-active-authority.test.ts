import { describe, expect, it } from 'vitest';
import { projectActivePassport } from './passports.js';

describe('active Passport authority projection', () => {
  it('returns only opaque authority references beside the active Passport', () => {
    const issuedAt = new Date('2026-08-24T10:00:00.000Z');
    const expiresAt = new Date('2026-08-24T10:15:00.000Z');
    const authorityRefs = [{
      binding_id: 'abn_safe',
      binding_version: 1,
      binding_claim_id: 'pc_safe',
      binding_digest: `sha256:${'a'.repeat(64)}`,
      receiver_id: 'rcv_safe',
      receiver_profile_version_id: 'apv_safe',
      expires_at: 1_777_000_000,
    }];

    const projected = projectActivePassport({
      jti: 'ppt_safe',
      agent_id: 'agt_safe',
      session_id: 'ses_safe',
      delegation_depth: 0,
      parent_passport_id: null,
      identity_claim_ids: [],
      issued_at: issuedAt,
      expires_at: expiresAt,
      intent_summary: null,
      intent_services: [],
      intent_refs: [],
      mission_ids: [],
      estimated_duration_seconds: null,
      checkpoint_interval_seconds: null,
      checkpoint_count: 0,
      last_checkpoint_at: null,
    }, authorityRefs);

    expect(projected.authority_refs).toEqual(authorityRefs);
    expect(JSON.stringify(projected)).not.toMatch(/proof|mandate|credential|ciphertext|endpoint|key_material/i);
  });
});
