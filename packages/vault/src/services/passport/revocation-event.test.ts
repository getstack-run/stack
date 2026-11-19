import { describe, expect, it } from 'vitest';
import { RevocationEvent as RevocationEventSchema } from '@stack/shared';
import type { RevocationEvent } from './types.js';

// The published revocation-event schema (@stack/shared) and the type the
// publisher uses must be the same shape. Each direction is a compile-time
// assignment, so a variant or field that drifts fails the build, not only
// this test.
type Published = ReturnType<typeof RevocationEventSchema.parse>;
const published = (value: RevocationEvent): Published => value;
const internal = (value: Published): RevocationEvent => value;

const samples: RevocationEvent[] = [
  { type: 'single', operator_id: 'op_1', jti: 'ppt_1', cascaded: ['ppt_2'], reason: 'r', at: 1 },
  { type: 'bulk_agent', operator_id: 'op_1', agent_id: 'agt_1', revoked_count: 1, cascaded_count: 0, reason: 'r', at: 1 },
  { type: 'bulk_session', operator_id: 'op_1', session_id: 'ses_1', revoked_count: 1, reason: 'r', at: 1 },
  { type: 'bulk_operator', operator_id: 'op_1', revoked_count: 3, reason: 'r', at: 1 },
  { type: 'bulk_claim', operator_id: 'op_1', claim_id: 'pc_1', revoked_count: 1, reason: 'r', at: 1 },
  { type: 'bulk_mission', operator_id: 'op_1', mission_id: 'ms_1', revoke_reason: 'r', cascaded_passport_jtis: ['ppt_1'], at: 1 },
];

describe('RevocationEvent', () => {
  it('parses every variant the publisher can send', () => {
    for (const sample of samples) {
      expect(internal(RevocationEventSchema.parse(published(sample)))).toEqual(sample);
    }
  });

  it('rejects an unknown variant', () => {
    expect(() => RevocationEventSchema.parse({ type: 'bulk_galaxy', operator_id: 'op_1', at: 1 })).toThrow();
  });
});
