import { describe, expect, it } from 'vitest';
import { SESSION_JWT_AUDIENCE } from '@stack/shared';
import { PassportSigner } from './passport-signer.js';

describe('PassportSigner dashboard sessions', () => {
  it('mints owner and member sessions with distinct least-privilege claims', async () => {
    const signer = new PassportSigner({ kid: 'stack-passport-v1' });
    await signer.init();
    const owner = await signer.signDashboardOwnerSession({
      operatorId: 'op_synthetic', email: 'owner@test.invalid', tier: 'free',
      isAdmin: false, ownerSessionRevision: '4',
      sessionId: 'ses_owner_synthetic', tokenId: 'ses_jti_owner_synthetic', authenticatedAt: 1_788_732_000,
    });
    const member = await signer.signDashboardMemberSession({
      operatorId: 'op_synthetic', memberId: 'mem_synthetic',
      email: 'member@test.invalid', role: 'readonly', tier: 'free',
      sessionId: 'ses_member_synthetic', tokenId: 'ses_jti_member_synthetic', authenticatedAt: 1_788_732_000,
    });

    const ownerVerified = await signer.verifyAccessOrSession(owner);
    const memberVerified = await signer.verifyAccessOrSession(member);
    expect(ownerVerified.aud).toBe(SESSION_JWT_AUDIENCE);
    expect(ownerVerified.payload).toMatchObject({
      sub: 'op_synthetic', email: 'owner@test.invalid', owner_session_revision: '4',
      sid: 'ses_owner_synthetic', jti: 'ses_jti_owner_synthetic', auth_time: 1_788_732_000,
    });
    expect(ownerVerified.payload).not.toHaveProperty('member_id');
    expect(memberVerified.payload).toMatchObject({
      sub: 'op_synthetic', member_id: 'mem_synthetic', role: 'readonly', is_member: true,
      sid: 'ses_member_synthetic', jti: 'ses_jti_member_synthetic', auth_time: 1_788_732_000,
    });
    expect(memberVerified.payload).not.toHaveProperty('is_admin');
  });
});
