import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import {
  createDb, operators, teamMembers, oauthClients, oauthRefreshTokens, magicLinkTokens,
  oauthAuthorizationCodes, oauthDeviceCodes, operatorEmailChanges, operatorEmailDeliveryJobs,
} from '@stack/shared';
import { EmailChangeService } from './email-change-service.js';

const run = process.env.DATABASE_URL ? describe : describe.skip;
run('email transfer revokes owner OAuth credentials', () => {
  it('atomically revokes owner refresh families and pending exchanges while preserving members', async () => {
    const url = process.env.DATABASE_URL!;
    expect(['localhost', '127.0.0.1', '[::1]']).toContain(new URL(url).hostname);
    const db = createDb(url);
    const suffix = randomUUID().replaceAll('-', '');
    const operatorId = `op_email_sessions_${suffix}`;
    const memberId = `mem_email_sessions_${suffix}`;
    const clientId = `client_email_sessions_${suffix}`;
    const email = `${suffix}@session-test.invalid`;
    const expires = new Date(Date.now() + 86_400_000);
    await db.insert(operators).values({ id: operatorId, email, api_key_hash: suffix });
    await db.insert(teamMembers).values({ id: memberId, operator_id: operatorId, email: `member_${email}`, name: 'Synthetic member', role: 'admin', status: 'active' });
    await db.insert(oauthClients).values({ id: clientId, client_type: 'public', client_name: 'Synthetic client', redirect_uris: ['https://example.invalid/callback'], grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none' });
    for (const [actor, member] of [['owner', null], ['member', memberId]] as const) {
      await db.insert(magicLinkTokens).values({ id: `${actor}_${suffix}`, email: member ? `member_${email}` : email, token_hash: `${actor}_${suffix}`, intent: 'login', operator_id: operatorId, member_id: member, expires_at: expires });
      await db.insert(oauthRefreshTokens).values({ token_hash: `${actor}_${suffix}`, token_family_id: `${actor}_${suffix}`, client_id: clientId, operator_id: operatorId, member_id: member, scope: 'read', resource: 'https://api.getstack.run', expires_at: expires, replacement_token_encrypted: 'synthetic-encrypted-envelope', replacement_retry_expires_at: expires });
      await db.insert(oauthAuthorizationCodes).values({ code_hash: `${actor}_${suffix}`, client_id: clientId, operator_id: operatorId, member_id: member, redirect_uri: 'https://example.invalid/callback', scope: 'read', resource: 'https://api.getstack.run', code_challenge: 'synthetic', expires_at: expires });
      await db.insert(oauthDeviceCodes).values({ device_code_hash: `${actor}_${suffix}`, user_code: `${actor}_${suffix}`, client_id: clientId, operator_id: operatorId, member_id: member, scope: 'read', resource: 'https://api.getstack.run', status: 'approved', approved_at: new Date(), expires_at: expires });
    }
    let confirmation = '';
    const service = new EmailChangeService({
      db, rateLimitStore: null, dashboardUrl: 'https://example.invalid', audit: { write: async () => 'synthetic-audit' },
      email: { sendEmail: async (_to, _subject, text) => {
        const match = text.match(/\/account\/email-change\/confirm\?token=([^\s]+)/);
        if (match?.[1]) confirmation = decodeURIComponent(match[1]);
        return { id: 'synthetic-email' };
      } },
    });
    try {
      await service.request({ operatorId, newEmail: `new_${email}` }, { traceId: 'synthetic', spanId: 'synthetic' });
      expect(confirmation).not.toBe('');
      await service.confirm(confirmation, { traceId: 'synthetic', spanId: 'synthetic' });
      const transferred = await db.query.operators.findFirst({ where: eq(operators.id, operatorId) });
      expect(transferred?.owner_session_revision).not.toBe('0');
      for (const actor of ['owner', 'member']) {
        const refresh = await db.query.oauthRefreshTokens.findFirst({ where: eq(oauthRefreshTokens.token_hash, `${actor}_${suffix}`) });
        const code = await db.query.oauthAuthorizationCodes.findFirst({ where: eq(oauthAuthorizationCodes.code_hash, `${actor}_${suffix}`) });
        const device = await db.query.oauthDeviceCodes.findFirst({ where: eq(oauthDeviceCodes.device_code_hash, `${actor}_${suffix}`) });
        const challenge = await db.query.magicLinkTokens.findFirst({ where: eq(magicLinkTokens.id, `${actor}_${suffix}`) });
        if (actor === 'owner') {
          expect(refresh?.revoked_at).not.toBeNull();
          expect(refresh?.replacement_token_encrypted).toBeNull();
          expect(refresh?.replacement_retry_expires_at).toBeNull();
          expect(code?.consumed_at).not.toBeNull();
          expect(device?.status).toBe('denied');
          expect(challenge?.used).toBe(true);
        } else {
          expect(refresh?.revoked_at).toBeNull();
          expect(code?.consumed_at).toBeNull();
          expect(device?.status).toBe('approved');
          expect(challenge?.used).toBe(false);
        }
      }
      await service.request({ operatorId, newEmail: email }, { traceId: 'synthetic', spanId: 'synthetic' });
      await service.confirm(confirmation, { traceId: 'synthetic', spanId: 'synthetic' });
      const returned = await db.query.operators.findFirst({ where: eq(operators.id, operatorId) });
      expect(returned?.email).toBe(email);
      expect(returned?.owner_session_revision).not.toBe('0');
      expect(returned?.owner_session_revision).not.toBe(transferred?.owner_session_revision);
    } finally {
      await db.delete(magicLinkTokens).where(eq(magicLinkTokens.operator_id, operatorId));
      await db.delete(oauthRefreshTokens).where(eq(oauthRefreshTokens.operator_id, operatorId));
      await db.delete(oauthAuthorizationCodes).where(eq(oauthAuthorizationCodes.operator_id, operatorId));
      await db.delete(oauthDeviceCodes).where(eq(oauthDeviceCodes.operator_id, operatorId));
      await db.delete(operatorEmailDeliveryJobs).where(eq(operatorEmailDeliveryJobs.operator_id, operatorId));
      await db.delete(operatorEmailChanges).where(eq(operatorEmailChanges.operator_id, operatorId));
      await db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId));
      await db.delete(oauthClients).where(eq(oauthClients.id, clientId));
      await db.delete(operators).where(eq(operators.id, operatorId));
    }
  });
});
