import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { acquireOAuthOperatorLock, createDb, oauthAuthorizationCodes, oauthClients, oauthDeviceCodes, operators, teamMembers } from '@stack/shared';
import { decideDeviceCode, issueAuthorizationCode } from './oauth-grant-state.js';

const run = process.env.DATABASE_URL ? describe : describe.skip;
run('OAuth issuance rechecks the session identity inside the lifecycle lock', () => {
  for (const path of ['code', 'device'] as const) {
    for (const change of ['mailbox', 'revision'] as const) {
      it(`${path}/${change}: transfer first denies the old owner and preserves a current member`, async () => {
        const url = process.env.DATABASE_URL!;
        expect(['127.0.0.1', 'localhost', '[::1]']).toContain(new URL(url).hostname);
        const db = createDb(url);
        const suffix = randomUUID().replaceAll('-', '');
        const operatorId = `op_binding_${suffix}`;
        const memberId = `mem_binding_${suffix}`;
        const clientId = `client_binding_${suffix}`;
        const ownerEmail = `owner_${suffix}@test.invalid`;
        const memberEmail = `member_${suffix}@test.invalid`;
        await db.insert(operators).values({ id: operatorId, email: ownerEmail, api_key_hash: suffix });
        await db.insert(teamMembers).values({ id: memberId, operator_id: operatorId, email: memberEmail, name: 'Synthetic', role: 'admin', status: 'active' });
        await db.insert(oauthClients).values({ id: clientId, client_type: 'public', client_name: 'Synthetic', redirect_uris: ['https://example.invalid/callback'], grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none' });
        for (const actor of ['owner', 'member']) {
          await db.insert(oauthDeviceCodes).values({ device_code_hash: `${actor}_${suffix}`, user_code: `${actor}_${suffix}`, client_id: clientId, scope: 'read', resource: 'https://api.getstack.run', expires_at: new Date(Date.now() + 60_000) });
        }
        let release!: () => void;
        let held!: () => void;
        const ready = new Promise<void>(resolve => { held = resolve; });
        const unblock = new Promise<void>(resolve => { release = resolve; });
        const issue = (actor: 'owner' | 'member') => {
          const common = { operatorId, memberId: actor === 'member' ? memberId : null, sessionEmail: actor === 'member' ? memberEmail : ownerEmail, ownerSessionRevision: '0' };
          return path === 'code'
            ? issueAuthorizationCode(db, { ...common, clientId, redirectUri: 'https://example.invalid/callback', scope: 'read', resource: 'https://api.getstack.run', codeChallenge: 'synthetic', codeChallengeMethod: 'S256' })
            : decideDeviceCode(db, { ...common, userCode: `${actor}_${suffix}`, decision: 'approve' });
        };
        try {
          const transfer = db.transaction(async tx => {
            await acquireOAuthOperatorLock(tx, operatorId);
            await tx.update(operators).set(change === 'mailbox'
              ? { email: `new_${ownerEmail}`, owner_session_revision: 'after-transfer' }
              : { owner_session_revision: 'after-return-transfer' }).where(eq(operators.id, operatorId));
            held();
            await unblock;
          });
          await ready;
          const owner = issue('owner');
          const state = await Promise.race([owner.then(() => 'settled'), new Promise(resolve => setTimeout(() => resolve('blocked'), 75))]);
          release();
          await transfer;
          expect(state).toBe('blocked');
          expect((await owner).kind).toBe('operator_inactive');
          expect((await issue('member')).kind).toBe('success');
        } finally {
          release?.();
          await db.delete(oauthAuthorizationCodes).where(eq(oauthAuthorizationCodes.operator_id, operatorId));
          await db.delete(oauthDeviceCodes).where(eq(oauthDeviceCodes.client_id, clientId));
          await db.delete(teamMembers).where(eq(teamMembers.id, memberId));
          await db.delete(oauthClients).where(eq(oauthClients.id, clientId));
          await db.delete(operators).where(eq(operators.id, operatorId));
        }
      });
    }
  }
});
