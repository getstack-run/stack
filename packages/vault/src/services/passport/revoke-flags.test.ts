import { describe, expect, it, vi } from 'vitest';
import { ServiceUnavailableError } from '@stack/shared';
import {
  createMissionPassportRevoker,
  revokeAllForOperatorIn,
  PassportRevokeFlagsError,
  revokeBySession,
  revokePassport,
  revokePassportsByCarriedClaim,
} from './revoke.js';

type Entry = [Error | null, unknown];

/** A Redis whose pipelines answer like ioredis: exec resolves with one [error, result] entry per command, never rejects for a failed command. */
function fakeRedis(entryFor: (index: number, jti: string) => Entry = () => [null, 'OK']) {
  const batches: string[][] = [];
  const publish = vi.fn(async () => 1);
  const redis = {
    publish,
    pipeline() {
      const jtis: string[] = [];
      batches.push(jtis);
      return {
        set(key: string) {
          jtis.push(key.replace('revoked:', ''));
          return this;
        },
        exec: async () => jtis.map((jti, index) => entryFor(index, jti)),
      };
    },
  };
  return { redis, batches, publish };
}

const inAnHour = () => new Date(Date.now() + 3_600_000);
const rows = (count: number) => Array.from({ length: count }, (_, i) => ({ jti: `jti_${i}`, expires_at: inAnHour() }));

describe('revocation flag writes', () => {
  it('resolves when every flag is written', async () => {
    const { redis, batches } = fakeRedis();
    await expect(createMissionPassportRevoker({ redis: redis as never }).afterCommit(rows(3))).resolves.toBeUndefined();
    expect(batches.flat()).toEqual(['jti_0', 'jti_1', 'jti_2']);
  });

  it('sends a command that carried an error once more, and only that one', async () => {
    const timedOut = Object.assign(new Error('Command timed out'), { name: 'Error' });
    const seen = new Set<string>();
    const { redis, batches } = fakeRedis((_, jti) => {
      const first = !seen.has(jti);
      seen.add(jti);
      return jti === 'jti_1' && first ? [timedOut, null] : [null, 'OK'];
    });
    await expect(createMissionPassportRevoker({ redis: redis as never }).afterCommit(rows(3))).resolves.toBeUndefined();
    expect(batches).toEqual([['jti_0', 'jti_1', 'jti_2'], ['jti_1']]);
  });

  it('fails the call, retriable, when a flag is still not written after the second try', async () => {
    const timedOut = Object.assign(new Error('Command timed out'), { name: 'Error' });
    const { redis, batches } = fakeRedis((_, jti) => (jti === 'jti_1' ? [timedOut, null] : [null, 'OK']));
    const outcome = await createMissionPassportRevoker({ redis: redis as never })
      .afterCommit(rows(3))
      .catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
    expect((outcome as ServiceUnavailableError).statusCode).toBe(503);
    expect(batches).toEqual([['jti_0', 'jti_1', 'jti_2'], ['jti_1']]);
  });

  it('sends a batch once more when exec itself rejects, and still ends as the typed 503', async () => {
    let calls = 0;
    const batches: string[][] = [];
    const redis = {
      pipeline() {
        const jtis: string[] = [];
        batches.push(jtis);
        return {
          set(key: string) { jtis.push(key.replace('revoked:', '')); return this; },
          exec: async () => {
            calls += 1;
            if (calls === 1) throw new Error('Connection is closed.');
            return jtis.map(() => [null, 'OK'] as [null, string]);
          },
        };
      },
    };
    await expect(createMissionPassportRevoker({ redis: redis as never }).afterCommit(rows(2))).resolves.toBeUndefined();
    expect(batches).toEqual([['jti_0', 'jti_1'], ['jti_0', 'jti_1']]);

    const dead = { pipeline: () => ({ set() { return this; }, exec: async () => { throw new Error('Connection is closed.'); } }) };
    const outcome = await createMissionPassportRevoker({ redis: dead as never }).afterCommit(rows(1)).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
  });

  it('a single revoke whose flags fail carries what it revoked, so its audit rows can still be written', async () => {
    const { redis, publish } = fakeRedis(() => [new Error('Command timed out'), null]);
    const child = { jti: 'ppt_child', expires_at: inAnHour() };
    const record = { jti: 'ppt_root', operator_id: 'op_a', expires_at: inAnHour() };
    const ctx = {
      redis,
      db: { transaction: async (work: (tx: unknown) => unknown) => work({ execute: async () => undefined }) },
      passportRepo: {
        findByJti: vi.fn(async () => record),
        revoke: vi.fn(async () => undefined),
        findActiveChildren: vi.fn(async (parent: string) => (parent === 'ppt_root' ? [child] : [])),
      },
      passportClaimsRepo: {
        markAllRevokedByPassportId: vi.fn(async (jti: string) => (jti === 'ppt_root' ? [{ claim_id: 'pc_1', claim_hash: 'h1' }] : [])),
      },
    };
    const outcome = await revokePassport(ctx as never, { jti: 'ppt_root', operatorId: 'op_a', reason: 'test' }).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(PassportRevokeFlagsError);
    expect((outcome as PassportRevokeFlagsError).outcome).toEqual({
      operator_id: 'op_a',
      cascaded: ['ppt_child'],
      revoked_claims: [{ claim_id: 'pc_1', claim_hash: 'h1' }],
    });
    expect(publish).toHaveBeenCalledOnce();
  });

  it('fails the call when exec reports nothing at all', async () => {
    const redis = { pipeline: () => ({ set() { return this; }, exec: async () => null }) };
    await expect(createMissionPassportRevoker({ redis: redis as never }).afterCommit(rows(1))).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('splits a large revoke into pipelines of at most a thousand commands', async () => {
    const { redis, batches } = fakeRedis();
    await createMissionPassportRevoker({ redis: redis as never }).afterCommit(rows(2_500));
    expect(batches.map((batch) => batch.length)).toEqual([1_000, 1_000, 500]);
  });

  it('skips a flag whose Passport has already expired', async () => {
    const { redis, batches } = fakeRedis();
    await createMissionPassportRevoker({ redis: redis as never }).afterCommit([
      { jti: 'jti_gone', expires_at: new Date(Date.now() - 1_000) },
      { jti: 'jti_live', expires_at: inAnHour() },
    ]);
    expect(batches.flat()).toEqual(['jti_live']);
  });

  it('revoking by claim announces the real count, then answers 503, when a flag was not written', async () => {
    const { redis, publish } = fakeRedis(() => [new Error('Command timed out'), null]);
    const passportRepo = { revokeByCarriedClaim: vi.fn(async () => [{ jti: 'jti_a', expires_at: inAnHour() }, { jti: 'jti_b', expires_at: inAnHour() }]) };
    const outcome = await revokePassportsByCarriedClaim({
      passportRepo: passportRepo as never,
      redis: redis as never,
      operatorId: 'op_a',
      claimId: 'pc_a',
      reason: 'test',
    }).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(ServiceUnavailableError);
    expect(passportRepo.revokeByCarriedClaim).toHaveBeenCalledTimes(1);
    expect(publish).toHaveBeenCalledTimes(1);
    const [channel, body] = publish.mock.calls[0] as unknown as [string, string];
    expect(channel).toBe('stack:revoked');
    expect(JSON.parse(body)).toMatchObject({ type: 'bulk_claim', operator_id: 'op_a', claim_id: 'pc_a', revoked_count: 2 });
  });

  it('a retry that finds nothing left to revoke does not erase the first announcement', async () => {
    let attempt = 0;
    const { redis, publish } = fakeRedis(() => (attempt === 1 ? [new Error('Command timed out'), null] : [null, 'OK']));
    const passportRepo = {
      revokeByCarriedClaim: vi.fn(async () => {
        attempt += 1;
        return attempt === 1 ? [{ jti: 'jti_a', expires_at: inAnHour() }] : [];
      }),
    };
    const args = { passportRepo: passportRepo as never, redis: redis as never, operatorId: 'op_a', claimId: 'pc_a', reason: 'test' };
    await expect(revokePassportsByCarriedClaim(args)).rejects.toBeInstanceOf(ServiceUnavailableError);
    await expect(revokePassportsByCarriedClaim(args)).resolves.toEqual({ revoked_count: 0 });
    const counts = publish.mock.calls.map((call) => (JSON.parse((call as unknown as [string, string])[1]) as { revoked_count: number }).revoked_count);
    expect(counts).toEqual([1, 0]);
  });

  it('revoking a whole operator announces the real count, then answers 503, when a flag was not written', async () => {
    const { redis, publish } = fakeRedis(() => [new Error('Command timed out'), null]);
    const ctx = {
      redis,
      passportRepo: { revokeAllForOperator: vi.fn(async () => rows(3)) },
      passportClaimsRepo: { markAllRevokedByPassportId: vi.fn(async () => []) },
    };
    const revoked = await revokeAllForOperatorIn(ctx as never, 'op_a', 'test', {} as never);
    expect(revoked.revoked_count).toBe(3);
    await expect(revoked.publish()).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(JSON.parse((publish.mock.calls[0] as unknown as [string, string])[1])).toMatchObject({ type: 'bulk_operator', revoked_count: 3 });
  });

  it('revoking a session announces the real count, then answers 503, when a flag was not written', async () => {
    const { redis, publish } = fakeRedis(() => [new Error('Command timed out'), null]);
    const ctx = {
      redis,
      db: { transaction: async (work: (tx: unknown) => unknown) => work({ execute: async () => undefined }) },
      passportRepo: { revokeBySession: vi.fn(async () => rows(2)) },
      passportClaimsRepo: { markAllRevokedByPassportId: vi.fn(async () => []) },
    };
    await expect(revokeBySession(ctx as never, 'op_a', 'sess_a', 'test')).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(JSON.parse((publish.mock.calls[0] as unknown as [string, string])[1])).toMatchObject({ type: 'bulk_session', revoked_count: 2 });
  });
});
