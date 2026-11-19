import { describe, expect, it, vi } from 'vitest';
import type { DecisionReachedEvent } from '@stack/shared';
import { EngineRegistries } from './registries.js';
import { runDecisionEndsPass } from './decision-ends-runner.js';
import {
  AUTHORITY_COMPLETED_REQUEST_TTL_SECONDS,
  AUTHORITY_REQUEST_EXPIRY_KEY,
  AUTHORITY_REQUEST_KEY,
  announceAuthorityDecision,
  authorityRequestProjection,
  createAuthorityRequest,
  pendingAuthorityRequestTtlSeconds,
  type AuthoritySetupRequestRecord,
} from '../routes/authority-flows/setup-requests.js';

const NOW = new Date('2026-11-03T12:00:00.000Z');

/** The Redis calls the authority requests use: strings with a time to live, and one sorted set. */
function fakeRedis() {
  const strings = new Map<string, { value: string; ttl: number }>();
  const zset = new Map<string, number>();
  return {
    strings,
    zset,
    async set(key: string, value: string, _ex: 'EX', ttl: number, nx?: 'NX') {
      if (nx && strings.has(key)) return null;
      strings.set(key, { value, ttl });
      return 'OK';
    },
    async get(key: string) { return strings.get(key)?.value ?? null; },
    async zadd(_key: string, score: number, member: string) { zset.set(member, score); return 1; },
    async zrem(_key: string, member: string) { return zset.delete(member) ? 1 : 0; },
    async zrangebyscore(_key: string, _min: string, max: number) {
      return [...zset.entries()].filter(([, score]) => score <= max).map(([member]) => member);
    },
  };
}

const kms = {
  async encrypt(plaintext: string) { return { ciphertext: plaintext }; },
  async decrypt(ciphertext: string) { return ciphertext; },
};

function record(over: Partial<AuthoritySetupRequestRecord> = {}): AuthoritySetupRequestRecord {
  return {
    request_id: 'areq_1',
    operator_id: 'op_1',
    request_hash: 'h',
    request: { agent_id: 'agt_1' },
    status: 'pending',
    created_at: new Date(NOW.getTime() - 20 * 60_000).toISOString(),
    expires_at: new Date(NOW.getTime() - 5 * 60_000).toISOString(),
    ...over,
  } as AuthoritySetupRequestRecord;
}

function services(over: Record<string, unknown> = {}) {
  const registries = new EngineRegistries();
  const decisions: DecisionReachedEvent[] = [];
  registries.decisionReached.register(async (event) => { decisions.push(event); });
  const published: Array<Record<string, unknown>> = [];
  const redis = fakeRedis();
  const built = {
    registries,
    redis,
    kms,
    intentApproval: { expireDue: vi.fn(async () => 0) },
    controlReviews: { expirePending: vi.fn(async () => 0) },
    proxyOperation: { markUnresolvedDue: vi.fn(async () => []) },
    identity: { expireDue: vi.fn(async () => 0) },
    notification: { publishEvent: vi.fn(async (event: Record<string, unknown>) => { published.push(event); return { dispatched: 1 }; }) },
    ...over,
  };
  return { services: built, decisions, published, redis };
}

describe('the pass that ends what ran out of time', () => {
  it('runs every sweep, and one that fails does not stop the others', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const built = services({ intentApproval: { expireDue: vi.fn(async () => { throw new Error('database blip'); }) } });
    await runDecisionEndsPass(built.services as never, NOW);
    expect(built.services.controlReviews.expirePending).toHaveBeenCalledTimes(1);
    expect(built.services.proxyOperation.markUnresolvedDue).toHaveBeenCalledWith(NOW);
    expect(built.services.identity.expireDue).toHaveBeenCalledWith(NOW);
    log.mockRestore();
  });

  it('a proxied write left unresolved tells its agent (named by the hash of its operation id) and its owner', async () => {
    const built = services({
      proxyOperation: {
        markUnresolvedDue: vi.fn(async () => [{
          id: 'pop_1', operator_id: 'op_1', agent_id: 'agt_1', operation_key_hash: 'a'.repeat(64), provider: 'stripe', method: 'POST',
        }]),
      },
    });
    await runDecisionEndsPass(built.services as never, NOW);
    expect(built.decisions).toEqual([{
      operatorId: 'op_1', agentId: 'agt_1', kind: 'proxy_operation', itemId: `sha256:${'a'.repeat(64)}`, result: 'unresolved', occurredAt: NOW,
    }]);
    expect(built.published).toEqual([expect.objectContaining({
      operatorId: 'op_1',
      eventType: 'proxy_operation.unresolved',
      severity: 'warning',
      payload: expect.objectContaining({ operation_id_hash: `sha256:${'a'.repeat(64)}`, agent_id: 'agt_1', provider: 'stripe', method: 'POST' }),
    })]);
  });

  it('an authority request nobody decided is told to its agent as expired, once across machines', async () => {
    const built = services();
    const pending = record();
    built.redis.strings.set(AUTHORITY_REQUEST_KEY + pending.request_id, { value: JSON.stringify(pending), ttl: 1 });
    built.redis.zset.set('op_1:areq_1', new Date(pending.expires_at).getTime());
    await runDecisionEndsPass(built.services as never, NOW);
    await runDecisionEndsPass(built.services as never, NOW);
    expect(built.decisions).toEqual([{ operatorId: 'op_1', agentId: 'agt_1', kind: 'authority_request', itemId: 'areq_1', result: 'expired' }]);
  });

  it('an authority request not yet due, or already decided, is not told as expired', async () => {
    const built = services();
    const notDue = record({ request_id: 'areq_2', expires_at: new Date(NOW.getTime() + 60_000).toISOString() });
    const decided = record({ request_id: 'areq_3', status: 'rejected' });
    for (const r of [notDue, decided]) {
      built.redis.strings.set(AUTHORITY_REQUEST_KEY + r.request_id, { value: JSON.stringify(r), ttl: 1 });
      built.redis.zset.set(`op_1:${r.request_id}`, Math.min(new Date(r.expires_at).getTime(), NOW.getTime()));
    }
    await runDecisionEndsPass(built.services as never, NOW);
    expect(built.decisions).toEqual([]);
  });
});

describe('authority requests', () => {
  it('a pending request is kept until it expires and a day after, so a read says expired instead of not found', async () => {
    const built = services();
    const fresh = record({ expires_at: new Date(Date.now() + 15 * 60_000).toISOString() });
    expect(await createAuthorityRequest(built.services as never, fresh)).toBe(true);
    const stored = built.redis.strings.get(AUTHORITY_REQUEST_KEY + fresh.request_id)!;
    expect(stored.ttl).toBeGreaterThanOrEqual(15 * 60 + AUTHORITY_COMPLETED_REQUEST_TTL_SECONDS - 1);
    expect(built.redis.zset.has('op_1:areq_1')).toBe(true);
    expect(pendingAuthorityRequestTtlSeconds(record(), NOW.getTime())).toBe(1 + AUTHORITY_COMPLETED_REQUEST_TTL_SECONDS);
    expect(authorityRequestProjection(record()).status).toBe('expired');
    expect(AUTHORITY_REQUEST_EXPIRY_KEY).toBe('authority:oidc-request-expiry');
  });

  it('a decision tells the agent it was for and takes the request off the expiry list', async () => {
    const built = services();
    built.redis.zset.set('op_1:areq_1', 1);
    await announceAuthorityDecision(built.services as never, record({ status: 'completed' }), 'approved');
    expect(built.redis.zset.size).toBe(0);
    expect(built.decisions).toEqual([{ operatorId: 'op_1', agentId: 'agt_1', kind: 'authority_request', itemId: 'areq_1', result: 'approved' }]);
  });

  it('a request made for no agent tells nobody', async () => {
    const built = services();
    await announceAuthorityDecision(built.services as never, record({ request: {} as never }), 'rejected');
    expect(built.decisions).toEqual([]);
  });
});
