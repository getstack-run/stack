import { describe, expect, it, vi } from 'vitest';
import { ForbiddenError, normalizeRequest } from '@stack/shared';
import { enforceScopeWall, type WallServiceScope } from './scope-wall.js';
import { observeEntities } from '../routes/proxy-call/signed-claims.js';

/**
 * What the agent itself SENT to a service (the request's own URL: host, path, query) is not content READ from it.
 * What a service RETURNED is. These run the whole trail in memory: a call is recorded the way the proxy records it
 * (`observeEntities`), the rows come back the way the repository hands them to the wall, and the next call is judged
 * by `enforceScopeWall`.
 *
 * The first group holds the wall where it was and passes before and after the change that stopped counting a request's
 * own URL; the second is the defect.
 */

const A = 'openai';
const B = 'anthropic';
const HOST: Record<string, string> = { openai: 'api.openai.com', anthropic: 'api.anthropic.com' };
const DANA = 'dana.whitfield@bank.example';

type Payload = Record<string, any>;

function world(opts: { controls?: boolean; belongsToAccount?: boolean; readFails?: boolean } = {}) {
  const payloads: Payload[] = [];
  const events: Array<Record<string, any>> = [];
  const services = {
    claimRegistry: {
      registerClaim: vi.fn(async (c: { payload: Payload }) => { payloads.push(c.payload); return { claimId: `pc_${payloads.length}` }; }),
      recordIntentDenial: vi.fn(async () => undefined),
    },
    securityEvent: { record: vi.fn(async (e: Record<string, any>) => { events.push(e); }) },
    mission: { findById: vi.fn(async () => null) },
    passportClaimsRepo: {
      // The rows as the repository returns them: what each observation recorded, and which of it was only the request's own URL.
      findObservedContentForFlow: vi.fn(async () => {
        if (opts.readFails) throw new Error('trail unreadable');
        return payloads.map((p) => ({
          entities: p.entities, fingerprints: p.content_fingerprints, sourceService: p.source_service,
          requestEntities: p.request_entities ?? null,
        }));
      }),
      findObservedEntitiesForAgent: vi.fn(async () => payloads.flatMap((p) => p.entities)),
    },
    entitlements: { controlsEnabled: vi.fn(async () => opts.controls ?? true) },
    accountDetection: { forAgent: vi.fn(async () => (opts.belongsToAccount === false ? null : { mode: 'standard', skipL3: true, withhold: false })) },
  };
  return { services, payloads, events };
}

type World = ReturnType<typeof world>;

/** The agent's call to `service` at `url` is made and answered with `response`; the proxy records it. */
async function recordCall(w: World, c: { service: string; url: string; method?: string; body?: unknown; response?: unknown }) {
  await observeEntities(
    w.services as never,
    { input: { service: c.service, method: c.method ?? 'GET', url: c.url, ...(c.body === undefined ? {} : { body: c.body }) }, isMutation: false, operationKey: null } as never,
    { jti: 'pas_1', agentId: 'ag_1', operatorId: 'op_1', missionIds: ['ms_1'], missionRef: 'ms_1' } as never,
    { resolvedUrl: c.url } as never,
    { status: 200, headers: {}, body: JSON.stringify(c.response ?? { ok: true }) } as never,
  );
  // The undeclared-counterparty check runs detached.
  await new Promise<void>((resolve) => setImmediate(resolve));
  await new Promise<void>((resolve) => setImmediate(resolve));
}

/** The wall judges the agent's next call. */
function wall(w: World, c: { service: string; url: string; method?: string; body?: unknown; scope?: Partial<WallServiceScope>; mode?: 'enforced' | 'logged' | 'standard' }) {
  const normalized = normalizeRequest({ service: c.service, url: c.url, method: c.method ?? 'GET', ...(c.body === undefined ? {} : { body: c.body }) } as never);
  return enforceScopeWall({
    services: w.services as never, operatorId: 'op_1', agentId: 'ag_1', passportJti: 'pas_1', mode: c.mode ?? 'enforced',
    missionIds: ['ms_1'], destinationService: c.service, serviceScope: { service_name: c.service, ...c.scope } as WallServiceScope,
    normalized, rawUrl: c.url, namedIntent: `${c.service}:call`, producer: '[test]',
  });
}

const leaks = (w: World) => w.events.filter((e) => e['signalType'] === 'credential_outside_scope' && (e['metadata'] as Record<string, unknown>)['data_flow_from']);

describe('what a service returned is still content read from it', () => {
  it('a value in A\'s response, sent to B in the body, is refused', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models`, response: { data: [{ owner: DANA }] } });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { content: `mail ${DANA}` } })).rejects.toThrow(/read from "openai"/);
  });

  it('a value in A\'s response, sent to B in the query string, is refused', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models`, response: { data: [{ owner: DANA }] } });
    await expect(wall(w, { service: B, url: `https://${HOST[B]}/v1/search?who=${encodeURIComponent(DANA)}` })).rejects.toThrow(/read from "openai"/);
  });

  it('an id in A\'s response, sent to B in the URL path, is refused', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models`, response: { data: [{ id: 'file_8f3a9c2d41' }] } });
    await expect(wall(w, { service: B, url: `https://${HOST[B]}/v1/files/file_8f3a9c2d41` })).rejects.toThrow(/read from "openai"/);
  });

  it('a value the agent put in A\'s path and A echoed back is read from A: sent to B it is refused', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/files/file_77aa88bb99`, response: { id: 'file_77aa88bb99', purpose: 'assistants' } });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { ref: 'file_77aa88bb99' } })).rejects.toThrow(/read from "openai"/);
  });

  it('a value the agent put in A\'s query and A echoed back is read from A: sent to B it is refused', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/search?customer=${DANA}`, response: { echo: DANA } });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { content: DANA } })).rejects.toThrow(/read from "openai"/);
  });

  it('A\'s URL echoed in A\'s response, with its path, is read from A', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/files/file_55cc66dd77`, response: { url: `https://${HOST[A]}/v1/files/file_55cc66dd77` } });
    await expect(wall(w, { service: B, url: `https://${HOST[B]}/v1/files/file_55cc66dd77` })).rejects.toThrow(/read from "openai"/);
  });
});

describe('the rest of the wall is where it was', () => {
  it('the destination\'s own host is not content it carries (a read that mentioned it does not refuse the call to it)', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models`, response: { docs: `https://${HOST[B]}/docs` } });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { content: 'hello' } })).resolves.toBeDefined();
  });

  it('a declared flow (allow_data_from) passes', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models`, response: { data: [{ owner: DANA }] } });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { content: DANA }, scope: { allow_data_from: [A] } })).resolves.toBeDefined();
  });

  it('with controls off the flow is a warning and the call goes through', async () => {
    const w = world({ controls: false });
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models`, response: { data: [{ owner: DANA }] } });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { content: DANA } })).resolves.toBeDefined();
    expect(leaks(w).some((e) => (e['metadata'] as Record<string, unknown>)['data_flow_refused'] === false)).toBe(true);
  });

  it('an agent outside an account in enforced mode fails closed when the trail cannot be read', async () => {
    const w = world({ belongsToAccount: false, readFails: true });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { content: 'hello' }, mode: 'enforced' })).rejects.toThrow(ForbiddenError);
  });

  it('an account\'s agent with controls on fails closed on an unreadable trail for a write', async () => {
    const w = world({ readFails: true });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { content: 'hello' } })).rejects.toThrow(ForbiddenError);
  });
});

describe('the undeclared-counterparty check still knows what the agent called', () => {
  const undeclared = (w: World) => w.events.filter((e) => e['signalType'] === 'undeclared_target');

  it('a second call to a host and an id the agent already called is not new', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/files/file_11aa22bb33` });
    const before = undeclared(w).length;
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/files/file_11aa22bb33` });
    expect(undeclared(w).length).toBe(before);
  });

  it('a call to a host the agent never dealt with is flagged', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models` });
    const before = undeclared(w).length;
    await recordCall(w, { service: B, url: `https://${HOST[B]}/v1/models` });
    expect(undeclared(w).length).toBe(before + 1);
  });
});

describe('the defect: the agent\'s own request is not content it read', () => {
  it('GET /v1/models on OpenAI then on Anthropic: both pass', async () => {
    const w = world();
    await wall(w, { service: A, url: `https://${HOST[A]}/v1/models` });
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models`, response: { data: [{ id: 'gpt-x' }] } });
    await expect(wall(w, { service: B, url: `https://${HOST[B]}/v1/models` })).resolves.toBeDefined();
    await recordCall(w, { service: B, url: `https://${HOST[B]}/v1/models`, response: { data: [{ id: 'claude-x' }] } });
    await expect(wall(w, { service: A, url: `https://${HOST[A]}/v1/models` })).resolves.toBeDefined();
  });

  it('the same path with a body, POST /v1/messages on both: both pass', async () => {
    const w = world();
    await recordCall(w, { service: A, method: 'POST', url: `https://${HOST[A]}/v1/messages`, body: { prompt: 'hi' }, response: { text: 'hello' } });
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { prompt: 'hi' } })).resolves.toBeDefined();
  });

  it('a path that carries an id, called on both services: both pass', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/items/item_0a1b2c3d4e` });
    await expect(wall(w, { service: B, url: `https://${HOST[B]}/v1/items/item_0a1b2c3d4e` })).resolves.toBeDefined();
  });

  it('a query value the agent sent to A, not echoed, may be sent to B', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/search?customer=${DANA}`, response: { hits: 0 } });
    await expect(wall(w, { service: B, url: `https://${HOST[B]}/v1/search?customer=${encodeURIComponent(DANA)}` })).resolves.toBeDefined();
  });

  it('what A returned is still refused in the same trail', async () => {
    const w = world();
    await recordCall(w, { service: A, url: `https://${HOST[A]}/v1/models`, response: { data: [{ owner: DANA }] } });
    await expect(wall(w, { service: B, url: `https://${HOST[B]}/v1/models` })).resolves.toBeDefined();
    await expect(wall(w, { service: B, method: 'POST', url: `https://${HOST[B]}/v1/messages`, body: { content: DANA } })).rejects.toThrow(/read from "openai"/);
  });
});
