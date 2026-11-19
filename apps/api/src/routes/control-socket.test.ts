import Fastify from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ControlSocketAddressError,
  GovernanceApprovalRequiredError,
  type ControlSocketRow,
} from '@stack/shared';
import { ControlSocketService } from '@stack/vault';
import { createErrorHandler } from '../middleware/error-handler.js';
import type { Services } from '../config/services.js';

const context = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));
vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: object) => Object.assign(request, context.current),
}));

const { registerControlSocketRoutes } = await import('./control-socket.js');

const OP = 'op_1';

/** The slice of the repository the service and the routes use, in memory. */
class MemoryRepo {
  row: ControlSocketRow | null = null;
  decisions: Array<Record<string, unknown>> = [];
  async get(operatorId: string) {
    return this.row && this.row.operator_id === operatorId ? this.row : null;
  }
  async getOrCreate(operatorId: string) {
    this.row ??= {
      operator_id: operatorId, socket_id: 'csk_test1', decision_mode: 'auto', decision_url: null, decision_candidate_url: null,
      decision_timeout_ms: 1500, decision_candidate_timeout_ms: null, decision_secret_encrypted: null,
      decision_secret_previous_encrypted: null, decision_secret_rotated_at: null, decision_status: 'unverified',
      decision_verified_at: null, decision_bad_answers: 0, checked_types: null, events_url: null, events_secret_encrypted: null,
      events_secret_previous_encrypted: null, events_secret_rotated_at: null, events_status: 'off', events_verified_at: null,
      events_last_seq: 0, events_acked_seq: 0, events_attempts: 0, events_client_errors: 0, events_first_failure_at: null,
      events_next_attempt_at: null, events_lease_until: null, events_last_error: null, created_at: new Date(), updated_at: new Date(),
    } as ControlSocketRow;
    return this.row;
  }
  async update(_operatorId: string, patch: Record<string, unknown>) {
    this.row = { ...this.row!, ...patch } as ControlSocketRow;
    return this.row;
  }
  async activateEvents(_operatorId: string, patch: Record<string, unknown>) {
    this.row = { ...this.row!, ...patch } as ControlSocketRow;
    return { gap: null };
  }
  async clearOutbox() {}
  async countBadAnswer() { return 0; }
  async outboxCounts() { return { pending: 0, dead: 0 }; }
  async listDecisions() { return this.decisions as never; }
  async getDecision(_op: string, id: string) { return (this.decisions.find((d) => d['id'] === id) ?? null) as never; }
}

/** A KMS that binds ciphertext to its context, as the real one does, and keeps nothing readable. */
const kms = {
  encrypt: vi.fn(async (plaintext: string, ctx: Record<string, string>) => ({
    ciphertext: Buffer.from(JSON.stringify({ p: Buffer.from(plaintext).toString('base64'), ctx })).toString('base64'),
  })),
  decrypt: vi.fn(async (ciphertext: string, ctx: Record<string, string>) => {
    const parsed = JSON.parse(Buffer.from(ciphertext, 'base64').toString()) as { p: string; ctx: Record<string, string> };
    if (JSON.stringify(parsed.ctx) !== JSON.stringify(ctx)) throw new Error('context mismatch');
    return Buffer.from(parsed.p, 'base64').toString();
  }),
};

let repo: MemoryRepo;
let sockets: ControlSocketService;
let controlsOn = true;
let services: Services;
const approvals = { requireApproval: vi.fn(), consume: vi.fn(async () => undefined) };
const probe = { remote: vi.fn(), events: vi.fn() };
const audit = { write: vi.fn(async () => 'aud_1') };
const apps: ReturnType<typeof Fastify>[] = [];
const redisValues = new Map<string, string>();
const redis = {
  set: vi.fn(async (key: string, value: string) => { redisValues.set(key, value); return 'OK'; }),
  getdel: vi.fn(async (key: string) => { const value = redisValues.get(key) ?? null; redisValues.delete(key); return value; }),
};

async function makeApp(deps: Parameters<typeof registerControlSocketRoutes>[2] = { checkAddress: async (url) => url }) {
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(createErrorHandler());
  registerControlSocketRoutes(app, services, deps);
  await app.ready();
  return app;
}

const human = () => { context.current = { operatorId: OP, isDashboardSession: true }; };
const apiKey = () => { context.current = { operatorId: OP }; };
/** A chat assistant: an OAuth access token, which always carries a scope. */
const oauth = () => { context.current = { operatorId: OP, oauthScope: 'accounts:manage' }; };

beforeEach(() => {
  repo = new MemoryRepo();
  sockets = new ControlSocketService({ repo: repo as never, kms: kms as never });
  controlsOn = true;
  approvals.requireApproval.mockReset();
  approvals.requireApproval.mockImplementation(async () => {
    throw new GovernanceApprovalRequiredError('gvr_1', 'https://getstack.run/app/approve/gvr_1', 'operator');
  });
  approvals.consume.mockClear();
  probe.remote.mockReset();
  probe.events.mockReset();
  audit.write.mockClear();
  services = {
    controlSocket: sockets,
    controlSocketRepo: repo,
    controlRemote: { probe: probe.remote },
    controlEvents: { probe: probe.events },
    entitlements: { controlsEnabled: vi.fn(async () => controlsOn) },
    governanceApprovals: approvals,
    audit,
    redis,
  } as unknown as Services;
  redisValues.clear();
  redis.set.mockClear();
  redis.getdel.mockClear();
  context.current = { operatorId: OP };
});
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

const DECISION_URL = 'https://control.customer.example/stack/decide';

describe('who may change the socket', () => {
  it('refuses agent contexts on every route, so an agent can never change its own controls', async () => {
    const app = await makeApp();
    context.current = { operatorId: OP, agentId: 'agt_1' };
    for (const [method, url, payload] of [
      ['GET', '/v1/control-socket', undefined],
      ['PUT', '/v1/control-socket/decision', { url: DECISION_URL }],
      ['PUT', '/v1/control-socket/events', { url: DECISION_URL }],
      ['DELETE', '/v1/control-socket/decision', undefined],
      ['POST', '/v1/control-socket/decision/verify', {}],
      ['POST', '/v1/control-socket/decision/test', {}],
      ['POST', '/v1/control-socket/decision/secret/rotate', {}],
      ['PUT', '/v1/control-socket/mode', { mode: 'none' }],
      ['PUT', '/v1/control-socket/checked-types', { types: ['email.send'] }],
      ['PUT', '/v1/control-socket/on-unavailable', { on_unavailable: 'allow' }],
      ['GET', '/v1/control-decisions', undefined],
    ] as const) {
      const res = await app.inject({ method, url, ...(payload ? { payload } : {}) });
      expect(res.statusCode, `${method} ${url}`).toBe(403);
    }
    expect(repo.row).toBeNull();
    expect(approvals.requireApproval).not.toHaveBeenCalled();
  });

  it('refuses a non-admin member', async () => {
    const app = await makeApp();
    context.current = { operatorId: OP, memberId: 'mem_1', memberRole: 'standard' };
    const res = await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'none' } });
    expect(res.statusCode).toBe(403);
  });
});

describe('the decision address', () => {
  it('checks the address before anyone is asked to approve it', async () => {
    const checkAddress = vi.fn(async () => { throw new ControlSocketAddressError('The address must be a public https URL with no credentials.', 'unsafe_url'); });
    const app = await makeApp({ checkAddress });
    apiKey();
    const res = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: 'https://169.254.169.254/x' } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatchObject({ code: 'CONTROL_SOCKET_ADDRESS_REFUSED', details: { cause: 'unsafe_url' } });
    expect(approvals.requireApproval).not.toHaveBeenCalled();
    expect(repo.row).toBeNull();
  });

  it('an API key gets the approval link, bound to the exact address, and nothing is stored', async () => {
    const app = await makeApp();
    apiKey();
    const res = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL, timeout_ms: 800 } });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('GOVERNANCE_APPROVAL_REQUIRED');
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      operatorId: OP, action: 'control_socket_change', resourceId: OP,
      payload: { target: 'decision', url: DECISION_URL, timeout_ms: 800 },
      requestedVia: 'operator_key',
      summary: expect.stringContaining('control.customer.example'),
    }));
    // The page says what is being approved, in plain words.
    expect(approvals.requireApproval.mock.calls[0]![0].summary).toMatch(/only approve a server you run/i);
    expect(repo.row).toBeNull();
  });

  it('a retry that cites the approval consumes it against the same payload and stores the address, showing the secret once', async () => {
    const app = await makeApp();
    apiKey();
    const res = await app.inject({
      method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL, timeout_ms: 800 },
      headers: { 'x-governance-approval': 'gvr_1' },
    });
    expect(res.statusCode).toBe(201);
    expect(approvals.consume).toHaveBeenCalledWith({
      approvalId: 'gvr_1', operatorId: OP, action: 'control_socket_change', resourceId: OP,
      payload: { target: 'decision', url: DECISION_URL, timeout_ms: 800 }, memberId: null,
    });
    const body = res.json();
    expect(body.secret).toMatch(/^whsec_/);
    expect(body.socket.decision).toMatchObject({ url: DECISION_URL, status: 'unverified', timeout_ms: 800, secret_set: true });
    // Never stored in the clear, and bound to its owner, socket and purpose.
    expect(JSON.stringify(repo.row)).not.toContain(body.secret);
    expect(kms.encrypt).toHaveBeenCalledWith(body.secret, { operator_id: OP, socket_id: 'csk_test1', purpose: 'control_socket_decision' });
    // Not unwrappable under another customer, socket or purpose.
    await expect(kms.decrypt(repo.row!.decision_secret_encrypted!, { operator_id: 'op_2', socket_id: 'csk_test1', purpose: 'control_socket_decision' })).rejects.toThrow();
    await expect(kms.decrypt(repo.row!.decision_secret_encrypted!, { operator_id: OP, socket_id: 'csk_test1', purpose: 'control_socket_events' })).rejects.toThrow();
    expect(audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'control_socket.decision.set', outcome: 'success' }));
    expect(JSON.stringify(audit.write.mock.calls)).not.toContain(body.secret);
  });

  it('a signed-in person approves in the browser itself; the secret is shown once, and a second set does not show it again', async () => {
    const app = await makeApp();
    human();
    const first = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    expect(first.statusCode).toBe(201);
    expect(first.json().secret).toMatch(/^whsec_/);
    expect(approvals.requireApproval).not.toHaveBeenCalled();
    const second = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: 'https://control.customer.example/v2' } });
    expect(second.statusCode).toBe(200);
    expect(second.json().secret).toBeNull();
    const read = await app.inject({ method: 'GET', url: '/v1/control-socket' });
    expect(read.json()).toMatchObject({ decision: { url: 'https://control.customer.example/v2', secret_set: true } });
    expect(read.body).not.toContain('whsec_');
  });

  it('a new address for an enforcing socket waits as a candidate; the current one keeps deciding', async () => {
    const app = await makeApp();
    human();
    await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    probe.remote.mockResolvedValue({ verdict: 'allow' });
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/decision/verify', payload: {} })).json()).toMatchObject({ ok: true, activated: true });
    const changed = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: 'https://other.customer.example/d' } });
    expect(changed.json().socket).toMatchObject({
      effective_mode: 'remote',
      decision: { url: DECISION_URL, pending_url: 'https://other.customer.example/d', status: 'enforcing' },
    });
  });
});

describe('verifying and testing the address', () => {
  it('a passing check puts it into use; a failing one changes nothing and asks no one', async () => {
    const app = await makeApp();
    controlsOn = false;
    apiKey();
    approvals.requireApproval.mockImplementation(async () => { throw new GovernanceApprovalRequiredError('gvr_2', 'x', 'operator'); });
    await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL }, headers: { 'x-governance-approval': 'gvr_1' } });
    approvals.requireApproval.mockClear();

    probe.remote.mockResolvedValueOnce({ verdict: 'unavailable', cause: 'bad_signature' });
    const failed = await app.inject({ method: 'POST', url: '/v1/control-socket/decision/verify', payload: {} });
    expect(failed.json()).toMatchObject({ target: 'decision', ok: false, activated: false, verdict: null, cause: 'bad_signature' });
    expect((await app.inject({ method: 'GET', url: '/v1/control-socket' })).json().effective_mode).toBe('none');
    expect(approvals.requireApproval).not.toHaveBeenCalled();

    // None to your own server only adds checks: no approval.
    probe.remote.mockResolvedValueOnce({ verdict: 'allow' });
    const passed = await app.inject({ method: 'POST', url: '/v1/control-socket/decision/verify', payload: {} });
    expect(passed.json()).toMatchObject({ ok: true, activated: true, verdict: 'allow', cause: null });
    expect((await app.inject({ method: 'GET', url: '/v1/control-socket' })).json()).toMatchObject({ effective_mode: 'remote', decision: { status: 'enforcing' } });
    expect(approvals.requireApproval).not.toHaveBeenCalled();
  });

  it('moving from hosted controls to your own server loosens them: an API key needs the approval, a person does not', async () => {
    const app = await makeApp();
    human();
    await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    probe.remote.mockResolvedValue({ verdict: 'allow' });
    apiKey();
    const blocked = await app.inject({ method: 'POST', url: '/v1/control-socket/decision/verify', payload: {} });
    expect(blocked.statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'account_control_loosen', payload: { target: 'decision', activate: true, url: DECISION_URL, from: 'hosted' },
      summary: expect.stringContaining('Switch from STACK'),
    }));
    expect((await app.inject({ method: 'GET', url: '/v1/control-socket' })).json().effective_mode).toBe('hosted');
    human();
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/decision/verify', payload: {} })).json().activated).toBe(true);
  });

  it('a test exchange changes nothing, and re-checks the address at the moment of the call', async () => {
    const checkAddress = vi.fn(async (url: string) => url);
    const app = await makeApp({ checkAddress });
    human();
    await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    checkAddress.mockClear();
    probe.remote.mockResolvedValue({ verdict: 'deny', reason: { code: 'x', message: null } });
    const res = await app.inject({ method: 'POST', url: '/v1/control-socket/decision/test', payload: {} });
    expect(res.json()).toMatchObject({ ok: false, verdict: 'deny', activated: false });
    expect(checkAddress).toHaveBeenCalledWith(DECISION_URL);
    const sent = probe.remote.mock.calls[0]!;
    expect(sent[0]).toBe(DECISION_URL);
    expect(sent[1].request).toMatchObject({ test: true, action: { type: 'test' }, actor: { kind: 'owner' }, account: null, agent: null });
  });

  it('a test of an address that was never set is 404', async () => {
    const app = await makeApp();
    human();
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/decision/test', payload: {} })).statusCode).toBe(404);
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/events/verify', payload: {} })).statusCode).toBe(404);
  });
});

describe('what loosens needs a person in a browser', () => {
  async function enforcing() {
    const app = await makeApp();
    human();
    await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    probe.remote.mockResolvedValue({ verdict: 'allow' });
    await app.inject({ method: 'POST', url: '/v1/control-socket/decision/verify', payload: {} });
    return app;
  }

  it('clearing an enforcing socket is account_control_loosen; clearing one never verified is control_socket_change', async () => {
    const app = await enforcing();
    apiKey();
    expect((await app.inject({ method: 'DELETE', url: '/v1/control-socket/decision' })).statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenLastCalledWith(expect.objectContaining({
      action: 'account_control_loosen', payload: { target: 'decision', clear: true },
    }));
    human();
    const cleared = await app.inject({ method: 'DELETE', url: '/v1/control-socket/decision' });
    expect(cleared.json()).toMatchObject({ effective_mode: 'hosted', decision: { url: null, secret_set: false, status: 'unverified' } });

    const unverified = await makeApp();
    human();
    await unverified.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    apiKey();
    approvals.requireApproval.mockClear();
    await unverified.inject({ method: 'DELETE', url: '/v1/control-socket/decision' });
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({ action: 'control_socket_change' }));
  });

  it('switching hosted controls to none is a loosening; none to hosted is not, and needs hosted controls to be on', async () => {
    const app = await makeApp();
    apiKey();
    const loosen = await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'none' } });
    expect(loosen.statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'account_control_loosen', payload: { mode: 'none', from: 'hosted' },
    }));
    human();
    expect((await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'none' } })).json().effective_mode).toBe('none');
    approvals.requireApproval.mockClear();
    apiKey();
    const tighten = await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'hosted' } });
    expect(tighten.statusCode).toBe(200);
    expect(tighten.json()).toMatchObject({ mode_setting: 'hosted', effective_mode: 'hosted' });
    expect(approvals.requireApproval).not.toHaveBeenCalled();

    controlsOn = false;
    const refused = await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'hosted' } });
    expect(refused.statusCode).toBe(409);
    expect(refused.json().error.code).toBe('CONTROLS_NOT_ENABLED');
  });

  it('unchecking a kind is a loosening that names it; checking more applies at once', async () => {
    const app = await makeApp();
    human();
    const narrowed = await app.inject({ method: 'PUT', url: '/v1/control-socket/checked-types', payload: { types: ['email.send', 'sms.send', 'tool.run'] } });
    expect(narrowed.json()).toMatchObject({ checks_all_types: false, checked_types: ['email.send', 'sms.send', 'tool.run'] });
    apiKey();
    const remove = await app.inject({ method: 'PUT', url: '/v1/control-socket/checked-types', payload: { types: ['email.send'] } });
    expect(remove.statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'account_control_loosen', payload: { removed: ['sms.send', 'tool.run'], types: ['email.send'] },
      summary: expect.stringContaining('sms.send, tool.run'),
    }));
    approvals.requireApproval.mockClear();
    const add = await app.inject({ method: 'PUT', url: '/v1/control-socket/checked-types', payload: { types: ['email.send', 'sms.send', 'tool.run', 'model.call'] } });
    expect(add.statusCode).toBe(200);
    const all = await app.inject({ method: 'PUT', url: '/v1/control-socket/checked-types', payload: { types: null } });
    expect(all.json()).toMatchObject({ checks_all_types: true });
    expect(approvals.requireApproval).not.toHaveBeenCalled();
  });

  it('what happens when your own server does not answer: refuse by default, allow is a loosening that needs the browser approval, refuse again applies at once', async () => {
    const app = await makeApp();
    human();
    expect((await app.inject({ method: 'GET', url: '/v1/control-socket' })).json().decision.on_unavailable).toBe('refuse');
    // Refusing, which is what it already is, asks no one.
    const same = await app.inject({ method: 'PUT', url: '/v1/control-socket/on-unavailable', payload: { on_unavailable: 'refuse' } });
    expect(same.statusCode).toBe(200);
    expect(approvals.requireApproval).not.toHaveBeenCalled();
    // Allow asks for the existing loosening approval from an API key, and changes nothing until it is given.
    apiKey();
    const asked = await app.inject({ method: 'PUT', url: '/v1/control-socket/on-unavailable', payload: { on_unavailable: 'allow' } });
    expect(asked.statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'account_control_loosen', payload: { on_unavailable: 'allow', from: 'refuse' },
    }));
    expect((await app.inject({ method: 'GET', url: '/v1/control-socket' })).json().decision.on_unavailable).toBe('refuse');
    // A signed-in person does it directly.
    human();
    const allowed = await app.inject({ method: 'PUT', url: '/v1/control-socket/on-unavailable', payload: { on_unavailable: 'allow' } });
    expect(allowed.statusCode).toBe(200);
    expect(allowed.json().decision.on_unavailable).toBe('allow');
    // Back to refuse applies at once, even from an API key; allow again while it is already allow asks no one.
    approvals.requireApproval.mockClear();
    apiKey();
    expect((await app.inject({ method: 'PUT', url: '/v1/control-socket/on-unavailable', payload: { on_unavailable: 'allow' } })).statusCode).toBe(200);
    const back = await app.inject({ method: 'PUT', url: '/v1/control-socket/on-unavailable', payload: { on_unavailable: 'refuse' } });
    expect(back.statusCode).toBe(200);
    expect(back.json().decision.on_unavailable).toBe('refuse');
    expect(approvals.requireApproval).not.toHaveBeenCalled();
    // Nothing else is a setting.
    for (const payload of [{ on_unavailable: 'maybe' }, {}, { on_unavailable: 'allow', extra: 1 }]) {
      expect((await app.inject({ method: 'PUT', url: '/v1/control-socket/on-unavailable', payload })).statusCode).toBe(400);
    }
  });

  it('rejects an unknown kind and an empty list', async () => {
    const app = await makeApp();
    human();
    for (const types of [['telepathy'], []]) {
      expect((await app.inject({ method: 'PUT', url: '/v1/control-socket/checked-types', payload: { types } })).statusCode).toBe(400);
    }
  });

  it('rotating a secret is a socket change; the new secret is shown once and the old one keeps verifying for 24 hours', async () => {
    const app = await makeApp();
    human();
    const set = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    const original = set.json().secret as string;
    apiKey();
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/decision/secret/rotate', payload: {} })).statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({ action: 'control_socket_change', payload: { target: 'decision', rotate: true } }));
    human();
    const rotated = await app.inject({ method: 'POST', url: '/v1/control-socket/decision/secret/rotate', payload: {} });
    expect(rotated.statusCode).toBe(201);
    const fresh = rotated.json().secret as string;
    expect(fresh).toMatch(/^whsec_/);
    expect(fresh).not.toBe(original);
    expect(new Date(rotated.json().previous_valid_until).getTime()).toBeGreaterThan(Date.now() + 23 * 3600_000);
    expect(await sockets.secrets(OP, 'decision')).toEqual([fresh, original]);
  });

  it('choosing none while controls are off still needs the browser approval, and choosing it again does not', async () => {
    const app = await makeApp();
    controlsOn = false;
    apiKey();
    // Nothing decides today, but the setting would outlive a controls subscription and switch its checks off.
    const first = await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'none' } });
    expect(first.statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'account_control_loosen', payload: { mode: 'none', from: 'none' },
    }));
    expect(repo.row?.decision_mode ?? 'auto').toBe('auto');

    human();
    expect((await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'none' } })).json()).toMatchObject({ mode_setting: 'none', effective_mode: 'none' });

    // Already chosen: nothing changes, nothing to approve.
    approvals.requireApproval.mockClear();
    apiKey();
    const again = await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'none' } });
    expect(again.statusCode).toBe(200);
    expect(approvals.requireApproval).not.toHaveBeenCalled();
  });

  it('a controls subscription that starts later does not turn an unapproved none into silent no-checks', async () => {
    const app = await makeApp();
    controlsOn = false;
    apiKey();
    await app.inject({ method: 'PUT', url: '/v1/control-socket/mode', payload: { mode: 'none' } });
    controlsOn = true;
    // Refused, so the setting is still auto and the subscription brings hosted checks with it.
    expect((await app.inject({ method: 'GET', url: '/v1/control-socket' })).json()).toMatchObject({ mode_setting: 'auto', effective_mode: 'hosted' });
  });

  it('refuses to rotate a secret that does not exist', async () => {
    const app = await makeApp();
    human();
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/events/secret/rotate', payload: {} })).statusCode).toBe(404);
  });
});

describe('the events address', () => {
  it('is set behind the approval, verified with a signed test batch, and cleared behind the approval', async () => {
    const app = await makeApp();
    apiKey();
    const blocked = await app.inject({ method: 'PUT', url: '/v1/control-socket/events', payload: { url: 'https://logs.customer.example/stack' } });
    expect(blocked.statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({
      action: 'control_socket_change', payload: { target: 'events', url: 'https://logs.customer.example/stack' },
      summary: expect.stringContaining('whole record'),
    }));
    human();
    const set = await app.inject({ method: 'PUT', url: '/v1/control-socket/events', payload: { url: 'https://logs.customer.example/stack' } });
    expect(set.json().secret).toMatch(/^whsec_/);
    expect(set.json().socket.events).toMatchObject({ status: 'unverified', url: 'https://logs.customer.example/stack' });

    probe.events.mockResolvedValue({ ok: false, cause: 'http_status', latencyMs: 40 });
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/events/verify', payload: {} })).json()).toMatchObject({
      target: 'events', ok: false, activated: false, cause: 'http_status',
    });
    probe.events.mockResolvedValue({ ok: true, cause: null, latencyMs: 40 });
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/events/verify', payload: {} })).json()).toMatchObject({ ok: true, activated: true, latency_ms: 40 });
    expect((await app.inject({ method: 'GET', url: '/v1/control-socket' })).json().events.status).toBe('active');

    apiKey();
    approvals.requireApproval.mockClear();
    expect((await app.inject({ method: 'DELETE', url: '/v1/control-socket/events' })).statusCode).toBe(403);
    expect(approvals.requireApproval).toHaveBeenCalledWith(expect.objectContaining({ action: 'control_socket_change', payload: { target: 'events', clear: true } }));
  });
});

describe('reading the decisions', () => {
  it('lists and reads decisions of the operator, with the request only where one was kept', async () => {
    const app = await makeApp();
    human();
    repo.decisions = [
      {
        id: 'dec_aaaaaaaaaaaaaaaaaaaaaaaa', operator_id: OP, account_id: 'acct_1', agent_id: 'agt_1', action_type: 'email.send',
        decider: 'remote', verdict: 'deny', reason_code: 'blocked', cause: null, latency_ms: 31, charged: false,
        request_digest: `sha256:${'a'.repeat(64)}`, request: { action: { type: 'email.send' } }, created_at: new Date('2026-10-21T10:00:00Z'),
      },
    ];
    const list = await app.inject({ method: 'GET', url: '/v1/control-decisions?limit=10&verdict=deny' });
    expect(list.json().decisions).toEqual([expect.objectContaining({
      id: 'dec_aaaaaaaaaaaaaaaaaaaaaaaa', verdict: 'deny', reason_code: 'blocked', decider: 'remote', charged: false,
      request: { action: { type: 'email.send' } }, created_at: '2026-10-21T10:00:00.000Z',
    })]);
    expect((await app.inject({ method: 'GET', url: '/v1/control-decisions/dec_aaaaaaaaaaaaaaaaaaaaaaaa' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/v1/control-decisions/dec_bbbbbbbbbbbbbbbbbbbbbbbb' })).statusCode).toBe(404);
    expect((await app.inject({ method: 'GET', url: '/v1/control-decisions/nope' })).statusCode).toBe(400);
    expect((await app.inject({ method: 'GET', url: '/v1/control-decisions?limit=9999' })).statusCode).toBe(400);
  });
});

describe('who may hold a signing secret', () => {
  const approved = { 'x-governance-approval': 'gvr_1' };
  const tokenOf = (reveal: { url: string }) => reveal.url.split('#')[1]!;

  it('an OAuth caller is never given the secret, only a Console link to read it once', async () => {
    const app = await makeApp();
    oauth();
    for (const [url, payload] of [
      ['/v1/control-socket/decision', { url: DECISION_URL }],
      ['/v1/control-socket/events', { url: DECISION_URL }],
    ] as const) {
      repo.row = null;
      const res = await app.inject({ method: 'PUT', url, payload, headers: approved });
      expect(res.statusCode, url).toBe(201);
      expect(res.body, url).not.toContain('whsec_');
      expect(res.json().secret, url).toBeNull();
      expect(res.json().secret_reveal.url, url).toMatch(/\/app\/control-secret#[A-Za-z0-9_-]{43}$/);
      expect(new Date(res.json().secret_reveal.expires_at).getTime()).toBeGreaterThan(Date.now() + 55 * 60_000);
    }
  });

  it('an OAuth caller rotating gets a link too, and the answer holds no secret', async () => {
    const app = await makeApp();
    human();
    await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    oauth();
    const rotated = await app.inject({ method: 'POST', url: '/v1/control-socket/decision/secret/rotate', payload: {}, headers: approved });
    expect(rotated.statusCode).toBe(201);
    expect(rotated.body).not.toContain('whsec_');
    expect(rotated.json()).toMatchObject({ target: 'decision', secret: null, secret_reveal: { url: expect.stringContaining('/app/control-secret#') } });
  });

  it('a dashboard session and an API key still receive the secret in the answer, with no link', async () => {
    const app = await makeApp();
    human();
    const first = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    expect(first.json()).toMatchObject({ secret: expect.stringMatching(/^whsec_/), secret_reveal: null });
    apiKey();
    const rotated = await app.inject({ method: 'POST', url: '/v1/control-socket/decision/secret/rotate', payload: {}, headers: approved });
    expect(rotated.json()).toMatchObject({ secret: expect.stringMatching(/^whsec_/), secret_reveal: null });
  });

  it('a call that created no secret leaves no link', async () => {
    const app = await makeApp();
    human();
    await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL } });
    oauth();
    const again = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: 'https://control.customer.example/v2' }, headers: approved });
    expect(again.json()).toMatchObject({ secret: null, secret_reveal: null });
    expect(redis.set).toHaveBeenCalledTimes(0);
  });

  it('the person reads the secret once, signed in, from the link; a second read finds nothing', async () => {
    const app = await makeApp();
    oauth();
    const set = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL }, headers: approved });
    const token = tokenOf(set.json().secret_reveal);
    // Only the hash of the token is held.
    expect([...redisValues.keys()].join()).not.toContain(token);

    human();
    const read = await app.inject({ method: 'POST', url: '/v1/control-socket/secret/reveal', payload: { token } });
    expect(read.statusCode).toBe(200);
    const live = await sockets.secrets(OP, 'decision');
    expect(read.json()).toEqual({ target: 'decision', secret: live![0] });
    expect(read.json().secret).toMatch(/^whsec_/);
    expect(audit.write).toHaveBeenCalledWith(expect.objectContaining({ action: 'control_socket.decision.secret.reveal' }));
    expect(JSON.stringify(audit.write.mock.calls)).not.toContain(live![0]);

    const again = await app.inject({ method: 'POST', url: '/v1/control-socket/secret/reveal', payload: { token } });
    expect(again.statusCode).toBe(404);
    expect(again.body).not.toContain('whsec_');
  });

  it('only a signed-in person can use the link: not an OAuth token, not an API key, not an agent', async () => {
    const app = await makeApp();
    oauth();
    const set = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL }, headers: approved });
    const token = tokenOf(set.json().secret_reveal);
    for (const set of [oauth, apiKey, () => { context.current = { operatorId: OP, agentId: 'agt_1' }; }]) {
      set();
      const res = await app.inject({ method: 'POST', url: '/v1/control-socket/secret/reveal', payload: { token } });
      expect(res.statusCode).toBe(403);
      expect(res.body).not.toContain('whsec_');
    }
    // None of those spent it.
    human();
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/secret/reveal', payload: { token } })).statusCode).toBe(200);
  });

  it('a link is bound to its customer, and an unknown or malformed token reveals nothing', async () => {
    const app = await makeApp();
    oauth();
    const set = await app.inject({ method: 'PUT', url: '/v1/control-socket/decision', payload: { url: DECISION_URL }, headers: approved });
    const token = tokenOf(set.json().secret_reveal);
    context.current = { operatorId: 'op_2', isDashboardSession: true };
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/secret/reveal', payload: { token } })).statusCode).toBe(404);
    human();
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/secret/reveal', payload: { token: 'x'.repeat(43) } })).statusCode).toBe(404);
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/secret/reveal', payload: { token: 'short' } })).statusCode).toBe(400);
    expect((await app.inject({ method: 'POST', url: '/v1/control-socket/secret/reveal', payload: {} })).statusCode).toBe(400);
  });
});
