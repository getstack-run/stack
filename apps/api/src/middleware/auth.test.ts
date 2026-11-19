// Behavioural tests for createAuthMiddleware.
//
// This file exists because the middleware had NONE. The only test that
// touched the dashboard-session path (require-platform.test.ts) counted
// occurrences of a string in the source, so it passed identically with
// and without the privilege-escalation bug it was nominally guarding.
//
// The bug: a team member's dashboard session carries `member_id`, but the
// SESSION_JWT_AUDIENCE branch never read it. The request therefore
// authenticated as the bare parent operator — inheriting is_admin off the
// operator row, skipping requireOperatorAdmin's role gate, and losing
// allowed_connections scoping (which fails OPEN when undefined).

import { describe, it, expect } from 'vitest';
import { SESSION_JWT_AUDIENCE } from '@stack/shared';
import {
  createAuthMiddleware,
  createEnrollmentAuthMiddleware,
  MAX_BEARER_TOKEN_LENGTH,
} from './auth.js';
import { requireOperatorAdmin } from './require-platform.js';
import { fakeEntitlements } from '../test/entitlements.js';
import { fakeBrowserSessions } from '../test/browser-sessions.js';
import { EngineRegistries } from '../config/registries.js';

const OPERATOR = {
  id: 'op_acme',
  email: 'owner@acme.test',
  tier: 'business',
  status: 'active',
  is_admin: true, // operator-account-admin: suspend/comp/tier-toggle authority
  is_platform_staff: true, // STACK staff account
  is_partner: true,
  stripe_customer_id: 'cus_1',
};

const MEMBER_READONLY = {
  id: 'mem_ro',
  operator_id: 'op_acme',
  email: 'ro@acme.test',
  role: 'readonly',
  status: 'active',
  allowed_connections: ['conn_1'],
};

type MemberRow = typeof MEMBER_READONLY;

/**
 * Minimal Services double. Only the collaborators the JWT path touches:
 * the signer (which resolves the token), the operator lookup, and the
 * member lookup. Anything else the middleware reaches for is a genuine
 * test failure, not something to stub away.
 */
function fakeServices(opts: {
  aud: string;
  payload?: Record<string, unknown>;
  sub?: string;
  members?: MemberRow[];
  operator?: Partial<typeof OPERATOR>;
  passportClaims?: Record<string, unknown>;
  sessionActive?: boolean;
}) {
  const operator = { ...OPERATOR, ...(opts.operator ?? {}) };
  const members = opts.members ?? [MEMBER_READONLY];
  return {
    get browserSessions() { return fakeBrowserSessions(this); },
    signer: {
      verifyAccessOrSession: async () => ({
        sub: opts.sub ?? operator.id,
        aud: opts.aud,
        payload: {
          email: opts.payload?.['member_id'] ? (members.find(member => member.id === opts.payload?.['member_id'])?.email ?? 'removed@acme.test') : operator.email,
          ...(opts.payload?.['member_id'] ? { is_member: true } : {}),
          ...(opts.payload ?? {}),
        },
      }),
    },
    registries: new EngineRegistries(),
    entitlements: fakeEntitlements(), operator: {
      getById: async (id: string) => {
        if (id !== operator.id) throw new Error('operator not found');
        return operator;
      },
    },
    member: {
      findById: async (id: string) => members.find((m) => m.id === id),
    },
    dashboardSessions: {
      assertActive: async () => {
        if (opts.sessionActive === false) throw new Error('synthetic revoked session family');
      },
    },
    passport: {
      verify: async () => opts.passportClaims,
    },
  } as never;
}

function fakeRequest(token = 'not-an-sk-live-token', route: { method: string; url: string } = { method: 'GET', url: '/v1/agents' }) {
  const logged: unknown[] = [];
  const req = {
    headers: { authorization: `Bearer ${token}` },
    method: route.method,
    routeOptions: { url: route.url },
    log: {
      info: (...a: unknown[]) => logged.push(a),
      warn: (...a: unknown[]) => logged.push(a),
      error: (...a: unknown[]) => logged.push(a),
    },
  };
  return req as unknown as Parameters<ReturnType<typeof createAuthMiddleware>>[0];
}

const fakeReply = {
  header() { return this; },
  status() { return this; },
  send() { return this; },
} as unknown as Parameters<ReturnType<typeof createAuthMiddleware>>[1];

async function authenticateWith(services: never, token?: string, route?: { method: string; url: string }) {
  const req = fakeRequest(token, route);
  await createAuthMiddleware(services)(req, fakeReply);
  return req as unknown as Record<string, unknown>;
}

function peekableJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.signature`;
}

describe('bearer size ceiling', () => {
  function noLookupServices(events: string[]) {
    return {
      signer: {
        verifyAccessOrSession: async () => { events.push('session-verify'); },
        verifyEnrollmentTicket: async () => { events.push('ticket-verify'); },
      },
      entitlements: fakeEntitlements(), operator: {
        authenticateByApiKey: async () => { events.push('api-key-db'); },
        getById: async () => { events.push('operator-db'); },
      },
      agent: {
        getById: async () => { events.push('agent-db'); },
      },
      passport: {
        verify: async () => { events.push('passport-verify'); },
      },
      redis: {
        get: async () => { events.push('redis-get'); },
        set: async () => { events.push('redis-set'); },
      },
    } as never;
  }

  it('rejects an oversized JWT before decode, verification, DB, or Redis work', async () => {
    const events: string[] = [];
    const services = noLookupServices(events);
    await expect(authenticateWith(services, 'x'.repeat(MAX_BEARER_TOKEN_LENGTH + 1)))
      .rejects.toThrow();
    expect(events).toEqual([]);
  });

  it('also rejects it before the enrollment-ticket verifier runs', async () => {
    const events: string[] = [];
    const services = noLookupServices(events);
    await expect(createEnrollmentAuthMiddleware(services)(
      fakeRequest('x'.repeat(MAX_BEARER_TOKEN_LENGTH + 1)),
      fakeReply,
    )).rejects.toThrow();
    expect(events).toEqual([]);
  });
});

describe('dashboard session carrying member_id', () => {
  it('populates the member context from the DB row', async () => {
    const req = await authenticateWith(
      fakeServices({ aud: SESSION_JWT_AUDIENCE, payload: { member_id: 'mem_ro' } }),
    );

    expect(req['operatorId']).toBe('op_acme');
    expect(req['memberId']).toBe('mem_ro');
    expect(req['memberRole']).toBe('readonly');
    expect(req['allowedConnections']).toEqual(['conn_1']);
  });

  it('does NOT inherit the operator row authority flags', async () => {
    // The escalation. The operator row has all three set; the member
    // must end up with none of them.
    const req = await authenticateWith(
      fakeServices({ aud: SESSION_JWT_AUDIENCE, payload: { member_id: 'mem_ro' } }),
    );

    expect(req['isAdmin']).toBe(false);
    expect(req['isPlatformStaff']).toBe(false);
    expect(req['isPartner']).toBe(false);
  });

  it('is refused by requireOperatorAdmin at role readonly', async () => {
    // End-to-end proof of the actual exploit: before the fix memberId was
    // unset, requireOperatorAdmin took its "the operator owns their own
    // account" branch, and this resolved — reaching member CRUD, i.e.
    // PATCH /v1/team/members/:id, i.e. self-promotion to admin.
    const req = await authenticateWith(
      fakeServices({ aud: SESSION_JWT_AUDIENCE, payload: { member_id: 'mem_ro' } }),
    );

    await expect(
      requireOperatorAdmin(
        req as unknown as Parameters<typeof requireOperatorAdmin>[0],
        {} as unknown as Parameters<typeof requireOperatorAdmin>[1],
      ),
    ).rejects.toThrow(/operator-admin/);
  });

  it('still allows an admin member through requireOperatorAdmin', async () => {
    const admin = { ...MEMBER_READONLY, id: 'mem_admin', role: 'admin' };
    const req = await authenticateWith(
      fakeServices({
        aud: SESSION_JWT_AUDIENCE,
        payload: { member_id: 'mem_admin' },
        members: [admin],
      }),
    );

    expect(req['memberRole']).toBe('admin');
    await expect(
      requireOperatorAdmin(
        req as unknown as Parameters<typeof requireOperatorAdmin>[0],
        {} as unknown as Parameters<typeof requireOperatorAdmin>[1],
      ),
    ).resolves.toBeUndefined();
  });

  it('keeps isDashboardSession set — it describes the channel, not privilege', async () => {
    // the human at the browser IS the step-up ceremony. The fix
    // must not take this away, or every member action starts demanding an
    // approval that only a dashboard session can grant.
    const req = await authenticateWith(
      fakeServices({ aud: SESSION_JWT_AUDIENCE, payload: { member_id: 'mem_ro' } }),
    );
    expect(req['isDashboardSession']).toBe(true);
  });

  it('fails closed when the member was revoked after the token was issued', async () => {
    const revoked = { ...MEMBER_READONLY, status: 'revoked' };
    await expect(
      authenticateWith(
        fakeServices({
          aud: SESSION_JWT_AUDIENCE,
          payload: { member_id: 'mem_ro' },
          members: [revoked],
        }),
      ),
    ).rejects.toThrow();
  });

  it('fails closed when the server-side session family was revoked', async () => {
    await expect(authenticateWith(fakeServices({
      aud: SESSION_JWT_AUDIENCE,
      payload: { member_id: 'mem_ro' },
      sessionActive: false,
    }))).rejects.toThrow('synthetic revoked session family');
  });

  it('fails closed when the member row is gone entirely', async () => {
    await expect(
      authenticateWith(
        fakeServices({
          aud: SESSION_JWT_AUDIENCE,
          payload: { member_id: 'mem_ghost' },
          members: [],
        }),
      ),
    ).rejects.toThrow();
  });

  it('fails closed when the member belongs to a different operator', async () => {
    // Cross-operator binding. No path can forge this today (we sign the
    // token), but none of the three re-load sites checked it either, so
    // any future issuer that gets member_id wrong would have been honoured
    // against whatever operator sat in `sub`.
    const foreign = { ...MEMBER_READONLY, operator_id: 'op_other' };
    await expect(
      authenticateWith(
        fakeServices({
          aud: SESSION_JWT_AUDIENCE,
          payload: { member_id: 'mem_ro' },
          members: [foreign],
        }),
      ),
    ).rejects.toThrow();
  });

  it('leaves no inherited authority behind when the member load fails', async () => {
    // The flags are cleared BEFORE the load precisely so a throw cannot
    // leave a half-built request carrying operator authority.
    const req = fakeRequest();
    const services = fakeServices({
      aud: SESSION_JWT_AUDIENCE,
      payload: { member_id: 'mem_ghost' },
      members: [],
    });
    await expect(createAuthMiddleware(services)(req, fakeReply)).rejects.toThrow();

    const r = req as unknown as Record<string, unknown>;
    expect(r['isAdmin']).toBe(false);
    expect(r['isPlatformStaff']).toBe(false);
    expect(r['isPartner']).toBe(false);
    expect(r['memberId']).toBeUndefined();
  });
});

describe('dashboard session with no member_id (the operator themselves)', () => {
  it('keeps the operator row authority', async () => {
    const req = await authenticateWith(fakeServices({ aud: SESSION_JWT_AUDIENCE, payload: {} }));

    expect(req['operatorId']).toBe('op_acme');
    expect(req['memberId']).toBeUndefined();
    expect(req['isAdmin']).toBe(true);
    expect(req['isPlatformStaff']).toBe(true);
    expect(req['isPartner']).toBe(true);
    expect(req['isDashboardSession']).toBe(true);
  });
});

describe('OAuth access token carrying member_id', () => {
  it('clears inherited authority the same way the session path does', async () => {
    // The OAuth branch re-loaded the member row but cleared none of the
    // operator flags, so an OAuth member context kept is_admin AND
    // is_platform_staff. Both member paths must agree.
    const req = await authenticateWith(
      fakeServices({ aud: 'stack:api', payload: { member_id: 'mem_ro', scope: 'agents:read' } }),
    );

    expect(req['memberId']).toBe('mem_ro');
    expect(req['memberRole']).toBe('readonly');
    expect(req['isAdmin']).toBe(false);
    expect(req['isPlatformStaff']).toBe(false);
    expect(req['isPartner']).toBe(false);
    // Not a browser session — must not get the step-up free pass.
    expect(req['isDashboardSession']).toBeUndefined();
  });
});

describe('verified inbound Passport context', () => {
  it('stamps generic verified authority without exposing credential references', async () => {
    const token = peekableJwt({ aud: 'stack:passport' });
    const req = await authenticateWith(
      fakeServices({
        aud: 'stack:passport',
        passportClaims: {
          jti: 'pp_verified',
          stk: {
            operator_id: 'op_acme',
            agent_id: 'agt_verified',
            mission_ids: ['ms_verified'],
            intent_services: ['github'],
            services: [{
              service_id: 'svc_github',
              service_name: 'github',
              scopes: ['issues:read'],
              connection_id: 'scon_github',
              credential_ref: 'must-not-propagate',
            }],
          },
        },
      }),
      token,
    );

    expect(req['agentId']).toBe('agt_verified');
    expect(req['passportContext']).toEqual({
      jti: 'pp_verified',
      operator_id: 'op_acme',
      agent_id: 'agt_verified',
      mission_ids: ['ms_verified'],
      intent_services: ['github'],
      services: [{
        service_id: 'svc_github',
        service_name: 'github',
        scopes: ['issues:read'],
        connection_id: 'scon_github',
      }],
    });
    expect(req['platformPassport']).toBeUndefined();
  });

  it('normalizes optional mission and intent lists for legacy Passports', async () => {
    const token = peekableJwt({ aud: 'stack:passport' });
    const req = await authenticateWith(
      fakeServices({
        aud: 'stack:passport',
        passportClaims: {
          jti: 'pp_legacy',
          stk: {
            operator_id: 'op_acme',
            agent_id: 'agt_legacy',
            services: [],
          },
        },
      }),
      token,
    );

    expect(req['passportContext']).toMatchObject({
      mission_ids: [],
      intent_services: [],
    });
  });
});

describe('a Passport made for a workspace command', () => {
  const token = peekableJwt({ aud: 'stack:passport' });
  const commandPassport = () => fakeServices({
    aud: 'stack:passport',
    passportClaims: {
      jti: 'pp_command',
      stk: {
        operator_id: 'op_acme',
        agent_id: 'agt_command',
        mission_ids: ['ms_command'],
        services: [],
        workspace_command: { workspace_id: 'ws_1' },
      },
    },
  });

  it('is accepted on the proxy routes it was made for', async () => {
    for (const route of [
      { method: 'POST', url: '/v1/proxy' },
      { method: 'GET', url: '/v1/proxy/usage' },
      { method: 'POST', url: '/v1/proxy/operations/get' },
    ]) {
      const req = await authenticateWith(commandPassport(), token, route);
      expect(req['agentId'], route.url).toBe('agt_command');
    }
  });

  it('is refused as a bearer on every route that mints or renews a Passport, and on every workspace route', async () => {
    for (const route of [
      { method: 'POST', url: '/v1/passports/issue' },
      { method: 'POST', url: '/v1/passports/refresh' },
      { method: 'POST', url: '/v1/passports/delegate' },
      { method: 'POST', url: '/v1/passports/revoke' },
      { method: 'POST', url: '/v1/accounts/:id/workspaces/exec' },
      { method: 'GET', url: '/v1/accounts/:id/workspaces' },
      { method: 'POST', url: '/v1/accounts/:id/workspaces/:wid/files/read' },
      { method: 'POST', url: '/v1/accounts/:id/workspaces/:wid/stop' },
      { method: 'GET', url: '/v1/agents' },
    ]) {
      await expect(authenticateWith(commandPassport(), token, route), `${route.method} ${route.url}`)
        .rejects.toMatchObject({ code: 'FORBIDDEN' });
    }
  });

  it('is refused where the route is unknown, so a new route is closed to it until someone opens it', async () => {
    const req = fakeRequest(token);
    (req as unknown as { routeOptions: unknown }).routeOptions = undefined;
    await expect(createAuthMiddleware(commandPassport())(req, fakeReply)).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
});

describe('operator with a pending erasure job', () => {
  it('rejects a dashboard session before member context is applied', async () => {
    await expect(authenticateWith(fakeServices({
      aud: SESSION_JWT_AUDIENCE,
      payload: { member_id: 'mem_ro' },
      operator: { status: 'deleted' },
    }))).rejects.toMatchObject({ code: 'OPERATOR_DELETED' });
  });

  it('rejects an OAuth access token before its live-family check', async () => {
    await expect(authenticateWith(fakeServices({
      aud: 'stack:api',
      payload: { token_family_id: 'family_pending_erasure' },
      operator: { status: 'deleted' },
    }))).rejects.toMatchObject({ code: 'OPERATOR_DELETED' });
  });
});

describe('unknown audience', () => {
  it('is refused', async () => {
    await expect(
      authenticateWith(fakeServices({ aud: 'stack:something-else' })),
    ).rejects.toThrow();
  });
});

describe('agent JWT replay protection ordering', () => {
  function agentServices(options?: {
    verifyError?: Error;
    redisResult?: 'OK' | null;
    oversizedAgentLookup?: () => void;
    /** The `exp` the signer reports for the verified token (seconds), default a minute from now. */
    verifiedExp?: number;
  }) {
    const events: string[] = [];
    const replayWrites: unknown[][] = [];
    return {
      events,
      replayWrites,
      services: {
        agent: {
          getById: async () => {
            options?.oversizedAgentLookup?.();
            events.push('agent');
            return {
              id: 'agt_verified',
              operator_id: 'op_acme',
              pubkey: { kty: 'OKP', crv: 'Ed25519', x: 'public' },
              enrolled_at: new Date(),
              status: 'active',
              passport_blocked: false,
            };
          },
        },
        signer: {
          verifyAgentJwt: async () => {
            events.push('verify');
            if (options?.verifyError) throw options.verifyError;
            return { sub: 'agt_verified', jti: 'aj_0123456789abcdefghijkl', iat: 0, exp: options?.verifiedExp ?? Math.floor(Date.now() / 1_000) + 60 };
          },
        },
        entitlements: fakeEntitlements(), operator: {
          getById: async () => {
            events.push('operator');
            return OPERATOR;
          },
        },
        redis: {
          set: async (...args: unknown[]) => {
            events.push('redis');
            replayWrites.push(args);
            return options && 'redisResult' in options ? options.redisResult : 'OK';
          },
        },
      } as never,
    };
  }

  function agentJwt(overrides: Record<string, unknown> = {}): string {
    return peekableJwt({
      iss: 'stack-sdk',
      sub: 'agt_verified',
      jti: 'aj_0123456789abcdefghijkl',
      exp: Math.floor(Date.now() / 1_000) + 60,
      ...overrides,
    });
  }

  it('does not write an attacker-controlled replay key before signature verification', async () => {
    const signatureError = new Error('bad signature');
    signatureError.name = 'JWSSignatureVerificationFailed';
    const fixture = agentServices({ verifyError: signatureError });
    await expect(authenticateWith(fixture.services, agentJwt())).rejects.toThrow();
    expect(fixture.events).toEqual(['agent', 'verify']);
  });

  it('claims the replay nonce only after signature and live operator checks', async () => {
    const fixture = agentServices();
    const request = await authenticateWith(fixture.services, agentJwt());
    expect(fixture.events).toEqual(['agent', 'verify', 'operator', 'redis']);
    expect(request['agentId']).toBe('agt_verified');
  });

  it('rejects a verified nonce already claimed by another request', async () => {
    const fixture = agentServices({ redisResult: null });
    await expect(authenticateWith(fixture.services, agentJwt()))
      .rejects.toMatchObject({ code: 'AGENT_JWT_REPLAYED' });
    expect(fixture.events).toEqual(['agent', 'verify', 'operator', 'redis']);
  });

  it('remembers a nonce for the whole life of the token: its exp plus the clock tolerance, never under 120 seconds', async () => {
    const now = Math.floor(Date.now() / 1_000);
    const sixty = agentServices({ verifiedExp: now + 60 });
    await authenticateWith(sixty.services, agentJwt());
    expect(sixty.replayWrites[0]?.slice(2, 5)).toEqual(['EX', 120, 'NX']);
    // A third-party token may live 120 seconds and still verifies for 30 more: a 120 second memory ended inside that window.
    const longest = agentServices({ verifiedExp: now + 120 });
    await authenticateWith(longest.services, agentJwt());
    const ttl = longest.replayWrites[0]?.[3] as number;
    expect(ttl).toBeGreaterThanOrEqual(120 + 30);
    expect(longest.replayWrites[0]?.slice(2, 3)).toEqual(['EX']);
  });

  it('rejects oversized unverified identifiers before DB or Redis work', async () => {
    let lookedUp = false;
    const fixture = agentServices({ oversizedAgentLookup: () => { lookedUp = true; } });
    await expect(authenticateWith(
      fixture.services,
      agentJwt({ jti: `aj_${'x'.repeat(300)}` }),
    )).rejects.toThrow();
    expect(lookedUp).toBe(false);
    expect(fixture.events).toEqual([]);
  });
});
