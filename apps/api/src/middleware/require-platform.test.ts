import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { engineRoutes } from '../test/route-scan.js';
import { isAdminReaders, unclassifiedMutatingRoutes, withoutComments } from './require-platform.checks.js';
import {
  denyAgentContexts,
  requirePlatformStaff,
  requirePlatformMonitorOrStaff,
  requireOperatorAdmin,
} from './require-platform.js';

// Build a minimal fake FastifyRequest. We never actually hit Fastify's
// runtime here; the middlewares only read the fields we set.
function fakeRequest(overrides: Record<string, unknown>) {
  return overrides as unknown as Parameters<typeof requirePlatformStaff>[0];
}
const fakeReply = {} as unknown as Parameters<typeof requirePlatformStaff>[1];

describe('requirePlatformStaff', () => {
  it('passes when isPlatformStaff = true', async () => {
    await expect(
      requirePlatformStaff(fakeRequest({ isPlatformStaff: true }), fakeReply),
    ).resolves.toBeUndefined();
  });

  it('refuses when isPlatformStaff = false', async () => {
    await expect(
      requirePlatformStaff(fakeRequest({ isPlatformStaff: false }), fakeReply),
    ).rejects.toThrow(/platform-staff/);
  });

  it('refuses when isPlatformStaff is undefined (fail-closed)', async () => {
    await expect(
      requirePlatformStaff(fakeRequest({}), fakeReply),
    ).rejects.toThrow(/platform-staff/);
  });

  it('refuses when isPlatformStaff is truthy-but-not-true (e.g. "yes")', async () => {
    // Strict equality — only literal `true` passes.
    await expect(
      requirePlatformStaff(fakeRequest({ isPlatformStaff: 'yes' }), fakeReply),
    ).rejects.toThrow(/platform-staff/);
  });

  it('refuses when only memberRole = admin (operator-admin is NOT platform-staff)', async () => {
    await expect(
      requirePlatformStaff(
        fakeRequest({ isPlatformStaff: false, memberRole: 'admin' }),
        fakeReply,
      ),
    ).rejects.toThrow(/platform-staff/);
  });

  it('refuses when only isAdmin = true (operator-account-admin is NOT platform-staff)', async () => {
    // Critical regression test: today's bug is that isAdmin is being
    // used as platform-staff. After, isAdmin alone must NOT
    // pass the platform gate — the operator must have is_platform_staff
    // = true on their row, which the auth middleware reflects into
    // request.isPlatformStaff.
    await expect(
      requirePlatformStaff(
        fakeRequest({ isAdmin: true, isPlatformStaff: false }),
        fakeReply,
      ),
    ).rejects.toThrow(/platform-staff/);
  });
});

describe('requirePlatformMonitorOrStaff', () => {
  it('passes when isPlatformStaff = true (staff is a superset)', async () => {
    await expect(
      requirePlatformMonitorOrStaff(
        fakeRequest({ isPlatformStaff: true }),
        fakeReply,
      ),
    ).resolves.toBeUndefined();
  });

  it('passes when platformPassport.platform_intent = monitor', async () => {
    await expect(
      requirePlatformMonitorOrStaff(
        fakeRequest({
          isPlatformStaff: false,
          platformPassport: {
            jti: 'pass_x',
            operator_id: 'op_stack_system',
            agent_id: 'agt_monitor',
            platform_intent: 'monitor',
          },
        }),
        fakeReply,
      ),
    ).resolves.toBeUndefined();
  });

  it('refuses when platformPassport.platform_intent = staff (must be monitor or staff-flag)', async () => {
    // Belt-and-suspenders: an explicit staff passport carrying
    // platform_intent='staff' would have ALSO set isPlatformStaff=true
    // via the auth middleware. If for some reason it didn't (bug or
    // test mock), this gate refuses — staff intent without the flag
    // shouldn't pass either of the two pass conditions.
    await expect(
      requirePlatformMonitorOrStaff(
        fakeRequest({
          isPlatformStaff: false,
          platformPassport: {
            jti: 'pass_x',
            operator_id: 'op_other',
            agent_id: 'agt_other',
            platform_intent: 'staff',
          },
        }),
        fakeReply,
      ),
    ).rejects.toThrow();
  });

  it('refuses an unauthenticated-shape request', async () => {
    await expect(
      requirePlatformMonitorOrStaff(fakeRequest({}), fakeReply),
    ).rejects.toThrow();
  });
});

describe('requireOperatorAdmin', () => {
  it('passes for operator (no member context)', async () => {
    await expect(
      requireOperatorAdmin(
        fakeRequest({ operatorId: 'op_x', isAdmin: false }),
        fakeReply,
      ),
    ).resolves.toBeUndefined();
  });

  it('passes for member with role = admin', async () => {
    await expect(
      requireOperatorAdmin(
        fakeRequest({ operatorId: 'op_x', memberId: 'mem_a', memberRole: 'admin' }),
        fakeReply,
      ),
    ).resolves.toBeUndefined();
  });

  it('refuses member with role = standard', async () => {
    await expect(
      requireOperatorAdmin(
        fakeRequest({ operatorId: 'op_x', memberId: 'mem_a', memberRole: 'standard' }),
        fakeReply,
      ),
    ).rejects.toThrow(/operator-admin/);
  });

  it('refuses member with role = readonly', async () => {
    await expect(
      requireOperatorAdmin(
        fakeRequest({ operatorId: 'op_x', memberId: 'mem_a', memberRole: 'readonly' }),
        fakeReply,
      ),
    ).rejects.toThrow(/operator-admin/);
  });

  it('refuses member with no role (fail-closed)', async () => {
    await expect(
      requireOperatorAdmin(
        fakeRequest({ operatorId: 'op_x', memberId: 'mem_a' }),
        fakeReply,
      ),
    ).rejects.toThrow(/operator-admin/);
  });
});

// ─── Source-lint structural assertions ─────────────────────────────────
// These tests read the actual route source files and assert that the
// fragility patterns we just removed do not creep back. CI fails any
// commit that adds a new route file violating the invariant.
//
// What's enforced:
//   1. No route file references `request.isAdmin` to gate access.
//      Exception (allowlisted): agents.ts force-rotation site uses the
//      named `requireOperatorAdmin` helper — not raw isAdmin.
//   2. Platform-staff route files do NOT call createAuthMiddleware /
//      requireRole / inline `request.isPlatformStaff` checks. They
//      inherit auth from the /v1/admin encapsulation block.
//   3. The skills approve/reject/pending-reviews URLs no longer live
//      in skills.ts — they moved to admin-skills.ts under /v1/admin/*.
const here = dirname(fileURLToPath(import.meta.url));
describe('structural — route files', () => {
  const readRoute = (name: string): string => engineRoutes.read(name);

  it('no route file references request.isAdmin (fragility: privilege gate inline in handler)', () => {
    expect(isAdminReaders(engineRoutes)).toEqual([]);
  });

  it('operator-admin route files do not declare per-route requireRole calls (gate at scope)', () => {
    for (const f of ['members.ts', 'oauth-apps.ts', 'sso-domains.ts']) {
      const src = readRoute(f);
      const stripped = withoutComments(src);
      expect(stripped, `${f} should not call requireRole inline`).not.toMatch(/\brequireRole\s*\(/);
    }
  });

  // ─── Workload route — auth-bypass safety (R4) ────────────────────
  // The /v1/workload/passport route is intentionally unauthenticated
  // by STACK middleware: the SVID Bearer IS the auth. Defense against
  // a future dev accidentally adding an authenticated sibling route
  // under /v1/workload/* (which would break the SPIFFE consumer's
  // architecture by gating workloads behind operator API keys).
  describe('workload route — R4 structural guard', () => {
    it('workload.ts contains exactly one route declaration: POST /v1/workload/passport', () => {
      const src = readRoute('workload.ts');
      const stripped = withoutComments(src);
      // Match app.<verb>(...) declarations: app.get / app.post / etc.
      const routeDecls = [...stripped.matchAll(/\bapp\.(get|post|put|patch|delete|all|head|options)\s*\(/g)];
      expect(routeDecls).toHaveLength(1);
      expect(stripped).toMatch(/['"`]\/v1\/workload\/passport['"`]/);
    });

    it('workload.ts does NOT wire any STACK auth middleware', () => {
      const src = readRoute('workload.ts');
      const stripped = withoutComments(src);
      // Anti-patterns: importing auth middleware, declaring per-route
      // preHandler: auth, calling createAuthMiddleware, gate helpers.
      expect(stripped, 'workload.ts must not import auth middleware').not.toMatch(
        /from\s+['"]\.\.\/middleware\/auth\.js['"]/,
      );
      expect(stripped, 'workload.ts must not declare preHandler: auth').not.toMatch(
        /preHandler:\s*auth\b/,
      );
      expect(stripped, 'workload.ts must not call createAuthMiddleware').not.toMatch(
        /createAuthMiddleware\s*\(/,
      );
      expect(stripped, 'workload.ts must not call requireRole').not.toMatch(/\brequireRole\s*\(/);
      expect(stripped, 'workload.ts must not check request.operatorId for auth').not.toMatch(
        /request\.operatorId\s*[?&|=!]/,
      );
      expect(stripped, 'workload.ts must not check request.isPlatformStaff').not.toMatch(
        /request\.isPlatformStaff/,
      );
      expect(stripped, 'workload.ts must not check request.isAdmin').not.toMatch(
        /request\.isAdmin/,
      );
    });

    it('server.ts mounts workload routes OUTSIDE every encapsulation register block', () => {
      const serverSrc = readFileSync(join(here, '..', 'start.ts'), 'utf8');
      // Find the registerWorkloadRoutes call site and assert it is NOT
      // inside any `await app.register(async (...) => { ... })` block.
      const callIdx = serverSrc.indexOf('registerWorkloadRoutes(app, services)');
      expect(callIdx, 'registerWorkloadRoutes must be called at top level in server.ts').toBeGreaterThan(0);
      // Walk braces from start of file up to callIdx — the call must
      // sit at depth ≤ 1 (inside the createServices/start function but
      // not inside any nested register block).
      let depth = 0;
      let maxNesting = 0;
      for (let i = 0; i < callIdx; i++) {
        const ch = serverSrc[i];
        if (ch === '{') {
          depth++;
          if (depth > maxNesting) maxNesting = depth;
        } else if (ch === '}') {
          depth--;
        }
      }
      expect(depth, 'registerWorkloadRoutes nesting depth at call site').toBeLessThanOrEqual(1);
    });
  });

  // ─── WIMSE workload route — same R4 guard, parallel file ─────────
  // /v1/workload/wit (Part of the Signed Primitive epic).
  // Same security posture as /v1/workload/passport — the WIT bearer
  // IS the auth. Parallel structural test so a future dev cannot wire
  // STACK auth middleware onto this route either.
  describe('WIMSE workload route — R4 structural guard', () => {
    it('workload-wit.ts contains exactly one route declaration: POST /v1/workload/wit', () => {
      const src = readRoute('workload-wit.ts');
      const stripped = withoutComments(src);
      const routeDecls = [...stripped.matchAll(/\bapp\.(get|post|put|patch|delete|all|head|options)\s*\(/g)];
      expect(routeDecls).toHaveLength(1);
      expect(stripped).toMatch(/['"`]\/v1\/workload\/wit['"`]/);
    });

    it('workload-wit.ts does NOT wire any STACK auth middleware', () => {
      const src = readRoute('workload-wit.ts');
      const stripped = withoutComments(src);
      expect(stripped, 'workload-wit.ts must not import auth middleware').not.toMatch(
        /from\s+['"]\.\.\/middleware\/auth\.js['"]/,
      );
      expect(stripped, 'workload-wit.ts must not declare preHandler: auth').not.toMatch(
        /preHandler:\s*auth\b/,
      );
      expect(stripped, 'workload-wit.ts must not call createAuthMiddleware').not.toMatch(
        /createAuthMiddleware\s*\(/,
      );
      expect(stripped, 'workload-wit.ts must not call requireRole').not.toMatch(/\brequireRole\s*\(/);
      expect(stripped, 'workload-wit.ts must not check request.operatorId for auth').not.toMatch(
        /request\.operatorId\s*[?&|=!]/,
      );
      expect(stripped, 'workload-wit.ts must not check request.isPlatformStaff').not.toMatch(
        /request\.isPlatformStaff/,
      );
      expect(stripped, 'workload-wit.ts must not check request.isAdmin').not.toMatch(
        /request\.isAdmin/,
      );
    });

    it('server.ts mounts WIMSE workload routes OUTSIDE every encapsulation register block', () => {
      const serverSrc = readFileSync(join(here, '..', 'start.ts'), 'utf8');
      const callIdx = serverSrc.indexOf('registerWorkloadWitRoutes(app, services)');
      expect(callIdx, 'registerWorkloadWitRoutes must be called at top level in server.ts').toBeGreaterThan(0);
      let depth = 0;
      for (let i = 0; i < callIdx; i++) {
        const ch = serverSrc[i];
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      expect(depth, 'registerWorkloadWitRoutes nesting depth at call site').toBeLessThanOrEqual(1);
    });
  });
});

// ─── no-self-authorization ─────────────────────────────────

describe('denyAgentContexts', () => {
  it('passes a plain operator-key context (no agentId)', async () => {
    await expect(
      denyAgentContexts(fakeRequest({ operatorId: 'op_x' }), fakeReply),
    ).resolves.toBeUndefined();
  });

  it('passes a member context (no agentId)', async () => {
    await expect(
      denyAgentContexts(fakeRequest({ operatorId: 'op_x', memberId: 'mem_a', memberRole: 'standard' }), fakeReply),
    ).resolves.toBeUndefined();
  });

  it('refuses a passport-as-inbound context (agentId set)', async () => {
    await expect(
      denyAgentContexts(fakeRequest({ operatorId: 'op_x', agentId: 'agt_watched' }), fakeReply),
    ).rejects.toThrow(/non-agent principal/);
  });

  it('refuses an agent-JWT context even with operator is_admin inherited', async () => {
    await expect(
      denyAgentContexts(fakeRequest({ operatorId: 'op_x', agentId: 'agt_watched', isAdmin: true }), fakeReply),
    ).rejects.toThrow(/non-agent principal/);
  });
});

describe('requireOperatorAdmin - hardening', () => {
  it('refuses an agent-bearing context even with no member context (the old silent pass)', async () => {
    await expect(
      requireOperatorAdmin(fakeRequest({ operatorId: 'op_x', agentId: 'agt_watched' }), fakeReply),
    ).rejects.toThrow(/non-agent principal/);
  });

  it('refuses an agent-bearing context regardless of inherited isAdmin', async () => {
    await expect(
      requireOperatorAdmin(fakeRequest({ operatorId: 'op_x', agentId: 'agt_watched', isAdmin: true }), fakeReply),
    ).rejects.toThrow(/non-agent principal/);
  });
});

describe('structural - every mutating route of the engine denies agent contexts or is operationally allowlisted', () => {
  // Files whose routes are gated by their encapsulation scope or by a
  // non-Bearer auth model; their mutating routes are exempt here
  // because the scope/auth itself excludes watched-agent credentials.
  const SCOPE_OR_PUBLIC_FILES = new Set([
    'members.ts', // operator-admin scope (requireOperatorAdmin denies agents)
    'oauth-apps.ts', // operator-admin scope
    'sso-domains.ts', // operator-admin scope (requireOperatorAdmin denies agents)
    'partner.ts', // requirePartner scope
    'inbound.ts', // signature/HMAC-authed public receivers
    'provider-oauth.ts', // dashboard-proxy secret + live dashboard session only
    'workload.ts',
    'workload-wit.ts', // SVID/WIT bearer IS the auth (R4)
    'oauth.ts', // OAuth protocol machinery (public token endpoints)
    'a2a.ts', // operational A2A dispatcher (dropoff mapper)
    // Email transfer, public half. The emailed single-use token IS the auth,
    // and cancel MUST work with no session: the person stopping a hijack is
    // the one who cannot log in. The authenticated half (request the
    // transfer) stays in operators.ts and carries denyAgentContexts.
    'operator-email-change-public.ts',
    // decide is public-scope by DESIGN: its auth is the dashboard
    // cookie session; a Bearer credential must never approve its own
    // elevation. The list route inside carries denyAgentContexts normally.
    'governance.ts',
    // Authority management routes are individually denyAgentContexts-gated;
    // the approval-decision route in the same file is public-scope by design
    // and accepts dashboard-cookie auth only. authority-security.test.ts
    // structurally checks both halves so exempting the mixed file here does
    // not weaken coverage.
    'authority.ts',
    // mixes an agent status read with cookie-only human recovery
    // mutations. proxy-operation-human-auth.test.ts exercises the latter's
    // exact Origin, single-cookie, session-family and owner/admin boundary.
    'proxy-operations.ts',
  ]);

  // Mutating paths agents legitimately call: the operational surface.
  // Everything here is either safety-increasing (revocation, checkpoint)
  // or the agent's own working loop (dropoffs, skills, missions, LLM).
  const OPERATIONAL_MUTATING = new Set([
    '/v1/passports/issue',
    '/v1/passports/verify',
    '/v1/passports/revoke',
    '/v1/passports/delegate',
    '/v1/passports/refresh',
    '/v1/passports/revoke-agent/:agentId',
    '/v1/passports/revoke-session/:sessionId',
    '/v1/passports/revoke-all',
    '/v1/passports/:jti/checkpoint',
    '/v1/passports/:jti/checkout',
    '/v1/dropoffs',
    '/v1/dropoffs/:id/deposit',
    '/v1/dropoffs/:id/collect',
    '/v1/dropoffs/:id/expire',
    '/v1/proxy',
    '/v1/intents/simulate',
    '/v1/intents/submit',
    '/v1/missions',
    '/v1/missions/start', // approved fleet policy, authenticated worker, immutable Mission scope
    '/v1/missions/:id/renew', // same scope and budget, live policy and membership
    '/v1/fleets/:id/enrollment-challenges', // exact provisioner selected in human-approved policy
    '/v1/fleets/session', // fresh agent key proof, bounded live membership
    '/v1/fleets/:id/workload/enrollment-challenges', // issuer-verified workload, pinned tenant policy
    '/v1/fleets/:id/workload/enroll', // issuer and fresh worker key proof both required
    '/v1/fleets/:id/enroll', // proof of possession plus live provisioner policy and atomic quotas
    '/v1/missions/:id/complete',
    '/v1/missions/:id/revoke', // revocation = safety-increasing
    '/v1/evidence-packs',
    '/v1/scan', // content scanning is the agent working loop
    '/v1/services/agents/:agentId/revoke', // grant revoke = TIGHTENING (asymmetry rule)
    // detector PUT is DIRECTION-GATED, not blanket-denied: the
    // handler classifies the delta and (a) allows agent contexts only on
    // strictly-tightening writes, (b) demands a governance approval from
    // Bearer contexts on loosening/mixed. Source-asserted below.
    '/v1/detectors/:detector_key/config',
    // NOTE: POST '/v1/operator/inbound-webhooks' is deliberately NOT here.
    // Creating one nominates a forward_url — an egress destination STACK will
    // send inbound payloads to under its own signature. Choosing where data
    // leaves to is governance, so create is agent-denied. Revoke
    // stays operational: tearing down your own egress is safety-increasing.
    '/v1/operator/inbound-webhooks/:id',
    // enrollment routes carry their own single-use-ticket auth model
    '/v1/agents/:id/enrollment-challenge',
    '/v1/agents/:id/enroll',
    // SSO login handoff. Public and unauthenticated by necessity — the
    // caller is a browser belonging to someone who is not signed in yet,
    // which is the entire point of a login route. The single-use 60-second
    // ref IS the credential, the same model as the enrollment tickets above
    // and the emailed magic-link token. It cannot be reached without one:
    // the ref is minted only by the OIDC callback after a verified ID token
    // and is consumed atomically (GETDEL) on first read.
    //
    // Not governance: it authenticates a human, it does not expand anyone's
    // scope. Provisioning lands at the connection's configured default role,
    // which an operator-admin set, and a revoked member is refused outright.
    '/v1/identity/sso/handoff',
  ]);

  it('classifies every mutating route', () => {
    expect(
      unclassifiedMutatingRoutes(engineRoutes, {
        scopeOrPublicFiles: SCOPE_OR_PUBLIC_FILES,
        operationalMutating: OPERATIONAL_MUTATING,
      }),
      'unclassified mutating routes (add denyAgentContexts or allowlist deliberately)',
    ).toEqual([]);
  });
});

describe('structural - every credential-read route rejects agent principals', () => {
  // The test above only classifies MUTATING routes (POST/PUT/PATCH
  // DELETE). Raw-secret retrieval is a GET, so it slipped that net — a
  // agent could read a plaintext credential.
  // credentials.ts is the ONLY route file that returns a raw decrypted secret
  // to the caller, so we assert every read route in it carries the
  // unconditional principal-keyed guard. If credential retrieval ever moves to
  // another file, add it here.
  it('every app.get in credentials.ts calls assertNotProxyOnlyAgent', () => {
    const src = engineRoutes.read('credentials.ts');
    const getRoutes = [...src.matchAll(/app\.get[^(]*\(\s*[`'"](\/[^`'"]*)[`'"]/g)].map(
      (m) => m[1],
    );
    // Sanity: both known credential-read routes are present, so a silent
    // refactor that drops a route can't make this test vacuously pass.
    expect(getRoutes).toContain('/v1/credentials/:provider');
    expect(getRoutes).toContain('/v1/credentials/by-connection/:connectionId');

    // Each GET handler must invoke the guard. Slice from each route decl to the
    // next route decl (or EOF) and assert the guard call appears in that body.
    const decls = [...src.matchAll(/app\.get\b/g)].map((m) => m.index ?? 0);
    const unguarded: string[] = [];
    for (let i = 0; i < decls.length; i++) {
      const from = decls[i];
      const to = i + 1 < decls.length ? decls[i + 1] : src.length;
      const body = src.slice(from, to);
      const pathMatch = body.match(/[`'"](\/[^`'"]*)[`'"]/);
      if (!body.includes('assertNotProxyOnlyAgent')) {
        unguarded.push(pathMatch?.[1] ?? '(unparsed)');
      }
    }
    expect(
      unguarded,
      'credential-read GET routes missing the unconditional agent guard',
    ).toEqual([]);
  });
});

// ─── governance step-up + direction gate structural assertions ──
describe('structural - governance step-up', () => {
  const detectorSrc = engineRoutes.read('detector-config.ts');
  const accountabilitySrc = engineRoutes.read('accountability.ts');
  const agentsSrc = engineRoutes.read('agents.ts');
  const governanceSrc = engineRoutes.read('governance.ts');
  const authSrc = readFileSync(join(here, 'auth.ts'), 'utf8');

  it('detector PUT is direction-gated for agents: classifies the delta and denies non-tightening agent writes', () => {
    expect(detectorSrc).toContain('classifyUpsert');
    expect(detectorSrc).toMatch(/delta\.direction !== 'tightening'/);
  });

  it('detector settings are a controls feature with no approval: a customer with controls changes and resets them directly', () => {
    expect(detectorSrc).not.toContain('enforceGovernanceStepUp');
    expect(detectorSrc).not.toContain('planRules');
    expect(detectorSrc.match(/requireControls\(services, 'detector_settings'\)/g)).toHaveLength(2);
    // The DELETE route keeps agent contexts out: a reset's direction is not knowable up front.
    const deleteBlock = detectorSrc.slice(detectorSrc.indexOf('app.delete'));
    expect(deleteBlock).toContain('denyAgentContexts');
  });

  it('review decide gates ONLY the approve direction', () => {
    expect(accountabilitySrc).toMatch(/decision === 'approved'/);
    expect(accountabilitySrc).toContain("action: 'review_decide_approve'");
  });

  it('agent unblock is step-up gated', () => {
    expect(agentsSrc).toContain("action: 'agent_unblock'");
  });

  it('the decide endpoint requires a dashboard cookie session, never a Bearer', () => {
    expect(governanceSrc).toContain("session.aud !== 'stack:dashboard'");
    expect(governanceSrc).not.toContain('createAuthMiddleware(services)\n\n  app.post');
  });

  it('only the session branch of auth may stamp isDashboardSession', () => {
    const stamps = [...authSrc.matchAll(/request\.isDashboardSession = true/g)];
    expect(stamps).toHaveLength(1);
  });
});
