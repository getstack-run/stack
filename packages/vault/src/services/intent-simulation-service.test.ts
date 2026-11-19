import { describe, it, expect, beforeEach } from 'vitest';
import { trailEntityDigest, type IntentClaim, type IntentSimulationClaim, type ServiceScope } from '@stack/shared';
import {
  IntentSimulationService,
  type IntentSimulationDeps,
  type OveragePeekSnapshot,
  type SimulableMeter,
} from './intent-simulation-service.js';
import type { OperatorTier } from '@stack/shared';
import type { ClaimRegistryService, RegisterClaimInput, RegisterClaimResult } from './claim-registry-service.js';
import type { PassportService } from './passport-service.js';

/**
 * Service-layer invariants for the intent simulation producer.
 *
 *  Group A — Happy path (3)
 *    A1: http_call in scope, no constraints, accountability matches
 *    A2: persist=false skips claim registration
 *    A3: skill_invocation (non-http) skips constraint check, allowed
 *
 *  Group B — Scope mismatch (2)
 *    B1: target not in services[] or intent_services[] → scope_mismatch
 *    B2: target in intent_services[] only → allowed (matches proxy.ts:62-63)
 *
 *  Group C — Constraint violation (3)
 *    C1: body.amount lt 100 violated → constraint_violation
 *    C2: starts_with /v1/ conforming → allowed
 *    C3: http_call but parameters lack url/method → constraint_violation (deny-by-default)
 *
 *  Group D — Accountability monotonicity (3)
 *    D1: enforced passport, logged intent → accountability_monotonicity
 *    D2: enforced passport, enforced intent → allowed
 *    D3: default-standard passport, enforced intent → allowed (upgrade)
 *
 *  Group E — Multi-denial accumulation (1)
 *    E1: constraint + accountability → both reasons present, in chain order
 *
 *  Group T — tier_limit (5)
 *    T1: no peek dep wired → tier_limit not checked, allowed
 *    T2: peek wouldDeny=true on http_call → tier_limit denial + diagnostics
 *    T3: peek wouldDeny=false → allowed
 *    T4: skill_invocation spends the same single meter as http_call
 *    T5: non-metered intent_types skip the peek call entirely
 *
 *  Group F — Invariants (3)
 *    F2: simulated_at on the registered claim is integer unix-ms within 1s of now
 *    F3: predicted_detector_fires === [] (locks v1 deferral)
 *    F4: intent_claim_ref propagates onto the registered payload
 *
 * Envelope round-trip (F1) is exercised by the integration smoke
 * where a real
 * ClaimRegistryService + signer + DB are wired together. Unit tests
 * stub the registry to isolate the simulator's decision logic.
 */

interface StubRegistryCall {
  input: RegisterClaimInput;
}

function makeStubClaimRegistry(): {
  service: ClaimRegistryService;
  calls: StubRegistryCall[];
} {
  const calls: StubRegistryCall[] = [];
  let seq = 0;
  const service = {
    registerClaim: async (input: RegisterClaimInput): Promise<RegisterClaimResult> => {
      calls.push({ input });
      const claimId = `pc_test_${++seq}`;
      return { claimId, envelopeCose: 'stub-envelope', subject: `stack://operator/${input.operatorId}/passport/${input.passportJti}` };
    },
  } as unknown as ClaimRegistryService;
  return { service, calls };
}

interface FakePassportClaims {
  operator_id?: string;
  agent_id?: string;
  services: ServiceScope[];
  intent_services?: string[];
  accountability?: 'enforced' | 'logged' | 'standard';
  /** exposed so requires_unmet tests can pin a session id. */
  session_id?: string;
}

function makeStubPassportService(claims: FakePassportClaims, jti = 'pas_test_1'): PassportService {
  const stk = {
    operator_id: claims.operator_id ?? 'op_test',
    agent_id: claims.agent_id ?? 'ag_test',
    services: claims.services,
    intent_services: claims.intent_services ?? [],
    accountability: claims.accountability ?? 'standard',
    session_id: claims.session_id ?? 'ses_test',
  };
  return {
    verify: async () => ({ jti, stk }),
  } as unknown as PassportService;
}

function makeService(deps: Partial<IntentSimulationDeps> & {
  claims?: FakePassportClaims;
  jti?: string;
  tier?: OperatorTier;
  peek?: (operatorId: string, tier: OperatorTier, meter: SimulableMeter) => Promise<OveragePeekSnapshot>;
} = {}) {
  const passportClaims: FakePassportClaims = deps.claims ?? {
    operator_id: 'op_test',
    agent_id: 'ag_test',
    services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
    intent_services: [],
    accountability: 'standard',
  };
  const passportService = deps.passportService ?? makeStubPassportService(passportClaims, deps.jti ?? 'pas_test_1');
  const reg = makeStubClaimRegistry();
  const claimRegistry = deps.claimRegistry ?? reg.service;
  const ctorDeps: IntentSimulationDeps = { passportService, claimRegistry };
  if (deps.peek) {
    ctorDeps.peekOverage = deps.peek;
    ctorDeps.resolveOperatorTier = async () => deps.tier ?? 'business';
  }
  const service = new IntentSimulationService(ctorDeps);
  return { service, registryCalls: reg.calls };
}

function makeIntent(overrides: Partial<IntentClaim> = {}): IntentClaim {
  return {
    type: 'intent_claim',
    intent_type: 'http_call',
    agent_id: 'ag_test',
    named_intent: 'stripe:charges:create',
    target: 'stripe',
    action: 'POST /v1/charges',
    parameters: { url: 'https://api.stripe.com/v1/charges', method: 'POST', body: { amount: 50 } },
    estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
    accountability: 'standard',
    reason: null,
    requires: [],
    user_subject: null,
    mission_ref: null,
    submitted_at: Date.now(),
    ...overrides,
  };
}

describe('IntentSimulationService', () => {
  // ── Group A — Happy path ────────────────────────────────────────────
  describe('A — Happy path', () => {
    it('A1: http_call in scope, no constraints, accountability matches → allowed', async () => {
      const { service, registryCalls } = makeService();
      const before = Date.now();
      const result = await service.simulate({ passportToken: 'tok', intent: makeIntent() });
      const after = Date.now();

      expect(result.allowed).toBe(true);
      expect(result.denialReasons).toEqual([]);
      expect(result.claimId).toBe('pc_test_1');
      expect(result.simulatedAt).toBeGreaterThanOrEqual(before);
      expect(result.simulatedAt).toBeLessThanOrEqual(after);
      expect(registryCalls).toHaveLength(1);
      expect(registryCalls[0]!.input.claimType).toBe('intent_simulation');
    });

    it('A2: persist=false skips claim registration', async () => {
      const { service, registryCalls } = makeService();
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent(),
        persist: false,
      });
      expect(result.allowed).toBe(true);
      expect(result.claimId).toBeUndefined();
      expect(registryCalls).toHaveLength(0);
    });

    it('A3: skill_invocation skips constraint check, allowed when in scope', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{
            service_id: 'svc_skill', service_name: 'skill:abc', scopes: [], credential_ref: 'kms:stub',
            // Constraint exists but should NOT run for non-http_call:
            constraints: [{ path: 'body.amount', op: 'eq', value: 999 }],
          }],
          intent_services: [],
          accountability: 'standard',
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          intent_type: 'skill_invocation',
          target: 'skill:abc',
          named_intent: 'stack:skill:invoke',
          parameters: { skill_id: 'skill:abc' },
        }),
      });
      expect(result.allowed).toBe(true);
      expect(result.denialReasons).toEqual([]);
    });
  });

  // ── Group B — Scope mismatch ────────────────────────────────────────
  describe('B — Scope mismatch', () => {
    it('B1: target not in services[] or intent_services[] → scope_mismatch', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: [],
          accountability: 'standard',
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({ target: 'slack', named_intent: 'slack:messages:send' }),
      });
      expect(result.allowed).toBe(false);
      expect(result.denialReasons).toContain('scope_mismatch');
      expect(result.diagnostics.scopeMissingService).toBe('slack');
    });

 it('B2: target in intent_services[] only, NO grant → DENIED (grant is sole authority)', async () => {
      // Pre- this was allowed — a self-declared intent could
      // authorize a call with no grant. The grant-authority fix denies it:
      // intent may only narrow granted scope, never substitute for a grant.
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [],
          intent_services: ['slack'],
          accountability: 'standard',
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({ target: 'slack', named_intent: 'slack:messages:send' }),
      });
      expect(result.allowed).toBe(false);
      expect(result.denialReasons).toContain('scope_mismatch');
    });
  });

  // ── Group C — Constraint violation ──────────────────────────────────
  describe('C — Constraint violation', () => {
    it('C1: body.amount eq 50 ok, eq 1000 violates', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{
            service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub',
            constraints: [{ path: 'body.amount', op: 'eq', value: 50 }],
          }],
          intent_services: [],
          accountability: 'standard',
        },
      });
      const ok = await service.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(ok.allowed).toBe(true);

      const violated = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          parameters: { url: 'https://api.stripe.com/v1/charges', method: 'POST', body: { amount: 1000 } },
        }),
      });
      expect(violated.allowed).toBe(false);
      expect(violated.denialReasons).toContain('constraint_violation');
      expect(violated.diagnostics.failedConstraint).toEqual({ path: 'body.amount', op: 'eq' });
    });

    it('C2: starts_with /v1/ on conforming pathname → allowed', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{
            service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub',
            constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1/' }],
          }],
          intent_services: [],
          accountability: 'standard',
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          parameters: { url: 'https://api.stripe.com/v1/charges', method: 'POST' },
        }),
      });
      expect(result.allowed).toBe(true);
    });

    it('C3: http_call missing url/method in parameters → constraint_violation (deny-by-default)', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{
            service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub',
            constraints: [{ path: 'body.amount', op: 'eq', value: 50 }],
          }],
          intent_services: [],
          accountability: 'standard',
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({ parameters: { /* no url, no method */ body: { amount: 50 } } }),
      });
      expect(result.allowed).toBe(false);
      expect(result.denialReasons).toContain('constraint_violation');
    });
    it('C4: two scopes of one service: refused without a named connection, judged by the named scope with one', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [
            { service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub', connection_id: 'scon_a', constraints: [{ path: 'body.amount', op: 'eq', value: 50 }] },
            { service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub', connection_id: 'scon_b' },
          ],
          intent_services: [],
          accountability: 'standard',
        },
      });
      const unnamed = await service.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(unnamed.denialReasons).toContain('constraint_violation');
      expect(unnamed.diagnostics.connectionAmbiguousService).toBe('stripe');
      const params = { url: 'https://api.stripe.com/v1/charges', method: 'POST', body: { amount: 1000 } };
      const b = await service.simulate({ passportToken: 'tok', intent: makeIntent({ parameters: { ...params, connection: 'scon_b' } }) });
      expect(b.allowed).toBe(true);
      const a = await service.simulate({ passportToken: 'tok', intent: makeIntent({ parameters: { ...params, connection: 'scon_a' } }) });
      expect(a.denialReasons).toContain('constraint_violation');
      const unknown = await service.simulate({ passportToken: 'tok', intent: makeIntent({ parameters: { ...params, connection: 'scon_zzz' } }) });
      expect(unknown.denialReasons).toContain('constraint_violation');
    });
  });

  // ── Group D — Accountability monotonicity ───────────────────────────
  describe('D — Accountability monotonicity', () => {
    it('D1: enforced passport, logged intent → accountability_monotonicity', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: [],
          accountability: 'enforced',
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({ accountability: 'logged' }),
      });
      expect(result.allowed).toBe(false);
      expect(result.denialReasons).toContain('accountability_monotonicity');
      expect(result.diagnostics.accountabilityPassport).toBe('enforced');
      expect(result.diagnostics.accountabilityIntent).toBe('logged');
    });

    it('D2: enforced passport, enforced intent → allowed', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: [],
          accountability: 'enforced',
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({ accountability: 'enforced' }),
      });
      expect(result.allowed).toBe(true);
    });

    it('D3: default-standard passport, enforced intent → allowed (upgrade)', async () => {
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: [],
          // accountability omitted → defaults to 'standard'
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({ accountability: 'enforced' }),
      });
      expect(result.allowed).toBe(true);
    });
  });

  // ── Group E — Multi-denial accumulation ─────────────────────────────
  describe('E — Multi-denial accumulation', () => {
    it('E1: constraint violation + accountability downgrade → both reasons present, in chain order', async () => {
      // Target IS in services[] (no scope_mismatch), but the constraint
      // fails AND intent downgrades passport accountability — both denial
      // reasons accumulate per D7.
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{
            service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub',
            constraints: [{ path: 'body.amount', op: 'eq', value: 50 }],
          }],
          intent_services: [],
          accountability: 'enforced',
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          target: 'stripe',
          accountability: 'logged',
          parameters: { url: 'https://api.stripe.com/v1/charges', method: 'POST', body: { amount: 1000 } },
        }),
      });
      expect(result.allowed).toBe(false);
      expect(result.denialReasons).toContain('constraint_violation');
      expect(result.denialReasons).toContain('accountability_monotonicity');
      // Order: constraint before accountability per the implementation chain.
      const idxConstraint = result.denialReasons.indexOf('constraint_violation');
      const idxAccountability = result.denialReasons.indexOf('accountability_monotonicity');
      expect(idxConstraint).toBeLessThan(idxAccountability);
    });
  });

  // ── Group T — tier_limit ────────────────────────────────────────────
  describe('T — tier_limit', () => {
    const allow: OveragePeekSnapshot = {
      used: 5, cap: 1000, walletBalanceCents: 0, overagePriceCents: 0.1, wouldDeny: false,
    };
    const deny: OveragePeekSnapshot = {
      used: 1000, cap: 1000, walletBalanceCents: 0, overagePriceCents: 0.1, wouldDeny: true,
    };

    it('T1: under cap + no peek wired → tier_limit not checked, allowed', async () => {
      const { service } = makeService();  // no peek dep
      const result = await service.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(result.allowed).toBe(true);
      expect(result.denialReasons).not.toContain('tier_limit');
    });

    it('T2: peek says wouldDeny=true on http_call → tier_limit denial, diagnostics set', async () => {
      const { service } = makeService({ peek: async () => deny });
      const result = await service.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(result.allowed).toBe(false);
      expect(result.denialReasons).toContain('tier_limit');
      expect(result.diagnostics.tierLimit).toEqual({
        meter: 'action',
        cap: 1000,
        used: 1000,
        walletBalanceCents: 0,
        overagePriceCents: 0.1,
      });
    });

    it('T3: peek says wouldDeny=false → allowed (under cap or wallet covers overage)', async () => {
      const { service } = makeService({ peek: async () => allow });
      const result = await service.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(result.allowed).toBe(true);
      expect(result.denialReasons).not.toContain('tier_limit');
    });

    it('T4: skill_invocation spends the same single meter as http_call', async () => {
      let lastMeter: SimulableMeter | undefined;
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{ service_id: 'svc_skill', service_name: 'skill:abc', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: [],
          accountability: 'standard',
        },
        peek: async (_op, _tier, meter) => {
          lastMeter = meter;
          return { ...deny, cap: 100, used: 100 };
        },
      });
      const result = await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          intent_type: 'skill_invocation',
          target: 'skill:abc',
          named_intent: 'stack:skill:invoke',
          parameters: { skill_id: 'skill:abc' },
        }),
      });
      expect(lastMeter).toBe('action');
      expect(result.denialReasons).toContain('tier_limit');
    });

    it('T5: non-metered intent_types (mcp_tool, task_complete, onchain_tx) skip the peek call entirely', async () => {
      let peekCalled = 0;
      const { service } = makeService({
        claims: {
          operator_id: 'op_test',
          agent_id: 'ag_test',
          services: [{ service_id: 'svc_tool', service_name: 'mcp:something', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: [],
          accountability: 'standard',
        },
        peek: async () => { peekCalled++; return deny; },
      });
      await service.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          intent_type: 'task_complete',
          target: 'mcp:something',
          named_intent: 'stack:task:complete',
          parameters: {},
        }),
      });
      expect(peekCalled).toBe(0);
    });
  });

  // ── Group F — Invariants ────────────────────────────────────────────
  describe('F — Invariants', () => {
    it('F2: simulated_at is integer unix-ms within 1s of Date.now()', async () => {
      const { service, registryCalls } = makeService();
      const before = Date.now();
      await service.simulate({ passportToken: 'tok', intent: makeIntent() });
      const after = Date.now();

      const payload = registryCalls[0]!.input.payload as IntentSimulationClaim;
      expect(Number.isInteger(payload.simulated_at)).toBe(true);
      expect(payload.simulated_at).toBeGreaterThanOrEqual(before);
      expect(payload.simulated_at).toBeLessThanOrEqual(after);
    });

    it('F3: predicted_detector_fires === [] in v1 (locks the 2.3 deferral)', async () => {
      const { service, registryCalls } = makeService();
      const result = await service.simulate({ passportToken: 'tok', intent: makeIntent() });

      expect(result.predictedDetectorFires).toEqual([]);
      const payload = registryCalls[0]!.input.payload as IntentSimulationClaim;
      expect(payload.predicted_detector_fires).toEqual([]);
    });

    it('F4: intent_claim_ref propagates onto the registered payload', async () => {
      const { service, registryCalls } = makeService();
      await service.simulate({
        passportToken: 'tok',
        intent: makeIntent(),
        intentClaimRef: 'pc_existing_intent',
      });
      const payload = registryCalls[0]!.input.payload as IntentSimulationClaim;
      expect(payload.intent_claim_ref).toBe('pc_existing_intent');
    });
  });

  // ── Group D2 — detector_block via DetectorService.dryRun ─
  describe('D2 — detector_block', () => {
    function makeDetectorStub(verdict: 'clean' | 'warning' | 'critical') {
      let calls = 0;
      const stub = {
        scanInput: async (args: { dryRun?: boolean }) => {
          calls++;
          if (args.dryRun !== true) throw new Error('simulator must pass dryRun: true');
          return { verdict };
        },
      };
      return { stub, getCalls: () => calls };
    }

    it('detector critical → denialReasons contains detector_block + predicted fire severity critical', async () => {
      const { stub } = makeDetectorStub('critical');
      const { service, registryCalls } = makeService();
      // Replace the freshly-constructed service with one that has the detector dep
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        detector: stub,
      });
      const result = await svc.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(result.allowed).toBe(false);
      expect(result.denialReasons).toContain('detector_block');
      expect(result.predictedDetectorFires).toContainEqual({
        detector_key: 'prompt_injection',
        severity: 'critical',
      });
      void service; void registryCalls;
    });

    it('detector warning → predicted fire severity medium, NO denial', async () => {
      const { stub } = makeDetectorStub('warning');
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        detector: stub,
      });
      const result = await svc.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(result.allowed).toBe(true);
      expect(result.denialReasons).not.toContain('detector_block');
      expect(result.predictedDetectorFires).toContainEqual({
        detector_key: 'prompt_injection',
        severity: 'medium',
      });
    });

    it('detector clean → no predicted fire, no denial', async () => {
      const { stub } = makeDetectorStub('clean');
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        detector: stub,
      });
      const result = await svc.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(result.predictedDetectorFires).toEqual([]);
    });

    it('no detector dep wired → skips detector check cleanly (no fires, no denial)', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
      });
      const result = await svc.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(result.predictedDetectorFires).toEqual([]);
      expect(result.denialReasons).not.toContain('detector_block');
    });

    it('non-http_call intent_type → detector skipped (only http payloads scanned)', async () => {
      const { stub, getCalls } = makeDetectorStub('critical');
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_skill', service_name: 'skill:abc', scopes: [], credential_ref: 'kms:stub' }],
        }),
        claimRegistry: reg.service,
        detector: stub,
      });
      await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          intent_type: 'skill_invocation',
          target: 'skill:abc',
          named_intent: 'stack:skill:invoke',
          parameters: { skill_id: 'skill:abc' },
        }),
      });
      expect(getCalls()).toBe(0);
    });
  });

  // ── Group U — undeclared_target via prior entity_observation claims ─
  describe('U — undeclared_target', () => {
    function makeRepoStub(observedEntities: string[]) {
      return {
        findActiveByPassportId: async () => [
          {
            type: 'entity_observation',
            body_json: { entities: observedEntities },
          },
        ],
        // requires_unmet stub — these tests don't exercise
        // the requires path (empty intent.requires array), so the
        // simulator never hits this method. Present for the dep shape.
        findActiveOutcomesByClaimIdsAndSessionId: async () => [],
      };
    }

    it('candidate entity absent from prior observations → predicted fire (no denial)', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub(['api.stripe.com']),
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          parameters: {
            url: 'https://api.stripe.com/v1/refunds',
            method: 'POST',
            body: { account: 'acct_unseen_xyz123' },
          },
        }),
      });
      // The unseen acct_* and the unseen /v1/refunds path both fire.
      expect(result.allowed).toBe(true); // flag, not block
      expect(result.predictedDetectorFires).toContainEqual({
        detector_key: 'undeclared_target',
        severity: 'medium',
      });
      expect(result.diagnostics.undeclaredEntities?.length).toBeGreaterThan(0);
    });

    it('an observation kept as one-way digests counts as dealt with', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub(['stripe', 'api.stripe.com', '/v1/refunds', 'acct_seen_xyz123'].map(trailEntityDigest)),
      });
      const intent = makeIntent({
        parameters: {
          url: 'https://api.stripe.com/v1/refunds',
          method: 'POST',
          body: { account: 'acct_seen_xyz123' },
        },
      });
      const seen = await svc.simulate({ passportToken: 'tok', intent });
      expect(seen.predictedDetectorFires.map((f) => f.detector_key)).not.toContain('undeclared_target');

      // The same intent against a history that does not hold the account still fires.
      const unseen = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: makeStubClaimRegistry().service,
        passportClaimsRepo: makeRepoStub(['stripe', 'api.stripe.com', '/v1/refunds'].map(trailEntityDigest)),
      });
      const fired = await unseen.simulate({ passportToken: 'tok', intent });
      expect(fired.predictedDetectorFires.map((f) => f.detector_key)).toContain('undeclared_target');
    });

    it('all candidate entities present in prior observations → no fire', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub(['stripe', 'api.stripe.com', '/v1/charges']),
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          parameters: {
            url: 'https://api.stripe.com/v1/charges',
            method: 'POST',
            body: { amount: 50 },
          },
        }),
      });
      expect(result.predictedDetectorFires.find((f) => f.detector_key === 'undeclared_target')).toBeUndefined();
    });

    it('no passportClaimsRepo dep → skips undeclared_target check cleanly', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
      });
      const result = await svc.simulate({ passportToken: 'tok', intent: makeIntent() });
      expect(result.predictedDetectorFires.find((f) => f.detector_key === 'undeclared_target')).toBeUndefined();
    });

    // #6 — a counterparty PRE-DECLARED on the bound mission is seeded
    // into the observed set, so it does NOT trip the first-touch flag.
    it('mission-declared counterparty (via missionLookup) → NOT flagged on first touch', async () => {
      const reg = makeStubClaimRegistry();
      const wallet = 'acct_declared_xyz123';
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        // The wallet is NOT in prior observations...
        passportClaimsRepo: makeRepoStub(['stripe', 'api.stripe.com', '/v1/charges']),
        // ...but IS pre-declared on the bound mission.
        missionLookup: {
          findById: async (id: string) =>
            id === 'ms_declared' ? { expected_counterparties: [wallet] } : null,
        },
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          mission_ref: 'ms_declared',
          parameters: { url: 'https://api.stripe.com/v1/charges', method: 'POST', body: { account: wallet } },
        }),
      });
      // Pre-declared → suppressed. (Without the missionLookup seed, the unseen
      // acct_* would have fired undeclared_target — see the first test in U.)
      const fired = result.predictedDetectorFires.find((f) => f.detector_key === 'undeclared_target');
      const flaggedEntities = (result.diagnostics.undeclaredEntities ?? []).map((e) => e.entity.toLowerCase());
      expect(flaggedEntities).not.toContain(wallet.toLowerCase());
      // (No other unseen entity in this call, so the detector should not fire at all.)
      expect(fired).toBeUndefined();
    });

    it('mission_ref set but missionLookup returns null → falls back to observation-only (still flags)', async () => {
      const reg = makeStubClaimRegistry();
      const wallet = 'acct_undeclared_zzz';
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub(['stripe', 'api.stripe.com', '/v1/charges']),
        missionLookup: { findById: async () => null },
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({
          mission_ref: 'ms_missing',
          parameters: { url: 'https://api.stripe.com/v1/charges', method: 'POST', body: { account: wallet } },
        }),
      });
      expect(result.predictedDetectorFires).toContainEqual({ detector_key: 'undeclared_target', severity: 'medium' });
    });
  });

  /**
   * Group R — requires_unmet
   *
   *  R1: empty requires → no denial (short-circuit, no SQL)
   *  R2: all required outcomes succeeded on same session → no denial
   *  R3: required outcome missing entirely → requires_unmet denial
   *  R4: required outcome present but body.status=failed → requires_unmet
   *  R5: mixed batch (1 of 2 satisfied) → requires_unmet, only the missing
   *      id surfaces in diagnostics.failingRequires
   *  R6: no passportClaimsRepo dep → skips the check entirely (allowed when
   *      no other denial fires)
   */
  describe('R — requires_unmet (section 2g)', () => {
    function makeRepoStub(outcomeRows: Array<{
      claim_id: string;
      type: string;
      body_json: unknown;
    }>) {
      return {
        // 2f side — these tests don't exercise undeclared_target, return
        // empty so it doesn't false-fire.
        findActiveByPassportId: async () => [],
        findActiveOutcomesByClaimIdsAndSessionId: async (
          claimIds: string[],
          _sessionId: string,
        ) => outcomeRows.filter((r) => claimIds.includes(r.claim_id)),
      };
    }

    it('R1: empty requires → no denial', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub([]),
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({ requires: [] }),
      });
      expect(result.denialReasons).not.toContain('requires_unmet');
      expect(result.diagnostics.failingRequires).toBeUndefined();
    });

    it('R2: all required outcomes succeeded on same session → no denial', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub([
          { claim_id: 'pc_a', type: 'intent_outcome', body_json: { status: 'succeeded' } },
          { claim_id: 'pc_b', type: 'intent_outcome', body_json: { status: 'succeeded' } },
        ]),
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({ requires: ['pc_a', 'pc_b'] }),
      });
      expect(result.denialReasons).not.toContain('requires_unmet');
      expect(result.diagnostics.failingRequires).toBeUndefined();
    });

    it('R3: required outcome missing → requires_unmet denial', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub([]),
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({ requires: ['pc_missing'] }),
      });
      expect(result.allowed).toBe(false);
      expect(result.denialReasons).toContain('requires_unmet');
      expect(result.diagnostics.failingRequires).toEqual(['pc_missing']);
    });

    it('R4: required outcome status=failed → requires_unmet denial', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub([
          { claim_id: 'pc_f', type: 'intent_outcome', body_json: { status: 'failed' } },
        ]),
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({ requires: ['pc_f'] }),
      });
      expect(result.denialReasons).toContain('requires_unmet');
      expect(result.diagnostics.failingRequires).toEqual(['pc_f']);
    });

    it('R5: mixed batch — only missing id surfaces in diagnostics', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
        passportClaimsRepo: makeRepoStub([
          { claim_id: 'pc_ok', type: 'intent_outcome', body_json: { status: 'succeeded' } },
        ]),
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({ requires: ['pc_ok', 'pc_gone'] }),
      });
      expect(result.denialReasons).toContain('requires_unmet');
      expect(result.diagnostics.failingRequires).toEqual(['pc_gone']);
    });

    it('R6: no passportClaimsRepo dep → skips check (allowed)', async () => {
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({
        passportService: makeStubPassportService({
          services: [{ service_id: 'svc_stripe', service_name: 'stripe', scopes: [], credential_ref: 'kms:stub' }],
          intent_services: ['stripe'],
        }),
        claimRegistry: reg.service,
      });
      const result = await svc.simulate({
        passportToken: 'tok',
        intent: makeIntent({ requires: ['pc_anything'] }),
      });
      expect(result.denialReasons).not.toContain('requires_unmet');
    });
  });

  // Sanity: passport-token verification is called every time.
  describe('Passport verification gate', () => {
    let verifyCalls: number;
    beforeEach(() => { verifyCalls = 0; });

    it('throws when the passport service rejects the token', async () => {
      const passportService = {
        verify: async () => {
          verifyCalls++;
          throw new Error('signature_mismatch');
        },
      } as unknown as PassportService;
      const reg = makeStubClaimRegistry();
      const svc = new IntentSimulationService({ passportService, claimRegistry: reg.service });
      await expect(
        svc.simulate({ passportToken: 'bad', intent: makeIntent() }),
      ).rejects.toThrow('signature_mismatch');
      expect(verifyCalls).toBe(1);
      expect(reg.calls).toHaveLength(0);
    });
  });
});
