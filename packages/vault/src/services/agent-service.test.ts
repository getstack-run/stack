import { describe, it, expect } from 'vitest';
import { resolveAgentProfile } from '@stack/shared';
import { AgentService } from './agent-service.js';
import type { AgentRepository } from '../repositories/agent-repo.js';

/**
 * AgentService — hardening: delete precondition cascade-block.
 *
 * The delete operation must block when an agent is referenced by an
 * active resource (inbound webhook, partner-issued passport, etc.).
 * The cascade-block is a late-bound check registered by the bootstrap
 * (apps/api/src/config/services.ts).
 *
 *   D1: delete with no preconditions registered → proceeds
 *   D2: delete with a preconditions returning empty → proceeds
 *   D3: delete with a precondition returning non-empty → ConflictError
 *   D4: multiple preconditions stack — first non-empty triggers throw
 */

const OPERATOR_ID = 'op_test';
const AGENT_ID = 'agt_test';

function makeRepoStub(): AgentRepository {
  let status = 'active';
  return {
    async findById(id: string) {
      if (id !== AGENT_ID) return null;
      return { id, operator_id: OPERATOR_ID, name: 'grocery-bot', status } as never;
    },
    async updateStatus(_id: string, newStatus: string) {
      status = newStatus;
      return { id: AGENT_ID, operator_id: OPERATOR_ID, status } as never;
    },
  } as unknown as AgentRepository;
}

describe('AgentService.delete — cascade-block precondition checks', () => {
  it('D1 proceeds when no preconditions are registered', async () => {
    const svc = new AgentService(makeRepoStub());
    await expect(svc.delete(AGENT_ID, OPERATOR_ID)).resolves.toBeDefined();
  });

  it('D2 proceeds when a precondition returns an empty list', async () => {
    const svc = new AgentService(makeRepoStub());
    svc.registerDeletePreconditionCheck(async () => []);
    await expect(svc.delete(AGENT_ID, OPERATOR_ID)).resolves.toBeDefined();
  });

  it('D3 throws ConflictError when a precondition returns a non-empty list', async () => {
    const svc = new AgentService(makeRepoStub());
    svc.registerDeletePreconditionCheck(async () => [
      'inbound webhook iwh_abc (agentmail, slug=s_a...x)',
    ]);
    await expect(svc.delete(AGENT_ID, OPERATOR_ID)).rejects.toThrow(
      /cannot be deleted while active references exist.*iwh_abc/i,
    );
  });

  it('D4 stacks multiple checks — all collected references appear in the error', async () => {
    const svc = new AgentService(makeRepoStub());
    svc.registerDeletePreconditionCheck(async () => ['inbound webhook iwh_a']);
    svc.registerDeletePreconditionCheck(async () => ['inbound webhook iwh_b', 'passport pas_c']);
    await expect(svc.delete(AGENT_ID, OPERATOR_ID)).rejects.toThrow(/iwh_a.*iwh_b.*pas_c/);
  });
});

/**
 * registration preset (`proxied-llm-bot`).
 *
 * The preset must expand to the safe LLM-bot posture (proxy_only +
 * logged + stack_managed); explicit fields must override the preset; and
 * omitting the profile must leave the base secure-by-default posture
 * (logged + proxy_only) untouched.
 */
describe('resolveAgentProfile — pure preset expansion', () => {
  it('undefined profile → empty object (base defaults apply)', () => {
    expect(resolveAgentProfile(undefined)).toEqual({});
  });

  it("'proxied-llm-bot' → proxy_only + logged + stack_managed", () => {
    expect(resolveAgentProfile('proxied-llm-bot')).toEqual({
      credential_access: 'proxy_only',
      accountability_mode: 'logged',
      key_mode: 'stack_managed',
    });
  });
});

describe('AgentService.register — preset expansion + precedence', () => {
  // A repo stub that echoes the created row back so we can assert the
  // resolved field values, plus the two lookups register() performs.
  function makeRegisterRepoStub(): AgentRepository {
    return {
      async countByOperator() {
        return 0;
      },
      async findByOperatorAndName() {
        return null;
      },
      async create(row: Record<string, unknown>) {
        return row as never;
      },
    } as unknown as AgentRepository;
  }

  const TIER = 'business' as const;

  it('applies the preset posture when profile is passed alone', async () => {
    const svc = new AgentService(makeRegisterRepoStub());
    const agent = (await svc.register(OPERATOR_ID, TIER, {
      name: 'familybot',
      profile: 'proxied-llm-bot',
    })) as unknown as {
      credential_access: string;
      accountability_mode: string;
      key_mode: string;
    };
    expect(agent.credential_access).toBe('proxy_only');
    expect(agent.accountability_mode).toBe('logged');
    expect(agent.key_mode).toBe('stack_managed');
  });

  it('explicit fields override the preset', async () => {
    const svc = new AgentService(makeRegisterRepoStub());
    const agent = (await svc.register(OPERATOR_ID, TIER, {
      name: 'familybot',
      profile: 'proxied-llm-bot',
      accountability_mode: 'enforced', // caller re-tightens over the preset
    })) as unknown as { credential_access: string; accountability_mode: string };
    expect(agent.accountability_mode).toBe('enforced'); // explicit wins
    expect(agent.credential_access).toBe('proxy_only'); // preset still applies to un-overridden field
  });

  // the base posture is logged + proxy_only: start loose, the owner tightens. It used to be
  // enforced + direct, which meant every agent nobody configured could pull
  // the raw secret and call the provider itself, around every wall the proxy
  // path enforces.
  it('no profile → base posture (logged + proxy_only): no per-call approval until the owner asks for it', async () => {
    const svc = new AgentService(makeRegisterRepoStub());
    const agent = (await svc.register(OPERATOR_ID, TIER, {
      name: 'plainbot',
    })) as unknown as {
      credential_access: string;
      accountability_mode: string;
      key_mode?: string;
    };
    expect(agent.accountability_mode).toBe('logged');
    expect(agent.credential_access).toBe('proxy_only');
    // No preset + no explicit key_mode → key_mode omitted so the DB
    // default ('stack_managed') applies; it must not be forced here.
    expect(agent.key_mode).toBeUndefined();
  });

  it('a strict mode is the owner\'s choice: enforced registers as enforced, and on_warning/on_critical stay notify', async () => {
    const svc = new AgentService(makeRegisterRepoStub());
    const agent = (await svc.register(OPERATOR_ID, TIER, { name: 'strictbot', accountability_mode: 'enforced' })) as unknown as {
      accountability_mode: string;
      on_warning: string;
      on_critical: string;
    };
    expect(agent.accountability_mode).toBe('enforced');
    const loose = (await svc.register(OPERATOR_ID, TIER, { name: 'loosebot' })) as unknown as { on_warning: string; on_critical: string };
    expect(loose.on_warning).toBe('notify');
    expect(loose.on_critical).toBe('notify');
  });

  it('eval_traffic set at registration is stored with the agent, and left to the column default when omitted', async () => {
    const svc = new AgentService(makeRegisterRepoStub());
    const marked = (await svc.register(OPERATOR_ID, TIER, { name: 'evalbot', eval_traffic: true })) as unknown as { eval_traffic?: boolean };
    expect(marked.eval_traffic).toBe(true);
    const plain = (await svc.register(OPERATOR_ID, TIER, { name: 'realbot' })) as unknown as { eval_traffic?: boolean };
    expect(plain.eval_traffic).toBeUndefined();
  });

  it('assertCanRegister says what register would say, so a combined request refuses before anyone is asked', async () => {
    const taken = new AgentService({
      async countByOperator() { return 0; },
      async findByOperatorAndName() { return { id: 'agt_existing' }; },
    } as unknown as AgentRepository);
    await expect(taken.assertCanRegister(OPERATOR_ID, TIER, 'dup')).rejects.toThrow(/already exists/);
  });
});

/**
 * LLM gateway per-agent toggles (llm_inject_system_prompt +
 * llm_redact_pii) must round-trip through register AND update, with an
 * explicit `false` treated as a real write (the silent-strip bug this
 * fixes was exactly a `false` never reaching the row).
 */
describe('AgentService — LLM gateway toggles', () => {
  function makeRegisterRepoStub(): AgentRepository {
    return {
      async countByOperator() {
        return 0;
      },
      async findByOperatorAndName() {
        return null;
      },
      async create(row: Record<string, unknown>) {
        return row as never;
      },
    } as unknown as AgentRepository;
  }

  function makeUpdateRepoStub(captured: { updates?: Record<string, unknown> }): AgentRepository {
    return {
      async findById(id: string) {
        return { id, operator_id: OPERATOR_ID, status: 'active' } as never;
      },
      async update(_id: string, updates: Record<string, unknown>) {
        captured.updates = updates;
        return { id: AGENT_ID, ...updates } as never;
      },
    } as unknown as AgentRepository;
  }

  it('register with both flags false persists them on the created row', async () => {
    const svc = new AgentService(makeRegisterRepoStub());
    const agent = (await svc.register(OPERATOR_ID, 'business', {
      name: 'cachedbot',
      llm_inject_system_prompt: false,
      llm_redact_pii: false,
    })) as unknown as { llm_inject_system_prompt: boolean; llm_redact_pii: boolean };
    expect(agent.llm_inject_system_prompt).toBe(false);
    expect(agent.llm_redact_pii).toBe(false);
  });

  it('register without the flags omits them (DB defaults apply, both true)', async () => {
    const svc = new AgentService(makeRegisterRepoStub());
    const agent = (await svc.register(OPERATOR_ID, 'business', { name: 'plainbot' })) as Record<
      string,
      unknown
    >;
    expect('llm_inject_system_prompt' in agent).toBe(false);
    expect('llm_redact_pii' in agent).toBe(false);
  });

  it('update writes an explicit false for both flags', async () => {
    const captured: { updates?: Record<string, unknown> } = {};
    const svc = new AgentService(makeUpdateRepoStub(captured));
    await svc.update(AGENT_ID, OPERATOR_ID, {
      llm_inject_system_prompt: false,
      llm_redact_pii: false,
    });
    expect(captured.updates).toEqual({
      llm_inject_system_prompt: false,
      llm_redact_pii: false,
    });
  });

  it('update omitting the flags leaves them untouched', async () => {
    const captured: { updates?: Record<string, unknown> } = {};
    const svc = new AgentService(makeUpdateRepoStub(captured));
    await svc.update(AGENT_ID, OPERATOR_ID, { on_warning: 'block' });
    expect(captured.updates).toEqual({ on_warning: 'block' });
  });
});
