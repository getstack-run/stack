import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { ConflictError, ForbiddenError, NotFoundError, SchemaValidationError, type MissionClaim } from '@stack/shared';
import {
  MissionService,
  MissionRecipientPinReader,
  DEFAULT_CAP_BEHAVIOR,
  effectiveCapBehavior,
  type MissionServiceDeps,
} from './mission-service.js';
import type { MissionRepository } from '../repositories/mission-repo.js';
import type { MissionSpendSource } from './spend/spend-ledger.js';
import type {
  ClaimRegistryService,
  RegisterClaimInput,
  RegisterClaimResult,
} from './claim-registry-service.js';

/**
 * MissionService invariants:
 *
 *  O1: open() signs a mission claim + inserts a missions row
 *  O2: open() has no maximum length and needs no limit at any length
 *  O3: open() validates parentPassportServices subset (when provided)
 *  O4: open() with empty intent_services always passes subset check
 *  O5: open() omits subset check when parentPassportServices not provided
 *  O6: open() applies cap defaults (nulls / empty maps)
 *
 *  C1: complete() emits new claim + updates row with terminal_state='completed_successful'
 *  C2: complete() is idempotent — second call returns prior terminal state, transitioned=false
 *  C3: complete() throws ConflictError when mission is already revoked
 *  C4: complete() throws NotFoundError when mission_id unknown
 *  C5: complete({expired:true}) sets terminal_state='completed_expired'
 *  C6: complete({capBreached:true}) sets terminal_state='completed_cap_breached'
 *
 *  R1: revoke({reason:'adversarial'}) sets terminal_state='revoked_adversarial' + fires callback
 *  R2: revoke({reason:'operator_initiated_clean'}) sets terminal_state='revoked_operator_clean'
 *  R3: revoke() is idempotent — second call returns prior state, transitioned=false
 *  R4: revoke() throws ConflictError when mission is already completed
 *  R5: revoke() throws NotFoundError when mission_id unknown
 *  R6: revoke()'s onMissionRevoked callback errors are swallowed (best-effort)
 *  R7: autoRevokeForCapBreach() emits with reason='cap_breach_hard'
 *
 *  H1: effectiveCapBehavior() returns pause, the default, when mission has no override
 *  H2: effectiveCapBehavior() returns mission override when present
 */

let claimSeq = 0;

interface InsertedRow {
  assigned_agent_id: string | null;
  authorization_digest: string | null;
  mission_id: string;
  claim_id: string;
  operator_id: string;
  passport_jti: string | null;
  intent_summary: string;
  intent_services: string[];
  expected_counterparties: string[];
  max_actions: number | null;
  max_dropoff_bytes: number | null;
  coverage_cap_cents: number | null;
  max_duration_seconds: number | null;
  max_concurrent_intents: number | null;
  max_actions_per_service: Record<string, number>;
  cap_behavior: Record<string, 'pause' | 'refuse_action' | 'end_mission'>;
  baseline_profile: Record<string, unknown> | null;
  expected_output_shape: Record<string, unknown> | null;
  recipient_pins: unknown[] | null;
  started_at: Date;
  expires_at: Date;
  completed_at: Date | null;
  revoked_at: Date | null;
  revoked_reason: string | null;
  terminal_state: string | null;
}

function makeStubRepo(opts?: {
  countIntents?: number;
  countByService?: Record<string, number>;
  countInflight?: number;
  walletDebitCents?: number;
  dropoffBytes?: number;
  agentAccountId?: string;
}) {
  const rows = new Map<string, InsertedRow>();
  const repo = {
    async createWithClaim(data: Omit<Parameters<MissionRepository['insert']>[0], 'claim_id'>, signAndPersist: Parameters<MissionRepository['createWithClaim']>[1]) {
      const claimId = await signAndPersist({ insert: async () => { throw new Error('The claim registry fixture does not invoke persistence'); } });
      return repo.insert({ ...data, claim_id: claimId });
    },
    async insert(data: Record<string, unknown>) {
      const row: InsertedRow = {
        assigned_agent_id: (data.assigned_agent_id as string | null) ?? null,
        authorization_digest: (data.authorization_digest as string | null) ?? null,
        mission_id: data.mission_id as string,
        claim_id: data.claim_id as string,
        operator_id: data.operator_id as string,
        passport_jti: (data.passport_jti as string | null | undefined) ?? null,
        intent_summary: data.intent_summary as string,
        intent_services: (data.intent_services as string[]) ?? [],
        expected_counterparties: (data.expected_counterparties as string[]) ?? [],
        max_actions: (data.max_actions as number | null) ?? null,
        max_dropoff_bytes: (data.max_dropoff_bytes as number | null) ?? null,
        coverage_cap_cents: (data.coverage_cap_cents as number | null) ?? null,
        max_duration_seconds: (data.max_duration_seconds as number | null) ?? null,
        max_concurrent_intents: (data.max_concurrent_intents as number | null) ?? null,
        max_actions_per_service: (data.max_actions_per_service as Record<string, number>) ?? {},
        cap_behavior: (data.cap_behavior as Record<string, 'pause' | 'refuse_action' | 'end_mission'>) ?? {},
        baseline_profile: (data.baseline_profile as Record<string, unknown> | null) ?? null,
        expected_output_shape: (data.expected_output_shape as Record<string, unknown> | null) ?? null,
        recipient_pins: (data.recipient_pins as unknown[] | null | undefined) ?? null,
        started_at: data.started_at as Date,
        expires_at: data.expires_at as Date,
        completed_at: null,
        revoked_at: null,
        revoked_reason: null,
        terminal_state: null,
      };
      rows.set(row.mission_id, row);
      return row as unknown as Awaited<ReturnType<MissionRepository['insert']>>;
    },
    async findById(missionId: string) {
      return (rows.get(missionId) ?? undefined) as unknown as Awaited<
        ReturnType<MissionRepository['findById']>
      >;
    },
    async transitionWithClaim(
      missionId: string,
      expected: string,
      patch: Parameters<MissionRepository['updateLifecycle']>[1],
      sign: Parameters<MissionRepository['transitionWithClaim']>[3],
      _output?: Parameters<MissionRepository['transitionWithClaim']>[4],
      endBoundPassports?: Parameters<MissionRepository['transitionWithClaim']>[5],
    ) {
      const row = rows.get(missionId);
      if (!row || row.claim_id !== expected || row.completed_at || row.revoked_at) throw new ConflictError('Conflict');
      const claimId = await sign({ insert: async () => { throw new Error('Fixture persistence unavailable'); } });
      // Simulate the transaction: the Passport step runs after the update
      // and a throw restores the row exactly as the real rollback would.
      const before = { ...row };
      const updated = (await repo.updateLifecycle(missionId, { ...patch, claim_id: claimId }))!;
      if (endBoundPassports) {
        try {
          await endBoundPassports.run({ fixtureTransaction: true } as never);
        } catch (err) {
          rows.set(missionId, before);
          throw err;
        }
      }
      return updated;
    },
    async updateLifecycle(
      missionId: string,
      patch: {
        claim_id?: string;
        completed_at?: Date | null;
        revoked_at?: Date | null;
        revoked_reason?: string | null;
        terminal_state?: string | null;
      },
    ) {
      const row = rows.get(missionId);
      if (!row) return null;
      if (patch.claim_id !== undefined) row.claim_id = patch.claim_id;
      if (patch.completed_at !== undefined) row.completed_at = patch.completed_at;
      if (patch.revoked_at !== undefined) row.revoked_at = patch.revoked_at;
      if (patch.revoked_reason !== undefined) row.revoked_reason = patch.revoked_reason ?? null;
      if (patch.terminal_state !== undefined) row.terminal_state = patch.terminal_state ?? null;
      return row as unknown as Awaited<ReturnType<MissionRepository['updateLifecycle']>>;
    },
    async listByOperator() {
      return [] as unknown as Awaited<ReturnType<MissionRepository['listByOperator']>>;
    },
    async countByOperator() { return 0; },
    async findExpiredActive() {
      return [] as unknown as Awaited<ReturnType<MissionRepository['findExpiredActive']>>;
    },
    async countIntentsByMissionId() { return opts?.countIntents ?? 0; },
    async countIntentsByMissionIdGroupedByService() { return opts?.countByService ?? {}; },
    async countInflightIntentsByMissionId() { return opts?.countInflight ?? 0; },
    async sumDropoffBytesByMission() { return opts?.dropoffBytes ?? 0; },
  } satisfies Partial<MissionRepository> as unknown as MissionRepository;
  return { repo, rows };
}

function makeStubClaimRegistry() {
  const registered: RegisterClaimInput[] = [];
  const registry = {
    async registerClaim(input: RegisterClaimInput): Promise<RegisterClaimResult> {
      registered.push(input);
      claimSeq += 1;
      return {
        claimId: `pc_test_${claimSeq}`,
        envelopeCose: 'fake-base64',
      } as RegisterClaimResult;
    },
  } as unknown as ClaimRegistryService;
  return { registry, registered };
}

function makeDeps(
  overrides?: Partial<MissionServiceDeps>,
  repoOpts?: {
    countIntents?: number;
    countByService?: Record<string, number>;
    countInflight?: number;
    walletDebitCents?: number;
    dropoffBytes?: number;
    agentAccountId?: string;
  },
): {
  deps: MissionServiceDeps;
  rows: Map<string, InsertedRow>;
  registered: RegisterClaimInput[];
} {
  const { repo, rows } = makeStubRepo(repoOpts);
  const { registry, registered } = makeStubClaimRegistry();
  // What the wallet says of a Mission: its credit spend, and whether an agent account's budget governs it.
  const missionSpend: MissionSpendSource = {
    spentCents: vi.fn(async () => repoOpts?.walletDebitCents ?? 0),
    governedByAccountBudget: async () => repoOpts?.agentAccountId !== undefined,
  };
  return {
    deps: { repo, claimRegistry: registry, missionSpend, ...overrides },
    rows,
    registered,
  };
}

/** Records the Mission-end Passport revokes and their post-commit sync. */
function makeRevoker(jtis: string[]) {
  const calls: Array<{ operatorId: string; missionId: string; reason: string; revokeAttachedClaims: boolean }> = [];
  const synced: string[][] = [];
  const revoker: NonNullable<MissionServiceDeps['passportRevoker']> = {
    async revokeInTransaction(_tx, input) {
      calls.push(input);
      return jtis.map((jti) => ({ jti, expires_at: new Date(Date.now() + 60_000) }));
    },
    async afterCommit(rows) {
      synced.push(rows.map((row) => row.jti));
    },
  };
  return { revoker, calls, synced };
}

beforeEach(() => {
  claimSeq = 0;
});

describe('MissionService.open', () => {
  it('preserves a durable start identifier and signed authorization commitment through completion', async () => {
    const { deps, rows, registered } = makeDeps();
    const svc = new MissionService(deps);
    const digest = 'a'.repeat(64);
    const result = await svc.open({ operatorId: 'op_test', missionId: 'ms_reserved', assignedAgentId: 'agt_owner', authorizationDigest: digest, intent_summary: 'work' });
    expect(result.mission_id).toBe('ms_reserved');
    expect(rows.get('ms_reserved')!.authorization_digest).toBe(digest);
    await svc.complete('ms_reserved');
    expect(registered.map(entry => entry.payload)).toEqual([
      expect.objectContaining({ mission_id: 'ms_reserved', authorization_digest: digest, assigned_agent_id: 'agt_owner' }),
      expect.objectContaining({ mission_id: 'ms_reserved', authorization_digest: digest, assigned_agent_id: 'agt_owner' }),
    ]);
  });
  it('O1: signs a mission claim and inserts a row', async () => {
    const { deps, rows, registered } = makeDeps();
    const svc = new MissionService(deps);
    const result = await svc.open({
      operatorId: 'op_test',
      intent_summary: 'process refund',
      intent_services: ['stripe'],
    });
    expect(result.mission_id).toMatch(/^ms_/);
    expect(result.claim_id).toMatch(/^pc_/);
    expect(registered).toHaveLength(1);
    expect(registered[0]!.claimType).toBe('mission');
    expect(registered[0]!.subjectOverride).toBe('operator');
    expect(registered[0]!.operatorId).toBe('op_test');
    const row = rows.get(result.mission_id);
    expect(row).toBeDefined();
    expect(row!.intent_services).toEqual(['stripe']);
  });

  it('O2: has no maximum length and needs no limit at any length', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);

    const week = 7 * 86_400;
    // A week, a year and more, with no spend limit and no action limit.
    const long = await svc.open({ operatorId: 'op_test', intent_summary: 'a week, no limit', expiresInSeconds: week });
    expect(long.expires_at.getTime() - Date.now()).toBeGreaterThan(week * 1000 - 5_000);
    const longer = await svc.open({ operatorId: 'op_test', intent_summary: 'long, no limit', expiresInSeconds: 400 * 86_400 });
    expect(longer.expires_at.getTime() - Date.now()).toBeGreaterThan(399 * 86_400 * 1000);
    // It may still carry one.
    await svc.open({ operatorId: 'op_test', intent_summary: 'long, with a budget', expiresInSeconds: week, coverage_cap_cents: 5_000 });
    await svc.open({ operatorId: 'op_test', intent_summary: 'long, with an action limit', expiresInSeconds: week, max_actions: 100 });

    // A lifetime no date can hold is refused in words, not stored as an invalid date.
    await expect(
      svc.open({ operatorId: 'op_test', intent_summary: 'forever', expiresInSeconds: 1e15, coverage_cap_cents: 5_000 }),
    ).rejects.toThrow('A Mission cannot end after 31 December 9999. Choose an earlier end.');

    const tiny = await svc.open({
      operatorId: 'op_test',
      intent_summary: 'short',
      expiresInSeconds: -5,
    });
    expect(tiny.expires_at.getTime() - Date.now()).toBeGreaterThanOrEqual(0);
  });

  it('O2b: a renewal has no maximum length either', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const plain = await svc.open({ operatorId: 'op_test', intent_summary: 'standing', expiresInSeconds: 86_400 });
    const week = new Date(Date.now() + 7 * 86_400 * 1000);
    const renewed = await svc.extend(plain.mission_id, { expiresAt: week, coverageCapCents: null });
    expect(renewed.expires_at.getTime()).toBe(week.getTime());
    const latest = new Date(Date.UTC(9999, 11, 31, 23, 59, 59, 999));
    const last = await svc.extend(plain.mission_id, { expiresAt: latest, coverageCapCents: null });
    expect(last.expires_at.toISOString()).toBe('9999-12-31T23:59:59.999Z');
    await expect(svc.extend(plain.mission_id, { expiresAt: new Date(latest.getTime() + 1), coverageCapCents: null })).rejects.toThrow('A Mission cannot end after 31 December 9999. Choose an earlier end.');
  });

  it('O3: validates parentPassportServices subset', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    await expect(
      svc.open({
        operatorId: 'op_test',
        intent_summary: 'attempt',
        intent_services: ['stripe', 'github'],
        parentPassportServices: ['stripe', 'slack'],
      }),
    ).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('O4: empty intent_services always passes subset check', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    await expect(
      svc.open({
        operatorId: 'op_test',
        intent_summary: 'no services',
        intent_services: [],
        parentPassportServices: ['stripe'],
      }),
    ).resolves.toBeDefined();
  });

  it('O5: omits subset check when parentPassportServices not provided', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    await expect(
      svc.open({
        operatorId: 'op_test',
        intent_summary: 'standalone mission',
        intent_services: ['anything', 'goes'],
      }),
    ).resolves.toBeDefined();
  });

  it('O6: applies cap defaults (nulls / empty maps)', async () => {
    const { deps, rows } = makeDeps();
    const svc = new MissionService(deps);
    const result = await svc.open({
      operatorId: 'op_test',
      intent_summary: 'minimal',
    });
    const row = rows.get(result.mission_id)!;
    expect(row.max_actions).toBeNull();
    expect(row.max_dropoff_bytes).toBeNull();
    expect(row.coverage_cap_cents).toBeNull();
    expect(row.max_duration_seconds).toBeNull();
    expect(row.max_concurrent_intents).toBeNull();
    expect(row.max_actions_per_service).toEqual({});
    expect(row.cap_behavior).toEqual({});
    expect(row.recipient_pins).toBeNull();
  });

  it('O7: stores the recipient pins a Mission opens with, reads them back, and leaves the signed claim as it was', async () => {
    const { deps, rows, registered } = makeDeps();
    const svc = new MissionService(deps);
    const pins = [{ path: '*', op: 'in' as const, value: ['ana@example.com'] }];
    const result = await svc.open({ operatorId: 'op_test', intent_summary: 'reply', recipient_pins: pins });
    expect(rows.get(result.mission_id)!.recipient_pins).toEqual(pins);
    expect((await svc.findById(result.mission_id))?.recipient_pins).toEqual(pins);
    // The published claim schema is additive-only and carries no pins: they are read from the row.
    expect(JSON.stringify(registered)).not.toContain('ana@example.com');
    const plain = await svc.open({ operatorId: 'op_test', intent_summary: 'no pins' });
    expect((await svc.findById(plain.mission_id))?.recipient_pins).toBeNull();
  });

  it('O8: reads a stored pin that no longer parses as no pin, never as a wider set', async () => {
    const { deps, rows } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'reply', recipient_pins: [{ path: '*', op: 'in', value: ['a@x.com'] }] });
    rows.get(mission_id)!.recipient_pins = [{ path: '*', op: 'matches', value: '.*' }];
    expect((await svc.findById(mission_id))?.recipient_pins).toBeNull();
  });
});

describe('MissionRecipientPinReader', () => {
  const repoOf = (row: { operator_id: string; recipient_pins: unknown; assigned_agent_id?: string | null } | undefined) => {
    const findById = vi.fn(async () => row as never);
    return { reader: new MissionRecipientPinReader({ findById }), findById };
  };
  const pins = [{ path: '*', op: 'in' as const, value: ['ana@example.com'] }];
  const nobody = { pins: null, assignedAgentId: null };

  it('reads a Mission\'s pins and the agent it is for once and keeps them, since they never change', async () => {
    const { reader, findById } = repoOf({ operator_id: 'op_a', recipient_pins: pins, assigned_agent_id: 'agt_a' });
    expect(await reader.read('op_a', 'ms_1')).toEqual({ pins, assignedAgentId: 'agt_a' });
    expect(await reader.read('op_a', 'ms_1')).toEqual({ pins, assignedAgentId: 'agt_a' });
    expect(findById).toHaveBeenCalledTimes(1);
  });

  it('reads another operator\'s Mission, a missing one and an unreadable pin as pinning no one', async () => {
    expect(await repoOf({ operator_id: 'op_b', recipient_pins: pins, assigned_agent_id: 'agt_a' }).reader.read('op_a', 'ms_1')).toEqual(nobody);
    const missing = repoOf(undefined);
    expect(await missing.reader.read('op_a', 'ms_1')).toEqual(nobody);
    await missing.reader.read('op_a', 'ms_1');
    expect(missing.findById).toHaveBeenCalledTimes(2);
    expect(await repoOf({ operator_id: 'op_a', recipient_pins: 'garbage' }).reader.read('op_a', 'ms_1')).toEqual(nobody);
    expect(await repoOf({ operator_id: 'op_a', recipient_pins: null, assigned_agent_id: 'agt_a' }).reader.read('op_a', 'ms_1')).toEqual({ pins: null, assignedAgentId: 'agt_a' });
  });

  it('lets a read that fails reach the caller, which refuses the send', async () => {
    const reader = new MissionRecipientPinReader({ findById: vi.fn(async () => { throw new Error('database down'); }) });
    await expect(reader.read('op_a', 'ms_1')).rejects.toThrow('database down');
  });
});

describe('MissionService.complete', () => {
  it('rejects a sibling agent and a foreign operator before producing evidence', async () => {
    const { deps, registered } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', assignedAgentId: 'agt_owner', intent_summary: 'work' });
    for (const actor of [{ operatorId: 'op_test', agentId: 'agt_sibling' }, { operatorId: 'op_other' }]) {
      await expect(svc.complete(mission_id, { actor })).rejects.toBeInstanceOf(NotFoundError);
    }
    expect(registered).toHaveLength(1);
    await expect(svc.complete(mission_id, { actor: { operatorId: 'op_test', agentId: 'agt_owner' } })).resolves.toMatchObject({ transitioned: true });
  });

  it('requires valid output before completing a declared success schema', async () => {
    const { deps, registered, rows } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'work', expected_output_shape: {
      type: 'object', properties: { done: { const: true } }, required: ['done'], additionalProperties: false,
    } });
    await expect(svc.complete(mission_id)).rejects.toBeInstanceOf(SchemaValidationError);
    await expect(svc.complete(mission_id, { output: { done: false } })).rejects.toBeInstanceOf(SchemaValidationError);
    expect(registered).toHaveLength(1);
    expect(rows.get(mission_id)!.completed_at).toBeNull();
  });

  it('rejects unsafe output schemas before writing a Mission', async () => {
    const { deps, registered } = makeDeps();
    const svc = new MissionService(deps);
    await expect(svc.open({ operatorId: 'op_test', intent_summary: 'work', expected_output_shape: {
      type: 'object', properties: { text: { type: 'string', pattern: '(a+)+$', maxLength: 4096 } },
    } })).rejects.toBeInstanceOf(SchemaValidationError);
    expect(registered).toHaveLength(0);
  });

  it('bounds supplied output before encryption or signing', async () => {
    const encrypt = vi.fn(async () => ({ ciphertext: 'encrypted', keyRef: 'test-key' }));
    const { deps, registered } = makeDeps({ kms: { encrypt, decrypt: async () => '{}' } });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'work' });
    let output: Record<string, unknown> = {};
    for (let depth = 0; depth < 40; depth++) output = { nested: output };
    await expect(svc.complete(mission_id, { output })).rejects.toBeInstanceOf(SchemaValidationError);
    expect(encrypt).not.toHaveBeenCalled();
    expect(registered).toHaveLength(1);
  });

  it('commits output separately with a salted digest and verifies it on authorized retrieval', async () => {
    let committed = '';
    const { deps, registered } = makeDeps({ kms: { encrypt: async (plaintext, context) => {
      committed = plaintext;
      expect(context).toMatchObject({ operator_id: 'op_test', store: 'mission_output' });
      return { ciphertext: 'encrypted-output', keyRef: 'test-key' };
    }, decrypt: async () => committed } });
    const transition = vi.spyOn(deps.repo, 'transitionWithClaim');
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'work' });
    await svc.complete(mission_id, { output: { secret: 'CANARY_OUTPUT_SECRET' } });
    const digest = createHash('sha256').update(committed).digest('hex');
    const decoded = JSON.parse(committed);
    expect(decoded).toEqual({ output: { secret: 'CANARY_OUTPUT_SECRET' }, salt: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(registered.at(-1)!.payload).toMatchObject({ output_digest: digest });
    expect(registered.at(-1)!.payload).not.toHaveProperty('output_encrypted');
    expect(transition.mock.calls[0]![4]).toEqual({ output_digest: digest, output_encrypted: 'encrypted-output', key_ref: 'test-key' });
    expect(JSON.stringify(registered)).not.toContain('CANARY_OUTPUT_SECRET');
    deps.repo.findOutput = vi.fn(async () => ({ output_encrypted: 'encrypted-output', output_digest: digest, claim: registered.at(-1)!.payload as Record<string, unknown> }));
    await expect(svc.readOutput(mission_id, { operatorId: 'op_other' })).rejects.toBeInstanceOf(NotFoundError);
    expect(deps.repo.findOutput).not.toHaveBeenCalled();
    await expect(svc.readOutput(mission_id, { operatorId: 'op_test' })).resolves.toMatchObject({ output: decoded.output, output_salt: decoded.salt, output_digest: digest });
    committed = committed.replace('CANARY_OUTPUT_SECRET', 'TAMPERED');
    await expect(svc.readOutput(mission_id, { operatorId: 'op_test' })).rejects.toBeInstanceOf(ConflictError);
  });

  it('does not report successful completion after expiry even before the worker sweep', async () => {
    const { deps, rows } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'work' });
    rows.get(mission_id)!.expires_at = new Date(Date.now() - 1);
    await expect(svc.checkGate({ missionId: mission_id, requestedService: 'slack' })).resolves.toMatchObject({ allowed: false });
    await expect(svc.complete(mission_id)).resolves.toMatchObject({ terminal_state: 'completed_expired' });
  });

  it('C1: emits new claim and sets terminal_state=completed_successful', async () => {
    const { deps, rows, registered } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_test',
      intent_summary: 'work',
    });
    const result = await svc.complete(mission_id);
    expect(result.terminal_state).toBe('completed_successful');
    expect(result.transitioned).toBe(true);
    expect(registered).toHaveLength(2); // open + complete
    const row = rows.get(mission_id)!;
    expect(row.completed_at).not.toBeNull();
    expect(row.terminal_state).toBe('completed_successful');
    expect(row.claim_id).toBe(result.claim_id);
  });

  it('C2: idempotent — second call returns prior state, transitioned=false', async () => {
    const { deps, registered } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await svc.complete(mission_id);
    const second = await svc.complete(mission_id);
    expect(second.transitioned).toBe(false);
    expect(second.terminal_state).toBe('completed_successful');
    expect(registered).toHaveLength(2); // open + complete; second complete does NOT emit
  });

  it('C3: throws ConflictError when mission is already revoked', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await svc.revoke(mission_id, { reason: 'operator_initiated_clean' });
    await expect(svc.complete(mission_id)).rejects.toBeInstanceOf(ConflictError);
  });

  it('C4: throws NotFoundError when mission_id unknown', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    await expect(svc.complete('ms_unknown')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('C5: complete({expired:true}) sets terminal_state=completed_expired', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    const result = await svc.complete(mission_id, { expired: true });
    expect(result.terminal_state).toBe('completed_expired');
  });

  it('C6: complete({capBreached:true}) sets terminal_state=completed_cap_breached', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    const result = await svc.complete(mission_id, { capBreached: true });
    expect(result.terminal_state).toBe('completed_cap_breached');
  });

  it('C7: every completion ends the Mission\'s Passports in the transition and keeps their claims as evidence', async () => {
    for (const input of [{}, { expired: true }, { capBreached: true }]) {
      const revoker = makeRevoker(['pas_done']);
      const published: Array<{ revoke_reason: string; cascaded_passport_jtis: string[] }> = [];
      const { deps } = makeDeps({
        passportRevoker: revoker.revoker,
        publishMissionRevocation: async (event) => { published.push(event); },
      });
      const svc = new MissionService(deps);
      const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
      const result = await svc.complete(mission_id, input);
      expect(revoker.calls).toEqual([{
        operatorId: 'op_test', missionId: mission_id,
        reason: `mission ${mission_id} ended (${result.terminal_state})`, revokeAttachedClaims: false,
      }]);
      expect(revoker.synced).toEqual([['pas_done']]);
      expect(published).toEqual([{
        operator_id: 'op_test', mission_id, revoke_reason: result.terminal_state, cascaded_passport_jtis: ['pas_done'],
      }]);
    }
  });

  it('C8: a failed Passport revoke rolls the completion back (fail closed)', async () => {
    const { deps, rows } = makeDeps({
      passportRevoker: {
        async revokeInTransaction() { throw new Error('passport store unavailable'); },
        async afterCommit() { throw new Error('must not run'); },
      },
    });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await expect(svc.complete(mission_id)).rejects.toThrow('passport store unavailable');
    expect(rows.get(mission_id)!.completed_at).toBeNull();
  });

  it('C9: an idempotent second completion does not revoke again', async () => {
    const revoker = makeRevoker([]);
    const { deps } = makeDeps({ passportRevoker: revoker.revoker });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await svc.complete(mission_id);
    await svc.complete(mission_id);
    expect(revoker.calls).toHaveLength(1);
  });
});

describe('MissionService.revoke', () => {
  it('R1: adversarial reason sets terminal_state=revoked_adversarial and ends the Mission\'s Passports', async () => {
    const revoker = makeRevoker(['pas_a']);
    const { deps } = makeDeps({ passportRevoker: revoker.revoker });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    const result = await svc.revoke(mission_id, { reason: 'adversarial' });
    expect(result.terminal_state).toBe('revoked_adversarial');
    expect(result.transitioned).toBe(true);
    expect(revoker.calls).toEqual([{
      operatorId: 'op_test', missionId: mission_id,
      reason: `mission ${mission_id} revoked (adversarial)`, revokeAttachedClaims: true,
    }]);
    expect(revoker.synced).toEqual([['pas_a']]);
  });

  it('R1b: EVERY revoke reason ends the Mission\'s Passports inside the transition', async () => {
    for (const reason of ['adversarial', 'cap_breach_hard', 'operator_initiated_clean', 'cascade_from_passport'] as const) {
      const revoker = makeRevoker(['pas_x']);
      const { deps } = makeDeps({ passportRevoker: revoker.revoker });
      const svc = new MissionService(deps);
      const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
      await svc.revoke(mission_id, { reason });
      expect(revoker.calls, reason).toHaveLength(1);
      expect(revoker.calls[0]!.missionId).toBe(mission_id);
      // Claims carried by the Passports are revoked only for the adversarial
      // reasons, matching a direct Passport revoke; a clean end keeps them as evidence.
      expect(revoker.calls[0]!.revokeAttachedClaims, reason)
        .toBe(reason === 'adversarial' || reason === 'cap_breach_hard');
      expect(revoker.synced, reason).toEqual([['pas_x']]);
    }
  });

  it('R1c: a failed Passport revoke rolls the Mission revoke back (fail closed)', async () => {
    const { deps, rows } = makeDeps({
      passportRevoker: {
        async revokeInTransaction() { throw new Error('passport store unavailable'); },
        async afterCommit() { throw new Error('must not run'); },
      },
    });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await expect(svc.revoke(mission_id, { reason: 'operator_initiated_clean' })).rejects.toThrow('passport store unavailable');
    expect(rows.get(mission_id)!.revoked_at).toBeNull();
    expect(rows.get(mission_id)!.terminal_state).toBeNull();
  });

  it('R2: operator_initiated_clean reason sets terminal_state=revoked_operator_clean', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    const result = await svc.revoke(mission_id, { reason: 'operator_initiated_clean' });
    expect(result.terminal_state).toBe('revoked_operator_clean');
  });

  it('R3: idempotent — second call returns prior state, transitioned=false', async () => {
    const { deps, registered } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await svc.revoke(mission_id, { reason: 'adversarial' });
    const second = await svc.revoke(mission_id, { reason: 'adversarial' });
    expect(second.transitioned).toBe(false);
    expect(registered).toHaveLength(2); // open + revoke; second revoke does NOT re-emit
  });

  it('R4: throws ConflictError when mission is already completed', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await svc.complete(mission_id);
    await expect(
      svc.revoke(mission_id, { reason: 'operator_initiated_clean' }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('R5: throws NotFoundError when mission_id unknown', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    await expect(
      svc.revoke('ms_unknown', { reason: 'adversarial' }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('R6: a post-commit Redis sync failure does not fail the committed revoke', async () => {
    const { deps } = makeDeps({
      passportRevoker: {
        async revokeInTransaction() { return [{ jti: 'pas_a', expires_at: new Date(Date.now() + 60_000) }]; },
        async afterCommit() { throw new Error('redis kaboom'); },
      },
    });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    // The database revoke already committed and verify() falls back to it.
    await expect(svc.revoke(mission_id, { reason: 'adversarial' })).resolves.toBeDefined();
  });

  it('R8: publishMissionRevocation carries the Passports the Mission end revoked', async () => {
    const published: Array<{ mission_id: string; cascaded_passport_jtis: string[]; revoke_reason: string }> = [];
    const { deps } = makeDeps({
      passportRevoker: makeRevoker(['pas_a', 'pas_b']).revoker,
      publishMissionRevocation: async (event) => {
        published.push({
          mission_id: event.mission_id,
          cascaded_passport_jtis: event.cascaded_passport_jtis,
          revoke_reason: event.revoke_reason,
        });
      },
    });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await svc.revoke(mission_id, { reason: 'adversarial' });
    expect(published).toHaveLength(1);
    expect(published[0]!.mission_id).toBe(mission_id);
    expect(published[0]!.revoke_reason).toBe('adversarial');
    expect(published[0]!.cascaded_passport_jtis).toEqual(['pas_a', 'pas_b']);
  });

  it('R9: operator_initiated_clean also publishes the Passports it ended', async () => {
    const published: Array<{ cascaded_passport_jtis: string[] }> = [];
    const { deps } = makeDeps({
      passportRevoker: makeRevoker(['pas_clean']).revoker,
      publishMissionRevocation: async (event) => {
        published.push({ cascaded_passport_jtis: event.cascaded_passport_jtis });
      },
    });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    await svc.revoke(mission_id, { reason: 'operator_initiated_clean' });
    expect(published).toHaveLength(1);
    expect(published[0]!.cascaded_passport_jtis).toEqual(['pas_clean']);
  });

  it('R10: publishMissionRevocation errors are swallowed (best-effort)', async () => {
    const { deps } = makeDeps({
      publishMissionRevocation: async () => {
        throw new Error('pub/sub kaboom');
      },
    });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    // Should NOT throw — publish failure is best-effort.
    await expect(svc.revoke(mission_id, { reason: 'adversarial' })).resolves.toBeDefined();
  });

  it('R7: autoRevokeForCapBreach emits with reason=cap_breach_hard', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_test', intent_summary: 'x' });
    const result = await svc.autoRevokeForCapBreach(mission_id, 'coverage_cap_cents');
    expect(result.revoke_reason).toBe('cap_breach_hard');
    expect(result.terminal_state).toBe('revoked_adversarial');
  });
});

describe('effectiveCapBehavior', () => {
  it('H1: every cap pauses the Mission when it sets nothing of its own', () => {
    const mission = { cap_behavior: {} };
    for (const cap of ['coverage_cap_cents', 'max_actions', 'max_dropoff_bytes', 'max_concurrent_intents', 'max_duration_seconds', 'max_actions_per_service'] as const) {
      expect(effectiveCapBehavior(mission, cap)).toBe('pause');
    }
  });

  it('H2: returns mission override when present', () => {
    const mission = {
      cap_behavior: {
        max_actions: 'end_mission' as const,
        coverage_cap_cents: 'refuse_action' as const,
      },
    };
    expect(effectiveCapBehavior(mission, 'max_actions')).toBe('end_mission');
    expect(effectiveCapBehavior(mission, 'coverage_cap_cents')).toBe('refuse_action');
    // Non-overridden caps fall back to the default
    expect(effectiveCapBehavior(mission, 'max_dropoff_bytes')).toBe('pause');
  });
});

describe('DEFAULT_CAP_BEHAVIOR table', () => {
  it('covers all six caps with explicit behavior', () => {
    const expected = [
      'coverage_cap_cents',
      'max_dropoff_bytes',
      'max_concurrent_intents',
      'max_actions',
      'max_duration_seconds',
      'max_actions_per_service',
    ] as const;
    for (const cap of expected) {
      expect(DEFAULT_CAP_BEHAVIOR[cap]).toBe('pause');
    }
  });
});

describe('MissionService.findById + listByOperator', () => {
  it('findById returns view shape', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_test',
      intent_summary: 'find me',
      intent_services: ['slack'],
    });
    const view = await svc.findById(mission_id);
    expect(view).not.toBeNull();
    expect(view!.mission_id).toBe(mission_id);
    expect(view!.intent_summary).toBe('find me');
    expect(view!.intent_services).toEqual(['slack']);
    expect(view!.terminal_state).toBeNull();
    expect(view!.revoked_reason).toBeNull();
  });

  it('findById returns null for unknown mission', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    expect(await svc.findById('ms_unknown')).toBeNull();
  });
});

describe('MissionService.checkGate (5.0.5 proxy gate)', () => {
  it('uses fleet admission counters only for a sealed fleet Mission, retaining lifecycle gates', async () => {
    const { deps } = makeDeps(undefined, { countIntents: 100 });
    const svc = new MissionService(deps);
    const fleet = await svc.open({ operatorId: 'op_t', intent_summary: 'fleet', intent_services: ['slack'], max_actions: 1, authorizationDigest: 'a'.repeat(64) });
    await expect(svc.checkGate({ missionId: fleet.mission_id, requestedService: 'slack', accounting: 'fleet' })).resolves.toMatchObject({ allowed: true });
    const ordinary = await svc.open({ operatorId: 'op_t', intent_summary: 'ordinary', max_actions: 1 });
    await expect(svc.checkGate({ missionId: ordinary.mission_id, requestedService: 'slack', accounting: 'fleet' })).rejects.toBeInstanceOf(ForbiddenError);
    await svc.complete(fleet.mission_id);
    await expect(svc.checkGate({ missionId: fleet.mission_id, requestedService: 'slack', accounting: 'fleet' })).resolves.toMatchObject({ allowed: false, reason: 'mission_completed' });
  });
  it('G1: returns mission_not_found for an unknown mission_id', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const v = await svc.checkGate({ missionId: 'ms_nope', requestedService: 'slack' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('mission_not_found');
    }
  });

  it('G2: returns mission_revoked when the mission is revoked', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_t', intent_summary: 'x', intent_services: ['slack'] });
    await svc.revoke(mission_id, { reason: 'operator_initiated_clean' });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('mission_revoked');
      expect(v.mission).toBeDefined();
    }
  });

  it('G3: returns mission_completed when the mission is completed', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_t', intent_summary: 'x', intent_services: ['slack'] });
    await svc.complete(mission_id);
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('mission_completed');
    }
  });

  it('G4: returns mission_scope_mismatch when service not in intent_services', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'narrow',
      intent_services: ['slack'],
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'github' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('mission_scope_mismatch');
    }
  });

  it('G5: allows when scope empty (no narrowing) and no caps', async () => {
    const { deps } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'unconstrained',
      intent_services: [],
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'github' });
    expect(v.allowed).toBe(true);
    if (v.allowed) expect(v.mission.mission_id).toBe(mission_id);
  });

  it('G6: cap_max_actions fires with the default behaviour, pause', async () => {
    const { deps } = makeDeps(undefined, { countIntents: 50 });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'capped',
      intent_services: ['slack'],
      max_actions: 50,
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('cap_max_actions');
      expect(v.capBehavior).toBe('pause');
    }
  });

  it('G7: cap_max_actions respects per-mission end_mission override', async () => {
    const { deps } = makeDeps(undefined, { countIntents: 50 });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'strict',
      intent_services: ['slack'],
      max_actions: 50,
      cap_behavior: { max_actions: 'end_mission' },
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('cap_max_actions');
      expect(v.capBehavior).toBe('end_mission');
    }
  });

  it('G8: cap_max_actions_per_service fires when per-service count hits cap', async () => {
    const { deps } = makeDeps(undefined, { countByService: { stripe: 5 } });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'risky service',
      intent_services: ['slack', 'stripe'],
      max_actions_per_service: { stripe: 5 },
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'stripe' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('cap_max_actions_per_service');
      expect(v.capBehavior).toBe('pause');
    }
  });

  it('G9: cap_max_actions_per_service does NOT fire on a different service', async () => {
    const { deps } = makeDeps(undefined, { countByService: { stripe: 5 } });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'mixed',
      intent_services: ['slack', 'stripe'],
      max_actions_per_service: { stripe: 5 },
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(true);
  });

  it('G10: cap_max_concurrent_intents fires with the default behaviour, pause', async () => {
    const { deps } = makeDeps(undefined, { countInflight: 5 });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'concurrent-bound',
      intent_services: ['slack'],
      max_concurrent_intents: 5,
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('cap_max_concurrent_intents');
      expect(v.capBehavior).toBe('pause');
    }
  });

  it('G11: cap_max_duration_seconds fires when wall-clock exceeds cap', async () => {
    const { deps, rows } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'time-bound',
      intent_services: ['slack'],
      max_duration_seconds: 60,
    });
    // Backdate started_at to make the cap appear exceeded.
    const row = rows.get(mission_id)!;
    row.started_at = new Date(Date.now() - 120_000); // 2 minutes ago
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('cap_max_duration_seconds');
      expect(v.capBehavior).toBe('pause');
    }
  });

  it('G12: returns allowed when all caps are below limits', async () => {
    const { deps } = makeDeps(undefined, {
      countIntents: 5,
      countByService: { slack: 1 },
      countInflight: 2,
      walletDebitCents: 100,
      dropoffBytes: 1024,
    });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'happy path',
      intent_services: ['slack', 'stripe'],
      max_actions: 50,
      max_actions_per_service: { slack: 10, stripe: 2 },
      max_concurrent_intents: 5,
      max_duration_seconds: 3600,
      coverage_cap_cents: 50_000,
      max_dropoff_bytes: 1_000_000,
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(true);
  });

  it('G13: cap_coverage_cap_cents fires with the default behaviour, pause, when wallet spend hits cap', async () => {
    const { deps } = makeDeps(undefined, { walletDebitCents: 49_500 });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'money-bound',
      intent_services: ['stripe'],
      coverage_cap_cents: 50_000,
    });
    // Projected spend exceeds cap when this call's estimate is added.
    const v = await svc.checkGate({
      missionId: mission_id,
      requestedService: 'stripe',
      estimatedWalletCents: 600,
    });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('cap_coverage_cap_cents');
      expect(v.capBehavior).toBe('pause');
    }
  });

  it('an agent account Mission leaves coverage_cap_cents to the budget ledger', async () => {
    const sumTotalCostByMission = vi.fn(async () => 40_000);
    const { deps } = makeDeps({ llmUsageRepo: { sumTotalCostByMission } }, {
      walletDebitCents: 49_500,
      agentAccountId: 'acct_ledger',
    });
    const sumWallet = vi.mocked(deps.missionSpend!.spentCents);
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'account budget',
      intent_services: ['stripe'],
      coverage_cap_cents: 50_000,
    });
    const v = await svc.checkGate({
      missionId: mission_id,
      requestedService: 'stripe',
      estimatedWalletCents: 600,
    });
    // The ledger reserved this spend atomically; the gate neither sums nor refuses it.
    expect(v.allowed).toBe(true);
    expect(sumWallet).not.toHaveBeenCalled();
    expect(sumTotalCostByMission).not.toHaveBeenCalled();
  });

  it('an agent account Mission still enforces every other cap', async () => {
    const { deps } = makeDeps(undefined, { countIntents: 5, agentAccountId: 'acct_ledger' });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'account budget',
      intent_services: ['stripe'],
      max_actions: 5,
      coverage_cap_cents: 50_000,
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'stripe' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) expect(v.reason).toBe('cap_max_actions');
  });

  it('coverage usage reports wallet debits plus LLM gross, the same sum the gate compares', async () => {
    const sumTotalCostByMission = vi.fn(async () => 700);
    const llmUsageRepo = { sumTotalCostByMission };
    const { deps } = makeDeps({ llmUsageRepo }, { walletDebitCents: 300 });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'wallet and llm spend',
      intent_services: ['stripe'],
      coverage_cap_cents: 1_000,
    });
    const usage = await svc.getCapUsage(mission_id);
    expect(usage?.coverage_cents).toEqual({ used: 1_000, limit: 1_000, period: 'mission' });
    expect(sumTotalCostByMission).toHaveBeenCalledWith('op_t', mission_id);
    // The gate sees the same 1000 used: any further estimate breaches the cap.
    const gate = await svc.checkGate({ missionId: mission_id, requestedService: 'stripe' });
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.message).toContain('mission spend 1000');
  });

  it('coverage usage falls back to wallet debits when no LLM usage repo is wired', async () => {
    const { deps } = makeDeps(undefined, { walletDebitCents: 300 });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'wallet only',
      intent_services: ['stripe'],
      coverage_cap_cents: 1_000,
    });
    expect((await svc.getCapUsage(mission_id))?.coverage_cents.used).toBe(300);
  });

  it('G14: cap_coverage_cap_cents does NOT fire when projected spend stays under cap', async () => {
    const { deps } = makeDeps(undefined, { walletDebitCents: 100 });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'plenty headroom',
      intent_services: ['stripe'],
      coverage_cap_cents: 50_000,
    });
    const v = await svc.checkGate({
      missionId: mission_id,
      requestedService: 'stripe',
      estimatedWalletCents: 500,
    });
    expect(v.allowed).toBe(true);
  });

  it('G15: cap_max_dropoff_bytes fires with the default behaviour, pause, when exfil cap hit', async () => {
    const { deps } = makeDeps(undefined, { dropoffBytes: 1_048_576 });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'exfil-bound',
      intent_services: ['slack'],
      max_dropoff_bytes: 1_048_576, // 1 MiB
    });
    const v = await svc.checkGate({ missionId: mission_id, requestedService: 'slack' });
    expect(v.allowed).toBe(false);
    if (!v.allowed) {
      expect(v.reason).toBe('cap_max_dropoff_bytes');
      expect(v.capBehavior).toBe('pause');
    }
  });
});

// ── Mission baseline integration ────────────────────

interface FakeGenomeRow {
  claim_id: string;
  body_json: Record<string, unknown>;
}

function makeStubBehavioralGenome(opts?: {
  latestForPassport?: Record<string, FakeGenomeRow | null>;
  missionWindowGenome?: Record<string, unknown>;
  diffResult?: { max_z: number; l2_norm: number; per_dimension: Record<string, number> };
  throwOnMissionWindow?: boolean;
}) {
  return {
    async getLatestForPassport(jti: string) {
      const row = opts?.latestForPassport?.[jti];
      return (row ?? null) as never;
    },
    async computeMissionWindowGenome(_jti: string, _start: number) {
      if (opts?.throwOnMissionWindow) throw new Error('compute boom');
      return (opts?.missionWindowGenome ?? {
        type: 'behavioral_genome',
        passport_jti: 'jti',
        window_start_ms: 0,
        window_end_ms: 0,
        call_count: 0,
        mean_latency_ms: 0,
        stddev_latency_ms: 0,
        mean_request_bytes: 0,
        stddev_request_bytes: 0,
        mean_response_bytes: 0,
        stddev_response_bytes: 0,
        mean_request_entropy: 0,
        stddev_request_entropy: 0,
        mean_response_entropy: 0,
        stddev_response_entropy: 0,
        mean_prompt_tokens: 0,
        stddev_prompt_tokens: 0,
        mean_completion_tokens: 0,
        stddev_completion_tokens: 0,
        error_rate: 0,
        scope_histogram: {},
        time_of_day_histogram: new Array(24).fill(0),
        model_distribution: {},
        prior_genome_ref: null,
      }) as never;
    },
    computeDiffFromPayloads(_current: unknown, _prior: unknown) {
      return opts?.diffResult ?? { max_z: 0, l2_norm: 0, per_dimension: {} };
    },
  } as never;
}

function makeStubRedis(opts?: { delThrow?: boolean }) {
  const dels: string[] = [];
  const redis = {
    async del(key: string) {
      dels.push(key);
      if (opts?.delThrow) throw new Error('redis boom');
      return 1;
    },
  } as never;
  return { redis, dels };
}

function makeValidGenomeBody(): Record<string, unknown> {
  return {
    type: 'behavioral_genome',
    passport_jti: 'jti_test',
    window_start_ms: 1_000_000,
    window_end_ms: 2_000_000,
    call_count: 100,
    mean_latency_ms: 200,
    stddev_latency_ms: 50,
    mean_request_bytes: 500,
    stddev_request_bytes: 100,
    mean_response_bytes: 2000,
    stddev_response_bytes: 400,
    mean_request_entropy: 4.5,
    stddev_request_entropy: 0.5,
    mean_response_entropy: 5.0,
    stddev_response_entropy: 0.5,
    mean_prompt_tokens: 0,
    stddev_prompt_tokens: 0,
    mean_completion_tokens: 0,
    stddev_completion_tokens: 0,
    error_rate: 0,
    scope_histogram: { credential: 100 },
    time_of_day_histogram: new Array(24).fill(0),
    model_distribution: {},
    prior_genome_ref: null,
  };
}

describe('MissionService baseline + diff integration', () => {
  it('M1: open() with passportJti + behavioralGenome wired snapshots baseline_profile', async () => {
    const genomeBody = makeValidGenomeBody();
    const behavioralGenome = makeStubBehavioralGenome({
      latestForPassport: { jti_5_1_5: { claim_id: 'pc_prior', body_json: genomeBody } },
    });
    const { redis } = makeStubRedis();
    const { deps, rows } = makeDeps({ behavioralGenome, redis });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'with baseline',
      passportJti: 'jti_5_1_5',
    });
    const row = rows.get(mission_id)!;
    expect(row.passport_jti).toBe('jti_5_1_5');
    expect(row.baseline_profile).toEqual(genomeBody);
  });

  it('M2: open() with passportJti but no prior genome leaves baseline_profile null', async () => {
    const behavioralGenome = makeStubBehavioralGenome({
      latestForPassport: { jti_cold: null },
    });
    const { redis } = makeStubRedis();
    const { deps, rows } = makeDeps({ behavioralGenome, redis });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'cold start',
      passportJti: 'jti_cold',
    });
    const row = rows.get(mission_id)!;
    expect(row.passport_jti).toBe('jti_cold');
    expect(row.baseline_profile).toBeNull();
  });

  it('M3: open() without passportJti preserves legacy baseline_profile input', async () => {
    const { deps, rows } = makeDeps();
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'legacy',
      baseline_profile: { legacy: 'shape' },
    });
    const row = rows.get(mission_id)!;
    expect(row.passport_jti).toBeNull();
    expect(row.baseline_profile).toEqual({ legacy: 'shape' });
  });

  it('M4: open() with passportJti calls redis.del(genome_drift_fired:<jti>)', async () => {
    const behavioralGenome = makeStubBehavioralGenome({ latestForPassport: { jti_x: null } });
    const { redis, dels } = makeStubRedis();
    const { deps } = makeDeps({ behavioralGenome, redis });
    const svc = new MissionService(deps);
    await svc.open({ operatorId: 'op_t', intent_summary: 't', passportJti: 'jti_x' });
    // del is fire-and-forget; await a microtask
    await new Promise((r) => setTimeout(r, 10));
    expect(dels).toContain('genome_drift_fired:jti_x');
  });

  it('M5: open() succeeds even when redis.del throws (best-effort)', async () => {
    const behavioralGenome = makeStubBehavioralGenome({ latestForPassport: { jti_x: null } });
    const { redis } = makeStubRedis({ delThrow: true });
    const { deps } = makeDeps({ behavioralGenome, redis });
    const svc = new MissionService(deps);
    const result = await svc.open({
      operatorId: 'op_t',
      intent_summary: 't',
      passportJti: 'jti_x',
    });
    expect(result.mission_id).toMatch(/^ms_/);
  });

  it('M6: complete() with baseline + passport_jti populates behavioral_diff', async () => {
    const genomeBody = makeValidGenomeBody();
    const behavioralGenome = makeStubBehavioralGenome({
      latestForPassport: { jti_t: { claim_id: 'pc_prior', body_json: genomeBody } },
      diffResult: { max_z: 4.2, l2_norm: 5.1, per_dimension: { z_mean_latency_ms: 4.2 } },
    });
    const { redis } = makeStubRedis();
    const { deps, registered } = makeDeps({ behavioralGenome, redis });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'm6',
      passportJti: 'jti_t',
    });
    registered.length = 0; // clear open-claim from log
    await svc.complete(mission_id);
    expect(registered).toHaveLength(1);
    const completePayload = registered[0]!.payload as MissionClaim;
    expect(completePayload.behavioral_diff).toEqual({
      max_z: 4.2,
      l2_norm: 5.1,
      per_dimension: { z_mean_latency_ms: 4.2 },
    });
  });

  it('M7: complete() with baseline that fails schema parse skips diff (sets null)', async () => {
    // baseline_profile is non-null but NOT a valid BehavioralGenomeClaim
    const behavioralGenome = makeStubBehavioralGenome({
      // latestForPassport returns null so open() preserves the legacy
      // input.baseline_profile (which is junk for this test)
      latestForPassport: { jti_bad: null },
      diffResult: { max_z: 99, l2_norm: 99, per_dimension: {} },
    });
    const { redis } = makeStubRedis();
    const { deps, registered } = makeDeps({ behavioralGenome, redis });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'm7',
      passportJti: 'jti_bad',
      baseline_profile: { junk: 'not a genome' },
    });
    registered.length = 0;
    await svc.complete(mission_id);
    const completePayload = registered[0]!.payload as MissionClaim;
    expect(completePayload.behavioral_diff).toBeNull();
  });

  it('M8: complete() with no baseline_profile returns null diff', async () => {
    const behavioralGenome = makeStubBehavioralGenome({
      latestForPassport: { jti_t: null },
      diffResult: { max_z: 5, l2_norm: 5, per_dimension: {} },
    });
    const { redis } = makeStubRedis();
    const { deps, registered } = makeDeps({ behavioralGenome, redis });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'm8',
      passportJti: 'jti_t',
    });
    registered.length = 0;
    await svc.complete(mission_id);
    const completePayload = registered[0]!.payload as MissionClaim;
    expect(completePayload.behavioral_diff).toBeNull();
  });

  it('M9: complete() still succeeds when computeMissionWindowGenome throws', async () => {
    const genomeBody = makeValidGenomeBody();
    const behavioralGenome = makeStubBehavioralGenome({
      latestForPassport: { jti_t: { claim_id: 'pc_prior', body_json: genomeBody } },
      throwOnMissionWindow: true,
    });
    const { redis } = makeStubRedis();
    const { deps, registered } = makeDeps({ behavioralGenome, redis });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({
      operatorId: 'op_t',
      intent_summary: 'm9',
      passportJti: 'jti_t',
    });
    registered.length = 0;
    const result = await svc.complete(mission_id);
    expect(result.terminal_state).toBe('completed_successful');
    const completePayload = registered[0]!.payload as MissionClaim;
    expect(completePayload.behavioral_diff).toBeNull();
  });
});

// Smoke-test the MissionClaim type stays imported (referenced for type-only purposes).
const _missionClaimPlaceholder: Partial<MissionClaim> = { type: 'mission' };
void _missionClaimPlaceholder;

// ─── resolveTwinPolicy pure helper ────────────────────

import { resolveTwinPolicy, type TwinPolicyEnum } from './mission-service.js';

describe('resolveTwinPolicy', () => {
  const NO_CAPS = { coverage_cap_cents: null, cap_behavior: {} };

  it('M-twin-1: always → true', () => {
    expect(resolveTwinPolicy({ policy: 'always', mission: NO_CAPS })).toBe(true);
  });

  it('M-twin-2: never → false', () => {
    expect(resolveTwinPolicy({ policy: 'never', mission: NO_CAPS })).toBe(false);
  });

  it('M-twin-3: per_mission without explicit → false', () => {
    expect(resolveTwinPolicy({ policy: 'per_mission', mission: NO_CAPS })).toBe(false);
  });

  it('M-twin-4: per_mission + explicitRunTwin=true → true', () => {
    expect(
      resolveTwinPolicy({ policy: 'per_mission', explicitRunTwin: true, mission: NO_CAPS }),
    ).toBe(true);
  });

  it('M-twin-5: high_stakes_only + coverage_cap_cents non-null → true', () => {
    expect(
      resolveTwinPolicy({
        policy: 'high_stakes_only',
        mission: { coverage_cap_cents: 10_000, cap_behavior: {} },
      }),
    ).toBe(true);
  });

  it('M-twin-6: high_stakes_only + any cap_behavior=end_mission → true', () => {
    expect(
      resolveTwinPolicy({
        policy: 'high_stakes_only',
        mission: { coverage_cap_cents: null, cap_behavior: { max_actions: 'end_mission' } },
      }),
    ).toBe(true);
  });

  it('M-twin-7: high_stakes_only + zero caps + no end_mission → false', () => {
    expect(
      resolveTwinPolicy({
        policy: 'high_stakes_only',
        mission: { coverage_cap_cents: null, cap_behavior: { max_actions: 'refuse_action' } },
      }),
    ).toBe(false);
  });

  it('M-twin-8: explicit run_twin=false overrides any policy', () => {
    const policies: TwinPolicyEnum[] = ['always', 'high_stakes_only', 'per_mission'];
    for (const policy of policies) {
      expect(
        resolveTwinPolicy({
          policy,
          explicitRunTwin: false,
          mission: { coverage_cap_cents: 10_000, cap_behavior: { x: 'end_mission' } },
        }),
      ).toBe(false);
    }
  });
});

// ─── MissionService.open twin-firing integration ──────

describe('MissionService.open — twin firing', () => {
  function makeTwinStub(opts?: { throwOnStart?: Error }) {
    const startCalls: Array<{ missionId: string; realPassportJti: string }> = [];
    return {
      startCalls,
      async startTwinForMission(input: { missionId: string; realPassportJti: string }) {
        startCalls.push(input);
        if (opts?.throwOnStart) throw opts.throwOnStart;
        return { twinPassportJti: 'pas_twin', twinRunId: 'twr_test' };
      },
    };
  }

  function makeAgentRepoStub(twin_policy: TwinPolicyEnum | null = 'per_mission') {
    return {
      async findById(id: string) {
        return { id, twin_policy };
      },
    };
  }

  function makePassportRepoStub() {
    return {
      async findByJti(jti: string) {
        return { jti, agent_id: 'agt_test' };
      },
    };
  }

  function makeMissionRepoStub() {
    const rows: Array<Record<string, unknown>> = [];
    return {
      rows,
      async createWithClaim(input: Record<string, unknown>, signAndPersist: Parameters<MissionRepository['createWithClaim']>[1]) {
        const claim_id = await signAndPersist({ insert: async () => { throw new Error('The claim fixture does not invoke persistence'); } });
        const row = { ...input, claim_id };
        rows.push(row);
        return row;
      },
      async insert(input: Record<string, unknown>) { rows.push(input); },
    };
  }
  function makeClaimRegistryStub() {
    const calls: Array<Record<string, unknown>> = [];
    return {
      calls,
      async registerClaim(input: Record<string, unknown>) {
        calls.push(input);
        return { claimId: `pc_mission_${calls.length}`, envelopeCose: 'fake', subject: 'stack://x' };
      },
    };
  }

  function baseDeps(overrides: Partial<Record<string, unknown>> = {}) {
    return {
      repo: makeMissionRepoStub() as never,
      claimRegistry: makeClaimRegistryStub() as never,
      ...overrides,
    } as never;
  }

  it('M-twin-9: open() fires startTwinForMission when policy=always + passportJti provided', async () => {
    const twin = makeTwinStub();
    const svc = new MissionService(baseDeps({
      agentRepo: makeAgentRepoStub('always'),
      passportRepo: makePassportRepoStub(),
      twinOrchestration: twin,
    }));
    await svc.open({
      operatorId: 'op_x',
      intent_summary: 'Test',
      passportJti: 'pas_real',
    });
    expect(twin.startCalls).toHaveLength(1);
    expect(twin.startCalls[0]!.realPassportJti).toBe('pas_real');
    expect(twin.startCalls[0]!.missionId).toMatch(/^ms_/);
  });

  it('M-twin-10: open() skips twin when passportJti absent', async () => {
    const twin = makeTwinStub();
    const svc = new MissionService(baseDeps({
      agentRepo: makeAgentRepoStub('always'),
      passportRepo: makePassportRepoStub(),
      twinOrchestration: twin,
    }));
    await svc.open({ operatorId: 'op_x', intent_summary: 'No passport' });
    expect(twin.startCalls).toHaveLength(0);
  });

  it('M-twin-11: open() best-effort — twin failure does NOT fail mission', async () => {
    const twin = makeTwinStub({ throwOnStart: new Error('twin issuance kaboom') });
    const svc = new MissionService(baseDeps({
      agentRepo: makeAgentRepoStub('always'),
      passportRepo: makePassportRepoStub(),
      twinOrchestration: twin,
    }));
    const result = await svc.open({
      operatorId: 'op_x',
      intent_summary: 'Twin will fail',
      passportJti: 'pas_real',
    });
    expect(result.mission_id).toMatch(/^ms_/);
    expect(result.claim_id).toMatch(/^pc_mission_/);
    expect(twin.startCalls).toHaveLength(1);
  });

  it('M-twin-12: per-mission run_twin=true overrides policy=never', async () => {
    const twin = makeTwinStub();
    const svc = new MissionService(baseDeps({
      agentRepo: makeAgentRepoStub('never'),
      passportRepo: makePassportRepoStub(),
      twinOrchestration: twin,
    }));
    await svc.open({
      operatorId: 'op_x',
      intent_summary: 'Override never',
      passportJti: 'pas_real',
      run_twin: true,
    });
    expect(twin.startCalls).toHaveLength(1);
  });

  it('M-twin-13: skips twin cleanly when twinOrchestration dep is unset (back-compat)', async () => {
    const svc = new MissionService(baseDeps({
      agentRepo: makeAgentRepoStub('always'),
      passportRepo: makePassportRepoStub(),
      // twinOrchestration intentionally omitted
    }));
    await expect(svc.open({
      operatorId: 'op_x',
      intent_summary: 'Back compat',
      passportJti: 'pas_real',
    })).resolves.toBeDefined();
  });
});

// ─── MissionService.complete/revoke twin eval wiring ───

describe('MissionService.complete/revoke — twin divergence eval', () => {
  function makeTwinEvalStub(opts?: { throwOnEval?: Error }) {
    const evalCalls: Array<{ missionId: string; operatorId: string }> = [];
    return {
      evalCalls,
      async startTwinForMission(_input: { missionId: string; realPassportJti: string }) {
        return { twinPassportJti: 'pas_twin', twinRunId: 'twr_x' };
      },
      async evaluateDivergence(input: { missionId: string; operatorId: string }) {
        evalCalls.push(input);
        if (opts?.throwOnEval) throw opts.throwOnEval;
        return { divergenceClaimId: 'pc_div_x' };
      },
    };
  }

  it('M-twin-eval-1: complete() fires evaluateDivergence once with correct mission/operator', async () => {
    const twin = makeTwinEvalStub();
    const { deps } = makeDeps({ twinOrchestration: twin as never });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_eval', intent_summary: 'x' });
    await svc.complete(mission_id);
    // wait a tick for the fire-and-forget catch chain
    await new Promise((r) => setImmediate(r));
    expect(twin.evalCalls).toHaveLength(1);
    expect(twin.evalCalls[0]!.missionId).toBe(mission_id);
    expect(twin.evalCalls[0]!.operatorId).toBe('op_eval');
  });

  it('M-twin-eval-2: complete() best-effort — evaluateDivergence throwing does NOT fail the mission', async () => {
    const twin = makeTwinEvalStub({ throwOnEval: new Error('eval kaboom') });
    const { deps } = makeDeps({ twinOrchestration: twin as never });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_eval', intent_summary: 'x' });
    // Should NOT throw — the eval is fire-and-forget.
    const result = await svc.complete(mission_id);
    expect(result.terminal_state).toBe('completed_successful');
    await new Promise((r) => setImmediate(r));
    expect(twin.evalCalls).toHaveLength(1);
  });

  it('M-twin-eval-3: revoke() fires evaluateDivergence once with correct mission/operator', async () => {
    const twin = makeTwinEvalStub();
    const { deps } = makeDeps({ twinOrchestration: twin as never });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_eval', intent_summary: 'x' });
    await svc.revoke(mission_id, { reason: 'adversarial' });
    await new Promise((r) => setImmediate(r));
    expect(twin.evalCalls).toHaveLength(1);
    expect(twin.evalCalls[0]!.missionId).toBe(mission_id);
    expect(twin.evalCalls[0]!.operatorId).toBe('op_eval');
  });

  it('M-twin-eval-4: revoke() best-effort — evaluateDivergence throwing does NOT fail the revoke', async () => {
    const twin = makeTwinEvalStub({ throwOnEval: new Error('eval kaboom') });
    const { deps } = makeDeps({ twinOrchestration: twin as never });
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_eval', intent_summary: 'x' });
    const result = await svc.revoke(mission_id, { reason: 'operator_initiated_clean' });
    expect(result.terminal_state).toBe('revoked_operator_clean');
    await new Promise((r) => setImmediate(r));
    expect(twin.evalCalls).toHaveLength(1);
  });

  it('M-twin-eval-5: complete() with twinOrchestration unset is a clean no-op (back-compat)', async () => {
    const { deps } = makeDeps(); // no twinOrchestration
    const svc = new MissionService(deps);
    const { mission_id } = await svc.open({ operatorId: 'op_eval', intent_summary: 'x' });
    const result = await svc.complete(mission_id);
    expect(result.terminal_state).toBe('completed_successful');
  });
});
