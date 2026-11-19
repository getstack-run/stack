import { describe, expect, it, vi } from 'vitest';
import { CONTROL_SECRET_ROTATION_GRACE_MS, type ControlSocketRow } from '@stack/shared';
import {
  CONTROL_BAD_ANSWER_PAUSE,
  CONTROL_SOCKET_CACHE_TTL_MS,
  ControlSocketService,
  effectiveDecider,
} from './control-socket-service.js';

const OP = 'op_1';

class MemoryRepo {
  row: ControlSocketRow | null = null;
  reads = 0;
  badAnswers = 0;
  async get() {
    this.reads += 1;
    return this.row;
  }
  async getOrCreate(operatorId: string) {
    this.row ??= {
      operator_id: operatorId, socket_id: 'csk_1', decision_mode: 'auto', decision_url: null, decision_candidate_url: null,
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
  async countBadAnswer(_operatorId: string, good: boolean) {
    this.badAnswers = good ? 0 : this.badAnswers + 1;
    return this.badAnswers;
  }
  async outboxCounts() {
    return { pending: 0, dead: 0 };
  }
}

const kms = {
  encrypt: async (plaintext: string, ctx: Record<string, string>) => ({ ciphertext: Buffer.from(JSON.stringify({ p: plaintext, ctx })).toString('base64') }),
  decrypt: async (ciphertext: string, ctx: Record<string, string>) => {
    const parsed = JSON.parse(Buffer.from(ciphertext, 'base64').toString()) as { p: string; ctx: Record<string, string> };
    if (JSON.stringify(parsed.ctx) !== JSON.stringify(ctx)) throw new Error('context mismatch');
    return parsed.p;
  },
};

function make(over: { publish?: (operatorId: string) => Promise<void> } = {}) {
  const repo = new MemoryRepo();
  let clock = 1_000_000_000_000;
  const service = new ControlSocketService({
    repo: repo as never, kms: kms as never, now: () => clock, ...(over.publish ? { publishInvalidation: over.publish } : {}),
  });
  return { repo, service, advance: (ms: number) => { clock += ms; } };
}

describe('ControlSocketService', () => {
  it('a customer with no socket row has no controls chosen and every kind checked', async () => {
    const { service } = make();
    await expect(service.runtime(OP)).resolves.toMatchObject({ socketId: null, modeSetting: 'auto', decisionUrl: null, checkedTypes: null });
    await expect(service.secrets(OP, 'decision')).resolves.toBeNull();
    expect(await service.view(OP, false)).toMatchObject({
      socket_id: null, mode_setting: 'auto', effective_mode: 'none', checks_all_types: true, decision: { secret_set: false },
    });
  });

  it('caches the runtime view for 30 seconds and drops it on any write, telling the other machines', async () => {
    const publish = vi.fn(async () => {});
    const { repo, service, advance } = make({ publish });
    await service.setMode(OP, 'none');
    repo.reads = 0;
    await service.runtime(OP);
    await service.runtime(OP);
    expect(repo.reads).toBe(1);
    advance(CONTROL_SOCKET_CACHE_TTL_MS + 1);
    await service.runtime(OP);
    expect(repo.reads).toBe(2);

    await service.setCheckedTypes(OP, ['email.send']);
    expect(publish).toHaveBeenLastCalledWith(OP);
    expect((await service.runtime(OP)).checkedTypes).toEqual(new Set(['email.send']));
  });

  it('a failed invalidation message never fails the write: the others expire on their own', async () => {
    const { service } = make({ publish: async () => { throw new Error('redis down'); } });
    await expect(service.setMode(OP, 'hosted')).resolves.toBeUndefined();
    expect((await service.runtime(OP)).modeSetting).toBe('hosted');
  });

  it('tells components that cache something derived from the socket', async () => {
    const { service } = make();
    const heard = vi.fn();
    service.onInvalidate(heard);
    await service.setEventsAddress(OP, 'https://logs.example/x');
    expect(heard).toHaveBeenCalledWith(OP);
    service.invalidateLocal('op_other');
    expect(heard).toHaveBeenCalledWith('op_other');
  });

  it('keeps a changed address as a candidate while the socket enforces, and promotes it only on activation', async () => {
    const { repo, service } = make();
    await service.setDecisionAddress(OP, { url: 'https://a.example/d', timeoutMs: 800 });
    expect(await service.addressToVerify(OP)).toEqual({ url: 'https://a.example/d', timeoutMs: 800 });
    await service.activateDecision(OP);
    expect(repo.row).toMatchObject({ decision_mode: 'remote', decision_status: 'enforcing', decision_url: 'https://a.example/d', decision_bad_answers: 0 });

    const changed = await service.setDecisionAddress(OP, { url: 'https://b.example/d', timeoutMs: 500 });
    expect(changed.secret).toBeNull();
    expect(repo.row).toMatchObject({ decision_url: 'https://a.example/d', decision_candidate_url: 'https://b.example/d', decision_status: 'enforcing' });
    expect(await service.addressToVerify(OP)).toEqual({ url: 'https://b.example/d', timeoutMs: 500 });
    expect((await service.runtime(OP)).decisionUrl).toBe('https://a.example/d');

    await service.activateDecision(OP);
    expect(repo.row).toMatchObject({ decision_url: 'https://b.example/d', decision_candidate_url: null, decision_timeout_ms: 500 });
  });

  it('clearing an address ends a remote socket back to the automatic choice, and forgets the secret', async () => {
    const { repo, service } = make();
    const { secret } = await service.setDecisionAddress(OP, { url: 'https://a.example/d' });
    expect(secret).toMatch(/^whsec_/);
    await service.activateDecision(OP);
    await service.clearDecision(OP);
    expect(repo.row).toMatchObject({ decision_mode: 'auto', decision_url: null, decision_secret_encrypted: null, decision_status: 'unverified' });
    await service.setMode(OP, 'none');
    await service.clearDecision(OP);
    expect(repo.row!.decision_mode).toBe('none');
  });

  it('leaving a remote socket for hosted or none leaves its address unverified', async () => {
    const { repo, service } = make();
    await service.setDecisionAddress(OP, { url: 'https://a.example/d' });
    await service.activateDecision(OP);
    await service.setMode(OP, 'hosted');
    expect(repo.row).toMatchObject({ decision_mode: 'hosted', decision_status: 'unverified', decision_verified_at: null });
  });

  it('pauses a decision address after fifty answers in a row that failed their signature, and a good one resets the count', async () => {
    const { repo, service } = make();
    await service.setDecisionAddress(OP, { url: 'https://a.example/d' });
    await service.activateDecision(OP);
    for (let n = 0; n < CONTROL_BAD_ANSWER_PAUSE - 1; n += 1) await service.noteAnswer(OP, false);
    expect(repo.row!.decision_status).toBe('enforcing');
    await service.noteAnswer(OP, true);
    for (let n = 0; n < CONTROL_BAD_ANSWER_PAUSE - 1; n += 1) await service.noteAnswer(OP, false);
    expect(repo.row!.decision_status).toBe('enforcing');
    await service.noteAnswer(OP, false);
    expect(repo.row!.decision_status).toBe('paused');
    expect((await service.runtime(OP)).decisionStatus).toBe('paused');
  });

  it('keeps the previous secret live for 24 hours after a rotation, then only the new one', async () => {
    const { service, advance } = make();
    const { secret: first } = await service.setDecisionAddress(OP, { url: 'https://a.example/d' });
    const rotated = await service.rotateSecret(OP, 'decision');
    expect(await service.secrets(OP, 'decision')).toEqual([rotated.secret, first]);
    expect(rotated.previousValidUntil.getTime()).toBe(1_000_000_000_000 + CONTROL_SECRET_ROTATION_GRACE_MS);
    advance(CONTROL_SECRET_ROTATION_GRACE_MS + 1);
    service.invalidateLocal(OP);
    expect(await service.secrets(OP, 'decision')).toEqual([rotated.secret]);
    await expect(service.rotateSecret(OP, 'events')).rejects.toThrow('No signing secret to rotate');
  });

  it('keeps the decision and the events secrets apart: neither unwraps under the other\'s purpose', async () => {
    const { repo, service } = make();
    await service.setDecisionAddress(OP, { url: 'https://a.example/d' });
    await service.setEventsAddress(OP, 'https://e.example/x');
    expect(repo.row!.decision_secret_encrypted).not.toBe(repo.row!.events_secret_encrypted);
    const decision = await service.secrets(OP, 'decision');
    const events = await service.secrets(OP, 'events');
    expect(decision![0]).not.toBe(events![0]);
    await expect(kms.decrypt(repo.row!.events_secret_encrypted!, { operator_id: OP, socket_id: 'csk_1', purpose: 'control_socket_decision' })).rejects.toThrow();
  });
});

describe('effectiveDecider', () => {
  it.each([
    ['auto', true, 'hosted'],
    ['auto', false, 'none'],
    ['hosted', true, 'hosted'],
    ['hosted', false, 'none'],
    ['none', true, 'none'],
    ['none', false, 'none'],
    ['remote', true, 'remote'],
    ['remote', false, 'remote'],
  ] as const)('%s with controls %s decides as %s', (setting, controls, expected) => {
    expect(effectiveDecider(setting, controls)).toBe(expected);
  });
});
