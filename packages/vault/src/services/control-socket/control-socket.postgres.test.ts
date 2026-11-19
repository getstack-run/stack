import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { eq, sql } from 'drizzle-orm';
import {
  AUDIT_CHAIN_GENESIS,
  CONTROL_EVENTS_BATCH_MAX_EVENTS,
  controlDecisions,
  controlEventOutbox,
  controlSockets,
  createDb,
  operators,
  signStandardWebhook,
  verifyStandardWebhook,
  type ControlEventsBatch,
  type Database,
} from '@stack/shared';
import { ControlSocketRepository } from '../../repositories/control-socket-repo.js';
import { resolveVaultFixtureDatabaseUrl } from '../../test/dedicated-test-database.js';
import { AuditService } from '../audit-service.js';
import { ControlSocketService } from './control-socket-service.js';
import { ControlEventsDelivery, ControlEventsSink } from './events-outbox.js';

/**
 * The customer's record against PostgreSQL: an event is written inside the
 * audit write's own transaction (gapless, in chain order, rolled back with it),
 * and delivered at least once, in order, signed, with retries, a dead-letter
 * state and a lease so two machines never post the same batch. Runs only on the
 * dedicated test database.
 */

const DATABASE_URL = resolveVaultFixtureDatabaseUrl();
const describeWithDb = DATABASE_URL ? describe : describe.skip;

/** A KMS that keeps nothing readable: it wraps the plaintext in a context-bound envelope. */
const kms = {
  encrypt: async (plaintext: string, ctx: Record<string, string>) => ({
    ciphertext: Buffer.from(JSON.stringify({ p: plaintext, ctx })).toString('base64'),
  }),
  decrypt: async (ciphertext: string, ctx: Record<string, string>) => {
    const parsed = JSON.parse(Buffer.from(ciphertext, 'base64').toString()) as { p: string; ctx: Record<string, string> };
    if (JSON.stringify(parsed.ctx) !== JSON.stringify(ctx)) throw new Error('context mismatch');
    return parsed.p;
  },
};

describeWithDb('the control socket in PostgreSQL', () => {
  const suffix = randomUUID().replaceAll('-', '').slice(0, 12);
  let db: Database;
  let repo: ControlSocketRepository;
  let sockets: ControlSocketService;
  let audit: AuditService;
  let sink: ControlEventsSink;
  const created: string[] = [];

  async function operator(label: string): Promise<string> {
    const id = `op_cs_${label}_${suffix}`;
    await db.insert(operators).values({ id, email: `${id}@test.invalid`, api_key_hash: `hash_${id}` });
    created.push(id);
    return id;
  }

  /** An operator whose events address is verified and delivering. */
  async function streaming(label: string): Promise<{ id: string; secrets: string[] }> {
    const id = await operator(label);
    await sockets.setEventsAddress(id, 'https://logs.customer.example/stack');
    await sockets.activateEvents(id);
    return { id, secrets: (await sockets.secrets(id, 'events'))! };
  }

  const ctx = (operatorId: string) => ({
    trace_id: `trace_${randomUUID()}`, span_id: `span_${randomUUID()}`, operator_id: operatorId, agent_id: 'system', passport_jti: 'none',
  });
  const writeAudit = (operatorId: string, action = 'test.action', extra: Partial<Parameters<AuditService['write']>[0]> = {}) =>
    audit.write({ ctx: ctx(operatorId), layer: 'system', action, outcome: 'success', ...extra });
  const outbox = (operatorId: string) =>
    db.select().from(controlEventOutbox).where(eq(controlEventOutbox.operator_id, operatorId)).orderBy(controlEventOutbox.seq);

  beforeAll(() => {
    db = createDb(DATABASE_URL!);
    repo = new ControlSocketRepository(db);
    sockets = new ControlSocketService({ repo, kms: kms as never });
    sink = new ControlEventsSink(repo, { negativeTtlMs: 0 });
    sockets.onInvalidate((id) => sink.forget(id));
    audit = new AuditService(db);
    audit.setOutboxSink((tx, row) => sink.write(tx, row));
  });

  afterAll(async () => {
    for (const id of created) {
      await db.delete(operators).where(eq(operators.id, id)).catch(() => undefined);
    }
    await (db as unknown as { $client: { end(o: { timeout: number }): Promise<void> } }).$client.end({ timeout: 5 });
  });

  describe('the outbox inside the audit write', () => {
    it('numbers events without a gap, in chain order, under concurrent writers, and the chain stays valid', async () => {
      const { id } = await streaming('chain');
      await Promise.all(Array.from({ length: 30 }, (_, n) => writeAudit(id, `test.concurrent.${n}`)));
      const rows = await outbox(id);
      expect(rows.map((r) => r.seq)).toEqual(Array.from({ length: 30 }, (_, n) => n + 1));
      const events = rows.map((r) => r.event as { chain: { entry_hash: string; prev_entry_hash: string }; type: string; id: string });
      expect(events[0]!.chain.prev_entry_hash).toBe(AUDIT_CHAIN_GENESIS);
      for (let n = 1; n < events.length; n += 1) {
        expect(events[n]!.chain.prev_entry_hash).toBe(events[n - 1]!.chain.entry_hash);
      }
      expect((await audit.verifyChain(id)).valid).toBe(true);
      // What an event carries: public fields of the audit row, never an error message or a payload.
      expect(Object.keys(events[0]!).sort()).toEqual([
        'account_id', 'agent_id', 'amount_cents', 'chain', 'decision_id', 'error_code', 'id', 'layer', 'occurred_at',
        'operator_id', 'outcome', 'seq', 'type',
      ]);
    });

    it('carries the decision and account a writer names, outside the hash, and no error message', async () => {
      const { id } = await streaming('details');
      await writeAudit(id, 'control.decision.deny', {
        outcome: 'blocked', error: { code: 'CONTROL_DENIED', message: 'private reason text' },
        event_details: { decision_id: 'dec_abc', account_id: 'acct_1', amount_cents: 12 },
      });
      const [row] = await outbox(id);
      expect(row!.event).toMatchObject({
        type: 'control.decision.deny', outcome: 'blocked', error_code: 'CONTROL_DENIED', decision_id: 'dec_abc', account_id: 'acct_1', amount_cents: 12,
      });
      expect(JSON.stringify(row!.event)).not.toContain('private reason text');
      expect((await audit.verifyChain(id)).valid).toBe(true);
    });

    it('writes nothing for a customer with no events address, or one not yet verified, and costs the audit write nothing', async () => {
      const none = await operator('none');
      const unverified = await operator('unverified');
      await sockets.setEventsAddress(unverified, 'https://logs.customer.example/stack');
      await writeAudit(none);
      await writeAudit(none);
      await writeAudit(unverified);
      expect(await outbox(none)).toEqual([]);
      expect(await outbox(unverified)).toEqual([]);
      const [socket] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, unverified));
      expect(socket!.events_last_seq).toBe(0);
    });

    it('streams nothing for a customer without controls, or whose controls cannot be read, and the audit row is still written', async () => {
      const off = await streaming('controls-off');
      const unreadable = await streaming('controls-unreadable');
      const on = await streaming('controls-on');
      const gated = new ControlEventsSink(repo, {
        negativeTtlMs: 0,
        controlsEnabled: async (operatorId) => {
          if (operatorId === unreadable.id) throw new Error('billing account unreadable');
          return operatorId === on.id;
        },
      });
      const gatedAudit = new AuditService(db);
      gatedAudit.setOutboxSink((tx, row) => gated.write(tx, row));
      for (const id of [off.id, unreadable.id, on.id]) {
        await gatedAudit.write({ ctx: ctx(id), layer: 'system', action: 'test.gated', outcome: 'success' });
      }
      expect(await outbox(off.id)).toEqual([]);
      expect(await outbox(unreadable.id)).toEqual([]);
      expect((await outbox(on.id)).map((row) => (row.event as { type: string }).type)).toEqual(['test.gated']);
      // The record itself is kept for every account: reading it is what controls decide.
      const kept = await gatedAudit.verifyChain(off.id);
      expect(kept.total_checked).toBeGreaterThan(0);
      expect(kept.valid).toBe(true);
    });

    it("streams for a customer whose own server decides, without controls; hosted without controls still streams nothing", async () => {
      const remote = await streaming('remote-no-controls');
      const hosted = await streaming('hosted-no-controls');
      const remoteWithControls = await streaming('remote-with-controls');
      const gated = new ControlEventsSink(repo, {
        negativeTtlMs: 0,
        controlsEnabled: async (operatorId) => operatorId === remoteWithControls.id,
        decidesRemotely: async (operatorId) => operatorId === remote.id || operatorId === remoteWithControls.id,
      });
      const gatedAudit = new AuditService(db);
      gatedAudit.setOutboxSink((tx, row) => gated.write(tx, row));
      for (const id of [remote.id, hosted.id, remoteWithControls.id]) {
        await gatedAudit.write({ ctx: ctx(id), layer: 'system', action: 'test.remote', outcome: 'success' });
      }
      expect((await outbox(remote.id)).map((row) => (row.event as { type: string }).type)).toEqual(['test.remote']);
      expect((await outbox(remoteWithControls.id)).map((row) => (row.event as { type: string }).type)).toEqual(['test.remote']);
      expect(await outbox(hosted.id)).toEqual([]);
    });

    it('streams nothing when it cannot be read whether the customer\'s own server decides', async () => {
      const unreadable = await streaming('remote-unreadable');
      const gated = new ControlEventsSink(repo, {
        negativeTtlMs: 0,
        controlsEnabled: async () => false,
        decidesRemotely: async () => { throw new Error('socket unreadable'); },
      });
      const gatedAudit = new AuditService(db);
      gatedAudit.setOutboxSink((tx, row) => gated.write(tx, row));
      const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      await expect(gatedAudit.write({ ctx: ctx(unreadable.id), layer: 'system', action: 'test.unreadable', outcome: 'success' })).resolves.toMatch(/^aud_/);
      error.mockRestore();
      expect(await outbox(unreadable.id)).toEqual([]);
    });

    it('commits or rolls back with the audit row, and a rollback does not consume a sequence number', async () => {
      const { id } = await streaming('rollback');
      await writeAudit(id);
      await expect(db.transaction(async (tx) => {
        await audit.write({ ctx: ctx(id), layer: 'system', action: 'test.rolled_back', outcome: 'success' }, tx);
        throw new Error('caller rolls back');
      })).rejects.toThrow('caller rolls back');
      await writeAudit(id);
      expect((await outbox(id)).map((r) => r.seq)).toEqual([1, 2]);
      expect((await outbox(id)).map((r) => (r.event as { type: string }).type)).not.toContain('test.rolled_back');
    });

    it('a failing outbox insert never fails the audit write, and leaves the sequence untouched', async () => {
      const { id } = await streaming('isolated');
      await writeAudit(id);
      // Make the next insert collide with an existing outbox row.
      await db.update(controlSockets).set({ events_last_seq: 0, events_acked_seq: 0 }).where(eq(controlSockets.operator_id, id));
      const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      await expect(writeAudit(id, 'test.survives')).resolves.toMatch(/^aud_/);
      error.mockRestore();
      const [socket] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id));
      expect(socket!.events_last_seq).toBe(0);
      expect((await audit.verifyChain(id)).valid).toBe(true);
      expect((await audit.verifyChain(id)).total_checked).toBe(2);
    });
  });

  describe('delivery', () => {
    function receiver(secrets: string[], script: Array<number | 'throw' | 'hang'> = []) {
      const received: Array<{ batch: ControlEventsBatch; signatureOk: boolean; batchId: string }> = [];
      const calls: string[] = [];
      let n = 0;
      const fetchFn = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        const body = String(init!.body);
        const headers = init!.headers as Record<string, string>;
        const verified = verifyStandardWebhook({ headers, body, secrets, toleranceSeconds: 300 });
        received.push({ batch: JSON.parse(body) as ControlEventsBatch, signatureOk: verified.ok, batchId: headers['webhook-id']! });
        const step = script[n] ?? 200;
        n += 1;
        calls.push(String(step));
        if (step === 'throw') throw new TypeError('fetch failed');
        return new Response('{}', { status: step === 'hang' ? 200 : step });
      });
      return { fetchFn, received, calls };
    }
    const delivery = (fetchFn: typeof fetch, over: Partial<ConstructorParameters<typeof ControlEventsDelivery>[0]> = {}) =>
      new ControlEventsDelivery({ repo, sockets, fetchFn, urlGuard: async () => {}, ...over });
    const due = (id: string) => db.update(controlSockets).set({ events_next_attempt_at: null }).where(eq(controlSockets.operator_id, id));

    it('posts signed batches of at most 100 events, in order, and deletes what was acknowledged', async () => {
      const { id, secrets } = await streaming('batches');
      for (let n = 0; n < 130; n += 1) await writeAudit(id, `test.event.${n}`);
      const r = receiver(secrets);
      const d = delivery(r.fetchFn as never);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ claimed: 1, delivered: 1 });
      await due(id);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ claimed: 1, delivered: 1 });
      expect(r.received.map((x) => x.batch.events.length)).toEqual([CONTROL_EVENTS_BATCH_MAX_EVENTS, 30]);
      expect(r.received.every((x) => x.signatureOk && x.batch.type === 'stack.events.batch' && !x.batch.test && x.batch.operator_id === id)).toBe(true);
      expect(r.received.flatMap((x) => x.batch.events.map((e) => e.seq))).toEqual(Array.from({ length: 130 }, (_, n) => n + 1));
      expect(await outbox(id)).toEqual([]);
      const [socket] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id));
      expect(socket).toMatchObject({ events_acked_seq: 130, events_attempts: 0, events_last_error: null });
      // Nothing left: an idle socket is not claimed again.
      expect((await d.deliverDue(25, { operatorId: id })).claimed).toBe(0);
    });

    it('is at least once: a failed batch is retried with its same events under a new batch id, after a backoff', async () => {
      const { id, secrets } = await streaming('retry');
      for (let n = 0; n < 3; n += 1) await writeAudit(id, `test.retry.${n}`);
      const r = receiver(secrets, [503, 'throw', 200]);
      const d = delivery(r.fetchFn as never);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ retrying: 1 });
      const [afterFirst] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id));
      expect(afterFirst).toMatchObject({ events_attempts: 1, events_last_error: 'http_503', events_status: 'active' });
      expect(afterFirst!.events_next_attempt_at!.getTime()).toBeGreaterThan(Date.now());
      // Backing off: not claimed again until its time.
      expect((await d.deliverDue(25, { operatorId: id })).claimed).toBe(0);
      expect(r.fetchFn).toHaveBeenCalledTimes(1);

      await due(id);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ retrying: 1 });
      await due(id);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ delivered: 1 });
      const ids = r.received.map((x) => x.batch.events.map((e) => e.id));
      expect(ids[1]).toEqual(ids[0]);
      expect(ids[2]).toEqual(ids[0]);
      expect(new Set(r.received.map((x) => x.batchId)).size).toBe(3);
      expect(await outbox(id)).toEqual([]);
    });

    it('two machines never post the same batch: one claims the socket, the other finds it leased', async () => {
      const { id, secrets } = await streaming('lease');
      await writeAudit(id);
      const r = receiver(secrets, ['hang']);
      const slow = vi.fn(async (...args: Parameters<typeof fetch>) => {
        await new Promise((resolve) => setTimeout(resolve, 150));
        return r.fetchFn(...args);
      });
      const a = delivery(slow as never);
      const b = delivery(r.fetchFn as never);
      const [first, second] = await Promise.all([a.deliverDue(25, { operatorId: id }), b.deliverDue(25, { operatorId: id })]);
      expect(first.claimed + second.claimed).toBe(1);
      expect(r.received).toHaveLength(1);
    });

    it('turns a batch the customer\'s server refuses three times into a dead letter, announced once by a gap marker, and carries on', async () => {
      const { id, secrets } = await streaming('dead');
      for (let n = 0; n < 4; n += 1) await writeAudit(id, `test.dead.${n}`);
      const r = receiver(secrets, [400, 400, 400]);
      const d = delivery(r.fetchFn as never);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ retrying: 1 });
      await due(id);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ retrying: 1 });
      await due(id);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ deadLettered: 1 });
      expect((await outbox(id)).map((row) => [row.status, row.gap_announced])).toEqual([['dead', false], ['dead', false], ['dead', false], ['dead', false]]);

      // A later event, then the next delivery announces the lost range first.
      await writeAudit(id, 'test.after_dead');
      await due(id);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ delivered: 1 });
      const last = r.received.at(-1)!.batch;
      expect(last.events.map((e) => ({ type: e.type, gap: e.gap ?? null }))).toEqual([
        { type: 'stack.events.gap', gap: { from_seq: 1, to_seq: 4 } },
        { type: 'test.after_dead', gap: null },
      ]);
      const left = await outbox(id);
      expect(left.every((row) => row.status === 'dead' && row.gap_announced)).toBe(true);
      expect(left).toHaveLength(4);
    });

    it('never counts a 408, a 429 or a timeout as a refusal: it backs off, and after 72 hours delivery pauses as failing', async () => {
      const { id, secrets } = await streaming('failing');
      await writeAudit(id);
      const r = receiver(secrets, [429, 408, 'throw', 500]);
      const d = delivery(r.fetchFn as never);
      for (let n = 0; n < 3; n += 1) {
        expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ retrying: 1 });
        await due(id);
      }
      const [socket] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id));
      expect(socket).toMatchObject({ events_client_errors: 0, events_status: 'active', events_attempts: 3 });
      await db.update(controlSockets).set({ events_first_failure_at: sql`now() - interval '73 hours'` }).where(eq(controlSockets.operator_id, id));
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ failing: 1 });
      const [paused] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id));
      expect(paused!.events_status).toBe('failing');
      // Paused: not claimed again, and nothing more is stored for it (it still takes its numbers).
      await due(id);
      expect((await d.deliverDue(25, { operatorId: id })).claimed).toBe(0);
      await writeAudit(id, 'test.while_failing');
      expect((await outbox(id)).length).toBe(1);
      const [skipped] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id));
      expect(Number(skipped!.events_last_seq)).toBe(2);
    });

    /** Drive a socket into `failing` the way delivery does: 72 hours of failures. */
    async function pause(id: string, secrets: string[], onFailing?: (operatorId: string) => Promise<void>) {
      const r = receiver(secrets, [500, 500, 500]);
      const d = delivery(r.fetchFn as never, onFailing ? { onFailing } : {});
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ retrying: 1 });
      await db.update(controlSockets).set({ events_first_failure_at: sql`now() - interval '73 hours'` }).where(eq(controlSockets.operator_id, id));
      await due(id);
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ failing: 1 });
      return d;
    }

    it('a paused address stores nothing more, so the outbox stops growing however long the outage lasts', async () => {
      const { id, secrets } = await streaming('nogrow');
      await writeAudit(id);
      await pause(id, secrets);
      for (let n = 0; n < 25; n += 1) await writeAudit(id, `test.outage.${n}`);
      expect(await outbox(id)).toHaveLength(1);
    });

    it('verifying a paused address again announces what it skipped with one gap marker, and delivery carries on in order', async () => {
      const { id, secrets } = await streaming('regap');
      await writeAudit(id, 'test.before');
      await pause(id, secrets);
      for (let n = 0; n < 3; n += 1) await writeAudit(id, `test.outage.${n}`);
      await sockets.activateEvents(id);
      await writeAudit(id, 'test.after');
      const r = receiver(secrets);
      await due(id);
      expect(await delivery(r.fetchFn as never).deliverDue(25, { operatorId: id })).toMatchObject({ delivered: 1 });
      expect(r.received.at(-1)!.batch.events.map((e) => ({ type: e.type, seq: e.seq, gap: e.gap ?? null }))).toEqual([
        { type: 'test.before', seq: 1, gap: null },
        { type: 'stack.events.gap', seq: 4, gap: { from_seq: 2, to_seq: 4 } },
        { type: 'test.after', seq: 5, gap: null },
      ]);
    });

    it('verifying an address that skipped nothing adds no gap marker', async () => {
      const { id } = await streaming('nogap');
      await writeAudit(id);
      await sockets.activateEvents(id);
      expect(await outbox(id)).toHaveLength(1);
    });

    it('retention runs for a paused address that is never claimed, and folds its dead events into one row', async () => {
      const { id, secrets } = await streaming('retain');
      for (let n = 0; n < 5; n += 1) await writeAudit(id, `test.held.${n}`);
      const d = await pause(id, secrets);
      await db.update(controlEventOutbox).set({ created_at: sql`now() - interval '8 days'` }).where(eq(controlEventOutbox.operator_id, id));
      expect(await d.sweep()).toMatchObject({ expired: 5, folded: 4 });
      const kept = await outbox(id);
      expect(kept).toHaveLength(1);
      expect(kept[0]).toMatchObject({ status: 'dead', gap_announced: false, seq: 5, event: { gap: { from_seq: 1, to_seq: 5 } } });
      // Nothing left to expire or fold, and verifying again announces the one range once.
      expect(await d.sweep()).toEqual({ expired: 0, folded: 0 });
      await sockets.activateEvents(id);
      expect(await outbox(id)).toHaveLength(1);
      const r = receiver(secrets);
      await due(id);
      await delivery(r.fetchFn as never).deliverDue(25, { operatorId: id });
      expect(r.received.at(-1)!.batch.events).toEqual([expect.objectContaining({ type: 'stack.events.gap', gap: { from_seq: 1, to_seq: 5 } })]);
    });

    it('never folds the dead events of a socket that is being delivered, nor a range with a pending event inside it', async () => {
      const { id } = await streaming('livefold');
      for (let n = 0; n < 3; n += 1) await writeAudit(id, `test.live.${n}`);
      await db.update(controlEventOutbox).set({ status: 'dead' }).where(eq(controlEventOutbox.operator_id, id));
      const d = delivery(receiver([]).fetchFn as never);
      expect(await d.sweep()).toMatchObject({ folded: 0 });
      expect(await outbox(id)).toHaveLength(3);
      // Paused, but a pending event sits between dead ones: left as it is.
      await db.update(controlEventOutbox).set({ status: 'pending' }).where(sql`${controlEventOutbox.operator_id} = ${id} AND ${controlEventOutbox.seq} = 2`);
      await db.update(controlSockets).set({ events_status: 'failing' }).where(eq(controlSockets.operator_id, id));
      expect(await d.sweep()).toMatchObject({ folded: 0 });
      expect(await outbox(id)).toHaveLength(3);
    });

    it('tells the owner once when delivery pauses, and a failing notice never breaks delivery', async () => {
      const { id, secrets } = await streaming('alert');
      await writeAudit(id);
      const told: string[] = [];
      await pause(id, secrets, async (operatorId) => { told.push(operatorId); });
      expect(told).toEqual([id]);
      const quiet = await streaming('alertbroken');
      await writeAudit(quiet.id);
      await pause(quiet.id, quiet.secrets, async () => { throw new Error('notification service down'); });
      const [socket] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, quiet.id));
      expect(socket!.events_status).toBe('failing');
    });

    it('clearing the events address leaves nothing in the outbox', async () => {
      const { id } = await streaming('cleared');
      await writeAudit(id);
      await writeAudit(id);
      await sockets.clearEvents(id);
      expect(await outbox(id)).toEqual([]);
    });

    it('guards the address at the moment of every delivery: an address that now points inside gets nothing', async () => {
      const { id, secrets } = await streaming('guard');
      await writeAudit(id);
      const r = receiver(secrets);
      const d = delivery(r.fetchFn as never, { urlGuard: async () => { throw new Error('non-public address'); } });
      expect(await d.deliverDue(25, { operatorId: id })).toMatchObject({ retrying: 1 });
      expect(r.fetchFn).not.toHaveBeenCalled();
      const [socket] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id));
      expect(socket!.events_last_error).toBe('unsafe_address');
    });

    it('events held longer than a week turn into a gap rather than being kept forever', async () => {
      const { id, secrets } = await streaming('stale');
      await writeAudit(id);
      await writeAudit(id);
      await db.update(controlEventOutbox).set({ created_at: sql`now() - interval '8 days'` }).where(eq(controlEventOutbox.operator_id, id));
      const r = receiver(secrets);
      await delivery(r.fetchFn as never).deliverDue(25, { operatorId: id });
      expect(r.received[0]!.batch.events).toEqual([expect.objectContaining({ type: 'stack.events.gap', gap: { from_seq: 1, to_seq: 2 } })]);
    });

    it('the setup check posts one signed empty test batch, and reports a refusal without changing anything', async () => {
      const { id, secrets } = await streaming('probe');
      const [socket] = await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id));
      const r = receiver(secrets, [200, 401]);
      const d = delivery(r.fetchFn as never);
      expect(await d.probe(id, socket!.socket_id, 'https://logs.customer.example/stack')).toMatchObject({ ok: true, cause: null });
      expect(r.received[0]!).toMatchObject({ signatureOk: true, batch: { test: true, events: [] } });
      expect(await d.probe(id, socket!.socket_id, 'https://logs.customer.example/stack')).toMatchObject({ ok: false, cause: 'http_status' });
      expect(await outbox(id)).toEqual([]);
    });

    it('signs with both secrets while a rotation is live, so a receiver on either accepts it', async () => {
      const { id, secrets } = await streaming('rotate');
      const rotated = await sockets.rotateSecret(id, 'events');
      await writeAudit(id);
      const live = (await sockets.secrets(id, 'events'))!;
      expect(live).toEqual([rotated.secret, secrets[0]]);
      let seen: Record<string, string> = {};
      const fetchFn = vi.fn(async (_u: string | URL | Request, init?: RequestInit) => {
        seen = init!.headers as Record<string, string>;
        return new Response('{}', { status: 200 });
      });
      await delivery(fetchFn as never).deliverDue(25, { operatorId: id });
      for (const secret of live) {
        expect(verifyStandardWebhook({ headers: seen, body: signedBodyFrom(fetchFn), secrets: [secret], toleranceSeconds: 300 }).ok).toBe(true);
      }
      // A captured batch replayed after the tolerance, and a body changed in transit, are refused.
      const issuedAt = Number(seen['webhook-timestamp']);
      expect(verifyStandardWebhook({ headers: seen, body: signedBodyFrom(fetchFn), secrets: [live[0]!], toleranceSeconds: 300, now: issuedAt + 301 })).toEqual({ ok: false, reason: 'stale' });
      expect(verifyStandardWebhook({ headers: seen, body: `${signedBodyFrom(fetchFn)} `, secrets: [live[0]!], toleranceSeconds: 300 })).toEqual({ ok: false, reason: 'bad_signature' });
      expect(signStandardWebhook).toBeDefined();
    });
  });

  describe('decisions', () => {
    it('keeps a slim row per decision, the request only for a refusal, and trims both by age', async () => {
      const id = await operator('decisions');
      const row = (n: number, verdict: string, request: Record<string, unknown> | null) => ({
        id: `dec_${suffix}_${n}`, operator_id: id, action_type: 'email.send', decider: 'remote', verdict, latency_ms: 20 + n,
        request_digest: `sha256:${'b'.repeat(64)}`, request, account_id: 'acct_1',
      });
      await repo.insertDecision(row(1, 'allow', null));
      await repo.insertDecision(row(2, 'deny', { action: { type: 'email.send' } }));
      await repo.insertDecision(row(3, 'unavailable', { action: { type: 'email.send' } }));
      await repo.insertDecision(row(2, 'deny', null)); // a repeated id changes nothing
      const denied = await repo.listDecisions(id, { limit: 10, verdict: 'deny' });
      expect(denied).toHaveLength(1);
      expect(denied[0]!.request).toEqual({ action: { type: 'email.send' } });
      expect(await repo.listDecisions(id, { limit: 10, accountId: 'acct_other' })).toEqual([]);
      expect(await repo.getDecision('op_someone_else', `dec_${suffix}_2`)).toBeNull();

      await db.update(controlDecisions).set({ created_at: sql`now() - interval '40 days'` }).where(eq(controlDecisions.id, `dec_${suffix}_2`));
      await db.update(controlDecisions).set({ created_at: sql`now() - interval '100 days'` }).where(eq(controlDecisions.id, `dec_${suffix}_3`));
      const pruned = await repo.pruneDecisions(30, 90);
      expect(pruned.requestsCleared).toBeGreaterThanOrEqual(1);
      expect(pruned.rowsDeleted).toBeGreaterThanOrEqual(1);
      expect((await repo.getDecision(id, `dec_${suffix}_2`))!.request).toBeNull();
      expect(await repo.getDecision(id, `dec_${suffix}_3`)).toBeNull();
      expect(await repo.getDecision(id, `dec_${suffix}_1`)).not.toBeNull();
    });
  });

  describe('the data model', () => {
    it('refuses a remote socket with no verified address, and a timeout outside 300 to 2000 ms', async () => {
      const id = await operator('checks');
      await repo.getOrCreate(id);
      await expect(db.update(controlSockets).set({ decision_mode: 'remote' }).where(eq(controlSockets.operator_id, id))).rejects.toThrow();
      await expect(db.update(controlSockets).set({ decision_timeout_ms: 5_000 }).where(eq(controlSockets.operator_id, id))).rejects.toThrow();
      await expect(db.update(controlSockets).set({ decision_mode: 'sometimes' }).where(eq(controlSockets.operator_id, id))).rejects.toThrow();
    });

    it('is deleted with the operator', async () => {
      const id = await operator('erased');
      await sockets.setEventsAddress(id, 'https://logs.customer.example/stack');
      await sockets.activateEvents(id);
      await writeAudit(id);
      await repo.insertDecision({
        id: `dec_${suffix}_erased`, operator_id: id, action_type: 'email.send', decider: 'hosted', verdict: 'allow', latency_ms: 1,
        request_digest: `sha256:${'c'.repeat(64)}`,
      });
      await db.delete(operators).where(eq(operators.id, id)).catch(() => undefined);
      // The audit log keeps its rows for erasure through the account-erasure service; the socket tables go with the operator.
      expect(await db.select().from(controlSockets).where(eq(controlSockets.operator_id, id))).toEqual([]);
      expect(await db.select().from(controlDecisions).where(eq(controlDecisions.operator_id, id))).toEqual([]);
      expect(await outbox(id)).toEqual([]);
    });
  });
});

function signedBodyFrom(fetchFn: { mock: { calls: unknown[][] } }): string {
  const init = fetchFn.mock.calls.at(-1)![1] as RequestInit;
  return String(init.body);
}
