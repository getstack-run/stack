// Conformance suite for a control socket EVENTS RECEIVER: the customer's server
// that takes in the signed stream of their record. The kit plays the gateway:
// it signs batches with the secret you give it and checks your answers against
// spec/control-socket/SPEC.md section 7.
//
// Point it at a test instance with a test secret. The batches hold synthetic
// events for the operator `op_conformance`.

import { randomBytes } from 'node:crypto';
import { sha256Hex } from './canonical.mjs';
import { assert, post, runChecks } from './harness.mjs';
import { WRONG_SECRET, signMessage } from './webhook.mjs';

const GENESIS = '0'.repeat(64);

function batchId() {
  return `evb_${randomBytes(18).toString('base64url')}`;
}

/** A run of consecutive events with a valid chain, starting at `fromSeq`. */
export function makeEvents(fromSeq, count) {
  const events = [];
  let previous = fromSeq === 1 ? GENESIS : sha256Hex(`entry-${fromSeq - 1}`);
  for (let seq = fromSeq; seq < fromSeq + count; seq += 1) {
    const hash = sha256Hex(`entry-${seq}`);
    events.push({
      id: `aud_conformance_${seq}`,
      seq,
      type: seq % 2 === 0 ? 'control.decision.deny' : 'passport.issue',
      occurred_at: new Date(1_790_000_000_000 + seq * 1000).toISOString(),
      operator_id: 'op_conformance',
      agent_id: 'agt_conformance',
      account_id: 'acct_conformance',
      outcome: seq % 2 === 0 ? 'blocked' : 'success',
      layer: 'vault',
      error_code: null,
      decision_id: seq % 2 === 0 ? `dec_${'a'.repeat(20)}` : null,
      amount_cents: null,
      chain: { entry_hash: hash, prev_entry_hash: previous },
    });
    previous = hash;
  }
  return events;
}

export function makeBatch({ events = [], test = false } = {}) {
  return {
    type: 'stack.events.batch',
    version: '1',
    batch_id: batchId(),
    test,
    operator_id: 'op_conformance',
    socket_id: 'csk_conformance',
    events,
  };
}

/**
 * @param {{ url: string, secret: string, timeoutMs?: number, fetchImpl?: typeof fetch }} options
 */
export async function runEventsReceiverSuite(options) {
  const { url, secret, timeoutMs = 12_000, fetchImpl } = options;
  const send = (batch, headers, body = JSON.stringify(batch)) =>
    post(url, { headers: { 'content-type': 'application/json', ...headers }, body, timeoutMs, fetchImpl });
  const goodHeaders = (batch, extra = {}) => signMessage({ id: batch.batch_id, body: JSON.stringify(batch), secrets: [secret], ...extra });
  const accepted = (r) => r.status >= 200 && r.status < 300;

  return runChecks('control socket events receiver', [
    {
      id: 'E01', level: 'MUST', title: 'accepts a signed test batch with a 2xx status',
      async run() {
        const batch = makeBatch({ test: true });
        const r = await send(batch, goodHeaders(batch));
        assert(accepted(r), `status ${r.status}`);
      },
    },
    {
      id: 'E02', level: 'MUST', title: 'accepts a signed batch of events with a 2xx status',
      async run() {
        const batch = makeBatch({ events: makeEvents(1, 3) });
        const r = await send(batch, goodHeaders(batch));
        assert(accepted(r), `status ${r.status}`);
      },
    },
    {
      id: 'E03', level: 'MUST', title: 'accepts the same batch again (delivery is at least once)',
      async run() {
        const batch = makeBatch({ events: makeEvents(4, 2) });
        for (let i = 0; i < 2; i += 1) {
          const r = await send(batch, goodHeaders(batch));
          assert(accepted(r), `delivery ${i + 1}: status ${r.status}`);
        }
      },
    },
    {
      id: 'E04', level: 'MUST', title: 'accepts a batch that carries a gap marker',
      async run() {
        const gap = {
          id: 'gap_7_9', seq: 9, type: 'stack.events.gap', occurred_at: new Date().toISOString(), operator_id: 'op_conformance',
          agent_id: null, account_id: null, outcome: 'failure', layer: 'system', error_code: null, decision_id: null,
          amount_cents: null, chain: null, gap: { from_seq: 7, to_seq: 9 },
        };
        const batch = makeBatch({ events: [gap, ...makeEvents(10, 1)] });
        const r = await send(batch, goodHeaders(batch));
        assert(accepted(r), `status ${r.status}`);
      },
    },
    {
      id: 'E05', level: 'MUST', title: 'accepts a request carrying two signatures when one matches (secret rotation)',
      async run() {
        const batch = makeBatch({ test: true });
        const r = await send(batch, signMessage({ id: batch.batch_id, body: JSON.stringify(batch), secrets: [WRONG_SECRET, secret] }));
        assert(accepted(r), `status ${r.status}`);
      },
    },
    {
      id: 'E06', level: 'MUST', title: 'answers within the gateway timeout of 10 seconds',
      async run() {
        const batch = makeBatch({ events: makeEvents(11, 5) });
        const r = await send(batch, goodHeaders(batch));
        assert(r.ms <= 10_000, `took ${r.ms} ms`);
      },
    },
    {
      id: 'E10', level: 'MUST', title: 'refuses a batch signed with the wrong secret (not a 2xx)',
      async run() {
        const batch = makeBatch({ events: makeEvents(1, 1) });
        const r = await send(batch, signMessage({ id: batch.batch_id, body: JSON.stringify(batch), secrets: [WRONG_SECRET] }));
        assert(!accepted(r), `accepted with status ${r.status}`);
      },
    },
    {
      id: 'E11', level: 'MUST', title: 'refuses a batch without signature headers',
      async run() {
        const batch = makeBatch({ events: makeEvents(1, 1) });
        const r = await send(batch, {});
        assert(!accepted(r), `accepted with status ${r.status}`);
      },
    },
    {
      id: 'E12', level: 'MUST', title: 'refuses a correctly signed batch whose timestamp is ten minutes old',
      async run() {
        const batch = makeBatch({ events: makeEvents(1, 1) });
        const r = await send(batch, goodHeaders(batch, { timestamp: Math.floor(Date.now() / 1000) - 600 }));
        assert(!accepted(r), `accepted with status ${r.status}`);
      },
    },
    {
      id: 'E13', level: 'MUST', title: 'refuses a body that was changed after it was signed',
      async run() {
        const batch = makeBatch({ events: makeEvents(1, 2) });
        const headers = goodHeaders(batch);
        const changed = JSON.stringify(batch).replace('"seq":1', '"seq":5');
        assert(changed !== JSON.stringify(batch), 'the kit could not alter the body');
        const r = await send(batch, headers, changed);
        assert(!accepted(r), `accepted with status ${r.status}`);
      },
    },
    {
      id: 'E14', level: 'SHOULD', title: 'answers an unauthenticated batch with a 4xx status (a 5xx asks the gateway to retry)',
      async run() {
        const batch = makeBatch({ events: makeEvents(1, 1) });
        const r = await send(batch, signMessage({ id: batch.batch_id, body: JSON.stringify(batch), secrets: [WRONG_SECRET] }));
        assert(r.status >= 400 && r.status < 500, `status ${r.status}`);
      },
    },
  ]);
}
