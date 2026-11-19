// node --test examples/control-socket
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import test from 'node:test';
import { createControlServer, decide, digestMatches, newState, POLICY, takeEvents } from './server.mjs';

const DECISION_SECRET = `whsec_${Buffer.alloc(32, 3).toString('base64')}`;
const EVENTS_SECRET = `whsec_${Buffer.alloc(32, 5).toString('base64')}`;

/** A request the way STACK builds it: the digest covers every other field. */
const request = (over = {}) => {
  const unsigned = {
    type: 'stack.decision.request', version: '1', decision_id: `dec_${Math.random().toString(36).slice(2).padEnd(16, '0')}`,
    test: false, operator_id: 'op_1', account: { id: 'acct_1' }, actor: { kind: 'agent' },
    action: { type: 'email.send' }, target: { recipients: [{ address: 'a@example.com', domain: 'example.com' }], recipient_count: 1 },
    amount: null, retry_ref: null, ...over,
  };
  const digest = `sha256:${createHash('sha256').update(canonicalize(unsigned)).digest('hex')}`;
  return { ...unsigned, request_digest: digest };
};

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

test('allows what the rules allow and refuses what they do not, with a reason', () => {
  const state = newState();
  assert.deepEqual(decide(request(), state), { verdict: 'allow' });
  const other = decide(request({ target: { recipients: [{ address: 'x@elsewhere.test', domain: 'elsewhere.test' }] } }), state);
  assert.equal(other.verdict, 'deny');
  assert.equal(other.reason.code, 'recipient_not_allowed');
  assert.equal(decide(request({ action: { type: 'browser.navigate' }, target: { origin: 'https://evil.test' } }), state).reason.code, 'origin_not_allowed');
  assert.equal(decide(request({ action: { type: 'tool.run' }, target: {}, amount: { max_cents: 5_000, currency: 'USD' } }), state).reason.code, 'over_cost_limit');
});

test('counts a day\'s sends once per decision, so a retried request is not counted twice', () => {
  const state = newState();
  const policy = { ...POLICY, sendsPerDay: 2 };
  const first = request();
  assert.equal(decide(first, state, policy).verdict, 'allow');
  assert.equal(decide(first, state, policy).verdict, 'allow');
  assert.equal(decide(request(), state, policy).verdict, 'allow');
  assert.equal(decide(request(), state, policy).reason.code, 'daily_send_limit');
});

test('holds a large purchase for a person, and allows the retry that cites the approved reference', () => {
  const state = newState();
  const checkout = (over = {}) => request({
    action: { type: 'card.checkout' }, target: { merchant_origin: 'https://shop.example', amount_minor: 9_900, currency: 'USD' }, ...over,
  });
  const held = decide(checkout(), state);
  assert.equal(held.verdict, 'deny');
  assert.equal(held.reason.code, 'approval_required');
  state.approved.add(held.retry.ref);
  assert.deepEqual(decide(checkout({ retry_ref: held.retry.ref }), state), { verdict: 'allow' });
});

test('checks the request digest: a request changed after it was built does not match', () => {
  const built = request();
  assert.equal(digestMatches(built), true);
  assert.equal(digestMatches({ ...built, amount: { max_cents: 1, currency: 'USD' } }), false);
  assert.equal(digestMatches({ ...built, request_digest: `sha256:${'0'.repeat(64)}` }), false);
});

test('takes events in at least once, and notes a gap or a broken chain', () => {
  const state = newState();
  const event = (seq, prev, hash) => ({ id: `aud_${seq}`, seq, type: 'x', chain: { prev_entry_hash: prev, entry_hash: hash } });
  takeEvents({ events: [event(1, 'g', 'h1'), event(2, 'h1', 'h2')] }, state);
  takeEvents({ events: [event(2, 'h1', 'h2'), event(3, 'h2', 'h3')] }, state);
  assert.equal(state.events.lastSeq, 3);
  assert.deepEqual(state.events.gaps, []);
  takeEvents({ events: [event(6, 'zz', 'h6')] }, state);
  assert.deepEqual(state.events.gaps, [{ from_seq: 4, to_seq: 5 }]);
  assert.equal(state.events.chainBreaks, 1);
});

/** What STACK does to a request: Standard Webhooks, HMAC-SHA256 over id.timestamp.body. */
function signed(id, body, secret) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  const signature = createHmac('sha256', key).update(`${id}.${timestamp}.${body}`).digest('base64');
  return { 'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': `v1,${signature}` };
}

test('answers a signed request with a signed answer that echoes the digest, and refuses an unsigned one', async (t) => {
  const server = createControlServer({ decisionSecret: DECISION_SECRET, eventsSecret: EVENTS_SECRET });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;

  const req = request();
  const body = JSON.stringify(req);
  const ok = await fetch(`${base}/stack/decide`, { method: 'POST', headers: signed(req.decision_id, body, DECISION_SECRET), body });
  assert.equal(ok.status, 200);
  const text = await ok.text();
  assert.deepEqual(JSON.parse(text), { decision_id: req.decision_id, request_digest: req.request_digest, verdict: 'allow' });
  const key = Buffer.from(DECISION_SECRET.slice('whsec_'.length), 'base64');
  const expected = createHmac('sha256', key).update(`${req.decision_id}.${ok.headers.get('webhook-timestamp')}.${text}`).digest('base64');
  assert.equal(ok.headers.get('webhook-id'), req.decision_id);
  assert.equal(ok.headers.get('webhook-signature'), `v1,${expected}`);

  const changed = JSON.stringify({ ...req, amount: { max_cents: 9, currency: 'USD' } });
  const refusedDigest = await fetch(`${base}/stack/decide`, { method: 'POST', headers: signed(req.decision_id, changed, DECISION_SECRET), body: changed });
  assert.equal(refusedDigest.status, 400);

  const forged = await fetch(`${base}/stack/decide`, { method: 'POST', headers: signed(req.decision_id, body, EVENTS_SECRET), body });
  assert.equal(forged.status, 401);
  const unsigned = await fetch(`${base}/stack/decide`, { method: 'POST', body });
  assert.equal(unsigned.status, 401);

  // The events secret is a different secret and a different endpoint.
  const batch = JSON.stringify({ type: 'stack.events.batch', version: '1', batch_id: 'evb_1', test: false, events: [{ id: 'aud_1', seq: 1, type: 'x', chain: null }] });
  const taken = await fetch(`${base}/stack/events`, { method: 'POST', headers: signed('evb_1', batch, EVENTS_SECRET), body: batch });
  assert.equal(taken.status, 200);
  const wrong = await fetch(`${base}/stack/events`, { method: 'POST', headers: signed('evb_1', batch, DECISION_SECRET), body: batch });
  assert.equal(wrong.status, 401);
});
