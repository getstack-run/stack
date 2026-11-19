// Conformance suite for a RECEIVER of STACK webhooks: the server (or the
// verification function) that takes in a request STACK signs. The kit plays the
// sender: it signs messages with the secret you give it and checks that your
// receiver accepts what it must and refuses what it must, against
// spec/webhooks/SPEC.md sections 4 and 5.
//
// Two ways to point it at a receiver:
//
//   { url, secret }       a test instance that answers 2xx to a message it accepts and a
//                         non-2xx to one it refuses. Use a TEST secret, never a production one.
//   { verify, secret }    a function ({ headers, body, secrets, now }) that returns true or
//                         false (or { ok }) for one message. `headers` has lower-case names,
//                         `body` is the raw string, `now` is the clock in unix seconds the
//                         function must use instead of its own.
//
// The messages are synthetic: a `stack.wake` test body and a notification body.

import { randomBytes } from 'node:crypto';
import { assert, post, runChecks, skip } from './harness.mjs';
import { WRONG_SECRET, signMessage } from './webhook.mjs';

function messageId() {
  return `msg_${randomBytes(18).toString('base64url')}`;
}

/** A synthetic body: the shape of a wake-up check, with a non-ASCII character so the raw bytes matter. */
export function makeWebhookBody(id = messageId()) {
  return JSON.stringify({
    type: 'stack.wake',
    version: '2',
    test: true,
    wake_id: id,
    account_id: 'acct_conformance',
    agent_id: 'agt_conformance',
    mission_id: null,
    source: 'schedule',
    task: 'Conformance check: nothing is waking you.',
    occurred_at: new Date(1_790_000_000_000).toISOString(),
    event: {},
  });
}

/** A pre-scheme secret: a 64-character hexadecimal string, as notification and inbound-webhook secrets were. */
export const LEGACY_SECRET = Buffer.alloc(32, 0x5c).toString('hex');

/**
 * @param {{
 *   url?: string,
 *   verify?: (input: { headers: Record<string, string>, body: string, secrets: string[], now: number }) => boolean | { ok: boolean } | Promise<boolean | { ok: boolean }>,
 *   secret: string,
 *   timeoutMs?: number,
 *   fetchImpl?: typeof fetch,
 * }} options
 */
export async function runWebhooksSuite(options) {
  const { url, verify, secret, timeoutMs = 12_000, fetchImpl } = options;
  if (!url === !verify) throw new Error('give the webhooks suite either a url or a verify function');
  const now = () => Math.floor(Date.now() / 1000);

  /** Present one message to the receiver. Returns whether it was accepted. */
  async function present({ headers, body, secrets = [secret] }) {
    if (verify) {
      const outcome = await verify({ headers: { ...headers }, body, secrets, now: now() });
      return typeof outcome === 'boolean' ? outcome : outcome.ok === true;
    }
    const r = await post(url, { headers: { 'content-type': 'application/json', ...headers }, body, timeoutMs, fetchImpl });
    return r.status >= 200 && r.status < 300;
  }
  const signed = (id, body, extra = {}) => signMessage({ id, body, secrets: [secret], ...extra });

  return runChecks('webhooks receiver', [
    {
      id: 'W01', level: 'MUST', title: 'accepts a correctly signed request',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        assert(await present({ headers: signed(id, body), body }), 'a correct signature was refused');
      },
    },
    {
      id: 'W02', level: 'MUST', title: 'verifies the raw body bytes: non-ASCII text and unusual spacing are not normalised',
      async run() {
        const id = messageId();
        const body = `{ "type" : "stack.wake",  "version":"2", "wake_id":"${id}", "task":"Café ☕  ", "source":"schedule" }\n`;
        assert(await present({ headers: signed(id, body), body }), 'a body with its own whitespace was refused');
      },
    },
    {
      id: 'W03', level: 'MUST', title: 'accepts a request carrying two signatures when one matches (secret rotation)',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        const both = signMessage({ id, body, secrets: [WRONG_SECRET, secret] });
        assert(await present({ headers: both, body }), 'the matching signature in second place was not found');
        // Another message: a receiver that remembers ids refuses the same one twice.
        const otherId = messageId();
        const otherBody = makeWebhookBody(otherId);
        const reversed = signMessage({ id: otherId, body: otherBody, secrets: [secret, WRONG_SECRET] });
        assert(await present({ headers: reversed, body: otherBody }), 'the matching signature in first place was not found');
      },
    },
    {
      id: 'W04', level: 'MUST', title: 'ignores a signature of an unknown version beside a valid one',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        const headers = signed(id, body);
        headers['webhook-signature'] = `v2,${Buffer.alloc(32, 1).toString('base64')} ${headers['webhook-signature']}`;
        assert(await present({ headers, body }), 'an unknown version made the valid signature unreadable');
      },
    },
    {
      id: 'W05', level: 'MUST', title: 'accepts a timestamp four minutes old and four minutes ahead (inside the 300 s tolerance)',
      async run() {
        for (const offset of [-240, 240]) {
          const id = messageId();
          const body = makeWebhookBody(id);
          const timestamp = now() + offset;
          assert(await present({ headers: signed(id, body, { timestamp }), body }), `refused a timestamp ${offset} s from now`);
        }
      },
    },
    {
      id: 'W06', level: 'SHOULD', title: 'reads a secret issued before the scheme (hexadecimal, no whsec_ prefix) as the specification says',
      async run() {
        if (!verify) return skip('needs a verify function: a deployed receiver holds one secret');
        const id = messageId();
        const body = makeWebhookBody(id);
        const headers = signMessage({ id, body, secrets: [LEGACY_SECRET] });
        const outcome = await verify({ headers: { ...headers }, body, secrets: [LEGACY_SECRET], now: now() });
        assert((typeof outcome === 'boolean' ? outcome : outcome.ok) === true, 'a pre-scheme secret was refused');
      },
    },
    {
      id: 'W10', level: 'MUST', title: 'refuses a request signed with the wrong secret',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        assert(!(await present({ headers: signMessage({ id, body, secrets: [WRONG_SECRET] }), body })), 'a wrong secret was accepted');
      },
    },
    {
      id: 'W11', level: 'MUST', title: 'refuses a body that was changed after it was signed',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        const changed = body.replace('"test":true', '"test":false');
        assert(changed !== body, 'the kit could not alter the body');
        assert(!(await present({ headers: signed(id, body), body: changed })), 'a tampered body was accepted');
      },
    },
    {
      id: 'W12', level: 'MUST', title: 'refuses a request whose id or timestamp was changed after it was signed',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        const headers = signed(id, body);
        assert(!(await present({ headers: { ...headers, 'webhook-id': messageId() }, body })), 'a changed id was accepted');
        const later = String(Number(headers['webhook-timestamp']) + 1);
        assert(!(await present({ headers: { ...headers, 'webhook-timestamp': later }, body })), 'a changed timestamp was accepted');
      },
    },
    {
      id: 'W13', level: 'MUST', title: 'refuses a request that lacks any of the three signature headers',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        const headers = signed(id, body);
        for (const name of ['webhook-id', 'webhook-timestamp', 'webhook-signature']) {
          const without = { ...headers };
          delete without[name];
          assert(!(await present({ headers: without, body })), `accepted without ${name}`);
        }
        assert(!(await present({ headers: {}, body })), 'accepted without any signature header');
      },
    },
    {
      id: 'W14', level: 'MUST', title: 'refuses a timestamp that is not a decimal integer',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        for (const timestamp of ['soon', '1.5e9', '-1', ' ']) {
          const headers = { ...signed(id, body), 'webhook-timestamp': timestamp };
          assert(!(await present({ headers, body })), `accepted the timestamp ${JSON.stringify(timestamp)}`);
        }
      },
    },
    {
      id: 'W15', level: 'MUST', title: 'refuses a correctly signed request ten minutes old (a captured request replayed later)',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        assert(!(await present({ headers: signed(id, body, { timestamp: now() - 600 }), body })), 'a stale request was accepted');
      },
    },
    {
      id: 'W16', level: 'MUST', title: 'refuses a correctly signed request ten minutes ahead of its clock',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        assert(!(await present({ headers: signed(id, body, { timestamp: now() + 600 }), body })), 'a future request was accepted');
      },
    },
    {
      id: 'W17', level: 'MUST', title: 'refuses a malformed signature without failing open',
      async run() {
        const id = messageId();
        const body = makeWebhookBody(id);
        for (const signature of ['', 'v1,', 'v1,!!!not base64!!!', 'v1', 'garbage', `v1,${Buffer.alloc(3).toString('base64')}`]) {
          const headers = { ...signed(id, body), 'webhook-signature': signature };
          assert(!(await present({ headers, body })), `accepted the signature ${JSON.stringify(signature)}`);
        }
      },
    },
    {
      id: 'W20', level: 'SHOULD', title: 'recognises a message id it has handled (a repeat inside the tolerance)',
      async run() {
        if (!verify) return skip('needs a verify function: from outside, a repeat answered 2xx cannot be told from one handled twice');
        const id = messageId();
        const body = makeWebhookBody(id);
        const headers = signed(id, body);
        assert(await present({ headers, body }), 'the first delivery was refused');
        assert(!(await present({ headers, body })), 'a repeat of the same id was accepted again: no replay memory');
      },
    },
  ]);
}
