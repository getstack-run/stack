// A self-hosted control server for STACK's control socket.
//
// STACK posts every checked action of your agents here before it runs
// (POST /stack/decide) and streams your whole record here afterwards
// (POST /stack/events). Both are signed; this server verifies each request,
// answers a signed allow or deny within the deadline, and takes events in
// without losing or double-counting any.
//
//   npm install @getstackrun/sdk
//   STACK_DECISION_SECRET=whsec_... STACK_EVENTS_SECRET=whsec_... node server.mjs
//
// Put it behind https on a public address near Stockholm or Frankfurt, then
// `npx @getstackrun/cli control-socket set-decision https://your.host/stack/decide`.
// The secrets are shown once when each address is set.

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { signControlSocketAnswer, verifyControlSocketRequest } from '@getstackrun/sdk';

/** Canonical JSON: keys sorted at every depth, no whitespace, undefined omitted. */
function canonicalize(value) {
  if (value === null || value === undefined || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().filter((k) => value[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

/**
 * The request's digest covers every other field. A request whose digest does
 * not match what it says was changed after STACK built it, or did not come from
 * STACK's builder: refuse it rather than answer for content you cannot vouch for.
 */
export function digestMatches(request) {
  const { request_digest: digest, ...rest } = request;
  return digest === `sha256:${createHash('sha256').update(canonicalize(rest)).digest('hex')}`;
}

/** The rules. Everything is an allow list or a number; change them to your own. */
export const POLICY = {
  /** Mail may only go to these domains. Empty allows any. */
  emailDomains: ['example.com'],
  /** The most an account may send in a UTC day, mail and texts together. */
  sendsPerDay: 50,
  /** A single paid action may not cost more than this many cents. */
  maxCents: 500,
  /** Browsing and checkout stay on these origins. Empty allows any. */
  origins: ['https://shop.example'],
  /** A checkout above this amount (minor units) waits for a person: deny now, allow on the retry that cites the reference. */
  approveAboveMinor: 5_000,
};

/**
 * One decision. Pure apart from the counters in `state`, so it is easy to test.
 * Returns what to answer: `{ verdict: 'allow' }` or `{ verdict: 'deny', reason, retry? }`.
 */
export function decide(request, state, policy = POLICY) {
  const type = request.action.type;
  const target = request.target;
  const deny = (code, message, retry) => ({ verdict: 'deny', reason: { code, message }, ...(retry ? { retry } : {}) });

  if (request.amount?.max_cents != null && request.amount.max_cents > policy.maxCents && type !== 'card.checkout') {
    return deny('over_cost_limit', `More than ${policy.maxCents} cents for one action.`);
  }

  if (type === 'email.send' || type === 'sms.send') {
    if (type === 'email.send' && policy.emailDomains.length > 0) {
      const outside = target.recipients.find((r) => !policy.emailDomains.includes(r.domain));
      if (outside) return deny('recipient_not_allowed', `Mail to ${outside.domain} is not allowed.`);
    }
    const day = new Date().toISOString().slice(0, 10);
    const key = `${request.account?.id ?? 'owner'}:${day}`;
    const sent = state.sends.get(key) ?? 0;
    // Counted by decision id, so a retried request is not counted twice.
    if (!state.counted.has(request.decision_id)) {
      if (sent >= policy.sendsPerDay) return deny('daily_send_limit', 'The daily send limit is reached.');
      state.sends.set(key, sent + 1);
      state.counted.add(request.decision_id);
    }
  }

  if (type === 'browser.navigate' && policy.origins.length > 0 && !policy.origins.includes(target.origin)) {
    return deny('origin_not_allowed', `${target.origin} is not an allowed site.`);
  }

  if (type === 'card.checkout') {
    if (policy.origins.length > 0 && !policy.origins.includes(target.merchant_origin)) {
      return deny('merchant_not_allowed', `${target.merchant_origin} is not an allowed merchant.`);
    }
    if (target.amount_minor > policy.approveAboveMinor && !state.approved.has(request.retry_ref ?? '')) {
      const ref = `approval-${request.decision_id}`;
      state.pending.add(ref);
      return deny('approval_required', 'A person has to approve this purchase.', { ref, after_seconds: 60 });
    }
  }

  return { verdict: 'allow' };
}

export function newState() {
  return {
    sends: new Map(),
    counted: new Set(),
    /** Approval references a person has approved; the agent sends one back as X-Control-Ref. */
    approved: new Set(),
    pending: new Set(),
    answers: new Map(),
    events: { seen: new Set(), lastSeq: 0, lastHash: null, gaps: [], chainBreaks: 0 },
  };
}

/**
 * Take a batch of events in: ignore ones already seen (STACK delivers at least
 * once), note a gap announced by STACK or a jump in the sequence, and check
 * that each event's `prev_entry_hash` is the hash of the one before it.
 * Store first and process later; acknowledge fast.
 */
export function takeEvents(batch, state) {
  const { events } = state;
  for (const event of batch.events) {
    if (events.seen.has(event.id)) continue;
    events.seen.add(event.id);
    if (event.type === 'stack.events.gap') {
      events.gaps.push(event.gap);
    } else {
      if (events.lastSeq && event.seq !== events.lastSeq + 1) events.gaps.push({ from_seq: events.lastSeq + 1, to_seq: event.seq - 1 });
      if (events.lastHash && event.chain && event.chain.prev_entry_hash !== events.lastHash) events.chainBreaks += 1;
      events.lastHash = event.chain?.entry_hash ?? events.lastHash;
    }
    events.lastSeq = Math.max(events.lastSeq, event.seq);
  }
}

async function readBody(req, limit = 256 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error('too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function createControlServer({ decisionSecret, eventsSecret, state = newState(), policy = POLICY }) {
  return createServer(async (req, res) => {
    try {
      if (req.method !== 'POST') return res.writeHead(405).end();
      const body = await readBody(req);

      if (req.url === '/stack/decide') {
        const checked = verifyControlSocketRequest({ headers: req.headers, body, secret: decisionSecret });
        if (!checked.ok) return res.writeHead(401).end();
        const { request } = checked;
        if (!digestMatches(request)) return res.writeHead(400).end();
        // A retried request gets the same answer.
        let answer = state.answers.get(request.decision_id);
        if (!answer) {
          answer = request.test ? { verdict: 'allow' } : decide(request, state, policy);
          state.answers.set(request.decision_id, answer);
          if (state.answers.size > 10_000) state.answers.delete(state.answers.keys().next().value);
        }
        const signed = signControlSocketAnswer({
          decisionId: request.decision_id,
          requestDigest: request.request_digest,
          secrets: [decisionSecret],
          ...answer,
        });
        return res.writeHead(200, { 'content-type': 'application/json', ...signed.headers }).end(signed.body);
      }

      if (req.url === '/stack/events') {
        // The events secret is a different secret: a log receiver can never sign an allow. The
        // helper checks the signature first, so a bad_body here means the signature was good and
        // the body is a batch of events, not a decision.
        const checked = verifyControlSocketRequest({ headers: req.headers, body, secret: eventsSecret });
        if (!checked.ok && checked.reason !== 'bad_body') return res.writeHead(401).end();
        const batch = JSON.parse(body);
        if (!batch.test) takeEvents(batch, state);
        return res.writeHead(200).end('{}');
      }

      return res.writeHead(404).end();
    } catch {
      return res.writeHead(400).end();
    }
  });
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('server.mjs')) {
  const decisionSecret = process.env.STACK_DECISION_SECRET;
  const eventsSecret = process.env.STACK_EVENTS_SECRET;
  if (!decisionSecret || !eventsSecret) {
    console.error('Set STACK_DECISION_SECRET and STACK_EVENTS_SECRET (the whsec_ values shown once when each address was set).');
    process.exit(1);
  }
  const port = Number(process.env.PORT ?? 8787);
  createControlServer({ decisionSecret, eventsSecret }).listen(port, () => console.log(`control server on :${port}`));
}
