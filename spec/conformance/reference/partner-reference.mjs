// A reference server of the partner API (spec/partner/SPEC.md): partner-managed accounts opened under
// the partner's own reference, the customer's invitation, the release of an account and how it ends, an
// account's inbound webhooks and the passports issued under an account, over an in-memory store. It is
// the smallest server that conforms to the wire contract; it signs nothing real (a passport it returns
// is the right shape and not a signed token: the passport suite judges the signing) and sends its mail
// into a list you can read.
//
// Operators: one partner (`sk_live_partner`), one that is not (`sk_live_plain`), and the accounts the
// partner opens. The customer's claim is theirs to run (a card and a sanctions check): `completeClaim`
// and `failClaim` on the reference stand in for it, ending a pending release the way the real claim does.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
const bad = (message) => new HttpError(400, 'VALIDATION_ERROR', message);
const hex = (n) => randomBytes(n).toString('hex');
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const equal = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PLACEHOLDER = '.stack-tenant.local';
const CLAIM_WINDOW_MS = 7 * 24 * 3600 * 1000;
const RESEND_MS = 10 * 60 * 1000;

/**
 * `options.releases`: false answers 404 on the release routes, as a server that does not run the claim does.
 * `options.mail`: the list the reference puts the mail it would send into.
 */
export function createReferencePartnerHandler(options = {}) {
  const releasesRun = options.releases !== false;
  const mail = options.mail ?? [];
  const baseUrl = options.baseUrl ?? (() => 'http://localhost');

  const operators = new Map([
    ['op_partner', { id: 'op_partner', key: 'sk_live_partner', email: 'ops@partner.test', partner: true, parent: null, status: 'active' }],
    ['op_plain', { id: 'op_plain', key: 'sk_live_plain', email: 'plain@plain.test', partner: false, parent: null, status: 'active' }],
  ]);
  const agents = new Map();
  const missions = new Map();
  const webhooks = new Map();
  const received = new Set();
  /** The partner's own record of its releases: `partner:account` -> the record and its internals. */
  const releases = new Map();
  const releaseKey = (partnerId, accountId) => `${partnerId}:${accountId}`;

  function authenticate(req) {
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    if (!token) throw new HttpError(401, 'UNAUTHORIZED', 'Authentication required');
    const operator = [...operators.values()].find((o) => o.key === token);
    if (!operator) throw new HttpError(401, 'INVALID_API_KEY', 'Invalid API key');
    if (operator.status !== 'active') throw new HttpError(403, 'OPERATOR_DELETED', 'This account was deleted');
    return { operator };
  }

  function requirePartner(ctx) {
    if (!ctx.operator.partner) throw new HttpError(403, 'FORBIDDEN', 'partner access required');
  }

  /** An account of this partner, by id; one that was claimed is no longer its own. */
  function accountOf(ctx, id) {
    const account = operators.get(id);
    if (!account || account.parent !== ctx.operator.id) throw new HttpError(404, 'NOT_FOUND', `account not found: ${id}`);
    return account;
  }

  const accountView = (a) => ({
    account_id: a.id, external_ref: a.ref, billing: 'partner', status: a.status, created_at: a.createdAt,
    deleted_at: a.deletedAt ?? null, invite: { status: a.invite ?? 'none' },
  });

  const releaseView = (r) => {
    const expired = r.status === 'pending' && Date.parse(r.expiresAt) <= Date.now();
    return {
      account_id: r.accountId, external_ref: r.ref, status: expired ? 'returned' : r.status, requested_by: r.requestedBy,
      requested_at: r.requestedAt, expires_at: r.expiresAt, completed_at: r.completedAt ?? null,
    };
  };

  function create(ctx, body) {
    if (!isObject(body ?? {})) throw bad('body must be an object');
    const input = body ?? {};
    if (Object.keys(input).some((k) => !['external_ref', 'tier'].includes(k))) throw bad('unknown field');
    if ('tier' in input) throw new HttpError(400, 'TENANT_TIER_NOT_ALLOWED', "Accounts share the partner's plan and cannot be given one. Remove `tier` from the request.");
    if (typeof input.external_ref !== 'string' || input.external_ref === '' || input.external_ref.length > 256) throw bad('external_ref is not valid');
    const own = [...operators.values()].find((o) => o.parent === ctx.operator.id && o.ref === input.external_ref);
    if (own) {
      if (own.status !== 'active') throw new HttpError(409, 'CONFLICT', `external_ref=${input.external_ref} belongs to a closed account and cannot be reused`);
      return { status: 200, body: { account_id: own.id, external_ref: own.ref, billing: 'partner', status: own.status, created: false, created_at: own.createdAt } };
    }
    const account = { id: `op_${hex(16)}`, key: `sk_live_${hex(16)}`, partner: false, parent: ctx.operator.id, status: 'active', ref: input.external_ref, createdAt: new Date().toISOString(), invite: 'none', invited: [] };
    operators.set(account.id, account);
    return { status: 201, body: { account_id: account.id, external_ref: account.ref, billing: 'partner', status: account.status, created: true, created_at: account.createdAt, api_key: account.key } };
  }

  function invite(ctx, account, body) {
    if (!isObject(body) || Object.keys(body).some((k) => !['email', 'name'].includes(k))) throw bad('only email and name');
    if (typeof body.email !== 'string' || !EMAIL.test(body.email)) throw bad('email is not valid');
    if (body.name !== undefined && (typeof body.name !== 'string' || body.name === '' || body.name.length > 100)) throw bad('name is not valid');
    const address = body.email.trim().toLowerCase();
    if (address.endsWith(PLACEHOLDER) || address === ctx.operator.email) throw new HttpError(403, 'FORBIDDEN', 'This address cannot be invited to an account.');
    account.invited.push(address);
    account.invite = 'invited';
    mail.push({ to: address, kind: 'invite' });
    return { status: 201, body: { status: 'invited', expires_at: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString() } };
  }

  function release(ctx, account, body) {
    if (!releasesRun) throw new HttpError(404, 'NOT_FOUND', 'not found');
    if (!isObject(body ?? {}) || Object.keys(body ?? {}).some((k) => k !== 'email')) throw bad('only email');
    const given = body?.email;
    if (given !== undefined && (typeof given !== 'string' || !EMAIL.test(given))) throw bad('email is not valid');
    if (account.status !== 'active') throw new HttpError(409, 'RELEASE_NOT_AVAILABLE', 'This account cannot be released now.');
    let address = given?.trim().toLowerCase();
    if (!address) {
      if (account.invited.length !== 1) throw new HttpError(400, 'RELEASE_EMAIL_REQUIRED', 'Say which address to send the claim link to: invite the customer first, or pass `email`.');
      address = account.invited[0];
    }
    if (address.endsWith(PLACEHOLDER) || address === ctx.operator.email) throw new HttpError(409, 'RELEASE_NOT_AVAILABLE', 'This address cannot claim an account.');
    const key = releaseKey(ctx.operator.id, account.id);
    const existing = releases.get(key);
    if (existing && existing.status === 'pending' && Date.now() - existing.mailedAt < RESEND_MS) {
      return { status: 202, body: { release: releaseView(existing) } };
    }
    const now = Date.now();
    const record = {
      accountId: account.id, ref: account.ref, status: 'pending', requestedBy: 'partner', requestedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + CLAIM_WINDOW_MS).toISOString(), completedAt: null, mailedAt: now, partner: ctx.operator.id,
    };
    releases.set(key, record);
    mail.push({ to: address, kind: 'claim' });
    return { status: 202, body: { release: releaseView(record) } };
  }

  function cancelRelease(ctx, account) {
    if (!releasesRun) throw new HttpError(404, 'NOT_FOUND', 'not found');
    const record = releases.get(releaseKey(ctx.operator.id, account.id));
    if (!record || record.status !== 'pending') return { status: 200, body: { cancelled: false } };
    if (record.requestedBy === 'customer') throw new HttpError(409, 'RELEASE_NOT_AVAILABLE', 'The customer asked to leave: this release cannot be withdrawn.');
    record.status = 'cancelled';
    return { status: 200, body: { cancelled: true } };
  }

  function createWebhook(operatorId, body) {
    if (!isObject(body) || typeof body.agent_id !== 'string' || !['agentmail', 'generic'].includes(body.provider)) throw bad('provider and agent_id are required');
    if (body.forward_url !== undefined && body.forward_url !== null) {
      let host;
      try {
        host = new URL(body.forward_url).hostname;
      } catch {
        throw bad('forward_url is not a URL');
      }
      if (/^(localhost|127\.|10\.|192\.168\.|\[::1\])/.test(host)) throw bad('forward_url is not a public address');
    }
    const agent = agents.get(body.agent_id);
    if (!agent || agent.operator !== operatorId) throw new HttpError(404, 'NOT_FOUND', `agent not found: ${body.agent_id}`);
    const hook = {
      id: `iwh_${hex(16)}`, operator: operatorId, provider: body.provider, slug: hex(12), agent: body.agent_id, forward: body.forward_url ?? null,
      downstream: `whsec_${randomBytes(32).toString('base64')}`, incoming: randomBytes(32).toString('hex'), createdAt: new Date().toISOString(), revoked: false,
    };
    webhooks.set(hook.id, hook);
    return {
      id: hook.id, provider: hook.provider, slug: hook.slug, webhook_url: `${baseUrl()}/v1/inbound/${hook.provider}/${hook.slug}`,
      webhook_secret: hook.downstream, incoming_signing_secret: hook.incoming, signing_configured: true, agent_id: hook.agent, forward_url: hook.forward, created_at: hook.createdAt,
    };
  }

  const hookView = (h) => ({
    id: h.id, provider: h.provider, slug: h.slug, webhook_url: `${baseUrl()}/v1/inbound/${h.provider}/${h.slug}`, agent_id: h.agent, forward_url: h.forward,
    created_at: h.createdAt, revoked_at: h.revoked ? new Date().toISOString() : null, last_used_at: null, last_block_at: null, total_calls: 0, total_blocked: 0, signing_configured: true,
  });

  function revokeAccount(account) {
    const transitioned = account.status === 'active';
    account.status = 'deleted';
    account.deletedAt ??= new Date().toISOString();
    let webhooksRevoked = 0;
    for (const h of webhooks.values()) {
      if (h.operator === account.id && !h.revoked) {
        h.revoked = true;
        webhooksRevoked += 1;
      }
    }
    let passports = 0;
    for (const m of missions.values()) {
      if (m.operator === account.id) {
        passports += m.passports;
        m.passports = 0;
      }
    }
    return { transitioned, webhooks_revoked: webhooksRevoked, passports_revoked: passports };
  }

  /** What the customer's claim does when it clears: the account leaves the partner, its key is replaced, the record completes. */
  function completeClaim(accountId) {
    const account = operators.get(accountId);
    const record = [...releases.values()].find((r) => r.accountId === accountId && r.status === 'pending');
    if (!account || !record) throw new Error(`no pending release of ${accountId}`);
    account.parent = null;
    account.ref = null;
    account.key = `sk_live_${hex(16)}`;
    for (const h of webhooks.values()) if (h.operator === account.id) h.revoked = true;
    record.status = 'completed';
    record.completedAt = new Date().toISOString();
  }

  /** What it does when the check or the checkout does not clear: nothing moves, the record says returned. */
  function failClaim(accountId) {
    const record = [...releases.values()].find((r) => r.accountId === accountId && r.status === 'pending');
    if (!record) throw new Error(`no pending release of ${accountId}`);
    record.status = 'returned';
  }

  /** The routes. `ctx` is the authenticated caller. */
  async function route(req, method, path, body, raw) {
    // The public receiver: the signature is the credential.
    let m = /^\/v1\/inbound\/(generic|agentmail)\/([^/]+)$/.exec(path);
    if (m && method === 'POST') {
      const hook = [...webhooks.values()].find((h) => h.slug === m[2] && h.provider === m[1] && !h.revoked);
      if (!hook) return { status: 404, body: { error: 'not_found' } };
      const header = String(req.headers['x-webhook-signature'] ?? '');
      const expected = createHmac('sha256', hook.incoming).update(raw).digest('hex');
      if (!header.startsWith('sha256=') || !equal(header.slice(7), expected)) return { status: 400, body: { error: 'signature_mismatch' } };
      const id = isObject(body) && typeof body.id === 'string' ? body.id : `body:${expected}`;
      const key = `${hook.id}:${id}`;
      if (received.has(key)) return { status: 200, body: { decision: 'deduplicated', message_id: id, forwarded: false } };
      received.add(key);
      return { status: 200, body: { decision: 'clean', forwarded: false, message_id: id, truncated_for_scan: false } };
    }

    const ctx = authenticate(req);

    if (path === '/v1/agents/register' && method === 'POST') {
      if (!isObject(body) || typeof body.name !== 'string' || !/^[a-z0-9_][a-z0-9_-]*[a-z0-9_]$/.test(body.name)) throw bad('name is not valid');
      const agent = { id: `agt_${hex(16)}`, operator: ctx.operator.id, name: body.name };
      agents.set(agent.id, agent);
      return { status: 201, body: { id: agent.id, name: agent.name, status: 'active' } };
    }
    if (path === '/v1/agents' && method === 'GET') {
      return { status: 200, body: [...agents.values()].filter((a) => a.operator === ctx.operator.id).map((a) => ({ id: a.id, name: a.name, status: 'active' })) };
    }
    if (path === '/v1/missions' && method === 'POST') {
      if (!isObject(body) || typeof body.intent_summary !== 'string' || body.intent_summary === '') throw bad('intent_summary is required');
      const agent = agents.get(body.agent_id);
      if (!agent || agent.operator !== ctx.operator.id) throw new HttpError(404, 'NOT_FOUND', 'agent not found');
      const mission = { id: `ms_${hex(16)}`, operator: ctx.operator.id, agent: agent.id, passports: 0 };
      missions.set(mission.id, mission);
      return { status: 201, body: { mission_id: mission.id, claim_id: `clm_${hex(8)}`, expires_at: new Date(Date.now() + 3_600_000).toISOString() } };
    }

    // The partner surface.
    if (path === '/v1/partner/accounts' && method === 'POST') {
      requirePartner(ctx);
      return create(ctx, body);
    }
    if (path === '/v1/partner/accounts' && method === 'GET') {
      requirePartner(ctx);
      const ref = new URL(req.url, 'http://x').searchParams.get('external_ref');
      return { status: 200, body: { accounts: [...operators.values()].filter((o) => o.parent === ctx.operator.id && (ref === null || o.ref === ref)).map(accountView) } };
    }
    if (path === '/v1/partner/releases' && method === 'GET') {
      requirePartner(ctx);
      if (!releasesRun) throw new HttpError(404, 'NOT_FOUND', 'not found');
      const mine = [...releases.values()].filter((r) => r.partner === ctx.operator.id).map(releaseView);
      return { status: 200, body: { releases: mine.sort((a, b) => b.requested_at.localeCompare(a.requested_at)) } };
    }
    m = /^\/v1\/partner\/accounts\/([^/]+)(?:\/(inbound-webhooks|passports\/issue|rotate-key|invite|release)(?:\/([^/]+))?)?$/.exec(path);
    if (m) {
      requirePartner(ctx);
      if (m[2] === 'release' && method === 'GET') {
        if (!releasesRun) throw new HttpError(404, 'NOT_FOUND', 'not found');
        const record = releases.get(releaseKey(ctx.operator.id, m[1]));
        if (!record) throw new HttpError(404, 'NOT_FOUND', `release not found: ${m[1]}`);
        return { status: 200, body: { release: releaseView(record) } };
      }
      const account = accountOf(ctx, m[1]);
      if (!m[2]) {
        if (method === 'GET') return { status: 200, body: accountView(account) };
        if (method === 'DELETE') return { status: 200, body: revokeAccount(account) };
      } else if (m[2] === 'rotate-key' && method === 'POST') {
        if (account.status !== 'active') throw new HttpError(403, 'FORBIDDEN', `account ${account.id} is not active`);
        account.key = `sk_live_${hex(16)}`;
        return { status: 200, body: { account_id: account.id, api_key: account.key } };
      } else if (m[2] === 'invite' && method === 'POST') {
        if (account.status !== 'active') throw new HttpError(403, 'FORBIDDEN', `account ${account.id} is not active`);
        return invite(ctx, account, body);
      } else if (m[2] === 'release') {
        if (method === 'POST') return release(ctx, account, body);
        if (method === 'DELETE') return cancelRelease(ctx, account);
      } else {
        if (account.status !== 'active') throw new HttpError(403, 'FORBIDDEN', `account ${account.id} is not active`);
        if (m[2] === 'inbound-webhooks') {
          if (!m[3] && method === 'POST') return { status: 201, body: createWebhook(account.id, body) };
          if (!m[3] && method === 'GET') return { status: 200, body: { webhooks: [...webhooks.values()].filter((h) => h.operator === account.id).map(hookView) } };
          if (m[3] && method === 'DELETE') {
            const hook = webhooks.get(m[3]);
            if (!hook || hook.operator !== account.id) throw new HttpError(404, 'NOT_FOUND', `inbound_webhook not found: ${m[3]}`);
            const transitioned = !hook.revoked;
            hook.revoked = true;
            return { status: 200, body: { transitioned } };
          }
        }
        if (m[2] === 'passports/issue' && method === 'POST') {
          if (!isObject(body) || typeof body.agent_id !== 'string' || !Array.isArray(body.mission_ids) || body.mission_ids.length !== 1) throw bad('mission_ids must hold exactly one Mission');
          const agent = agents.get(body.agent_id);
          const mission = missions.get(body.mission_ids[0]);
          if (!agent || agent.operator !== account.id || !mission || mission.operator !== account.id) throw new HttpError(404, 'NOT_FOUND', 'not found');
          mission.passports += 1;
          const part = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
          const exp = Math.floor(Date.now() / 1000) + (body.ttl_seconds ?? 900);
          return { status: 201, body: { token: `${part({ alg: 'none' })}.${part({ stk: { operator_id: account.id, agent_id: agent.id }, exp })}.`, jti: `pas_${hex(12)}`, expires_at: new Date(exp * 1000).toISOString() } };
        }
      }
    }
    if (path.startsWith('/v1/partner/')) requirePartner(ctx);
    throw new HttpError(404, 'NOT_FOUND', 'not found');
  }

  const handle = async (req, res) => {
    const send = (status, value, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers });
      res.end(JSON.stringify(value));
    };
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks);
      let body;
      if (raw.length > 0) {
        try {
          body = JSON.parse(raw.toString('utf8'));
        } catch {
          throw bad('the body is not JSON');
        }
      }
      const path = new URL(req.url, 'http://x').pathname;
      const out = await route(req, req.method, path, body, raw);
      send(out.status, out.body);
    } catch (error) {
      if (error instanceof HttpError) send(error.status, { error: { code: error.code, message: error.message } });
      else send(500, { error: { code: 'INTERNAL', message: 'failed' } });
    }
  };
  return { handle, mail, operators, releases, completeClaim, failClaim };
}

/** Start the reference on an ephemeral loopback port. */
export async function startReferencePartnerServer(options = {}) {
  let origin = '';
  const reference = createReferencePartnerHandler({ baseUrl: () => origin, ...options });
  const server = createServer((req, res) => {
    reference.handle(req, res).catch(() => res.writeHead(500).end());
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  return { url: origin, reference, close: () => new Promise((resolve) => server.close(resolve)) };
}
