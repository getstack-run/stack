// The reference partner server must pass the partner suite, and the suite must fail servers that
// each have one deliberate defect.

import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { formatReport, runPartnerSuite } from '../src/index.mjs';
import { createReferencePartnerHandler, startReferencePartnerServer } from './partner-reference.mjs';
import { listen } from './support.mjs';

const KEYS = { partnerKey: 'sk_live_partner', nonPartnerKey: 'sk_live_plain' };
const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);
const skipped = (report) => report.results.filter((r) => r.status === 'skip').map((r) => r.id);

/** The reference behind a wrapper that can rewrite a request or its answer. */
async function withDefect({ request, answer }) {
  let origin = '';
  const reference = createReferencePartnerHandler({ baseUrl: () => origin });
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks);
    const replay = Object.assign(Readable.from([raw]), { method: req.method, url: req.url, headers: { ...req.headers } });
    request?.(replay);
    const write = res.writeHead.bind(res);
    const end = res.end.bind(res);
    let status = 200;
    let headers = {};
    res.writeHead = (s, h) => {
      status = s;
      headers = h ?? {};
      return res;
    };
    res.end = (text) => {
      const body = text ? JSON.parse(text) : undefined;
      const out = answer ? answer({ method: req.method, url: req.url, headers: replay.headers, status, body }) ?? { status, body } : { status, body };
      write(out.status, headers);
      end(out.body === undefined ? undefined : JSON.stringify(out.body));
    };
    await reference.handle(replay, res);
  });
  const instance = await listen(server);
  origin = instance.url;
  return { ...instance, reference };
}

describe('the reference partner server', () => {
  it('passes the suite with every mailbox and both ends of a claim, nothing skipped but what needs an agent approval, and no warning', async () => {
    const server = await startReferencePartnerServer();
    try {
      const report = await runPartnerSuite({
        url: server.url, ...KEYS, inviteEmail: 'customer@example.test', releaseEmail: 'customer@example.test', timeoutMs: 3000,
        completeClaim: async ({ accountId }) => server.reference.completeClaim(accountId),
        failClaim: async ({ accountId }) => server.reference.failClaim(accountId),
      });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.warnings, formatReport(report)).toBe(0);
      expect(skipped(report)).toEqual([]);
      // Mail went to the mailbox that was given and to no one else: the invitation, the link of each release.
      expect(new Set(server.reference.mail.map((m) => m.to))).toEqual(new Set(['customer@example.test']));
      expect(server.reference.mail.filter((m) => m.kind === 'invite')).toHaveLength(1);
      // The repeat inside the window mailed nothing, so each release is one link.
      expect(server.reference.mail.filter((m) => m.kind === 'claim')).toHaveLength(4);
    } finally {
      await server.close();
    }
  });

  it('sends no mail without a mailbox, and skips what needs a mailbox, a second key or a way to end a claim', async () => {
    const server = await startReferencePartnerServer();
    try {
      const report = await runPartnerSuite({ url: server.url, partnerKey: KEYS.partnerKey, timeoutMs: 3000 });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(server.reference.mail).toEqual([]);
      expect(skipped(report)).toEqual(['P02', 'P21', 'P32', 'P33', 'P34', 'P35']);
    } finally {
      await server.close();
    }
  });

  it('a server that runs no releases answers 404 on them and passes the rest', async () => {
    const server = await startReferencePartnerServer({ releases: false });
    try {
      const report = await runPartnerSuite({ url: server.url, ...KEYS, releaseEmail: 'customer@example.test', timeoutMs: 3000 });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(skipped(report)).toEqual(['P21', 'P30', 'P31', 'P32', 'P33', 'P34', 'P35']);
      expect(server.reference.mail).toEqual([]);
    } finally {
      await server.close();
    }
  });
});

describe('a server that holds the registration of an account\'s agent for a person', () => {
  /** The reference with a step-up in front of the registration of an agent. */
  const holding = () => withDefect({
    request: (req) => {
      if (req.method === 'POST' && req.url === '/v1/agents/register' && !req.headers['x-governance-approval']) req.headers['x-hold'] = 'yes';
    },
    answer: ({ method, url, headers, status, body }) => (method === 'POST' && url === '/v1/agents/register' && headers['x-hold'] === 'yes'
      ? { status: 403, body: { error: { code: 'GOVERNANCE_APPROVAL_REQUIRED', message: 'A person must approve', details: { approval_id: 'gvr_test' } } } }
      : { status, body }),
  });

  it('is given the person\'s yes through approve, and the checks that need an agent pass', async () => {
    const server = await holding();
    const approvals = [];
    try {
      const report = await runPartnerSuite({ url: server.url, partnerKey: KEYS.partnerKey, approve: async (input) => { approvals.push(input.approvalId); }, timeoutMs: 3000 });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(approvals).toEqual(['gvr_test']);
      expect(report.results.filter((r) => ['P50', 'P51', 'P52', 'P53', 'P60'].includes(r.id)).map((r) => r.status)).toEqual(['pass', 'pass', 'pass', 'pass', 'pass']);
    } finally {
      await server.close();
    }
  });

  it('skips the checks that need an agent, and keeps the others, when no yes can be given', async () => {
    const server = await holding();
    try {
      const report = await runPartnerSuite({ url: server.url, partnerKey: KEYS.partnerKey, timeoutMs: 3000 });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.results.filter((r) => r.status === 'skip' && r.detail?.startsWith('needs approve')).map((r) => r.id)).toEqual(['P50', 'P51', 'P52', 'P53', 'P60']);
      expect(report.results.find((r) => r.id === 'P70')?.status).toBe('pass');
    } finally {
      await server.close();
    }
  });
});

describe('the suite fails a server with one defect', () => {
  const FULL = (server) => ({
    ...KEYS,
    inviteEmail: 'defect@example.test',
    releaseEmail: 'defect@example.test',
    timeoutMs: 3000,
    completeClaim: async ({ accountId }) => server.reference.completeClaim(accountId),
    failClaim: async ({ accountId }) => server.reference.failClaim(accountId),
  });
  it('one whose partner surface is open to any key', async () => {
    const server = await withDefect({ request: (req) => { if (req.url.startsWith('/v1/partner')) req.headers.authorization = 'Bearer sk_live_partner'; } });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toContain('P02');
    } finally {
      await server.close();
    }
  });

  it('one that shows the key again on a repeated open', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'POST' && url === '/v1/partner/accounts' && status === 200 ? { status, body: { ...body, api_key: 'sk_live_again' } } : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toEqual(['P11']);
    } finally {
      await server.close();
    }
  });

  it('one that takes a plan for an account', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'POST' && url === '/v1/partner/accounts' && status === 400 && body?.error?.code === 'TENANT_TIER_NOT_ALLOWED'
        ? { status: 201, body: { account_id: 'op_x', api_key: 'sk_live_x', billing: 'partner' } }
        : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toContain('P12');
    } finally {
      await server.close();
    }
  });

  it('one that shows the customer\'s address in the account view', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'GET' && /^\/v1\/partner\/accounts\/op_/.test(url) && status === 200 ? { status, body: { ...body, email: 'customer@example.test' } } : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toContain('P13');
    } finally {
      await server.close();
    }
  });

  it('one that returns the invitation token', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'POST' && url.endsWith('/invite') && status === 201 ? { status, body: { ...body, invite_token: 'inv_leaked' } } : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toEqual(['P21']);
    } finally {
      await server.close();
    }
  });

  it('one that mails a release again on a repeat inside the window, or sends without an address', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'POST' && url.endsWith('/release') && status === 400 && body?.error?.code === 'RELEASE_EMAIL_REQUIRED'
        ? { status: 202, body: { release: { account_id: 'x' } } }
        : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toContain('P31');
    } finally {
      await server.close();
    }
  });

  it('one whose returned release carries a reason', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'GET' && url.endsWith('/release') && body?.release?.status === 'returned' ? { status, body: { release: { ...body.release, reason: 'sanctions' } } } : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toEqual(['P34']);
    } finally {
      await server.close();
    }
  });

  it('one that still shows a claimed account to the partner', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'GET' && /^\/v1\/partner\/accounts\/op_[0-9a-f]+$/.test(url) && status === 404
        ? { status: 200, body: { account_id: 'op_x', billing: 'partner', status: 'active', invite: { status: 'none' } } }
        : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toContain('P33');
    } finally {
      await server.close();
    }
  });

  it('one whose claim leaves the partner\'s webhook taking events', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'POST' && /^\/v1\/inbound\/generic\//.test(url) && status === 404
        ? { status: 200, body: { decision: 'clean', forwarded: false } }
        : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toContain('P35');
    } finally {
      await server.close();
    }
  });

  it('one whose close leaves out the cascade counts', async () => {
    const server = await withDefect({
      answer: ({ method, status, body }) => (method === 'DELETE' && status === 200 && body && 'webhooks_revoked' in body ? { status, body: { transitioned: body.transitioned } } : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toEqual(['P70']);
    } finally {
      await server.close();
    }
  });

  it('one whose receiver does not check the signature', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'POST' && url.startsWith('/v1/inbound/') && status === 400 ? { status: 200, body: { decision: 'clean', forwarded: false } } : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toEqual(['P52']);
    } finally {
      await server.close();
    }
  });

  it('one that shows the account\'s key in its view', async () => {
    const server = await withDefect({
      answer: ({ method, url, status, body }) => (method === 'GET' && /^\/v1\/partner\/accounts\/op_/.test(url) && status === 200 ? { status, body: { ...body, api_key: 'sk_live_leaked' } } : { status, body }),
    });
    try {
      const report = await runPartnerSuite({ url: server.url, ...FULL(server) });
      expect(mustFailed(report)).toContain('P13');
    } finally {
      await server.close();
    }
  });
});
