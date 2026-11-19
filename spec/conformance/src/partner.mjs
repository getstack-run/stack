// Conformance suite for the partner API as STACK defines it (spec/partner/SPEC.md): partner-managed
// accounts opened under the partner's own reference, the customer's invitation, the release of an
// account to its customer and how it ends, an account's inbound webhooks and the passports a partner
// issues under an account. You give it the URL of a TEST instance and the API key of a TEST partner.
//
// The suite creates things on that instance and removes what it can: an account it creates is closed
// at the end. It never sends mail to an address that is not yours: the checks that can send one (an
// invitation, a release) run only when you give it `inviteEmail` or `releaseEmail`, a mailbox you own;
// the checks that always run are the ones that must be refused before anything is sent. A release is
// optional for a server: when the release routes answer 404 the release checks are skipped. A claim is
// the customer's own flow (a card and the deployment's sign-up checks) and cannot be driven from outside, so the
// checks of what a completed or a failed claim looks like to the partner take a function of yours,
// `completeClaim` or `failClaim`, which brings a release you started to that end on a test instance.
// A check that needs a handle you did not provide is reported as skipped, never as passed.

import { createHmac, randomBytes } from 'node:crypto';
import { assert, runChecks, skip } from './harness.mjs';

export const RELEASE_STATUSES = ['pending', 'completed', 'returned', 'cancelled'];

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
const NONE = 'op_00000000000000000000000000000000';
const RELEASE_FIELDS = ['account_id', 'external_ref', 'status', 'requested_by', 'requested_at', 'expires_at', 'completed_at'];

/**
 * @param {{
 *   url: string,
 *   partnerKey: string,
 *   nonPartnerKey?: string,      // a key of an operator that is not a partner
 *   inviteEmail?: string,        // a mailbox you own: runs the check that invites a customer
 *   releaseEmail?: string,       // a mailbox you own: runs the checks that release an account
 *   approve?: (input: { approvalId: string, accountId: string }) => Promise<void>,  // gives the person's yes when the server asks for it to register an account's agent
 *   completeClaim?: (input: { accountId: string, externalRef: string }) => Promise<void>,  // brings a release you started to a completed claim
 *   failClaim?: (input: { accountId: string, externalRef: string }) => Promise<void>,      // brings a release you started to a claim that did not clear
 *   timeoutMs?: number, fetchImpl?: typeof fetch,
 * }} options
 */
export async function runPartnerSuite(options) {
  const { url, partnerKey, nonPartnerKey, inviteEmail, releaseEmail, approve, completeClaim, failClaim, timeoutMs = 15_000, fetchImpl = fetch } = options;
  const base = new URL(url).origin;
  const run = randomBytes(5).toString('hex');

  async function api(method, path, { key, body, headers = {}, raw } = {}) {
    const response = await fetchImpl(`${base}${path}`, {
      method,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        ...(body !== undefined || raw !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(key ? { authorization: `Bearer ${key}` } : {}),
        ...headers,
      },
      ...(raw !== undefined ? { body: raw } : body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await response.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: response.status, headers: response.headers, text, json };
  }
  const partner = (method, path, body) => api(method, path, { key: partnerKey, ...(body !== undefined ? { body } : {}) });
  const errorCode = (r) => r.json?.error?.code;
  const expectError = (r, status, code, what) => {
    assert(r.status === status, `${what}: answered ${r.status}, expected ${status} (${r.text.slice(0, 140)})`);
    assert(r.json?.error && typeof r.json.error.code === 'string' && typeof r.json.error.message === 'string', `${what}: the body is not the error shape { error: { code, message } }`);
    if (code) assert(errorCode(r) === code, `${what}: code ${errorCode(r)}, expected ${code}`);
  };

  // ── state shared by the checks, with cleanup ──
  const state = { accounts: [], account: undefined, releasesSupported: undefined };
  const handle = (needed, why) => (needed ? null : skip(why));

  async function open(ref) {
    const r = await partner('POST', '/v1/partner/accounts', { external_ref: ref });
    assert(r.status === 201, `opening an account answered ${r.status}: ${r.text.slice(0, 160)}`);
    state.accounts.push(r.json.account_id);
    return r.json;
  }
  async function ensureAccount() {
    if (state.account) return state.account;
    state.account = await open(`conf-${run}`);
    return state.account;
  }
  /** Whether the server runs releases: its release routes answer, or answer 404. */
  async function releasesSupported() {
    if (state.releasesSupported === undefined) {
      const r = await partner('GET', '/v1/partner/releases');
      state.releasesSupported = r.status !== 404;
    }
    return state.releasesSupported;
  }
  const NO_RELEASES = 'the server does not run releases: its release routes answer 404';
  /**
   * An agent of the account, registered with the account's key. Registering an agent with a key is a change a person
   * approves, so a server that asks for it answers GOVERNANCE_APPROVAL_REQUIRED with an approval id; `approve` is
   * how the person's yes is given, and the call is made again with the id. Without `approve` there is no agent: null.
   */
  async function ensureAccountAgent() {
    return agentOf(await ensureAccount());
  }
  async function agentOf(account) {
    if (account.agent !== undefined) return account.agent;
    const body = { name: `conformance-${run}` };
    let r = await api('POST', '/v1/agents/register', { key: account.api_key, body });
    if (r.status === 403 && errorCode(r) === 'GOVERNANCE_APPROVAL_REQUIRED') {
      const approvalId = r.json.error.details?.approval_id;
      if (!approve || typeof approvalId !== 'string') {
        account.agent = null;
        return null;
      }
      await approve({ approvalId, accountId: account.account_id });
      r = await api('POST', '/v1/agents/register', { key: account.api_key, body, headers: { 'x-governance-approval': approvalId } });
    }
    assert(r.status === 201 && typeof r.json?.id === 'string', `registering an agent with the account's key answered ${r.status}: ${r.text.slice(0, 160)}`);
    account.agent = r.json.id;
    return account.agent;
  }
  const NO_AGENT = 'needs approve: this server asks a person to approve registering an agent, and no way to give the yes was provided';

  function assertRelease(record, what) {
    assert(record && typeof record === 'object', `${what}: no release in the answer`);
    for (const field of RELEASE_FIELDS) assert(field in record, `${what}: the release has no ${field}`);
    assert(Object.keys(record).length === RELEASE_FIELDS.length, `${what}: the release carries fields beyond ${RELEASE_FIELDS.join(', ')}: ${Object.keys(record).join(', ')} (a reason is never given)`);
    assert(RELEASE_STATUSES.includes(record.status), `${what}: status ${record.status}`);
    assert(['partner', 'customer'].includes(record.requested_by), `${what}: requested_by ${record.requested_by}`);
    assert(ISO.test(record.requested_at) && ISO.test(record.expires_at), `${what}: requested_at or expires_at is not ISO 8601`);
  }

  const checks = [
    // ─── who may call ───
    {
      id: 'P01', level: 'MUST', title: 'refuses a partner call with no credential or an unknown one: 401 in the error shape',
      async run() {
        expectError(await api('GET', '/v1/partner/accounts'), 401, undefined, 'no credential');
        expectError(await api('GET', '/v1/partner/accounts', { key: `sk_live_${'0'.repeat(32)}` }), 401, 'INVALID_API_KEY', 'an unknown key');
        expectError(await api('POST', '/v1/partner/accounts', { body: { external_ref: 'a' } }), 401, undefined, 'open with no credential');
      },
    },
    {
      id: 'P02', level: 'MUST', title: 'refuses the key of an operator that is not a partner: 403 on the accounts',
      async run() {
        const skipped = handle(nonPartnerKey, 'needs nonPartnerKey: the key of an operator that is not a partner');
        if (skipped) return skipped;
        for (const [method, path, body] of [
          ['GET', '/v1/partner/accounts'],
          ['POST', '/v1/partner/accounts', { external_ref: 'conformance' }],
        ]) {
          expectError(await api(method, path, { key: nonPartnerKey, ...(body ? { body } : {}) }), 403, undefined, `${method} ${path} as a non-partner`);
        }
      },
    },
    {
      id: 'P03', level: 'MUST', title: 'lists the partner\'s own accounts: { accounts: [...] }',
      async run() {
        const accounts = await partner('GET', '/v1/partner/accounts');
        assert(accounts.status === 200 && Array.isArray(accounts.json?.accounts), `accounts answered ${accounts.status} ${accounts.text.slice(0, 100)}`);
      },
    },

    // ─── accounts ───
    {
      id: 'P10', level: 'MUST', title: 'opens an account: 201 with its id, the partner\'s reference, billing "partner", its API key once, and no address of anyone',
      async run() {
        const a = await ensureAccount();
        assert(/^op_/.test(a.account_id), `account_id ${a.account_id}`);
        assert(typeof a.api_key === 'string' && a.api_key.startsWith('sk_live_'), 'no sk_live_ API key');
        assert(a.billing === 'partner', `billing ${a.billing}`);
        assert(a.created === true && a.status === 'active', `created ${a.created}, status ${a.status}`);
        assert(a.external_ref === `conf-${run}`, 'external_ref is not echoed');
        assert(ISO.test(a.created_at), 'created_at is not ISO 8601');
        assert(!JSON.stringify(a).includes('@'), 'the answer carries an address');
      },
    },
    {
      id: 'P11', level: 'MUST', title: 'opening again under the same external_ref returns the account that exists: 200, created false, no key, nothing made twice',
      async run() {
        const a = await ensureAccount();
        const again = await partner('POST', '/v1/partner/accounts', { external_ref: `conf-${run}` });
        assert(again.status === 200, `a repeat answered ${again.status}`);
        assert(again.json.created === false && again.json.account_id === a.account_id, 'a repeat did not return the same account with created false');
        assert(!('api_key' in again.json), 'a repeat carried a key');
        const found = await partner('GET', `/v1/partner/accounts?external_ref=${encodeURIComponent(`conf-${run}`)}`);
        assert(found.status === 200 && found.json.accounts.length === 1 && found.json.accounts[0].account_id === a.account_id, 'the list under the reference is not exactly the account');
      },
    },
    {
      id: 'P12', level: 'MUST', title: 'refuses a body that is not valid, a plan by name (400 TENANT_TIER_NOT_ALLOWED) and an unknown field (400)',
      async run() {
        expectError(await partner('POST', '/v1/partner/accounts', { external_ref: 'x', tier: 'enterprise' }), 400, 'TENANT_TIER_NOT_ALLOWED', 'a tier');
        expectError(await partner('POST', '/v1/partner/accounts', { external_ref: 'x', plan: 'enterprise' }), 400, 'VALIDATION_ERROR', 'an unknown field');
        expectError(await partner('POST', '/v1/partner/accounts', {}), 400, 'VALIDATION_ERROR', 'no reference');
        expectError(await partner('POST', '/v1/partner/accounts', { external_ref: '' }), 400, 'VALIDATION_ERROR', 'an empty reference');
        expectError(await partner('POST', '/v1/partner/accounts', { external_ref: 'x'.repeat(257) }), 400, 'VALIDATION_ERROR', 'a reference over 256 characters');
        const notJson = await api('POST', '/v1/partner/accounts', { key: partnerKey, raw: '{not json' });
        assert(notJson.status === 400, `a body that is not JSON answered ${notJson.status}`);
      },
    },
    {
      id: 'P13', level: 'MUST', title: 'reads an account: listed, got by id, no key and no address in the view, 404 for an id that is not the partner\'s',
      async run() {
        const a = await ensureAccount();
        const got = await partner('GET', `/v1/partner/accounts/${a.account_id}`);
        assert(got.status === 200 && got.json.account_id === a.account_id, `get answered ${got.status}`);
        for (const field of ['external_ref', 'billing', 'status', 'created_at', 'deleted_at', 'invite']) {
          assert(field in got.json, `the account view has no ${field}`);
        }
        assert(got.json.billing === 'partner' && got.json.status === 'active', 'the view does not read billing partner, status active');
        assert(['none', 'invited', 'active'].includes(got.json.invite?.status), `invite status ${got.json.invite?.status}`);
        assert(!JSON.stringify(got.json).includes('sk_live_') && !('api_key' in got.json), 'the view carries an API key');
        assert(!JSON.stringify(got.json).includes('@'), 'the view carries an address');
        const list = await partner('GET', '/v1/partner/accounts');
        assert(list.json.accounts.some((x) => x.account_id === a.account_id), 'the account is not listed');
        expectError(await partner('GET', `/v1/partner/accounts/${NONE}`), 404, 'NOT_FOUND', 'an unknown account');
      },
    },
    {
      id: 'P14', level: 'MUST', title: 'the account\'s own key works as that account and cannot reach the partner surface',
      async run() {
        const a = await ensureAccount();
        const own = await api('GET', '/v1/agents', { key: a.api_key });
        assert(own.status === 200, `the account key on GET /v1/agents answered ${own.status}`);
        expectError(await api('GET', '/v1/partner/accounts', { key: a.api_key }), 403, 'FORBIDDEN', 'an account key on the partner surface');
      },
    },
    {
      id: 'P15', level: 'MUST', title: 'replaces a lost key: a new one once, the old one refused at once, 404 for an account that is not the partner\'s',
      async run() {
        const a = await open(`conf-key-${run}`);
        const r = await partner('POST', `/v1/partner/accounts/${a.account_id}/rotate-key`);
        assert(r.status === 200 && typeof r.json?.api_key === 'string' && r.json.api_key !== a.api_key && r.json.account_id === a.account_id, `rotate-key answered ${r.status} ${r.text.slice(0, 100)}`);
        const old = await api('GET', '/v1/agents', { key: a.api_key });
        assert(old.status === 401 || old.status === 403, `the key that was replaced answered ${old.status}`);
        assert((await api('GET', '/v1/agents', { key: r.json.api_key })).status === 200, 'the new key does not authenticate');
        expectError(await partner('POST', `/v1/partner/accounts/${NONE}/rotate-key`), 404, 'NOT_FOUND', 'replacing the key of an account that is not the partner\'s');
      },
    },

    // ─── the customer ───
    {
      id: 'P20', level: 'MUST', title: 'an invitation refuses what it must before anything is sent: a body that is not valid, the reserved placeholder domain, an account that is not the partner\'s',
      async run() {
        const a = await ensureAccount();
        const path = `/v1/partner/accounts/${a.account_id}/invite`;
        expectError(await partner('POST', path, {}), 400, 'VALIDATION_ERROR', 'no address');
        expectError(await partner('POST', path, { email: 'not an address' }), 400, 'VALIDATION_ERROR', 'a bad address');
        expectError(await partner('POST', path, { email: 'a@example.invalid', role: 'admin' }), 400, 'VALIDATION_ERROR', 'a role');
        const placeholder = await partner('POST', path, { email: 'someone@acct.stack-tenant.local' });
        assert(placeholder.status === 403 || placeholder.status === 409, `the reserved placeholder domain answered ${placeholder.status}`);
        expectError(await partner('POST', `/v1/partner/accounts/${NONE}/invite`, { email: 'a@example.invalid' }), 404, 'NOT_FOUND', 'an account that is not the partner\'s');
      },
    },
    {
      id: 'P21', level: 'MUST', title: 'invites the customer: 201 { status: "invited", expires_at }, no token and no address in the answer, and the view says invited',
      async run() {
        const skipped = handle(inviteEmail, 'needs inviteEmail: a mailbox you own');
        if (skipped) return skipped;
        const a = await ensureAccount();
        const r = await partner('POST', `/v1/partner/accounts/${a.account_id}/invite`, { email: inviteEmail });
        assert(r.status === 201 && r.json?.status === 'invited', `invite answered ${r.status}: ${r.text.slice(0, 140)}`);
        assert(r.json.expires_at === null || ISO.test(r.json.expires_at), 'expires_at is not ISO 8601');
        assert(!r.text.includes(inviteEmail) && !/inv_/.test(r.text), 'the answer carries the address or the invitation token');
        const got = await partner('GET', `/v1/partner/accounts/${a.account_id}`);
        assert(got.json.invite.status === 'invited', `the view reads invite ${got.json.invite?.status}`);
        assert(!got.text.includes(inviteEmail), 'the view carries the address');
      },
    },

    // ─── releasing an account ───
    {
      id: 'P30', level: 'MUST', title: 'the release routes answer in the error shape and read what the partner has: { releases: [...] }, and 404 for an account with no release',
      async run() {
        if (!(await releasesSupported())) return skip(NO_RELEASES);
        const list = await partner('GET', '/v1/partner/releases');
        assert(list.status === 200 && Array.isArray(list.json?.releases), `releases answered ${list.status} ${list.text.slice(0, 100)}`);
        const a = await ensureAccount();
        expectError(await partner('GET', `/v1/partner/accounts/${a.account_id}/release`), 404, 'NOT_FOUND', 'an account with no release');
        expectError(await api('GET', '/v1/partner/releases'), 401, undefined, 'releases with no credential');
      },
    },
    {
      id: 'P31', level: 'MUST', title: 'a release refuses what it must before anything is sent: an account that is not the partner\'s, a body that is not valid, and no address to send to (400 RELEASE_EMAIL_REQUIRED)',
      async run() {
        if (!(await releasesSupported())) return skip(NO_RELEASES);
        const fresh = await open(`conf-nomail-${run}`);
        const path = `/v1/partner/accounts/${fresh.account_id}/release`;
        expectError(await partner('POST', `/v1/partner/accounts/${NONE}/release`, { email: 'a@example.invalid' }), 404, 'NOT_FOUND', 'an account that is not the partner\'s');
        expectError(await partner('POST', path, { email: 'not an address' }), 400, 'VALIDATION_ERROR', 'a bad address');
        expectError(await partner('POST', path, { email: 'a@example.invalid', reason: 'x' }), 400, 'VALIDATION_ERROR', 'an unknown field');
        expectError(await partner('POST', path, {}), 400, 'RELEASE_EMAIL_REQUIRED', 'no address and no invited customer');
        const placeholder = await partner('POST', path, { email: 'someone@acct.stack-tenant.local' });
        assert(placeholder.status === 409 || placeholder.status === 403, `the reserved placeholder domain answered ${placeholder.status}`);
        expectError(await partner('DELETE', `/v1/partner/accounts/${NONE}/release`), 404, 'NOT_FOUND', 'withdrawing the release of an account that is not the partner\'s');
        const none = await partner('DELETE', path);
        assert(none.status === 200 && none.json?.cancelled === false, `withdrawing a release that does not exist answered ${none.status} ${none.text.slice(0, 80)}`);
      },
    },
    {
      id: 'P32', level: 'MUST', title: 'a release mails the link and reads pending (202); a repeat answers the same one; it is read, listed and withdrawn (cancelled), and the account stays the partner\'s',
      async run() {
        const skipped = handle(releaseEmail, 'needs releaseEmail: a mailbox you own');
        if (skipped) return skipped;
        if (!(await releasesSupported())) return skip(NO_RELEASES);
        const a = await open(`conf-rel-${run}`);
        const path = `/v1/partner/accounts/${a.account_id}/release`;
        const r = await partner('POST', path, { email: releaseEmail });
        assert(r.status === 202, `release answered ${r.status}: ${r.text.slice(0, 160)}`);
        assertRelease(r.json.release, 'the release');
        assert(r.json.release.status === 'pending' && r.json.release.requested_by === 'partner' && r.json.release.completed_at === null, 'a new release does not read pending, by the partner, not completed');
        assert(r.json.release.account_id === a.account_id && r.json.release.external_ref === `conf-rel-${run}`, 'account_id or external_ref is wrong');
        assert(!r.text.includes(releaseEmail), 'the answer carries the address');
        const again = await partner('POST', path, { email: releaseEmail });
        assert(again.status === 202 && again.json.release.status === 'pending' && again.json.release.requested_at === r.json.release.requested_at, 'a repeat inside the resend window did not return the release that is pending');
        const got = await partner('GET', path);
        assert(got.status === 200 && got.json.release.status === 'pending', `reading the release answered ${got.status}`);
        const list = await partner('GET', '/v1/partner/releases');
        assert(list.json.releases.some((x) => x.account_id === a.account_id && x.status === 'pending'), 'the release is not listed');
        const cancelled = await partner('DELETE', path);
        assert(cancelled.status === 200 && cancelled.json?.cancelled === true, `withdrawing answered ${cancelled.status} ${cancelled.text.slice(0, 80)}`);
        const after = await partner('GET', path);
        assert(after.json.release.status === 'cancelled', `the withdrawn release reads ${after.json.release?.status}`);
        assert((await partner('DELETE', path)).json?.cancelled === false, 'withdrawing again did not answer cancelled false');
        const account = await partner('GET', `/v1/partner/accounts/${a.account_id}`);
        assert(account.status === 200 && account.json.status === 'active', 'the account is not the partner\'s and active after a release was withdrawn');
      },
    },
    {
      id: 'P33', level: 'MUST', title: 'a claim that completes moves the account: it is 404 for the partner, its old key is refused, the release reads completed, and the reference is free again',
      async run() {
        const skipped = handle(releaseEmail && completeClaim, 'needs releaseEmail and completeClaim: a mailbox you own and a way to complete a claim on a test instance');
        if (skipped) return skipped;
        if (!(await releasesSupported())) return skip(NO_RELEASES);
        const ref = `conf-claimed-${run}`;
        const a = await open(ref);
        // What the partner sets up before the claim is judged after it (P35): a webhook of its own, which takes events now.
        const agent = await agentOf(a);
        state.claimedWebhook = undefined;
        if (agent !== null) {
          const made = await partner('POST', `/v1/partner/accounts/${a.account_id}/inbound-webhooks`, { provider: 'generic', agent_id: agent, forward_url: null });
          assert(made.status === 201, `creating a webhook answered ${made.status}: ${made.text.slice(0, 160)}`);
          const path = new URL(made.json.webhook_url).pathname;
          const secret = made.json.incoming_signing_secret;
          const post = (text) => api('POST', path, { raw: text, headers: { 'x-webhook-signature': `sha256=${createHmac('sha256', secret).update(text).digest('hex')}` } });
          const before = await post(JSON.stringify({ id: `evt_claimed_${run}`, text: 'Conformance check: before the claim.' }));
          assert(before.status === 200, `the partner's webhook answered ${before.status} before the claim`);
          state.claimedWebhook = { post, run };
        }
        const released = await partner('POST', `/v1/partner/accounts/${a.account_id}/release`, { email: releaseEmail });
        assert(released.status === 202, `release answered ${released.status}`);
        await completeClaim({ accountId: a.account_id, externalRef: ref });
        expectError(await partner('GET', `/v1/partner/accounts/${a.account_id}`), 404, 'NOT_FOUND', 'an account the customer claimed');
        const old = await api('GET', '/v1/agents', { key: a.api_key });
        assert(old.status === 401 || old.status === 403, `the key of a claimed account answered ${old.status}: the partner's access must end with the move`);
        expectError(await partner('POST', `/v1/partner/accounts/${a.account_id}/inbound-webhooks`, { provider: 'generic', agent_id: 'agt_00000000000000000000000000000001' }), 404, 'NOT_FOUND', 'a webhook under a claimed account');
        const got = await partner('GET', `/v1/partner/accounts/${a.account_id}/release`);
        assert(got.status === 200, `the partner's record of the release answered ${got.status}`);
        assertRelease(got.json.release, 'the completed release');
        assert(got.json.release.status === 'completed' && ISO.test(got.json.release.completed_at), `the release reads ${got.json.release.status}, completed_at ${got.json.release.completed_at}`);
        assert((await partner('GET', '/v1/partner/releases')).json.releases.some((x) => x.account_id === a.account_id && x.status === 'completed'), 'the completed release is not listed');
        assert(!(await partner('GET', '/v1/partner/accounts')).json.accounts.some((x) => x.account_id === a.account_id), 'a claimed account is still in the partner\'s list');
        const again = await partner('POST', '/v1/partner/accounts', { external_ref: ref });
        assert(again.status === 201 && again.json.account_id !== a.account_id, `opening under the reference of a claimed account answered ${again.status}: the reference is free again`);
        state.accounts.push(again.json.account_id);
      },
    },
    {
      id: 'P34', level: 'MUST', title: 'a claim that does not clear leaves the account with the partner: it reads returned with no reason, the key still works, and the account can be released again',
      async run() {
        const skipped = handle(releaseEmail && failClaim, 'needs releaseEmail and failClaim: a mailbox you own and a way to fail a claim on a test instance');
        if (skipped) return skipped;
        if (!(await releasesSupported())) return skip(NO_RELEASES);
        const ref = `conf-returned-${run}`;
        const a = await open(ref);
        const path = `/v1/partner/accounts/${a.account_id}/release`;
        assert((await partner('POST', path, { email: releaseEmail })).status === 202, 'release was not accepted');
        await failClaim({ accountId: a.account_id, externalRef: ref });
        const got = await partner('GET', path);
        assert(got.status === 200, `reading the release answered ${got.status}`);
        assertRelease(got.json.release, 'the returned release');
        assert(got.json.release.status === 'returned' && got.json.release.completed_at === null, `the release reads ${got.json.release.status}`);
        const account = await partner('GET', `/v1/partner/accounts/${a.account_id}`);
        assert(account.status === 200 && account.json.status === 'active', 'the account is not the partner\'s and active after a claim that did not clear');
        assert((await api('GET', '/v1/agents', { key: a.api_key })).status === 200, 'the account key stopped working after a claim that did not clear');
        const again = await partner('POST', path, { email: releaseEmail });
        assert(again.status === 202 && again.json.release.status === 'pending', `releasing again answered ${again.status}`);
        await partner('DELETE', path);
      },
    },

    {
      id: 'P35', level: 'MUST', title: 'what the partner set up in an account does not outlive the claim: the webhook it created in P33 takes events before the claim and answers 404 at its receiver after it',
      async run() {
        const skipped = handle(releaseEmail && completeClaim, 'needs releaseEmail and completeClaim: a mailbox you own and a way to complete a claim on a test instance');
        if (skipped) return skipped;
        if (!(await releasesSupported())) return skip(NO_RELEASES);
        if (!state.claimedWebhook) return skip(NO_AGENT);
        const after = await state.claimedWebhook.post(JSON.stringify({ id: `evt_claimed_after_${state.claimedWebhook.run}`, text: 'Conformance check: after the claim.' }));
        assert(after.status === 404, `the receiver of a webhook the partner created answered ${after.status} after the claim: a claim must close what the partner set up, so the customer starts with none of it`);
      },
    },

    // ─── an account's inbound webhooks ───
    {
      id: 'P50', level: 'MUST', title: 'creates an inbound webhook under an account: 201 with the URL, the downstream secret and the incoming secret once, and no secret afterwards',
      async run() {
        const a = await ensureAccount();
        const agent = await ensureAccountAgent();
        if (agent === null) return skip(NO_AGENT);
        const r = await partner('POST', `/v1/partner/accounts/${a.account_id}/inbound-webhooks`, { provider: 'generic', agent_id: agent, forward_url: null });
        assert(r.status === 201, `create answered ${r.status}: ${r.text.slice(0, 160)}`);
        const w = r.json;
        assert(/^iwh_/.test(w.id) && typeof w.slug === 'string' && w.provider === 'generic', 'id, slug or provider is wrong');
        assert(typeof w.webhook_url === 'string' && w.webhook_url.includes(`/v1/inbound/generic/${w.slug}`), `webhook_url ${w.webhook_url}`);
        assert(typeof w.webhook_secret === 'string' && w.webhook_secret.startsWith('whsec_'), 'webhook_secret is not a whsec_ secret');
        assert(typeof w.incoming_signing_secret === 'string' && w.incoming_signing_secret.length >= 32, 'a generic webhook has no incoming_signing_secret');
        assert(w.incoming_signing_secret !== w.webhook_secret, 'the incoming and downstream secrets are the same');
        assert(w.agent_id === agent && w.forward_url === null && typeof w.signing_configured === 'boolean' && ISO.test(w.created_at), 'agent_id, forward_url, signing_configured or created_at is wrong');
        a.webhook = w;
        const list = await partner('GET', `/v1/partner/accounts/${a.account_id}/inbound-webhooks`);
        assert(list.status === 200 && Array.isArray(list.json?.webhooks) && list.json.webhooks.some((x) => x.id === w.id), 'the webhook is not listed');
        assert(!list.text.includes(w.webhook_secret) && !list.text.includes(w.incoming_signing_secret), 'the list carries a secret');
      },
    },
    {
      id: 'P51', level: 'MUST', title: 'refuses a webhook for an agent that is not the account\'s (404), a provider that does not exist, a body that is not valid, and a forward address that is not public',
      async run() {
        const a = await ensureAccount();
        const agent = await ensureAccountAgent();
        if (agent === null) return skip(NO_AGENT);
        const path = `/v1/partner/accounts/${a.account_id}/inbound-webhooks`;
        expectError(await partner('POST', path, { provider: 'generic', agent_id: 'agt_00000000000000000000000000000000' }), 404, 'NOT_FOUND', 'a foreign agent');
        expectError(await partner('POST', path, { provider: 'generic' }), 400, 'VALIDATION_ERROR', 'no agent');
        expectError(await partner('POST', path, { provider: 'no-such-provider', agent_id: agent }), 400, 'VALIDATION_ERROR', 'an unknown provider');
        const toPrivate = await partner('POST', path, { provider: 'generic', agent_id: agent, forward_url: 'http://127.0.0.1:1/forward' });
        assert(toPrivate.status >= 400 && toPrivate.status < 500, `a forward address on loopback answered ${toPrivate.status}`);
        expectError(await partner('POST', `/v1/partner/accounts/${NONE}/inbound-webhooks`, { provider: 'generic', agent_id: agent }), 404, 'NOT_FOUND', 'a webhook under an account that is not the partner\'s');
      },
    },
    {
      id: 'P52', level: 'MUST', title: 'the receiver of the webhook URL takes a signed request, answers a repeat as deduplicated, and refuses a bad signature (400) and an unknown slug (404)',
      async run() {
        const a = await ensureAccount();
        if (!a.webhook) await checks.find((c) => c.id === 'P50').run();
        if (!a.webhook) return skip(NO_AGENT);
        const w = a.webhook;
        const path = new URL(w.webhook_url).pathname;
        const body = JSON.stringify({ id: `evt_${run}`, text: 'Conformance check: hello.' });
        const sign = (secret, text = body) => `sha256=${createHmac('sha256', secret).update(text).digest('hex')}`;
        const post = (p, signature, text = body) => api('POST', p, { raw: text, headers: signature ? { 'x-webhook-signature': signature } : {} });

        const bad = await post(path, sign('not-the-secret'));
        assert(bad.status === 400, `a bad signature answered ${bad.status}`);
        const none = await post(path, undefined);
        assert(none.status === 400, `no signature answered ${none.status}`);
        const first = await post(path, sign(w.incoming_signing_secret));
        assert(first.status === 200 && first.json?.decision === 'clean' && first.json.forwarded === false, `a signed request answered ${first.status} ${first.text.slice(0, 160)}`);
        const repeat = await post(path, sign(w.incoming_signing_secret));
        assert(repeat.status === 200 && repeat.json?.decision === 'deduplicated', `a repeat answered ${repeat.status} ${repeat.text.slice(0, 160)}`);
        const unknown = await post(path.replace(w.slug, 'no-such-slug-conformance'), sign(w.incoming_signing_secret));
        assert(unknown.status === 404, `an unknown slug answered ${unknown.status}`);
      },
    },
    {
      id: 'P53', level: 'MUST', title: 'revokes an account\'s webhook: { transitioned: true } then false, and the receiver answers 404 from then on',
      async run() {
        const a = await ensureAccount();
        if (!a.webhook) await checks.find((c) => c.id === 'P50').run();
        if (!a.webhook) return skip(NO_AGENT);
        const w = a.webhook;
        const del = (id) => partner('DELETE', `/v1/partner/accounts/${a.account_id}/inbound-webhooks/${id}`);
        const first = await del(w.id);
        assert(first.status === 200 && first.json?.transitioned === true, `revoke answered ${first.status} ${first.text.slice(0, 100)}`);
        const again = await del(w.id);
        assert(again.status === 200 && again.json?.transitioned === false, `a second revoke answered ${again.status} ${again.text.slice(0, 100)}`);
        const body = JSON.stringify({ id: `evt2_${run}` });
        const after = await api('POST', new URL(w.webhook_url).pathname, { raw: body, headers: { 'x-webhook-signature': `sha256=${createHmac('sha256', w.incoming_signing_secret).update(body).digest('hex')}` } });
        assert(after.status === 404, `a revoked webhook's receiver answered ${after.status}`);
        expectError(await del('iwh_00000000000000000000000000000000'), 404, 'NOT_FOUND', 'revoking an unknown webhook');
        a.webhook = undefined;
      },
    },

    // ─── passports under an account ───
    {
      id: 'P60', level: 'MUST', title: 'issues a passport under an account for a live Mission the account opened: 201 with token, jti and expires_at',
      async run() {
        const a = await ensureAccount();
        const agent = await ensureAccountAgent();
        if (agent === null) return skip(NO_AGENT);
        const mission = await api('POST', '/v1/missions', { key: a.api_key, body: { agent_id: agent, intent_summary: 'Conformance check' } });
        assert(mission.status === 201 && /^ms_/.test(mission.json?.mission_id ?? ''), `opening a Mission with the account's key answered ${mission.status}: ${mission.text.slice(0, 140)}`);
        a.mission = mission.json.mission_id;
        const r = await partner('POST', `/v1/partner/accounts/${a.account_id}/passports/issue`, {
          agent_id: agent,
          mission_ids: [a.mission],
          ttl_seconds: 300,
          // The agent has the default accountability, which asks what it will do.
          intent: { summary: 'Conformance check: nothing is done.', services: [] },
        });
        assert(r.status === 201, `issue answered ${r.status}: ${r.text.slice(0, 160)}`);
        assert(typeof r.json.token === 'string' && JWT.test(r.json.token), 'token is not a compact JWS');
        assert(typeof r.json.jti === 'string' && typeof r.json.expires_at === 'string', 'jti or expires_at is missing');
        a.passport = r.json;
      },
    },
    {
      id: 'P61', level: 'MUST', title: 'refuses a passport without exactly one Mission, for an agent that is not the account\'s, and under an account that is not the partner\'s',
      async run() {
        const a = await ensureAccount();
        // Refusals that come before the agent is looked at need no real one.
        const agent = (await ensureAccountAgent()) ?? 'agt_00000000000000000000000000000001';
        const path = `/v1/partner/accounts/${a.account_id}/passports/issue`;
        expectError(await partner('POST', path, { agent_id: agent }), 400, undefined, 'no Mission');
        expectError(await partner('POST', path, { agent_id: agent, mission_ids: [] }), 400, undefined, 'an empty Mission list');
        const foreign = await partner('POST', path, { agent_id: 'agt_00000000000000000000000000000000', mission_ids: [a.mission ?? 'ms_00000000000000000000000000000000'] });
        assert(foreign.status === 404 || foreign.status === 403, `a foreign agent answered ${foreign.status}`);
        expectError(await partner('POST', `/v1/partner/accounts/${NONE}/passports/issue`, { agent_id: agent, mission_ids: ['ms_00000000000000000000000000000000'] }), 404, 'NOT_FOUND', 'an account that is not the partner\'s');
      },
    },

    // ─── closing an account ───
    {
      id: 'P70', level: 'MUST', title: 'closes an account with its cascade: { transitioned, webhooks_revoked, passports_revoked }, its key is refused from then on, and a retry answers transitioned false',
      async run() {
        const a = await ensureAccount();
        const agent = await ensureAccountAgent();
        if (agent !== null) {
          const hook = await partner('POST', `/v1/partner/accounts/${a.account_id}/inbound-webhooks`, { provider: 'generic', agent_id: agent, forward_url: null });
          assert(hook.status === 201, `creating a webhook answered ${hook.status}`);
        }
        const first = await partner('DELETE', `/v1/partner/accounts/${a.account_id}`);
        assert(first.status === 200 && first.json?.transitioned === true, `revoke answered ${first.status} ${first.text.slice(0, 100)}`);
        assert(Number.isInteger(first.json.webhooks_revoked), 'webhooks_revoked is not a number');
        if (agent !== null) assert(first.json.webhooks_revoked >= 1, `webhooks_revoked is ${first.json.webhooks_revoked}`);
        assert(Number.isInteger(first.json.passports_revoked), 'passports_revoked is not a number');
        if (a.passport) assert(first.json.passports_revoked >= 1, `passports_revoked is ${first.json.passports_revoked}, a passport was issued`);
        const refused = await api('GET', '/v1/agents', { key: a.api_key });
        assert(refused.status === 401 || refused.status === 403, `a closed account's key answered ${refused.status}: it must be refused (STACK answers 403 OPERATOR_DELETED)`);
        assert(refused.json?.error && typeof refused.json.error.code === 'string', 'the refusal is not in the error shape');
        const again = await partner('DELETE', `/v1/partner/accounts/${a.account_id}`);
        assert(again.status === 200 && again.json?.transitioned === false && again.json.webhooks_revoked === 0, `a retry answered ${again.status} ${again.text.slice(0, 100)}`);
        const got = await partner('GET', `/v1/partner/accounts/${a.account_id}`);
        assert(got.status === 200 && got.json.status !== 'active' && got.json.deleted_at !== null, 'the closed account still reads active');
        const afterHook = await partner('POST', `/v1/partner/accounts/${a.account_id}/inbound-webhooks`, { provider: 'generic', agent_id: agent ?? 'agt_00000000000000000000000000000001' });
        assert(afterHook.status >= 400 && afterHook.status < 500, `a webhook under a closed account answered ${afterHook.status}`);
        const reuse = await partner('POST', '/v1/partner/accounts', { external_ref: `conf-${run}` });
        expectError(reuse, 409, 'CONFLICT', 'the reference of a closed account');
        state.accounts = state.accounts.filter((id) => id !== a.account_id);
      },
    },
  ];

  const report = await runChecks('partner api', checks);

  // Leave nothing behind.
  for (const id of state.accounts) {
    try {
      await partner('DELETE', `/v1/partner/accounts/${id}`);
    } catch {
      // Already closed.
    }
  }
  return report;
}
