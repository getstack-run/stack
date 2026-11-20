import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import {
  AccountCallFailedError,
  AccountPieceNotReadyError,
  EmailAttachmentsTooLargeError,
  EmailMessageNotAnswerableError,
  AgentBudgetExceededError,
  DestinationNotAvailableError,
  GovernanceApprovalRequiredError,
  ProviderCapacityUnavailableError,
  BrowserTimeUsedUpError,
  BrowserSessionLengthRefusedError,
  StackError,
  ToolPriceRefusedError,
  ToolRunRejectedError,
  ToolsUnavailableError,
  BudgetNeedsControlsError,
  PlatformSubscriptionRequiredError,
  RecipientOptedOutError,
  SharedMailDailyLimitError,
  UnboundedSendRuleError,
} from '../errors.js';

interface Sent {
  method: string;
  path: string;
  search: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(reply: { status: number; body?: unknown } = { status: 200, body: {} }): Sent[] {
  const calls: Sent[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      const parsed = new URL(url);
      calls.push({
        method: init.method ?? 'GET',
        path: parsed.pathname,
        search: parsed.search,
        body: init.body ? JSON.parse(init.body) : undefined,
        headers: init.headers ?? {},
      });
      if (reply.status === 204) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(reply.body ?? {}), {
        status: reply.status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return calls;
}

const stack = () => new Stack({ apiKey: 'sk_live_accounts_test', baseUrl: 'http://api.fixture' });
const ACCOUNT = 'acct_0123456789abcdef0123456789abcdef';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('AccountsService', () => {
  it('opens with the Idempotency-Key and, on retry, the governance approval', async () => {
    const calls = stubFetch({ status: 201, body: { id: ACCOUNT } });
    await stack().accounts.open(
      { name: 'research-agent', monthly_budget_cents: 5000 },
      { idempotencyKey: 'open-key-0001', governanceApprovalId: 'gvr_1' },
    );
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: '/v1/accounts',
      body: { name: 'research-agent', monthly_budget_cents: 5000 },
    });
    expect(calls[0]!.headers['Idempotency-Key']).toBe('open-key-0001');
    expect(calls[0]!.headers['X-Governance-Approval']).toBe('gvr_1');
  });

  it('opens without a budget and without an approval header', async () => {
    const calls = stubFetch({ status: 201, body: { id: ACCOUNT } });
    await stack().accounts.open({ name: 'plain-agent' }, { idempotencyKey: 'open-key-0003' });
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/v1/accounts', body: { name: 'plain-agent' } });
    expect(calls[0]!.headers['X-Governance-Approval']).toBeUndefined();
  });

  it('refuses to open without an idempotency key the API accepts', async () => {
    const calls = stubFetch();
    await expect(
      stack().accounts.open({ name: 'a', monthly_budget_cents: 100 }, { idempotencyKey: 'short' }),
    ).rejects.toThrow(/idempotencyKey/);
    expect(calls).toHaveLength(0);
  });

  it('throws GovernanceApprovalRequiredError carrying the approval link', async () => {
    stubFetch({
      status: 403,
      body: {
        error: {
          code: 'GOVERNANCE_APPROVAL_REQUIRED',
          message: 'This action loosens a safety control and requires human approval.',
          details: { approval_id: 'gvr_2', approval_url: 'https://getstack.run/app/approve/gvr_2' },
        },
      },
    });
    const error = await stack()
      .accounts.open({ name: 'a', monthly_budget_cents: 100 }, { idempotencyKey: 'open-key-0002' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(GovernanceApprovalRequiredError);
    expect(error).toBeInstanceOf(StackError);
    const approval = error as GovernanceApprovalRequiredError;
    expect(approval.code).toBe('GOVERNANCE_APPROVAL_REQUIRED');
    expect(approval.status).toBe(403);
    expect(approval.approvalId).toBe('gvr_2');
    expect(approval.approvalUrl).toBe('https://getstack.run/app/approve/gvr_2');
  });

  it('throws AccountPieceNotReadyError naming the piece and its state', async () => {
    stubFetch({
      status: 409,
      body: {
        error: {
          code: 'ACCOUNT_PIECE_NOT_READY',
          message: "The agent account's inbox is pending.",
          details: { account_id: ACCOUNT, piece: 'inbox', state: 'pending' },
        },
      },
    });
    const error = await stack()
      .accounts.sendEmail(ACCOUNT, { to: 'a@example.test', subject: 'Hi', body: 'Hello' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AccountPieceNotReadyError);
    expect(error).toMatchObject({ accountId: ACCOUNT, piece: 'inbox', state: 'pending', status: 409 });
  });

  it('throws AgentBudgetExceededError with the remaining budget', async () => {
    stubFetch({
      status: 402,
      body: {
        error: {
          code: 'AGENT_BUDGET_EXCEEDED',
          message: 'This agent has reached its monthly budget.',
          details: { account_id: ACCOUNT, remaining_cents: 12 },
        },
      },
    });
    const error = await stack()
      .accounts.workspace.exec(ACCOUNT, { command: 'ls' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AgentBudgetExceededError);
    expect(error).toMatchObject({ accountId: ACCOUNT, remainingCents: 12, status: 402 });
  });

  it('keeps other errors as plain StackError', async () => {
    stubFetch({ status: 404, body: { error: { code: 'NOT_FOUND', message: 'account not found' } } });
    const error = await stack().accounts.get(ACCOUNT).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StackError);
    expect(error).not.toBeInstanceOf(GovernanceApprovalRequiredError);
    expect((error as StackError).code).toBe('NOT_FOUND');
  });

  it('reads, lists and closes', async () => {
    const calls = stubFetch({ status: 200, body: [] });
    const accounts = stack().accounts;
    await accounts.list({ limit: 10 });
    await accounts.get(ACCOUNT);
    await accounts.close(ACCOUNT);
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      'GET /v1/accounts?limit=10',
      `GET /v1/accounts/${ACCOUNT}`,
      `DELETE /v1/accounts/${ACCOUNT}`,
    ]);
  });

  it('reads and deletes messages, with the query in the query string', async () => {
    const calls = stubFetch({ status: 200, body: { messages: [], next_cursor: null } });
    const accounts = stack().accounts;
    await accounts.messages.list(ACCOUNT, { limit: 5, cursor: 'c1', channel: 'sms' });
    await accounts.messages.get(ACCOUNT, 'amsg_1');
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      `GET /v1/accounts/${ACCOUNT}/messages?limit=5&cursor=c1&channel=sms`,
      `GET /v1/accounts/${ACCOUNT}/messages/amsg_1`,
    ]);
    vi.unstubAllGlobals();
    const deletes = stubFetch({ status: 204 });
    await expect(accounts.messages.delete(ACCOUNT, 'amsg_1')).resolves.toBeUndefined();
    expect(deletes[0]).toMatchObject({ method: 'DELETE', path: `/v1/accounts/${ACCOUNT}/messages/amsg_1` });
  });

  it('searches every readable message with the filters in the query string, and reads an attachment through its message', async () => {
    const calls = stubFetch({ status: 200, body: { messages: [], next_cursor: null, window: { after: 'a', before: 'b' } } });
    const accounts = stack().accounts;
    await accounts.messages.search({ agentId: 'agt_one', channel: 'email', sender: 'a@example.com', threadId: 'th1', q: 'invoice', limit: 10 });
    await accounts.messages.search();
    await accounts.messages.readAttachment(ACCOUNT, 'amsg_1', 'file/1', { passportToken: 'pp' });
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      'GET /v1/messages?agent_id=agt_one&channel=email&sender=a%40example.com&thread_id=th1&q=invoice&limit=10',
      'GET /v1/messages',
      `GET /v1/accounts/${ACCOUNT}/messages/amsg_1/attachments/file%2F1`,
    ]);
    expect(JSON.stringify(calls[2]?.headers)).toContain('pp');
  });

  it('sends texts with the number in the body, never the URL', async () => {
    const calls = stubFetch();
    const accounts = stack().accounts;
    await accounts.sendSms(ACCOUNT, { to: '+14155550123', body: 'Hi' });
    await accounts.resumePiece(ACCOUNT, 'phone');
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['POST', `/v1/accounts/${ACCOUNT}/sms/send`, { to: '+14155550123', body: 'Hi' }],
      ['POST', `/v1/accounts/${ACCOUNT}/pieces/resume`, { piece: 'phone' }],
    ]);
  });

  it('sends reply_to_message in the body of an email, a text and a call', async () => {
    const calls = stubFetch();
    const accounts = stack().accounts;
    await accounts.sendEmail(ACCOUNT, { to: 'a@example.test', subject: 'Re: Hi', body: 'Hello', reply_to_message: 'amsg_1' });
    await accounts.sendSms(ACCOUNT, { to: '+14155550123', body: 'Hi', reply_to_message: 'amsg_2' });
    await accounts.calls.place(ACCOUNT, { to: '+14155550123', greeting: 'Hi', reply_to_message: 'amsg_3' });
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['POST', `/v1/accounts/${ACCOUNT}/email/send`, { to: 'a@example.test', subject: 'Re: Hi', body: 'Hello', reply_to_message: 'amsg_1' }],
      ['POST', `/v1/accounts/${ACCOUNT}/sms/send`, { to: '+14155550123', body: 'Hi', reply_to_message: 'amsg_2' }],
      ['POST', `/v1/accounts/${ACCOUNT}/calls`, { to: '+14155550123', greeting: 'Hi', reply_to_message: 'amsg_3' }],
    ]);
  });

  it('drives the browser and checkout on the account routes', async () => {
    const calls = stubFetch();
    const { browser, purchases } = stack().accounts;
    await browser.startSession(ACCOUNT);
    await browser.navigate(ACCOUNT, 'bws_1', { url: 'https://shop.example' });
    await browser.act(ACCOUNT, 'bws_1', { action: 'click', target: { role: 'button', name: 'Buy' } });
    await browser.read(ACCOUNT, 'bws_1');
    await browser.screenshot(ACCOUNT, 'bws_1');
    await browser.checkout(ACCOUNT, 'bws_1', { merchant_origin: 'https://shop.example', amount_minor: 1299, currency: 'USD' });
    await browser.endSession(ACCOUNT, 'bws_1');
    await purchases.get(ACCOUNT, 'pur_1');
    await purchases.reportMerchantResult(ACCOUNT, 'pur_1', { status: 'completed', order_id: 'o-1' });
    const base = `/v1/accounts/${ACCOUNT}`;
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `POST ${base}/browser/sessions`,
      `POST ${base}/browser/sessions/bws_1/navigate`,
      `POST ${base}/browser/sessions/bws_1/act`,
      `POST ${base}/browser/sessions/bws_1/read`,
      `POST ${base}/browser/sessions/bws_1/screenshot`,
      `POST ${base}/browser/sessions/bws_1/checkout`,
      `DELETE ${base}/browser/sessions/bws_1`,
      `GET ${base}/purchases/pur_1`,
      `POST ${base}/purchases/pur_1/merchant-result`,
    ]);
  });

  it('works in the workspace and pays from the wallet', async () => {
    const calls = stubFetch({ body: { workspaces: [] } });
    const accounts = stack().accounts;
    const agent = { passportToken: 'pas.jwt.token' };
    await accounts.workspace.exec(ACCOUNT, { command: 'ls', stack_access: true }, agent);
    await accounts.workspace.readFile(ACCOUNT, 'wsp_12345678', { path: 'a.txt' }, agent);
    await accounts.workspace.writeFile(ACCOUNT, 'wsp_12345678', { path: 'a.txt', content_text: 'x', mode: '755' }, agent);
    await accounts.workspace.saveFile(ACCOUNT, 'wsp_12345678', { path: 'a.csv' }, agent);
    expect(await accounts.workspace.list(ACCOUNT)).toEqual([]);
    expect(await accounts.workspace.list()).toEqual([]);
    await accounts.workspace.setSharing(ACCOUNT, 'wsp_12345678', false);
    await accounts.workspace.stop(ACCOUNT, 'wsp_12345678', { delete: true });
    await accounts.workspace.getSettings();
    await accounts.workspace.getSettings(ACCOUNT);
    await accounts.workspace.setSettings({ idle_pause_minutes: 0, delete_after_days: 30 });
    await accounts.workspace.setSettings({ max_workspaces: 5, idle_pause_minutes: null }, ACCOUNT);
    await accounts.wallet.pay(ACCOUNT, { typed_data: { primaryType: 'TransferWithAuthorization' }, agent_signature: 'sig' });
    await accounts.wallet.ownerStatus();
    const base = `/v1/accounts/${ACCOUNT}/workspaces`;
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `POST ${base}/exec`,
      `POST ${base}/wsp_12345678/files/read`,
      `POST ${base}/wsp_12345678/files/write`,
      `POST ${base}/wsp_12345678/files/save`,
      `GET ${base}`,
      'GET /v1/workspaces',
      `PUT ${base}/wsp_12345678/sharing`,
      `POST ${base}/wsp_12345678/stop`,
      'GET /v1/workspace/settings',
      `GET /v1/accounts/${ACCOUNT}/workspace/settings`,
      'PUT /v1/workspace/settings',
      `PUT /v1/accounts/${ACCOUNT}/workspace/settings`,
      `POST /v1/accounts/${ACCOUNT}/wallet/payments`,
      'GET /v1/accounts/wallet-owner',
    ]);
    // The settings are sent as written: 0 is "off" and "never", null clears, and nothing else is added.
    expect(calls.slice(-4, -2).map((c) => c.body)).toEqual([
      { idle_pause_minutes: 0, delete_after_days: 30 },
      { max_workspaces: 5, idle_pause_minutes: null },
    ]);
  });

  it("sends the agent's Passport as X-Passport-Token on agent calls, and nothing without one", async () => {
    const calls = stubFetch();
    const accounts = stack().accounts;
    const options = { passportToken: 'pas.jwt.token' };
    await accounts.messages.list(ACCOUNT, {}, options);
    await accounts.sendEmail(ACCOUNT, { to: 'a@example.test', subject: 'Hi', body: 'Hello' }, options);
    await accounts.browser.read(ACCOUNT, 'bws_1', options);
    await accounts.wallet.pay(ACCOUNT, { typed_data: {}, agent_signature: 'sig' }, options);
    await accounts.sendSms(ACCOUNT, { to: '+14155550123', body: 'Hi' });
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual([
      'pas.jwt.token', 'pas.jwt.token', 'pas.jwt.token', 'pas.jwt.token', undefined,
    ]);
  });

  it("sends the agent's Passport as the bearer credential of a wallet payment, and the client's own key without one", async () => {
    const calls = stubFetch();
    const accounts = stack().accounts;
    await accounts.wallet.pay(ACCOUNT, { typed_data: {}, agent_signature: 'sig' }, { passportToken: 'pas.jwt.token' });
    await accounts.wallet.pay(ACCOUNT, { typed_data: {}, agent_signature: 'sig' });
    await accounts.sendSms(ACCOUNT, { to: '+14155550123', body: 'Hi' }, { passportToken: 'pas.jwt.token' });
    expect(calls.map((c) => c.headers['Authorization'])).toEqual([
      'Bearer pas.jwt.token', 'Bearer sk_live_accounts_test', 'Bearer sk_live_accounts_test',
    ]);
  });

  it('encodes path segments', async () => {
    const calls = stubFetch();
    await stack().accounts.messages.get('acct_x/../y', 'm?1');
    expect(calls[0]!.path).toBe('/v1/accounts/acct_x%2F..%2Fy/messages/m%3F1');
  });
});

describe('AccountsService calls and tools', () => {
  const options = { passportToken: 'pas.jwt.token' };

  it('places, lists and reads calls, the number in the body and the Passport in its header', async () => {
    const calls = stubFetch({ status: 201, body: { call_id: 'acall_1' } });
    const accounts = stack().accounts;
    const call = { to: '+14155550123', on_behalf_of: 'Acme Dental', brief: 'Book a cleaning', max_seconds: 120 };
    await accounts.calls.place(ACCOUNT, call, options);
    await accounts.calls.list(ACCOUNT, { limit: 5, cursor: 'c1' }, options);
    await accounts.calls.get(ACCOUNT, 'acall_1', options);
    await accounts.calls.list(ACCOUNT);
    expect(calls.map((c) => `${c.method} ${c.path}${c.search}`)).toEqual([
      `POST /v1/accounts/${ACCOUNT}/calls`,
      `GET /v1/accounts/${ACCOUNT}/calls?limit=5&cursor=c1`,
      `GET /v1/accounts/${ACCOUNT}/calls/acall_1`,
      `GET /v1/accounts/${ACCOUNT}/calls`,
    ]);
    expect(calls[0]!.body).toEqual(call);
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual(['pas.jwt.token', 'pas.jwt.token', 'pas.jwt.token', undefined]);
  });

  it('answers a ringing call with the brief in the body, and declines it with none', async () => {
    const calls = stubFetch({ status: 200, body: { call_id: 'acall_1', state: 'in_progress', decision: 'answered' } });
    const accounts = stack().accounts;
    const brief = { greeting: 'Acme Dental.', max_seconds: 300, wait_seconds: 15 };
    const answered = await accounts.calls.answer(ACCOUNT, 'acall_1', brief, options);
    await accounts.calls.decline(ACCOUNT, 'acall_2', options);
    await accounts.calls.decline(ACCOUNT, 'acall_x/../y');
    expect(answered).toMatchObject({ call_id: 'acall_1', decision: 'answered' });
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/answer`, brief],
      ['POST', `/v1/accounts/${ACCOUNT}/calls/acall_2/decline`, undefined],
      ['POST', `/v1/accounts/${ACCOUNT}/calls/acall_x%2F..%2Fy/decline`, undefined],
    ]);
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual(['pas.jwt.token', 'pas.jwt.token', undefined]);
  });

  it('speaks, presses keys, changes the voice and hangs up a live call, and reads and sets the account voice', async () => {
    const calls = stubFetch({ status: 200, body: { call: { call_id: 'acall_1' }, events: [] } });
    const accounts = stack().accounts;
    await accounts.calls.say(ACCOUNT, 'acall_1', { text: 'Hello?', wait_seconds: 5 }, options);
    await accounts.calls.say(ACCOUNT, 'acall_1');
    await accounts.calls.pressKeys(ACCOUNT, 'acall_1', '1w#', options);
    await accounts.calls.setCallVoice(ACCOUNT, 'acall_1', { language: 'fr-FR' });
    await accounts.calls.hangUp(ACCOUNT, 'acall_1', options);
    await accounts.calls.getAccountVoice(ACCOUNT);
    await accounts.calls.setAccountVoice(ACCOUNT, { tts_provider: 'Google', voicemail_greeting: 'Leave a message.' }, options);
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/say`, { text: 'Hello?', wait_seconds: 5 }],
      ['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/say`, {}],
      ['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/keys`, { digits: '1w#' }],
      ['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/voice`, { voice: { language: 'fr-FR' } }],
      ['POST', `/v1/accounts/${ACCOUNT}/calls/acall_1/hang-up`, undefined],
      ['GET', `/v1/accounts/${ACCOUNT}/phone/voice`, undefined],
      ['PUT', `/v1/accounts/${ACCOUNT}/phone/voice`, { tts_provider: 'Google', voicemail_greeting: 'Leave a message.' }],
    ]);
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual(['pas.jwt.token', undefined, 'pas.jwt.token', undefined, 'pas.jwt.token', undefined, 'pas.jwt.token']);
  });

  it('opens the live stream with the credential, yields the events in order until the end, and streams words to the call', async () => {
    class FakeSocket {
      static last: FakeSocket;
      readyState = 0;
      sent: string[] = [];
      listeners: Record<string, ((event: { data?: unknown }) => void)[]> = {};
      constructor(readonly url: string, readonly init: { headers: Record<string, string> }) {
        FakeSocket.last = this;
        queueMicrotask(() => this.emit('open', {}));
      }
      addEventListener(type: string, listener: (event: { data?: unknown }) => void) {
        (this.listeners[type] ??= []).push(listener);
      }
      emit(type: string, event: { data?: unknown }) {
        for (const listener of this.listeners[type] ?? []) listener(event);
      }
      send(data: string) {
        this.sent.push(data);
      }
      close() {
        this.emit('close', {});
      }
    }
    const stream = await new Stack({ apiKey: 'sk_live_test', baseUrl: 'https://api.example.test' }).accounts.calls.live(
      ACCOUNT, 'acall_1', { passportToken: 'pas.jwt.token', webSocket: FakeSocket as never },
    );
    const socket = FakeSocket.last;
    expect(socket.url).toBe(`wss://api.example.test/v1/accounts/${ACCOUNT}/calls/acall_1/live`);
    expect(socket.init.headers).toEqual({ Authorization: 'Bearer sk_live_test', 'X-Passport-Token': 'pas.jwt.token' });
    await stream.text('Hello, ');
    await stream.text('is this Sam?', true);
    await stream.pressKeys('1');
    await stream.hangUp();
    expect(socket.sent.map((m) => JSON.parse(m))).toEqual([
      { type: 'text', token: 'Hello, ', last: false },
      { type: 'text', token: 'is this Sam?', last: true },
      { type: 'keys', digits: '1' },
      { type: 'hang_up' },
    ]);
    socket.emit('message', { data: JSON.stringify({ seq: 1, at: 't', type: 'heard', text: 'Yes.' }) });
    socket.emit('message', { data: JSON.stringify({ type: 'error', code: 'VALIDATION_ERROR', message: 'no' }) });
    socket.emit('message', { data: JSON.stringify({ seq: 2, at: 't', type: 'ended', reason: 'agent_hung_up' }) });
    socket.close();
    const seen = [];
    for await (const event of stream.events()) seen.push(event);
    expect(seen).toEqual([{ seq: 1, at: 't', type: 'heard', text: 'Yes.' }, { seq: 2, at: 't', type: 'ended', reason: 'agent_hung_up' }]);
    expect(stream.errors).toEqual([{ code: 'VALIDATION_ERROR', message: 'no' }]);
  });

  it('throws the API error of a call that is not ringing any more', async () => {
    stubFetch({ status: 409, body: { error: { code: 'CALL_NOT_RINGING', message: 'That call is not ringing any more. Read the call to see what happened to it.' } } });
    await expect(stack().accounts.calls.decline(ACCOUNT, 'acall_1', options)).rejects.toMatchObject({ code: 'CALL_NOT_RINGING', status: 409 });
  });

  it('maps RECIPIENT_OPTED_OUT on a text to its typed error', async () => {
    stubFetch({ status: 403, body: { error: { code: 'RECIPIENT_OPTED_OUT', message: 'asked not to be contacted', details: { account_id: ACCOUNT } } } });
    const error = await stack().accounts.sendSms(ACCOUNT, { to: '+14155550123', body: 'Hi' }, options).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RecipientOptedOutError);
    expect(error).toMatchObject({ code: 'RECIPIENT_OPTED_OUT', status: 403, accountId: ACCOUNT });
  });

  it('lists the do-not-contact numbers and removes one by its id', async () => {
    const calls = stubFetch({ status: 200, body: { opt_outs: [], removed: true } });
    const accounts = stack().accounts;
    await accounts.optOuts.list();
    await accounts.optOuts.add('+14155550123');
    await accounts.optOuts.remove('aoo_abc123');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(['GET /v1/opt-outs', 'POST /v1/opt-outs', 'DELETE /v1/opt-outs/aoo_abc123']);
    expect(calls[1]!.body).toEqual({ number: '+14155550123' });
  });

  it('lists the blocked callers, adds one by its number and removes one by its id', async () => {
    const calls = stubFetch({ status: 200, body: { blocked_callers: [], removed: true } });
    const accounts = stack().accounts;
    await accounts.blockedCallers.list();
    await accounts.blockedCallers.add('+14155550123');
    await accounts.blockedCallers.remove('abk_abc123');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(['GET /v1/blocked-callers', 'POST /v1/blocked-callers', 'DELETE /v1/blocked-callers/abk_abc123']);
    expect(calls[1]!.body).toEqual({ number: '+14155550123' });
  });

  it('discovers, inspects, runs and reads paid tools under the Passport', async () => {
    const calls = stubFetch({ status: 200, body: { withheld: false, results: [] } });
    const { tools } = stack().accounts;
    await tools.discover(ACCOUNT, { query: 'tweets about rust', limit: 5 }, options);
    await tools.inspect(ACCOUNT, { provider: 'acme', endpoint: '/acme/search' }, options);
    await tools.run(ACCOUNT, { provider: 'acme', endpoint: '/acme/search', input: { q: 'rust' }, max_results: 20 }, options);
    await tools.getRun(ACCOUNT, 'atr_12345678');
    const base = `/v1/accounts/${ACCOUNT}/tools`;
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['POST', `${base}/discover`, { query: 'tweets about rust', limit: 5 }],
      ['POST', `${base}/inspect`, { provider: 'acme', endpoint: '/acme/search' }],
      ['POST', `${base}/run`, { provider: 'acme', endpoint: '/acme/search', input: { q: 'rust' }, max_results: 20 }],
      ['GET', `${base}/runs/atr_12345678`, undefined],
    ]);
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual(['pas.jwt.token', 'pas.jwt.token', 'pas.jwt.token', undefined]);
  });

  it('submits the toll-free verification with the approval on retry, and reads its status', async () => {
    const calls = stubFetch({ status: 201, body: { account_id: ACCOUNT, status: 'PENDING_REVIEW' } });
    const tollFree = stack().accounts.tollFreeVerification;
    const details = {
      business_name: 'Acme Dental',
      business_website: 'https://acme.example',
      business_type: 'SOLE_PROPRIETOR' as const,
      business_address: { street: '1 Main St', city: 'Austin', region: 'TX', postal_code: '78701', country: 'US' },
      contact: { first_name: 'Ada', last_name: 'Lee', email: 'ada@acme.example', phone: '+15125550123' },
      notification_email: 'ada@acme.example',
      use_case_categories: ['ACCOUNT_NOTIFICATIONS'],
      use_case_summary: 'Appointment reminders',
      production_message_sample: 'Your cleaning is tomorrow at 9.',
      opt_in_type: 'WEB_FORM' as const,
      opt_in_image_urls: ['https://acme.example/opt-in'],
      message_volume: '100',
      privacy_policy_url: 'https://acme.example/privacy',
      terms_and_conditions_url: 'https://acme.example/terms',
    };
    await tollFree.submit(ACCOUNT, details, { governanceApprovalId: 'gvr_5' });
    await tollFree.get(ACCOUNT);
    const path = `/v1/accounts/${ACCOUNT}/phone/toll-free-verification`;
    expect(calls.map((c) => [c.method, c.path, c.headers['X-Governance-Approval']])).toEqual([
      ['POST', path, 'gvr_5'],
      ['GET', path, undefined],
    ]);
    expect(calls[0]!.body).toEqual(details);
  });

  it('returns a pending tool run (202) as a run, not an error', async () => {
    stubFetch({ status: 202, body: { id: 'atr_12345678', state: 'pending' } });
    const run = await stack().accounts.tools.run(ACCOUNT, { provider: 'p', endpoint: '/p/e' }, options);
    expect(run).toMatchObject({ id: 'atr_12345678', state: 'pending' });
  });

  it('sends no governance approval on a resume', async () => {
    const calls = stubFetch();
    const accounts = stack().accounts;
    await accounts.resumePiece(ACCOUNT, 'inbox');
    expect(calls.map((c) => [c.path, c.body, c.headers['X-Governance-Approval']])).toEqual([
      [`/v1/accounts/${ACCOUNT}/pieces/resume`, { piece: 'inbox' }, undefined],
    ]);
  });

  it.each([
    ['PROVIDER_CAPACITY_UNAVAILABLE', 503, { provider: 'acme' }, ProviderCapacityUnavailableError, { provider: 'acme' }],
    ['BROWSER_TIME_USED_UP', 503, { provider: 'acme' }, BrowserTimeUsedUpError, { provider: 'acme' }],
    ['BROWSER_SESSION_LENGTH_REFUSED', 503, { provider: 'acme' }, BrowserSessionLengthRefusedError, { provider: 'acme' }],
    ['ACCOUNT_CALL_FAILED', 502, { reason: 'provider_unavailable' }, AccountCallFailedError, { reason: 'provider_unavailable', retryable: true }],
    ['ACCOUNT_CALL_FAILED', 422, { reason: 'provider_21216' }, AccountCallFailedError, { reason: 'provider_21216', retryable: false }],
    ['DESTINATION_NOT_AVAILABLE', 422, { reason: 'no_price' }, DestinationNotAvailableError, { reason: 'no_price' }],
    ['DESTINATION_NOT_AVAILABLE', 422, { reason: 'refused_by_twilio' }, DestinationNotAvailableError, { reason: 'refused_by_twilio' }],
    ['RECIPIENT_OPTED_OUT', 403, { account_id: ACCOUNT }, RecipientOptedOutError, { accountId: ACCOUNT }],
  ] as const)('maps %s (%i) on a call to its typed error', async (code, status, details, type, fields) => {
    stubFetch({ status, body: { error: { code, message: 'refused', details } } });
    const error = await stack()
      .accounts.calls.place(ACCOUNT, { to: '+14155550123' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(type);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({ code, status, ...fields });
  });

  it.each([
    ['TOOL_PRICE_REFUSED', 422, { reason: 'unbounded_price' }, ToolPriceRefusedError, { reason: 'unbounded_price' }],
    ['TOOLS_UNAVAILABLE', 503, { reason: 'tools_provider_unavailable' }, ToolsUnavailableError, { reason: 'tools_provider_unavailable' }],
    ['TOOL_RUN_REJECTED', 400, { provider_status: 422 }, ToolRunRejectedError, { providerStatus: 422 }],
  ] as const)('maps %s on a tool run to its typed error', async (code, status, details, type, fields) => {
    stubFetch({ status, body: { error: { code, message: 'refused', details } } });
    const error = await stack()
      .accounts.tools.run(ACCOUNT, { provider: 'p', endpoint: '/p/e' }, options)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(type);
    expect(error).toMatchObject({ code, status, ...fields });
  });

  it.each([
    ['BUDGET_NEEDS_CONTROLS', 403, {}, BudgetNeedsControlsError, {}],
    ['PLATFORM_SUBSCRIPTION_REQUIRED', 402, { status: 'lapsed' }, PlatformSubscriptionRequiredError, { subscriptionStatus: 'lapsed' }],
    [
      'UNBOUNDED_SEND_RULE',
      400,
      { rules: [{ rule_id: 'mail', connection_id: 'scon_x', provider: 'resend', reason: 'unbound_recipient', intents: ['resend.send_email'], unbound_paths: ['body.to', 'body.cc'] }] },
      UnboundedSendRuleError,
      { rules: [{ ruleId: 'mail', connectionId: 'scon_x', provider: 'resend', reason: 'unbound_recipient', intents: ['resend.send_email'], unboundPaths: ['body.to', 'body.cc'] }] },
    ],
  ] as const)('maps %s on an open to its typed error', async (code, status, details, type, fields) => {
    stubFetch({ status, body: { error: { code, message: 'refused', details } } });
    const error = await stack()
      .accounts.open({ name: 'a', monthly_budget_cents: 1_000 }, { idempotencyKey: 'open-key-0009' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(type);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({ code, status, ...fields });
  });

  it('maps SHARED_MAIL_DAILY_LIMIT on an email send to its typed error', async () => {
    stubFetch({ status: 429, body: { error: { code: 'SHARED_MAIL_DAILY_LIMIT', message: 'limit', details: { limit: 20 } } } });
    const error = await stack()
      .accounts.sendEmail(ACCOUNT, { to: 'a@example.test', subject: 's', body: 'b' }, options)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SharedMailDailyLimitError);
    expect(error).toMatchObject({ code: 'SHARED_MAIL_DAILY_LIMIT', status: 429, limit: 20 });
  });
});

describe('AccountsService mail domains', () => {
  const domain = {
    id: 'omd_abcdefgh1234',
    domain: 'mail.example.com',
    status: 'pending',
    records: [{ type: 'TXT', name: '_om.mail.example.com', value: 'v=1' }],
    warnings: [],
    verified_at: null,
    checked_at: null,
    created_at: '2026-10-01T00:00:00.000Z',
    claim_expires_at: '2026-10-08T00:00:00.000Z',
  };

  it('lists, connects with the domain in the body, and verifies by id', async () => {
    const calls = stubFetch({ status: 200, body: { domains: [domain] } });
    const mailDomains = stack().accounts.mailDomains;
    const listed = await mailDomains.list();
    await mailDomains.connect({ domain: 'mail.example.com' });
    await mailDomains.verify('omd_abcdefgh1234');
    expect(listed.domains[0]).toMatchObject({ id: 'omd_abcdefgh1234', claim_expires_at: '2026-10-08T00:00:00.000Z' });
    expect(calls.map((c) => [c.method, c.path, c.body])).toEqual([
      ['GET', '/v1/accounts/mail-domains', undefined],
      ['POST', '/v1/accounts/mail-domains', { domain: 'mail.example.com' }],
      ['POST', '/v1/accounts/mail-domains/omd_abcdefgh1234/verify', undefined],
    ]);
  });

  it('returns the connected domain from the 201 with its records', async () => {
    stubFetch({ status: 201, body: domain });
    const connected = await stack().accounts.mailDomains.connect({ domain: 'mail.example.com' });
    expect(connected.records).toEqual(domain.records);
    expect(connected.status).toBe('pending');
  });

  it('encodes the domain id in the path', async () => {
    const calls = stubFetch({ status: 200, body: domain });
    await stack().accounts.mailDomains.verify('omd_a/b');
    expect(calls[0]?.path).toBe('/v1/accounts/mail-domains/omd_a%2Fb/verify');
  });

  it.each([
    ['CONFLICT', 409],
    ['NOT_FOUND', 404],
  ] as const)('keeps %s on a connect or verify as a plain StackError', async (code, status) => {
    stubFetch({ status, body: { error: { code, message: 'refused' } } });
    const error = await stack().accounts.mailDomains.verify('omd_abcdefgh1234').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({ code, status });
  });

  it('maps PLATFORM_SUBSCRIPTION_REQUIRED on a connect to its typed error', async () => {
    stubFetch({ status: 402, body: { error: { code: 'PLATFORM_SUBSCRIPTION_REQUIRED', message: 'refused', details: { status: 'none' } } } });
    const error = await stack().accounts.mailDomains.connect({ domain: 'mail.example.com' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(PlatformSubscriptionRequiredError);
    expect(error).toMatchObject({ subscriptionStatus: 'none' });
  });
});

describe('AccountsService email', () => {
  const options = { passportToken: 'pas.jwt.token' };
  const sent = {
    message_id: 'amsg_0123456789abcdef',
    channel: 'email',
    provider_message_id: 'prov_1',
    thread_id: 'thr_1',
    status: 'sent',
    to: ['a@example.test'],
    cc: ['b@example.test'],
    bcc: [],
    attachments: [{ filename: 'report.pdf', content_type: 'application/pdf', size_bytes: 10, file_id: 'drv_0123456789abcdef' }],
  };

  it('still sends to one address as a string', async () => {
    const calls = stubFetch({ status: 201, body: sent });
    await stack().accounts.sendEmail(ACCOUNT, { to: 'a@example.test', subject: 'Hi', body: 'Hello' });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ method: 'POST', path: `/v1/accounts/${ACCOUNT}/email/send`, body: { to: 'a@example.test', subject: 'Hi', body: 'Hello' } });
  });

  it('sends several recipients, copies and attachments as written, and returns the extended answer', async () => {
    const calls = stubFetch({ status: 201, body: sent });
    const input = {
      to: ['a@example.test', 'b@example.test'],
      cc: ['c@example.test'],
      bcc: ['d@example.test'],
      subject: 'Report',
      body: 'Attached.',
      attachments: [
        { file_id: 'drv_0123456789abcdef', filename: 'report.pdf' },
        { filename: 'notes.txt', content_type: 'text/plain', content_base64: 'aGVsbG8=' },
      ],
    };
    const result = await stack().accounts.sendEmail(ACCOUNT, input, options);
    expect(calls[0]!.body).toEqual(input);
    expect(calls[0]!.headers['X-Passport-Token']).toBe('pas.jwt.token');
    expect(result.to).toEqual(['a@example.test']);
    expect(result.cc).toEqual(['b@example.test']);
    expect(result.attachments[0]).toMatchObject({ filename: 'report.pdf', file_id: 'drv_0123456789abcdef' });
  });

  it('replies to a message in its thread, encoding the ids, and sends the Passport only when given', async () => {
    const calls = stubFetch({ status: 201, body: sent });
    const accounts = stack().accounts;
    await accounts.replyEmail(ACCOUNT, 'amsg_a/b?1', { body: 'Done.', reply_all: true, cc: ['c@example.test'] }, options);
    await accounts.replyEmail(ACCOUNT, 'amsg_x', { body: 'Done.' });
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: `/v1/accounts/${ACCOUNT}/messages/amsg_a%2Fb%3F1/reply`,
      body: { body: 'Done.', reply_all: true, cc: ['c@example.test'] },
    });
    expect(calls.map((c) => c.headers['X-Passport-Token'])).toEqual(['pas.jwt.token', undefined]);
  });

  it('forwards a message with a note, more files and the original files switched off', async () => {
    const calls = stubFetch({ status: 201, body: sent });
    const input = {
      to: ['a@example.test', 'b@example.test'],
      bcc: ['d@example.test'],
      body: 'For your records.',
      include_attachments: false,
      attachments: [{ file_id: 'drv_0123456789abcdef' }],
    };
    await stack().accounts.forwardEmail(ACCOUNT, 'amsg_0123456789abcdef', input, options);
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: `/v1/accounts/${ACCOUNT}/messages/amsg_0123456789abcdef/forward`,
      body: input,
    });
    expect(calls[0]!.headers['X-Passport-Token']).toBe('pas.jwt.token');
  });

  it('maps EMAIL_ATTACHMENTS_TOO_LARGE on a send to its typed error', async () => {
    stubFetch({
      status: 413,
      body: { error: { code: 'EMAIL_ATTACHMENTS_TOO_LARGE', message: 'too large', details: { total_bytes: 30_000_000, limit_bytes: 26_214_400 } } },
    });
    const error = await stack()
      .accounts.sendEmail(ACCOUNT, { to: 'a@example.test', subject: 's', body: 'b', attachments: [{ file_id: 'drv_0123456789abcdef' }] })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(EmailAttachmentsTooLargeError);
    expect(error).toBeInstanceOf(StackError);
    expect(error).toMatchObject({ code: 'EMAIL_ATTACHMENTS_TOO_LARGE', status: 413, totalBytes: 30_000_000, limitBytes: 26_214_400 });
  });

  it.each(['replyEmail', 'forwardEmail'] as const)('maps EMAIL_MESSAGE_NOT_ANSWERABLE on %s to its typed error', async (method) => {
    stubFetch({ status: 422, body: { error: { code: 'EMAIL_MESSAGE_NOT_ANSWERABLE', message: 'withheld', details: { reason: 'withheld' } } } });
    const accounts = stack().accounts;
    const error = await (method === 'replyEmail'
      ? accounts.replyEmail(ACCOUNT, 'amsg_x', { body: 'b' })
      : accounts.forwardEmail(ACCOUNT, 'amsg_x', { to: 'a@example.test' })
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(EmailMessageNotAnswerableError);
    expect(error).toMatchObject({ code: 'EMAIL_MESSAGE_NOT_ANSWERABLE', status: 422, reason: 'withheld' });
  });

  it('reads the attachments, bcc and thread id of a message', async () => {
    stubFetch({
      status: 200,
      body: {
        id: 'amsg_x',
        account_id: ACCOUNT,
        channel: 'email',
        direction: 'inbound',
        status: 'delivered',
        content: {
          from: 'p@example.test', to: ['agent@example.test'], cc: [], bcc: ['q@example.test'], thread_id: 'thr_1', subject: 'S', body_text: 'T',
          attachments: [
            { filename: 'a.pdf', content_type: 'application/pdf', size_bytes: 1, file_id: 'drv_0123456789abcdef' },
            { filename: 'b.zip', content_type: 'application/zip', size_bytes: 2, not_saved: 'too_large' },
          ],
          truncated: false,
          details: {},
        },
      },
    });
    const message = await stack().accounts.messages.get(ACCOUNT, 'amsg_x', options);
    expect(message.content?.thread_id).toBe('thr_1');
    expect(message.content?.bcc).toEqual(['q@example.test']);
    expect(message.content?.attachments.map((a) => a.file_id ?? a.not_saved)).toEqual(['drv_0123456789abcdef', 'too_large']);
  });
});

describe('accounts.setBudget', () => {
  it('sends PUT /budget with cents, and the approval on retry', async () => {
    const calls = stubFetch();
    await stack().accounts.setBudget(ACCOUNT, 2500);
    await stack().accounts.setBudget(ACCOUNT, 5000, { governanceApprovalId: 'gvr_9' });
    expect(calls[0]).toMatchObject({ method: 'PUT', path: `/v1/accounts/${ACCOUNT}/budget`, body: { monthly_budget_cents: 2500 } });
    expect(calls[0]!.headers['X-Governance-Approval']).toBeUndefined();
    expect(calls[1]!.headers['X-Governance-Approval']).toBe('gvr_9');
  });

  it('sends null to remove the budget', async () => {
    const calls = stubFetch();
    await stack().accounts.setBudget(ACCOUNT, null);
    expect(calls[0]).toMatchObject({ method: 'PUT', body: { monthly_budget_cents: null } });
  });

  it('rejects a budget that is not a positive whole number before sending', async () => {
    const calls = stubFetch();
    for (const bad of [0, -1, 12.5, Number.NaN]) await expect(stack().accounts.setBudget(ACCOUNT, bad)).rejects.toBeInstanceOf(TypeError);
    expect(calls).toHaveLength(0);
  });
});
