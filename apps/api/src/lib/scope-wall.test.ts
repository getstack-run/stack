import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ForbiddenError, expandIntents, extractEntities, normalizeRequest, trailEntity, type NormalizedRequest } from '@stack/shared';
import { dataFlowFailsClosed, enforceScopeWall, withDerivedEmail, type WallServiceScope } from './scope-wall.js';

/**
 * Complete mediation.
 *
 * These three gates were written for /v1/proxy and ran nowhere else. The LLM
 * gateway is the higher-volume door and checked only WHICH provider the
 * passport could reach, never WHAT the call carried. A scope that was closed
 * for proxy calls was open for LLM calls.
 *
 * The gates now live here and both routes call them, so these tests are the
 * spec for both doors at once.
 */

function makeServices(observedRows: unknown[] = [], controls: boolean | Error = true, belongsToAccount = true) {
  const securityEvents: Array<Record<string, unknown>> = [];
  const denials: Array<Record<string, unknown>> = [];
  const services = {
    securityEvent: {
      record: vi.fn(async (e: Record<string, unknown>) => {
        securityEvents.push(e);
      }),
    },
    claimRegistry: {
      recordIntentDenial: vi.fn(async (d: Record<string, unknown>) => {
        denials.push(d);
      }),
    },
    passportClaimsRepo: {
      findObservedContentForFlow: vi.fn(async () => observedRows),
    },
    entitlements: {
      controlsEnabled: vi.fn(async () => {
        if (controls instanceof Error) throw controls;
        return controls;
      }),
    },
    // An agent that belongs to an agent account follows its owner's controls;
    // any other agent keeps its accountability mode.
    accountDetection: {
      forAgent: vi.fn(async () => (belongsToAccount ? { mode: 'standard', skipL3: true, withhold: false } : null)),
    },
  };
  return { services, securityEvents, denials };
}

function makeRequest(overrides: Partial<NormalizedRequest> = {}): NormalizedRequest {
  return {
    method: 'POST',
    url: { pathname: '/v1/messages', host: 'api.anthropic.com', origin: 'https://api.anthropic.com' },
    body: { model: 'claude-x', messages: [{ role: 'user', content: 'hello' }] },
    query: {},
    headers: {},
    ...overrides,
  } as NormalizedRequest;
}

function call(args: {
  services: unknown;
  serviceScope: WallServiceScope | undefined;
  normalized?: NormalizedRequest;
  mode?: 'enforced' | 'logged' | 'standard';
}) {
  return enforceScopeWall({
    services: args.services as never,
    operatorId: 'op_1',
    agentId: 'ag_1',
    passportJti: 'jti_1',
    mode: args.mode ?? 'enforced',
    missionIds: undefined,
    destinationService: 'anthropic',
    serviceScope: args.serviceScope,
    normalized: args.normalized ?? makeRequest(),
    rawUrl: 'https://api.anthropic.com/v1/messages',
    namedIntent: 'anthropic:llm:messages',
    producer: '[test]',
  });
}

describe('enforceScopeWall - a scope that declares nothing', () => {
  beforeEach(() => vi.clearAllMocks());

  it('lets the call through when the scope has no policy and no constraints', async () => {
    const { services, securityEvents } = makeServices();
    await expect(call({ services, serviceScope: { service_name: 'anthropic' } })).resolves.toMatchObject({ carriedSources: expect.any(Array) });
    expect(securityEvents).toHaveLength(0);
  });

  it('lets the call through when the passport carries no scope entry at all', async () => {
    const { services } = makeServices();
    await expect(call({ services, serviceScope: undefined })).resolves.toMatchObject({ carriedSources: expect.any(Array) });
  });
});

describe('enforceScopeWall - closed operation policy', () => {
  beforeEach(() => vi.clearAllMocks());

  const closedScope: WallServiceScope = {
    service_name: 'anthropic',
    policy: {
      mode: 'closed',
      operations: [
        {
          id: 'send_messages',
          methods: ['POST'],
          path: { kind: 'exact', value: '/v1/messages' },
          allow_fields: ['body.model', 'body.messages', 'body.max_tokens'],
        },
      ],
    },
  };

  it('admits a declared operation carrying only declared fields', async () => {
    const { services } = makeServices();
    await expect(call({ services, serviceScope: closedScope })).resolves.toMatchObject({ carriedSources: expect.any(Array) });
  });

  it('refuses a field nobody declared', async () => {
    const { services, securityEvents } = makeServices();
    const normalized = makeRequest({
      body: { model: 'claude-x', messages: [], tools: [{ name: 'exfiltrate' }] },
    } as Partial<NormalizedRequest>);

    await expect(call({ services, serviceScope: closedScope, normalized })).rejects.toThrow(
      ForbiddenError,
    );
    expect(securityEvents).toHaveLength(1);
    expect(securityEvents[0]!.metadata).toMatchObject({ policy_denial: 'undeclared_field' });
  });

  it('refuses a path the policy never declared', async () => {
    const { services } = makeServices();
    const normalized = makeRequest({
      url: { pathname: '/v1/complete', host: 'api.anthropic.com', origin: 'https://api.anthropic.com' },
    } as Partial<NormalizedRequest>);

    await expect(call({ services, serviceScope: closedScope, normalized })).rejects.toThrow(
      ForbiddenError,
    );
  });

  it('records a signed denial, naming the field and never its value', async () => {
    const { services, securityEvents, denials } = makeServices();
    const normalized = makeRequest({
      body: { model: 'claude-x', messages: [], webhook_url: 'https://attacker.example/collect' },
    } as Partial<NormalizedRequest>);

    await expect(call({ services, serviceScope: closedScope, normalized })).rejects.toThrow();

    expect(denials).toHaveLength(1);
    const serialized = JSON.stringify(securityEvents) + JSON.stringify(denials);
    expect(serialized).toContain('webhook_url');
    expect(serialized).not.toContain('attacker.example');
  });

  it('leaves an open-mode policy alone', async () => {
    const { services } = makeServices();
    const openScope: WallServiceScope = {
      service_name: 'anthropic',
      policy: { mode: 'open', operations: [] },
    };
    const normalized = makeRequest({
      body: { anything: 'at all' },
    } as Partial<NormalizedRequest>);

    await expect(call({ services, serviceScope: openScope, normalized })).resolves.toMatchObject({ carriedSources: expect.any(Array) });
  });
});

describe('enforceScopeWall - the data-flow rule', () => {
  beforeEach(() => vi.clearAllMocks());

  const observedFromGuestbook = [
    {
      sourceService: 'guestbook',
      entities: ['alice.johnson@example.com'],
      fingerprints: [],
    },
  ];

  it('refuses content this passport read from another service', async () => {
    const { services, securityEvents } = makeServices(observedFromGuestbook);
    const normalized = makeRequest({
      body: { model: 'claude-x', messages: [{ role: 'user', content: 'mail alice.johnson@example.com' }] },
    } as Partial<NormalizedRequest>);

    await expect(
      call({ services, serviceScope: { service_name: 'anthropic' }, normalized }),
    ).rejects.toThrow(/read from "guestbook"/);
    expect(securityEvents[0]!.metadata).toMatchObject({
      data_flow_from: 'guestbook',
      data_flow_to: 'anthropic',
    });
    expect(securityEvents[0]!.severity).toBe('critical');
  });

  it('allows the movement once the operator declares it', async () => {
    const { services } = makeServices(observedFromGuestbook);
    const normalized = makeRequest({
      body: { model: 'claude-x', messages: [{ role: 'user', content: 'mail alice.johnson@example.com' }] },
    } as Partial<NormalizedRequest>);

    await expect(
      call({
        services,
        serviceScope: { service_name: 'anthropic', allow_data_from: ['guestbook'] },
        normalized,
      }),
    ).resolves.toMatchObject({ carriedSources: expect.any(Array) });
  });

  it('ignores an observation with no recorded origin rather than guessing', async () => {
    const { services } = makeServices([
      { sourceService: null, entities: ['alice.johnson@example.com'], fingerprints: [] },
    ]);
    const normalized = makeRequest({
      body: { model: 'claude-x', messages: [{ role: 'user', content: 'alice.johnson@example.com' }] },
    } as Partial<NormalizedRequest>);

    await expect(
      call({ services, serviceScope: { service_name: 'anthropic' }, normalized }),
    ).resolves.toMatchObject({ carriedSources: expect.any(Array) });
  });

  // When the data-flow rule cannot be evaluated (a DB hiccup, or an
  // attacker inducing load to switch the exfiltration control off), the failure
  // is no longer silent. It ALWAYS raises a critical alarm, then decides: a
  // write or send (any non-GET) fails closed in every mode; a GET fails closed
  // in enforced mode and open, loudly, in logged/standard. All of this is with the
  // account's controls on; with them off see the last describe.
  it('fails CLOSED and alarms when the observation query breaks in enforced mode', async () => {
    const { services, securityEvents } = makeServices();
    services.passportClaimsRepo.findObservedContentForFlow = vi.fn(async () => {
      throw new Error('connection reset');
    });

    await expect(
      call({ services, serviceScope: { service_name: 'anthropic' }, mode: 'enforced' }),
    ).rejects.toThrow(/could not be evaluated|enforced mode|fails closed/i);

    const alarm = securityEvents.find((e) => (e.metadata as Record<string, unknown>)?.data_flow_rule_unavailable);
    expect(alarm).toBeDefined();
    expect(alarm?.severity).toBe('critical');
    expect((alarm?.metadata as Record<string, unknown>)?.failed).toBe('closed');
  });

  it('fails CLOSED for a write or send when the observation query breaks in standard mode', async () => {
    for (const mode of ['standard', 'logged'] as const) {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const { services, securityEvents } = makeServices();
        services.passportClaimsRepo.findObservedContentForFlow = vi.fn(async () => {
          throw new Error('connection reset');
        });
        await expect(
          call({ services, serviceScope: { service_name: 'anthropic' }, mode, normalized: makeRequest({ method }) }),
        ).rejects.toThrow(/could not be evaluated/);
        const alarm = securityEvents.find((e) => (e.metadata as Record<string, unknown>)?.data_flow_rule_unavailable);
        expect(alarm?.severity).toBe('critical');
        expect((alarm?.metadata as Record<string, unknown>)?.failed).toBe('closed');
      }
    }
  });

  it('decides the posture from mode and method alone', () => {
    expect(dataFlowFailsClosed('standard', 'get')).toBe(false);
    expect(dataFlowFailsClosed('logged', 'GET')).toBe(false);
    expect(dataFlowFailsClosed(undefined, 'GET')).toBe(false);
    expect(dataFlowFailsClosed('enforced', 'GET')).toBe(true);
    expect(dataFlowFailsClosed('standard', 'HEAD')).toBe(true);
    expect(dataFlowFailsClosed('standard', 'post')).toBe(true);
  });

  it('fails OPEN but alarms for a read when the observation query breaks in standard mode', async () => {
    const { services, securityEvents } = makeServices();
    services.passportClaimsRepo.findObservedContentForFlow = vi.fn(async () => {
      throw new Error('connection reset');
    });
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(
      call({ services, serviceScope: { service_name: 'anthropic' }, mode: 'standard', normalized: makeRequest({ method: 'GET', body: undefined }) }),
    ).resolves.toMatchObject({ carriedSources: expect.any(Array) });

    const alarm = securityEvents.find((e) => (e.metadata as Record<string, unknown>)?.data_flow_rule_unavailable);
    expect(alarm).toBeDefined();
    expect(alarm?.severity).toBe('critical');
    expect((alarm?.metadata as Record<string, unknown>)?.failed).toBe('open');
    errorSpy.mockRestore();
  });
});

describe('enforceScopeWall - parameter constraints', () => {
  beforeEach(() => vi.clearAllMocks());

  const pinnedModel: WallServiceScope = {
    service_name: 'anthropic',
    constraints: [{ path: 'body.model', op: 'eq', value: 'claude-x' }],
  };

  it('admits a request that satisfies the constraint', async () => {
    const { services } = makeServices();
    await expect(call({ services, serviceScope: pinnedModel })).resolves.toMatchObject({ carriedSources: expect.any(Array) });
  });

  it('refuses a request that violates it', async () => {
    const { services, securityEvents, denials } = makeServices();
    const normalized = makeRequest({
      body: { model: 'something-else', messages: [] },
    } as Partial<NormalizedRequest>);

    await expect(call({ services, serviceScope: pinnedModel, normalized })).rejects.toThrow(
      /body\.model/,
    );
    expect(securityEvents).toHaveLength(1);
    expect(denials).toHaveLength(1);
  });

  it('names, for a choice of rules, the constraint each rule failed on, and never a value', async () => {
    const { services, securityEvents } = makeServices();
    const choice: WallServiceScope = {
      service_name: 'anthropic',
      constraints: [{
        path: 'any_of', op: 'any_of',
        value: [[{ path: 'method', op: 'eq', value: 'GET' }], [{ path: 'body.model', op: 'eq', value: 'claude-x' }]],
      } as never],
    };
    const normalized = makeRequest({ body: { model: 'secret-model-name', messages: [] } } as Partial<NormalizedRequest>);
    const refusal = call({ services, serviceScope: choice, normalized });
    await expect(refusal).rejects.toThrow('outside every rule the passport allows on anthropic: rule 1 fails on method (eq); rule 2 fails on body.model (eq)');
    expect(JSON.stringify(securityEvents)).not.toContain('secret-model-name');
    expect(securityEvents[0]!['metadata']).toMatchObject({ failed_alternatives: [{ path: 'method', op: 'eq' }, { path: 'body.model', op: 'eq' }] });
  });
});

describe('enforceScopeWall - denial severity', () => {
  beforeEach(() => vi.clearAllMocks());

  it('grades a denial down to warning in logged mode', async () => {
    const { services, securityEvents } = makeServices();
    await expect(
      enforceScopeWall({
        services: services as never,
        operatorId: 'op_1',
        agentId: 'ag_1',
        passportJti: 'jti_1',
        mode: 'logged',
        missionIds: undefined,
        destinationService: 'anthropic',
        serviceScope: {
          service_name: 'anthropic',
          constraints: [{ path: 'body.model', op: 'eq', value: 'claude-x' }],
        },
        normalized: makeRequest({ body: { model: 'other' } } as Partial<NormalizedRequest>),
        rawUrl: 'https://api.anthropic.com/v1/messages',
        namedIntent: 'anthropic:llm:messages',
        producer: '[test]',
      }),
    ).rejects.toThrow();
    expect(securityEvents[0]!.severity).toBe('warning');
  });

  const narrowConstraint: WallServiceScope = {
    service_name: 'anthropic',
    constraints: [{ path: 'url.pathname', op: 'starts_with', value: '/v1/products' }],
  };
  const closedScope: WallServiceScope = {
    service_name: 'anthropic',
    policy: { mode: 'closed', operations: [{ id: 'messages', methods: ['POST'], path: { kind: 'exact', value: '/v1/messages' }, allow_fields: ['body.model', 'body.messages'] }] },
  };
  const at = (pathname: string, method = 'POST') =>
    makeRequest({ method, url: { pathname, host: 'api.anthropic.com', origin: 'https://api.anthropic.com' } } as Partial<NormalizedRequest>);

  it.each(['enforced', 'standard', 'logged'] as const)(
    'a parameter constraint that is too narrow is refused as a warning in %s mode, not a critical',
    async (mode) => {
      const { services, securityEvents } = makeServices();
      await expect(call({ services, serviceScope: narrowConstraint, normalized: at('/v1/orders'), mode })).rejects.toThrow(ForbiddenError);
      expect(securityEvents[0]).toMatchObject({ severity: 'warning', signalType: 'credential_outside_scope' });
    },
  );

  it.each(['enforced', 'standard', 'logged'] as const)(
    'a call the closed operation policy does not list is refused as a warning in %s mode, not a critical',
    async (mode) => {
      const { services, securityEvents } = makeServices();
      await expect(call({ services, serviceScope: closedScope, normalized: at('/v1/complete'), mode })).rejects.toThrow(ForbiddenError);
      expect(securityEvents[0]).toMatchObject({ severity: 'warning' });
    },
  );

  it('data leaving for another service keeps the house rule: critical outside logged mode', async () => {
    const observed = [{ sourceService: 'guestbook', entities: ['alice.johnson@example.com'], fingerprints: [] }];
    const { services, securityEvents } = makeServices(observed);
    const normalized = makeRequest({ body: { messages: [{ role: 'user', content: 'mail alice.johnson@example.com' }] } } as Partial<NormalizedRequest>);
    await expect(call({ services, serviceScope: { service_name: 'anthropic' }, normalized, mode: 'enforced' })).rejects.toThrow(ForbiddenError);
    expect(securityEvents[0]).toMatchObject({ severity: 'critical' });
  });

  it('a flow that went through and the same flow later refused are different events: a critical is never folded into a warning', async () => {
    const observed = [{ sourceService: 'guestbook', entities: ['alice.johnson@example.com'], fingerprints: [] }];
    const normalized = makeRequest({ body: { messages: [{ role: 'user', content: 'mail alice.johnson@example.com' }] } } as Partial<NormalizedRequest>);
    const off = makeServices(observed, false);
    await expect(call({ services: off.services, serviceScope: { service_name: 'anthropic' }, normalized })).resolves.toBeDefined();
    const on = makeServices(observed, true);
    await expect(call({ services: on.services, serviceScope: { service_name: 'anthropic' }, normalized })).rejects.toThrow(ForbiddenError);
    expect(off.securityEvents[0]).toMatchObject({ severity: 'warning' });
    expect(on.securityEvents[0]).toMatchObject({ severity: 'critical' });
    expect(off.securityEvents[0]!['dedupKey']).not.toBe(on.securityEvents[0]!['dedupKey']);
  });

  it('every refusal is still a refusal: nothing is let through for being a warning', async () => {
    const { services } = makeServices();
    await expect(call({ services, serviceScope: narrowConstraint, normalized: at('/v1/orders') })).rejects.toThrow(/violates passport constraint/);
  });

  it('identical denials share one dedup gate, whatever id the path carries', async () => {
    const { services, securityEvents } = makeServices();
    for (const path of ['/v1/orders/1001/lines', '/v1/orders/1002/lines', '/v1/orders/9f1c2d3e-0000-4000-8000-123456789abc/lines']) {
      await call({ services, serviceScope: narrowConstraint, normalized: at(path) }).catch(() => undefined);
    }
    const keys = new Set(securityEvents.map((e) => e['dedupKey']));
    expect(keys.size).toBe(1);
    expect(securityEvents.every((e) => e['dedupWindowSeconds'] === 600)).toBe(true);
  });

  it('a different place, method, service, agent or reason is its own event', async () => {
    const { services, securityEvents } = makeServices();
    await call({ services, serviceScope: narrowConstraint, normalized: at('/v1/orders') }).catch(() => undefined);
    await call({ services, serviceScope: narrowConstraint, normalized: at('/v1/carts') }).catch(() => undefined);
    await call({ services, serviceScope: narrowConstraint, normalized: at('/v1/orders', 'DELETE') }).catch(() => undefined);
    await call({ services, serviceScope: { service_name: 'anthropic', constraints: [{ path: 'method', op: 'eq', value: 'GET' }] }, normalized: at('/v1/orders') }).catch(() => undefined);
    const keys = new Set(securityEvents.map((e) => e['dedupKey']));
    expect(keys.size).toBe(4);
  });
});

describe('enforceScopeWall - the data trail follows the data', () => {
  beforeEach(() => vi.clearAllMocks());

  const bankRead = () => {
    const entities = extractEntities({ availableBalance: 48213.55, accountNumber: '123456789012' }, { financial: true })
      .map((e) => e.entity);
    return [{ sourceService: 'mercury', entities, fingerprints: [] }];
  };
  const slackPost = (text: string) => makeRequest({
    url: { pathname: '/api/chat.postMessage', host: 'slack.com', origin: 'https://slack.com' },
    body: { channel: 'C_EXEC', text },
  } as Partial<NormalizedRequest>);
  const callTo = (services: unknown, normalized: NormalizedRequest, scope: WallServiceScope, missionIds?: string[]) =>
    enforceScopeWall({
      services: services as never, operatorId: 'op_1', agentId: 'ag_1', passportJti: 'jti_2', mode: 'standard',
      missionIds, destinationService: 'slack', serviceScope: scope, normalized,
      rawUrl: 'https://slack.com/api/chat.postMessage', namedIntent: 'slack:http:proxy', producer: '[test]',
    });

  it('reads what the agent read by MISSION, so a new Passport on the same job keeps the record', async () => {
    const { services } = makeServices([]);
    await callTo(services, slackPost('hello'), { service_name: 'slack' }, ['ms_job']);
    expect(services.passportClaimsRepo.findObservedContentForFlow).toHaveBeenCalledWith({
      operatorId: 'op_1', passportId: 'jti_2', missionId: 'ms_job',
    });
  });

  it('refuses a bank balance written into a Slack message, recognised as money', async () => {
    const { services, securityEvents, denials } = makeServices(bankRead());
    await expect(callTo(services, slackPost('Operating account holds $48,213.55 this month'), { service_name: 'slack' }, ['ms_job']))
      .rejects.toThrow(/read from "mercury"/);
    expect(securityEvents[0]!.metadata).toEqual({ data_flow_from: 'mercury', data_flow_to: 'slack', matched_via: 'entity', data_flow_refused: true });
    // A signed denial, with services and match method only - never the content.
    expect(denials).toHaveLength(1);
    expect(denials[0]!.metadata).toEqual({ data_flow_from: 'mercury', data_flow_to: 'slack', matched_via: 'entity' });
    expect(JSON.stringify([securityEvents, denials])).not.toMatch(/48[,.]?213/);
  });

  it('does not count the destination host as carried content', async () => {
    // A read that merely mentioned slack.com (a link in a bank memo, a shared
    // API host) must not refuse every later call to Slack.
    const { services } = makeServices([{ sourceService: 'mercury', entities: ['slack.com'], fingerprints: [] }]);
    await expect(callTo(services, slackPost('standup at ten'), { service_name: 'slack' }, ['ms_job']))
      .resolves.toEqual({ carriedSources: [] });
  });

  it('refuses an account number copied out of the bank', async () => {
    const { services } = makeServices(bankRead());
    await expect(callTo(services, slackPost('Wire it to 123456789012'), { service_name: 'slack' }, ['ms_job']))
      .rejects.toThrow(/read from "mercury"/);
  });

  it('reports the permitted sources a call carries, so a derived response can inherit them', async () => {
    const { services } = makeServices(bankRead());
    await expect(callTo(services, slackPost('Operating account holds $48,213.55'), { service_name: 'slack', allow_data_from: ['mercury'] }, ['ms_job']))
      .resolves.toEqual({ carriedSources: ['mercury'] });
  });

  it('reads a decoded email body attached as derived.email', async () => {
    const { services } = makeServices(bankRead());
    const normalized = {
      ...slackPost('see attached'),
      body: { raw: 'b3BhcXVlIHJmYzgyMiBieXRlcw' },
      derived: { email: { recipients: ['cfo@corp.example'], subject: 'cash', text: 'Balance is $48,213.55' } },
    } as unknown as NormalizedRequest;
    await expect(callTo(services, normalized, { service_name: 'slack' }, ['ms_job'])).rejects.toThrow(/read from "mercury"/);
  });
});

describe('enforceScopeWall - Gmail sends feed the data-flow rule (decoded email)', () => {
  beforeEach(() => vi.clearAllMocks());

  const bankRead = () => [{
    sourceService: 'mercury',
    entities: extractEntities({ availableBalance: 48213.55, accountNumber: '402981736455' }, { financial: true }).map((e) => e.entity),
    fingerprints: [],
  }];
  const raw = (text: string) => Buffer.from(
    ['From: cfo@corp.example', 'To: owner@corp.example', 'Subject: Monthly audit', 'Content-Type: text/plain; charset=utf-8', '', text, ''].join('\r\n'),
  ).toString('base64url');
  const gmailSend = (body: unknown) => normalizeRequest({
    service: 'gmail', method: 'POST', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', body,
  } as never);
  const callGmail = (services: unknown, normalized: NormalizedRequest, scope: WallServiceScope = { service_name: 'gmail' }) =>
    enforceScopeWall({
      services: services as never, operatorId: 'op_1', agentId: 'ag_1', passportJti: 'jti_3', mode: 'standard',
      missionIds: ['ms_job'], destinationService: 'gmail', serviceScope: scope, normalized,
      rawUrl: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', namedIntent: 'gmail:http:proxy', producer: '[test]',
    });

  it('decodes the message the proxy attaches and refuses Mercury figures inside it', async () => {
    const { services, securityEvents, denials } = makeServices(bankRead());
    const plain = gmailSend({ raw: raw('Operating account holds $48,213.55 this month.') });
    // The wall decodes it even when a caller did not attach it.
    await expect(callGmail(makeServices(bankRead()).services, plain)).rejects.toThrow(/read from "mercury"/);
    const attached = withDerivedEmail(plain);
    expect((attached as NormalizedRequest & { derived?: { email?: { recipients?: string[] } } }).derived?.email?.recipients).toEqual(['owner@corp.example']);
    await expect(callGmail(services, attached)).rejects.toThrow(/read from "mercury"/);
    expect(securityEvents[0]!.signalType).toBe('credential_outside_scope');
    expect(securityEvents[0]!.metadata).toEqual({ data_flow_from: 'mercury', data_flow_to: 'gmail', matched_via: 'entity', data_flow_refused: true });
    expect(denials).toHaveLength(1);
  });

  it('lets a decoded email through when it carries nothing from the bank', async () => {
    const { services } = makeServices(bankRead());
    await expect(callGmail(services, withDerivedEmail(gmailSend({ raw: raw('Audit done, nothing to report.') }))))
      .resolves.toEqual({ carriedSources: [] });
  });

  it('refuses an email it cannot read once the Mission holds bank data', async () => {
    const { services, securityEvents, denials } = makeServices(bankRead());
    const unreadable = withDerivedEmail(gmailSend({ raw: '%%%not-base64%%%' }));
    expect((unreadable as { derived?: unknown }).derived).toBeUndefined();
    await expect(callGmail(services, unreadable)).rejects.toThrow(/could not read/);
    expect(securityEvents[0]!.metadata).toEqual({ data_flow_from: 'mercury', data_flow_to: 'gmail', matched_via: 'unreadable_email', data_flow_refused: true });
    expect(denials[0]!.metadata).toEqual({ data_flow_from: 'mercury', data_flow_to: 'gmail', matched_via: 'unreadable_email' });
  });

  it('does not refuse an unreadable email when the bank flow is declared or nothing foreign was read', async () => {
    const unreadable = withDerivedEmail(gmailSend({ raw: '%%%not-base64%%%' }));
    await expect(callGmail(makeServices(bankRead()).services, unreadable, { service_name: 'gmail', allow_data_from: ['mercury'] }))
      .resolves.toEqual({ carriedSources: [] });
    await expect(callGmail(makeServices([]).services, unreadable)).resolves.toEqual({ carriedSources: [] });
  });
});

describe('enforceScopeWall - the data-flow rule follows the owner\'s controls', () => {
  beforeEach(() => vi.clearAllMocks());

  const observed = [{ sourceService: 'guestbook', entities: ['alice.johnson@example.com'], fingerprints: [] }];
  const leaking = () => makeRequest({
    body: { model: 'claude-x', messages: [{ role: 'user', content: 'mail alice.johnson@example.com' }] },
  } as Partial<NormalizedRequest>);

  it('with controls off, lets a flow the scope does not declare go through, as a warning that cannot block the agent', async () => {
    for (const mode of ['standard', 'logged', 'enforced'] as const) {
      const { services, securityEvents, denials } = makeServices(observed, false);
      await expect(call({ services, serviceScope: { service_name: 'anthropic' }, normalized: leaking(), mode }))
        .resolves.toEqual({ carriedSources: ['guestbook'] });
      expect(securityEvents).toHaveLength(1);
      expect(securityEvents[0]).toMatchObject({
        severity: 'warning',
        skipAgentAutoBlock: true,
        metadata: { data_flow_from: 'guestbook', data_flow_to: 'anthropic', matched_via: 'entity', data_flow_refused: false },
      });
      // No signed denial: nothing was refused.
      expect(denials).toHaveLength(0);
    }
  });

  it('with controls on, refuses the same flow, in every accountability mode, as a critical event that may block', async () => {
    for (const mode of ['standard', 'enforced'] as const) {
      const { services, securityEvents, denials } = makeServices(observed, true);
      await expect(call({ services, serviceScope: { service_name: 'anthropic' }, normalized: leaking(), mode }))
        .rejects.toThrow(/read from "guestbook"/);
      expect(securityEvents[0]!.severity).toBe('critical');
      expect(securityEvents[0]).not.toHaveProperty('skipAgentAutoBlock');
      expect(denials).toHaveLength(1);
    }
  });

  it('an unreadable controls status counts as controls on', async () => {
    const { services } = makeServices(observed, new Error('billing unavailable'));
    await expect(call({ services, serviceScope: { service_name: 'anthropic' }, normalized: leaking(), mode: 'standard' }))
      .rejects.toThrow(/read from "guestbook"/);
  });

  it('with controls off an unreadable email is flagged, not refused', async () => {
    const { services, securityEvents } = makeServices([{ sourceService: 'mercury', entities: ['x'], fingerprints: [] }], false);
    const unreadable = withDerivedEmail(normalizeRequest({
      service: 'gmail', method: 'POST', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', body: { raw: '%%%not-base64%%%' },
    } as never));
    await expect(enforceScopeWall({
      services: services as never, operatorId: 'op_1', agentId: 'ag_1', passportJti: 'jti_3', mode: 'standard',
      missionIds: ['ms_job'], destinationService: 'gmail', serviceScope: { service_name: 'gmail' }, normalized: unreadable,
      rawUrl: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', namedIntent: 'gmail:http:proxy', producer: '[test]',
    })).resolves.toBeDefined();
    expect(securityEvents[0]).toMatchObject({ severity: 'warning', skipAgentAutoBlock: true, metadata: { matched_via: 'unreadable_email', data_flow_refused: false } });
  });

  it('with controls off, a failure to evaluate the rule never blocks, whatever the method', async () => {
    for (const method of ['GET', 'POST', 'DELETE']) {
      const { services, securityEvents } = makeServices([], false);
      services.passportClaimsRepo.findObservedContentForFlow = vi.fn(async () => {
        throw new Error('connection reset');
      });
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      await expect(call({ services, serviceScope: { service_name: 'anthropic' }, mode: 'enforced', normalized: makeRequest({ method }) }))
        .resolves.toBeDefined();
      errorSpy.mockRestore();
      const alarm = securityEvents.find((e) => (e.metadata as Record<string, unknown>)?.data_flow_rule_unavailable);
      expect(alarm).toMatchObject({ severity: 'warning', skipAgentAutoBlock: true, metadata: { failed: 'open' } });
    }
  });

  it('every other gate still refuses with controls off', async () => {
    const { services } = makeServices([], false);
    await expect(call({
      services,
      serviceScope: { service_name: 'anthropic', constraints: [{ path: 'body.model', op: 'eq', value: 'claude-x' }] },
      normalized: makeRequest({ body: { model: 'other' } } as Partial<NormalizedRequest>),
    })).rejects.toThrow(/body\.model/);
  });

  it('recognises content read from an account\'s own mail by its digest, never its text', async () => {
    const entities = extractEntities({ from: 'Sam <sam.partner@acme.example>' }).map((e) => trailEntity(e.entity));
    expect(entities.every((e) => e.startsWith('h:'))).toBe(true);
    const mail = [{ sourceService: 'stack:account-messages', entities, fingerprints: [] }];
    const slack = makeRequest({
      url: { pathname: '/api/chat.postMessage', host: 'slack.com', origin: 'https://slack.com' },
      body: { text: 'forward this to sam.partner@acme.example' },
    } as Partial<NormalizedRequest>);
    const { services } = makeServices(mail, true);
    await expect(enforceScopeWall({
      services: services as never, operatorId: 'op_1', agentId: 'ag_1', passportJti: 'jti_4', mode: 'standard',
      missionIds: ['ms_acct'], destinationService: 'slack', serviceScope: { service_name: 'slack' }, normalized: slack,
      rawUrl: 'https://slack.com/api/chat.postMessage', namedIntent: 'slack:http:proxy', producer: '[test]',
    })).rejects.toThrow(/read from "stack:account-messages"/);
  });
});

describe('enforceScopeWall - an agent outside an account is unchanged by the owner\'s controls', () => {
  beforeEach(() => vi.clearAllMocks());

  const observed = [{ sourceService: 'guestbook', entities: ['alice.johnson@example.com'], fingerprints: [] }];
  const leaking = () => makeRequest({
    body: { model: 'claude-x', messages: [{ role: 'user', content: 'mail alice.johnson@example.com' }] },
  } as Partial<NormalizedRequest>);

  it('refuses a disallowed flow whatever the controls say, graded by its accountability mode as before', async () => {
    for (const controls of [true, false]) {
      for (const [mode, severity] of [['standard', 'critical'], ['enforced', 'critical'], ['logged', 'warning']] as const) {
        const { services, securityEvents, denials } = makeServices(observed, controls, false);
        await expect(call({ services, serviceScope: { service_name: 'anthropic' }, normalized: leaking(), mode }))
          .rejects.toThrow(/read from "guestbook"/);
        expect(securityEvents[0]).toMatchObject({ severity, metadata: { data_flow_refused: true } });
        // Refused, so the event may block the agent exactly as it did before.
        expect(securityEvents[0]).not.toHaveProperty('skipAgentAutoBlock');
        expect(denials).toHaveLength(1);
      }
    }
  });

  it('never reads the owner\'s controls for it', async () => {
    const { services } = makeServices(observed, false, false);
    await expect(call({ services, serviceScope: { service_name: 'anthropic' }, normalized: leaking(), mode: 'standard' })).rejects.toThrow();
    expect(services.entitlements.controlsEnabled).not.toHaveBeenCalled();
  });

  it('fails closed in enforced mode only when the rule cannot be evaluated, for every method and whatever the controls say', async () => {
    for (const controls of [true, false]) {
      for (const method of ['GET', 'POST', 'DELETE']) {
        for (const mode of ['enforced', 'standard', 'logged'] as const) {
          const { services, securityEvents } = makeServices([], controls, false);
          services.passportClaimsRepo.findObservedContentForFlow = vi.fn(async () => {
            throw new Error('connection reset');
          });
          const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
          const outcome = call({ services, serviceScope: { service_name: 'anthropic' }, mode, normalized: makeRequest({ method }) });
          if (mode === 'enforced') await expect(outcome).rejects.toThrow(/could not be evaluated/);
          else await expect(outcome).resolves.toBeDefined();
          errorSpy.mockRestore();
          const alarm = securityEvents.find((e) => (e.metadata as Record<string, unknown>)?.data_flow_rule_unavailable);
          expect(alarm).toMatchObject({ severity: 'critical', metadata: { failed: mode === 'enforced' ? 'closed' : 'open' } });
          expect(alarm).not.toHaveProperty('skipAgentAutoBlock');
        }
      }
    }
  });

  it('an account\'s agent, by contrast, follows its controls in the same situation', async () => {
    const off = makeServices(observed, false, true);
    await expect(call({ services: off.services, serviceScope: { service_name: 'anthropic' }, normalized: leaking(), mode: 'standard' }))
      .resolves.toEqual({ carriedSources: ['guestbook'] });
    const on = makeServices(observed, true, true);
    await expect(call({ services: on.services, serviceScope: { service_name: 'anthropic' }, normalized: leaking(), mode: 'standard' }))
      .rejects.toThrow(/read from "guestbook"/);
  });

  it('an agent whose account membership cannot be read is treated strictly', async () => {
    const { services } = makeServices(observed, false, true);
    services.accountDetection.forAgent = vi.fn(async () => { throw new Error('db down'); });
    await expect(call({ services, serviceScope: { service_name: 'anthropic' }, normalized: leaking(), mode: 'standard' }))
      .rejects.toThrow(/read from "guestbook"/);
  });
});

describe('enforceScopeWall - constraints read the recipients inside an encoded email', () => {
  beforeEach(() => vi.clearAllMocks());

  const message = (headers: string) => `${headers}\r\nSubject: Q3\r\n\r\nSee attached.\r\n`;
  const gmailSend = (headers: string | null) => withDerivedEmail(normalizeRequest({
    service: 'gmail', method: 'POST', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
    body: headers === null ? {} : { raw: Buffer.from(message(headers)).toString('base64url') },
  } as never));
  const scope = (): WallServiceScope => ({
    service_name: 'gmail',
    constraints: expandIntents([{ name: 'gmail.send_email_to', params: { to: ['cfo@acme.com'] } }]),
  });
  const send = (normalized: NormalizedRequest) => {
    const { services, securityEvents, denials } = makeServices([]);
    const result = enforceScopeWall({
      services: services as never, operatorId: 'op_1', agentId: 'ag_1', passportJti: 'jti_9', mode: 'standard',
      missionIds: ['ms_job'], destinationService: 'gmail', serviceScope: scope(), normalized,
      rawUrl: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', namedIntent: 'gmail:http:proxy', producer: '[test]',
    });
    return { result, securityEvents, denials };
  };

  it('lets a send to the pinned address through', async () => {
    await expect(send(gmailSend('To: CFO <cfo@acme.com>')).result).resolves.toEqual({ carriedSources: [] });
  });

  it('refuses a recipient off the pin, however it is hidden, and records the path and not the address', async () => {
    for (const headers of [
      'To: cfo@acme.com, attacker@evil.com',
      'To: cfo@acme.com\r\nBcc: cfo@acme.com,\r\n attacker@evil.com',
      'To: =?utf-8?q?attacker=40evil.com?=',
    ]) {
      const { result, securityEvents, denials } = send(gmailSend(headers));
      await expect(result).rejects.toThrow(/violates passport constraint on derived\.email\.recipients/);
      expect(securityEvents[0]!.metadata).toMatchObject({ failed_constraint: { path: 'derived.email.recipients', op: 'in' } });
      expect(JSON.stringify([securityEvents, denials])).not.toContain('attacker');
    }
  });

  it('refuses a message it cannot read: unknown recipients fail the pin', async () => {
    await expect(send(gmailSend(null)).result).rejects.toThrow(/violates passport constraint on derived\.email\.recipients/);
    const unreadable = withDerivedEmail(normalizeRequest({
      service: 'gmail', method: 'POST', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', body: { raw: '%%%not-base64%%%' },
    } as never));
    await expect(send(unreadable).result).rejects.toThrow(/violates passport constraint on derived\.email\.recipients/);
  });
});
