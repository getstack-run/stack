import { describe, expect, it, vi } from 'vitest';
import { SignJWT, exportJWK, generateKeyPair, type JWK } from 'jose';
import { DETECTION_RULES_AUDIENCE, DETECTION_RULES_TYP, PASSPORT_ISSUER } from '@stack/shared';
import { DetectionRulesFeed, NetworkClassifier, readNetworkClientConfig, NetworkIntentDeviationGrader, createNetworkClientServices } from './network-client.js';

const quiet = { log: vi.fn(), warn: vi.fn() };
const NOW = Date.parse('2026-10-21T12:00:00Z');

/** What STACK's network signs, as its signer writes it, and the keys it publishes. */
async function stackNetwork() {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'deployment-key-1', alg: 'EdDSA', use: 'sig' };
  const statement = (
    revision: number,
    rules: Array<{ id: string; severity: string; pattern: string; flags?: string }> = [{ id: 'r1', severity: 'critical', pattern: 'ignore all rules', flags: 'i' }],
    over: { lifetimeSeconds?: number; typ?: string; aud?: string; packs?: unknown } = {},
  ) => {
    const iat = Math.floor(NOW / 1000);
    return new SignJWT({
      rs: {
        v: 1, version: `2026-10-21.${revision}`, revision, sha256: 'x'.repeat(64),
        packs: over.packs ?? [
          { id: 'prompt_injection', direction: 'input', rules: rules.map((r) => ({ flags: 'i', ...r })) },
          { id: 'output_injection', direction: 'output', rules: [{ id: 'out1', severity: 'warning', pattern: 'secret key', flags: 'i' }] },
        ],
      },
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'deployment-key-1', typ: over.typ ?? DETECTION_RULES_TYP })
      .setIssuer(PASSPORT_ISSUER)
      .setAudience(over.aud ?? DETECTION_RULES_AUDIENCE)
      .setIssuedAt(iat)
      .setExpirationTime(iat + (over.lifetimeSeconds ?? 72 * 3600))
      .setJti(`rs_${revision}`)
      .sign(privateKey);
  };
  const answer = async (revision: number, ...rest: Parameters<typeof statement> extends [number, ...infer R] ? R : never) =>
    new Response(JSON.stringify({ version: `2026-10-21.${revision}`, revision, expires_at: '2026-10-24T12:00:00.000Z', statement: await statement(revision, ...rest) }), { status: 200 });
  return { keys: { jwks: { keys: [jwk] } }, statement, answer };
}

describe('network client', () => {
  it('is off unless configured, and needs a URL and a key together over https', () => {
    expect(readNetworkClientConfig({})).toBeNull();
    expect(() => readNetworkClientConfig({ STACK_NETWORK_URL: 'https://api.getstack.run' })).toThrow(/together/);
    expect(() => readNetworkClientConfig({ STACK_NETWORK_URL: 'http://api.getstack.run', STACK_NETWORK_KEY: 'k' })).toThrow(/https/);
    const config = readNetworkClientConfig({ STACK_NETWORK_URL: 'https://api.getstack.run/', STACK_NETWORK_KEY: 'k' });
    expect(config).toEqual({ url: 'https://api.getstack.run', key: 'k', rules: true, classifier: false });
    expect(
      readNetworkClientConfig({ STACK_NETWORK_URL: 'https://x.test', STACK_NETWORK_KEY: 'k', STACK_NETWORK_CLASSIFIER: 'true', STACK_NETWORK_RULES: 'false' }),
    ).toMatchObject({ rules: false, classifier: true });
  });

  it('applies a signed rule set, then drops it when it expires so the built-in rules alone remain', async () => {
    const net = await stackNetwork();
    let now = NOW;
    const fetchImpl = vi.fn(async () => net.answer(3));
    const feed = new DetectionRulesFeed({ url: 'https://net.test', key: 'secret-key' }, { fetchImpl: fetchImpl as unknown as typeof fetch, keys: net.keys, now: () => now, log: quiet });
    expect(feed.current()).toEqual([]);
    await feed.refresh();
    // The input pack applies to what comes in; the output pack is for what goes out.
    expect(feed.current().map((r) => r.id)).toEqual(['r1']);
    expect(feed.current()[0]!.re.test('Please IGNORE ALL RULES')).toBe(true);
    expect(feed.status()).toMatchObject({ revision: 3, rules: 1 });
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://net.test/v1/network/detection/rules',
      expect.objectContaining({ method: 'POST', body: '{}', headers: expect.objectContaining({ authorization: 'Bearer secret-key' }), redirect: 'error' }),
    );
    now = NOW + 4 * 24 * 3600 * 1000;
    expect(feed.current()).toEqual([]);
  });

  it('refuses a set that is not signed by STACK, is another kind of statement or went back a revision, and keeps the one in force', async () => {
    const net = await stackNetwork();
    const impostor = await stackNetwork();
    const bodies: Array<() => Promise<Response>> = [
      () => net.answer(5),
      () => impostor.answer(6),
      async () => new Response(JSON.stringify({ statement: await net.statement(7, undefined, { typ: 'stack-countersignature+jwt' }) }), { status: 200 }),
      async () => new Response(JSON.stringify({ statement: await net.statement(8, undefined, { aud: 'stack:passport' }) }), { status: 200 }),
      () => net.answer(4),
      async () => new Response(JSON.stringify({ statement: 'not a statement' }), { status: 200 }),
    ];
    let call = 0;
    const feed = new DetectionRulesFeed({ url: 'https://net.test', key: 'k' }, {
      fetchImpl: (async () => bodies[call++]!()) as unknown as typeof fetch, keys: net.keys, now: () => NOW, log: quiet,
    });
    await feed.refresh();
    expect(feed.status().revision).toBe(5);
    for (let i = 1; i < bodies.length; i += 1) {
      await feed.refresh();
      expect(feed.status().revision, `answer ${i} was refused`).toBe(5);
    }
    expect(feed.current()).toHaveLength(1);
  });

  it('moves forward to a newer revision, and a statement already expired is refused', async () => {
    const net = await stackNetwork();
    const answers = [
      () => net.answer(1),
      () => net.answer(2, [{ id: 'r2', severity: 'warning', pattern: 'new trick' }]),
      async () => new Response(JSON.stringify({ statement: await net.statement(3, undefined, { lifetimeSeconds: -3600 }) }), { status: 200 }),
    ];
    let call = 0;
    const feed = new DetectionRulesFeed({ url: 'https://net.test', key: 'k' }, {
      fetchImpl: (async () => answers[call++]!()) as unknown as typeof fetch, keys: net.keys, now: () => NOW, log: quiet,
    });
    await feed.refresh();
    await feed.refresh();
    expect(feed.current().map((r) => r.id)).toEqual(['r2']);
    await feed.refresh();
    expect(feed.status().revision).toBe(2);
  });

  it('runs a pattern RE2 can, drops one it cannot, and refuses a set of more than five hundred', async () => {
    const net = await stackNetwork();
    const feed = new DetectionRulesFeed({ url: 'https://net.test', key: 'k' }, {
      fetchImpl: (async () => net.answer(1, [
        { id: 'ok', severity: 'critical', pattern: 'ignore\\s+all' },
        { id: 'lookahead', severity: 'warning', pattern: 'foo(?=bar)' },
        { id: 'Bad Id', severity: 'warning', pattern: 'x' },
        { id: 'fatal', severity: 'fatal', pattern: 'x' },
      ])) as unknown as typeof fetch,
      keys: net.keys, now: () => NOW, log: quiet,
    });
    await feed.refresh();
    expect(feed.current().map((r) => r.id)).toEqual(['ok']);

    const many = Array.from({ length: 501 }, (_, i) => ({ id: `r${i}`, severity: 'warning', pattern: 'x' }));
    const refused = new DetectionRulesFeed({ url: 'https://net.test', key: 'k' }, {
      fetchImpl: (async () => net.answer(1, many)) as unknown as typeof fetch, keys: net.keys, now: () => NOW, log: quiet,
    });
    await refused.refresh();
    expect(refused.current()).toEqual([]);
  });

  it('keeps the rules in force when the network is down or answers an error', async () => {
    const net = await stackNetwork();
    const answers: Array<() => Response | Promise<Response>> = [
      () => net.answer(2),
      () => new Response('nope', { status: 503 }),
      () => { throw new Error('connect ECONNREFUSED'); },
    ];
    let call = 0;
    const feed = new DetectionRulesFeed({ url: 'https://net.test', key: 'k' }, {
      fetchImpl: (async () => answers[call++]!()) as unknown as typeof fetch, keys: net.keys, now: () => NOW, log: quiet,
    });
    await feed.refresh();
    await feed.refresh();
    await feed.refresh();
    expect(feed.status().revision).toBe(2);
  });

  it('sends only the content to the hosted classifier and returns its verdict', async () => {
    const fetchImpl = vi.fn(async (_url: string, _init: RequestInit) =>
      new Response(JSON.stringify({
        verdict: 'clean', request_id: 'req_1', match: null,
        llm: { verdict: 'clean', confidence: 2, reasoning: 'ok', model: 'stack-l3' }, l3_degraded: null,
      }), { status: 200 }),
    );
    const classifier = new NetworkClassifier({ url: 'https://net.test', key: 'k' }, fetchImpl as unknown as typeof fetch);
    const result = await classifier.classify('hello world', { timeoutMs: 1000 });
    expect(result).toMatchObject({ verdict: 'clean', confidence: 2, reasoning: 'ok', degraded: false, model: 'stack-l3', tokens_input: 0, tokens_output: 0 });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe('https://net.test/v1/network/detection/classify');
    expect(JSON.parse(String(init.body))).toEqual({ content: 'hello world' });
    expect(JSON.parse(String(init.body))).not.toHaveProperty('model');
  });

  it('grades a checkout\'s intent deviation through the network, sending the declared intent and what the agent did', async () => {
    const fetchImpl = vi.fn(async (_url: string, _init: RequestInit) =>
      new Response(JSON.stringify({ graded: true, score: 0.8, flag: { severity: 'critical', message: 'Intent deviation score 0.80: Different service.' } }), { status: 200 }),
    );
    const grader = new NetworkIntentDeviationGrader({ url: 'https://net.test', key: 'k' }, fetchImpl as unknown as typeof fetch);
    const input = {
      passport: { jti: 'pas_x', operator_id: 'op_x', intent_summary: 'Read calendar', intent_services: ['calendar'] },
      agent: { id: 'agt_x', accountability_mode: 'enforced' },
      checkpoints: [{ services_used: ['calendar'], tool_calls: [{ service: 'calendar', method: 'list' }] }],
      checkout: { services_used: ['email'], tool_calls: [{ service: 'email', method: 'send', target: 'a@b.test' }], actions_count: 2, summary: 'Sent email', delegated_to: [] },
      missionId: 'ms_x',
    } as never;
    expect(await grader.grade(input)).toEqual([{ type: 'intent_deviation', severity: 'critical', message: 'Intent deviation score 0.80: Different service.' }]);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe('https://net.test/v1/network/detection/intent-deviation');
    const sent = JSON.parse(String(init.body));
    expect(sent).toEqual({
      declared: { summary: 'Read calendar', services: ['calendar'] },
      observed: {
        services_used: ['calendar', 'email'],
        tool_calls: [{ service: 'calendar', method: 'list' }, { service: 'email', method: 'send', target: 'a@b.test' }],
        actions_count: 2,
        summary: 'Sent email',
      },
    });
    // No identifier of the install's passports, agents or operators leaves it.
    expect(String(init.body)).not.toMatch(/pas_x|agt_x|op_x|ms_x/);
  });

  it('passes the flag message the network gives on whole, however long', async () => {
    const message = `Intent deviation score 0.90: ${'The agent did something quite unrelated to what it declared. '.repeat(20)}`;
    expect(message.length).toBeGreaterThan(400);
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ graded: true, score: 0.9, flag: { severity: 'critical', message } }), { status: 200 }));
    const grader = new NetworkIntentDeviationGrader({ url: 'https://net.test', key: 'k' }, fetchImpl as unknown as typeof fetch);
    const input = { passport: { intent_summary: 'x', intent_services: [] }, agent: {}, checkpoints: [], checkout: { services_used: [], actions_count: 0 }, missionId: null } as never;
    expect(await grader.grade(input)).toEqual([{ type: 'intent_deviation', severity: 'critical', message }]);
  });

  it('adds no intent deviation flag without a declared intent, on a refusal, an ungraded answer or an error', async () => {
    const never = vi.fn();
    const noIntent = new NetworkIntentDeviationGrader({ url: 'https://net.test', key: 'k' }, never as unknown as typeof fetch);
    expect(await noIntent.grade({ passport: { intent_summary: null }, agent: {}, checkpoints: [], checkout: { services_used: [], actions_count: 0 }, missionId: null } as never)).toEqual([]);
    expect(never).not.toHaveBeenCalled();
    const input = { passport: { intent_summary: 'x', intent_services: [] }, agent: {}, checkpoints: [], checkout: { services_used: [], actions_count: 0 }, missionId: null } as never;
    for (const answer of [
      () => new Response('nope', { status: 402 }),
      () => new Response(JSON.stringify({ graded: false, score: null, flag: null }), { status: 200 }),
      () => new Response(JSON.stringify({ flag: { severity: 'loud', message: 3 } }), { status: 200 }),
      () => { throw new Error('connect ECONNREFUSED'); },
    ]) {
      const grader = new NetworkIntentDeviationGrader({ url: 'https://net.test', key: 'k' }, (async () => answer()) as unknown as typeof fetch);
      expect(await grader.grade(input)).toEqual([]);
    }
  });

  it('turns intent deviation on with the classifier and leaves it off without', () => {
    const quietLog = { log: () => {}, warn: () => {}, error: () => {} };
    const on = createNetworkClientServices({ url: 'https://net.test', key: 'k', rules: false, classifier: true }, quietLog as never);
    expect(on.intentDeviation).toBeInstanceOf(NetworkIntentDeviationGrader);
    const off = createNetworkClientServices({ url: 'https://net.test', key: 'k', rules: true, classifier: false }, quietLog as never);
    expect(off.intentDeviation).toBeNull();
    expect(createNetworkClientServices(null).intentDeviation).toBeNull();
  });

  it('degrades the classification, so the detector falls back to L1 and L2, on an answer without a verdict or an error', async () => {
    const noVerdict = new NetworkClassifier({ url: 'https://net.test', key: 'k' }, (async () =>
      new Response(JSON.stringify({ verdict: 'clean', llm: null, l3_degraded: { reason: 'timeout' } }), { status: 200 })) as unknown as typeof fetch);
    expect(await noVerdict.classify('u')).toMatchObject({ degraded: true, verdict: 'clean', reasoning: expect.stringMatching(/without a verdict/) });
    const junk = new NetworkClassifier({ url: 'https://net.test', key: 'k' }, (async () =>
      new Response(JSON.stringify({ llm: { verdict: 42, confidence: 'high' } }), { status: 200 })) as unknown as typeof fetch);
    expect(await junk.classify('u')).toMatchObject({ degraded: true, reasoning: expect.stringMatching(/without a verdict/) });
    const down = new NetworkClassifier({ url: 'https://net.test', key: 'k' }, (async () => new Response('', { status: 500 })) as unknown as typeof fetch);
    expect(await down.classify('u')).toMatchObject({ degraded: true, reasoning: expect.stringMatching(/500/) });
  });

  it('degrades when the scan is cancelled and when the answer is not JSON', async () => {
    const controller = new AbortController();
    controller.abort(new Error('l3_aborted'));
    const cancelled = new NetworkClassifier({ url: 'https://net.test', key: 'k' }, ((_url: string, init: RequestInit) =>
      init.signal?.aborted ? Promise.reject(init.signal.reason) : Promise.resolve(new Response('{}'))) as unknown as typeof fetch);
    expect(await cancelled.classify('u', { signal: controller.signal })).toMatchObject({ degraded: true, reasoning: expect.stringMatching(/l3_aborted/) });
    const html = new NetworkClassifier({ url: 'https://net.test', key: 'k' }, (async () => new Response('<html>', { status: 200 })) as unknown as typeof fetch);
    expect((await html.classify('u')).degraded).toBe(true);
  });
});
