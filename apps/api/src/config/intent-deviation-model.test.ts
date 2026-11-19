import { describe, expect, it, vi } from 'vitest';
import { INTENT_DEVIATION_SYSTEM_PROMPT } from '@stack/vault';
import { OwnModelIntentDeviationGrader, chooseInstallIntentGrader, readIntentModelConfig } from './intent-deviation-model.js';
import { createNetworkClientServices, NetworkIntentDeviationGrader } from './network-client.js';

const input = {
  passport: { jti: 'pas_x', operator_id: 'op_x', intent_summary: 'Read calendar', intent_services: ['calendar'] },
  agent: { id: 'agt_x', accountability_mode: 'enforced' },
  checkpoints: [{ services_used: ['calendar'], tool_calls: [{ service: 'calendar', method: 'list' }] }],
  checkout: { services_used: ['email'], tool_calls: [{ service: 'email', method: 'send', target: 'a@b.test' }], actions_count: 2, summary: 'Sent email', delegated_to: [] },
  missionId: 'ms_x',
} as never;

const answer = (content: unknown) => new Response(JSON.stringify({ choices: [{ message: { role: 'assistant', content } }] }), { status: 200 });

describe('an install with its own model for intent deviation', () => {
  it('reads nothing configured as off, and the endpoint and the model as one setting', () => {
    expect(readIntentModelConfig({})).toBeNull();
    expect(readIntentModelConfig({ STACK_INTENT_MODEL_URL: 'https://llm.example.com/v1/', STACK_INTENT_MODEL_NAME: 'gpt-x', STACK_INTENT_MODEL_KEY: ' k ' }))
      .toEqual({ url: 'https://llm.example.com/v1', model: 'gpt-x', key: 'k' });
    expect(readIntentModelConfig({ STACK_INTENT_MODEL_URL: 'http://localhost:11434/v1', STACK_INTENT_MODEL_NAME: 'llama' }))
      .toEqual({ url: 'http://localhost:11434/v1', model: 'llama', key: null });
    expect(() => readIntentModelConfig({ STACK_INTENT_MODEL_URL: 'https://llm.example.com/v1' })).toThrow(/set together/);
    expect(() => readIntentModelConfig({ STACK_INTENT_MODEL_NAME: 'gpt-x' })).toThrow(/set together/);
    expect(() => readIntentModelConfig({ STACK_INTENT_MODEL_KEY: 'k' })).toThrow(/set together/);
    for (const url of ['not a url', 'http://llm.example.com/v1', 'https://user:pw@llm.example.com/v1', 'https://llm.example.com/v1?x=1', 'ftp://llm.example.com']) {
      expect(() => readIntentModelConfig({ STACK_INTENT_MODEL_URL: url, STACK_INTENT_MODEL_NAME: 'm' }), url).toThrow(/STACK_INTENT_MODEL_URL/);
    }
  });

  it('asks the model by chat completions with the hosted prompt and raises the flag a hosted checkout would', async () => {
    const fetchImpl = vi.fn(async (_url: string, _init: RequestInit) => answer('```json\n{"score": 0.82, "reason": "It emailed someone instead of reading the calendar."}\n```'));
    const grader = new OwnModelIntentDeviationGrader({ url: 'https://llm.example.com/v1', model: 'gpt-x', key: 'sk-own' }, fetchImpl as unknown as typeof fetch);
    expect(await grader.grade(input)).toEqual([
      { type: 'intent_deviation', severity: 'critical', message: 'Intent deviation score 0.82: It emailed someone instead of reading the calendar.' },
    ]);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe('https://llm.example.com/v1/chat/completions');
    expect((init.headers as Record<string, string>)['authorization']).toBe('Bearer sk-own');
    const sent = JSON.parse(String(init.body));
    expect(sent).toMatchObject({ model: 'gpt-x', temperature: 0, max_tokens: 128 });
    expect(sent.messages[0]).toEqual({ role: 'system', content: INTENT_DEVIATION_SYSTEM_PROMPT });
    expect(sent.messages[1].content).toContain('Declared intent: "Read calendar"');
    expect(sent.messages[1].content).toContain('- email/send → a@b.test');
    // Nothing that names the install's passports, agents, operators or Missions is sent.
    expect(String(init.body)).not.toMatch(/pas_x|agt_x|op_x|ms_x/);
  });

  it('sends no authorization to an endpoint that takes no key, and raises a warning below the critical threshold', async () => {
    const fetchImpl = vi.fn(async (_url: string, _init: RequestInit) => answer('{"score": 0.5, "reason": "Partly off."}'));
    const grader = new OwnModelIntentDeviationGrader({ url: 'http://localhost:11434/v1', model: 'llama', key: null }, fetchImpl as unknown as typeof fetch);
    expect(await grader.grade(input)).toEqual([{ type: 'intent_deviation', severity: 'warning', message: 'Intent deviation score 0.50: Partly off.' }]);
    expect(fetchImpl.mock.calls[0]![1].headers).not.toHaveProperty('authorization');
  });

  it('grades every service and tool call of a long checkout, with no count cut', async () => {
    const fetchImpl = vi.fn(async (_url: string, _init: RequestInit) => answer('{"score": 0.1, "reason": "Fine."}'));
    const grader = new OwnModelIntentDeviationGrader({ url: 'https://llm.example.com/v1', model: 'm', key: null }, fetchImpl as unknown as typeof fetch);
    const many = Array.from({ length: 900 }, (_, i) => ({ service: `svc${i}`, method: 'get' }));
    await grader.grade({ ...(input as object), checkout: { services_used: many.map((c) => c.service), tool_calls: many, actions_count: 20_000_000, summary: null, delegated_to: [] } } as never);
    const user = JSON.parse(String(fetchImpl.mock.calls[0]![1].body)).messages[1].content as string;
    expect(user).toContain('- svc899/get');
    expect(user).toContain('Actions count: 20000000');
  });

  it('adds no flag without a declared intent, on a refusal, an unreadable answer, a low grade or an error', async () => {
    const never = vi.fn();
    const config = { url: 'https://llm.example.com/v1', model: 'm', key: null };
    expect(await new OwnModelIntentDeviationGrader(config, never as unknown as typeof fetch)
      .grade({ passport: { intent_summary: null }, agent: {}, checkpoints: [], checkout: { services_used: [], actions_count: 0 }, missionId: null } as never)).toEqual([]);
    expect(never).not.toHaveBeenCalled();
    for (const respond of [
      () => new Response('nope', { status: 500 }),
      () => answer('I cannot grade this.'),
      () => answer(null),
      () => answer('{"score": 7, "reason": "out of range"}'),
      () => answer('{"score": 0.1, "reason": "fine"}'),
      () => { throw new Error('connect ECONNREFUSED'); },
    ]) {
      const grader = new OwnModelIntentDeviationGrader(config, (async () => respond()) as unknown as typeof fetch);
      expect(await grader.grade(input)).toEqual([]);
    }
  });

  it('uses its own model before the network grader, the network grader without one, and none with neither', () => {
    const config = { url: 'https://llm.example.com/v1', model: 'm', key: null };
    const network = { grade: async () => [] };
    expect(chooseInstallIntentGrader(config, network)).toBeInstanceOf(OwnModelIntentDeviationGrader);
    expect(chooseInstallIntentGrader(config, null)).toBeInstanceOf(OwnModelIntentDeviationGrader);
    expect(chooseInstallIntentGrader(null, network)).toBe(network);
    expect(chooseInstallIntentGrader(null, null)).toBeNull();
  });

  it('leaves the network grader as it was: on with the classifier, off without it', () => {
    const quietLog = { log: () => {}, warn: () => {}, error: () => {} };
    const withClassifier = createNetworkClientServices({ url: 'https://net.test', key: 'k', rules: false, classifier: true }, quietLog as never);
    expect(withClassifier.intentDeviation).toBeInstanceOf(NetworkIntentDeviationGrader);
    expect(createNetworkClientServices(null).intentDeviation).toBeNull();
  });
});
