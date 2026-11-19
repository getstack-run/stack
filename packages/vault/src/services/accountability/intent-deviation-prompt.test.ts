import { describe, expect, it } from 'vitest';
import {
  INTENT_DEVIATION_SYSTEM_PROMPT,
  declaredAndObservedOf,
  intentDeviationFlagOf,
  intentDeviationUserInput,
  parseIntentDeviationResponse,
} from './intent-deviation-prompt.js';

// What a hosted checkout and an install's own model are both graded with.

describe('the intent deviation prompt', () => {
  it('asks for one JSON object with a score and a reason', () => {
    expect(INTENT_DEVIATION_SYSTEM_PROMPT).toContain('{"score": <0.0-1.0>, "reason": "<one sentence>"}');
  });

  it('reads what a checkout declared and did from the passport, the checkpoints and the checkout', () => {
    const input = {
      passport: { intent_summary: 'Read calendar', intent_services: ['calendar'] },
      checkpoints: [{ services_used: ['calendar'], tool_calls: [{ service: 'calendar', method: 'list' }] }],
      checkout: { services_used: ['calendar', 'email'], tool_calls: [{ service: 'email', method: 'send', target: 'a@b.test' }], actions_count: 3, summary: 'Sent' },
    } as never;
    const read = declaredAndObservedOf(input)!;
    expect(read.declared).toEqual({ summary: 'Read calendar', services: ['calendar'] });
    expect(read.observed.servicesUsed).toEqual(['calendar', 'email']);
    expect(read.observed.toolCalls).toHaveLength(2);
    expect(intentDeviationUserInput(read)).toBe([
      'Declared intent: "Read calendar"',
      'Declared services: [calendar]',
      'Observed behavior:',
      'Services used: [calendar, email]',
      'Tool calls:\n- calendar/list\n- email/send → a@b.test',
      'Actions count: 3',
      'Summary: "Sent"',
    ].join('\n'));
    expect(declaredAndObservedOf({ ...(input as object), passport: { intent_summary: null } } as never)).toBeNull();
    expect(declaredAndObservedOf({ ...(input as object), passport: { intent_summary: '' } } as never)).toBeNull();
  });

  it('flags nothing under 0.4, a warning from 0.4 and critical from 0.7', () => {
    expect(intentDeviationFlagOf({ score: 0.39, reason: 'fine' })).toBeNull();
    expect(intentDeviationFlagOf({ score: 0.4, reason: 'a bit' })).toEqual({ type: 'intent_deviation', severity: 'warning', message: 'Intent deviation score 0.40: a bit' });
    expect(intentDeviationFlagOf({ score: 0.7, reason: 'a lot' })).toMatchObject({ severity: 'critical' });
  });

  it('reads the answer through fences and prose, and refuses a score out of range', () => {
    expect(parseIntentDeviationResponse('Sure: ```json\n{"score": 0.2, "reason": "ok"}\n```')).toEqual({ score: 0.2, reason: 'ok' });
    expect(parseIntentDeviationResponse('{"score": 2, "reason": "x"}')).toBeNull();
    expect(parseIntentDeviationResponse('')).toBeNull();
  });
});
