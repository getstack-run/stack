import { describe, expect, it } from 'vitest';
import { trailEntity } from '@stack/shared';
import { proxyCallEntities } from './proxy-observation.js';

// The two recorders of a proxied call (the live path and the transaction-safe one) both build their observation here.

const call = (over: Partial<Parameters<typeof proxyCallEntities>[0]> = {}) => proxyCallEntities({
  service: 'openai', method: 'GET', resolvedUrl: 'https://api.openai.com/v1/files/file_77aa88bb99?owner=dana@bank.example',
  requestBody: undefined, responseHeaders: {}, responseBody: { ok: true }, ...over,
});

describe('proxyCallEntities', () => {
  it('records the request\'s URL and lists it as the request\'s own', () => {
    const { candidates, requestEntities } = call();
    const recorded = candidates.map((c) => c.entity);
    expect(recorded).toEqual(expect.arrayContaining(['api.openai.com', '/v1/files/file_77aa88bb99', 'file_77aa88bb99', 'dana@bank.example']));
    expect(requestEntities).toEqual(expect.arrayContaining(['api.openai.com', '/v1/files/file_77aa88bb99', 'file_77aa88bb99', 'dana@bank.example'].map(trailEntity)));
  });

  it('does not list what the answer carried: an echoed value is read content', () => {
    const { candidates, requestEntities } = call({ responseBody: { id: 'file_77aa88bb99', owner: 'dana@bank.example' } });
    expect(candidates.map((c) => c.entity)).toContain('file_77aa88bb99');
    expect(requestEntities).not.toContain(trailEntity('file_77aa88bb99'));
    expect(requestEntities).not.toContain(trailEntity('dana@bank.example'));
    expect(requestEntities).toContain(trailEntity('api.openai.com'));
  });

  it('does not list what the request body carried either', () => {
    const { requestEntities } = call({ method: 'POST', requestBody: { to: 'dana@bank.example' } });
    expect(requestEntities).not.toContain(trailEntity('dana@bank.example'));
  });

  it('keeps the sent URL and body for the undeclared-counterparty check', () => {
    const { outbound } = call({ method: 'POST', requestBody: { to: 'sam@counterparty.example' } });
    expect(outbound.map((c) => c.entity)).toEqual(expect.arrayContaining(['api.openai.com', '/v1/files/file_77aa88bb99', 'sam@counterparty.example']));
  });

  it('lists nothing as the request\'s own that the claim does not record', () => {
    const many = Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`k${i}`, `user${i}@read.example`]));
    const { candidates, requestEntities } = call({ responseBody: many });
    expect(candidates).toHaveLength(256);
    const recorded = new Set(candidates.map((c) => trailEntity(c.entity)));
    for (const entity of requestEntities) expect(recorded.has(entity)).toBe(true);
  });
});
