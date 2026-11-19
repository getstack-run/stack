import { describe, expect, it } from 'vitest';
import { DENIAL_DEDUP_WINDOW_SECONDS, denialDedup, hostnameOf, pathTemplate, pathnameOf } from './denial-dedup.js';

describe('pathTemplate', () => {
  it.each([
    ['/v1/orders/1001/lines', '/v1/orders/:id/lines'],
    ['/v1/orders/9f1c2d3e-0000-4000-8000-123456789abc', '/v1/orders/:id'],
    ['/v1/customers/cus_Nf83kd92Lx', '/v1/customers/:id'],
    ['/v1/files/3f2a9c4b7e1d5a60', '/v1/files/:id'],
    ['/v1/cart/items', '/v1/cart/items'],
    ['/', '/'],
    ['', '/'],
  ])('%s -> %s', (input, expected) => {
    expect(pathTemplate(input)).toBe(expected);
  });

  it('keeps words that only look like ids, and is bounded', () => {
    expect(pathTemplate('/v1/products/search')).toBe('/v1/products/search');
    expect(pathTemplate(`/${'a/'.repeat(100)}`).split('/').length).toBeLessThanOrEqual(17);
  });
});

describe('denialDedup', () => {
  const base = { agentId: 'agt_1', service: 'custom_grocer', method: 'POST', pathname: '/v1/orders/1', op: 'constraint:url.pathname:matches' };

  it('is the same gate for the same denial with a different id in the path', () => {
    expect(denialDedup({ ...base, pathname: '/v1/orders/2' })).toEqual(denialDedup(base));
  });

  it('is a different gate for another agent, service, method, place or reason', () => {
    const keys = new Set([
      denialDedup(base).dedupKey,
      denialDedup({ ...base, agentId: 'agt_2' }).dedupKey,
      denialDedup({ ...base, service: 'custom_other' }).dedupKey,
      denialDedup({ ...base, method: 'DELETE' }).dedupKey,
      denialDedup({ ...base, pathname: '/v1/carts/1' }).dedupKey,
      denialDedup({ ...base, op: 'policy:undeclared_operation' }).dedupKey,
      denialDedup({ ...base, host: 'api.one.example' }).dedupKey,
      denialDedup({ ...base, host: 'api.two.example' }).dedupKey,
    ]);
    expect(keys.size).toBe(8);
  });

  it('keeps the same denial to one host one gate, whatever the case of the host name', () => {
    expect(denialDedup({ ...base, host: 'API.One.Example' })).toEqual(denialDedup({ ...base, host: 'api.one.example' }));
  });

  it('reads the host of a URL and never throws on one that does not parse', () => {
    expect(hostnameOf('https://API.example.com:8443/v1/x?y=1')).toBe('api.example.com');
    expect(hostnameOf('not a url')).toBe('');
  });

  it('treats the method case-insensitively', () => {
    expect(denialDedup({ ...base, method: 'post' })).toEqual(denialDedup(base));
  });

  it('is a bounded digest that carries nothing of the call, over ten minutes', () => {
    const gate = denialDedup({ ...base, pathname: `/v1/${'x'.repeat(5000)}` });
    expect(gate.dedupKey).toMatch(/^denial:[0-9a-f]{32}$/);
    expect(gate.dedupWindowSeconds).toBe(DENIAL_DEDUP_WINDOW_SECONDS);
    expect(DENIAL_DEDUP_WINDOW_SECONDS).toBe(600);
  });
});

describe('pathnameOf', () => {
  it('reads the path of a URL and never throws on one that does not parse', () => {
    expect(pathnameOf('https://api.example.com/v1/x?y=1')).toBe('/v1/x');
    expect(pathnameOf('not a url')).toBe('/');
  });
});
