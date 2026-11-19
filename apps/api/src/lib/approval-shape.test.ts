import { describe, it, expect } from 'vitest';
import { compareApprovedShape, canonicalBodyHash } from './approval-shape.js';

const approved = (parameters: Record<string, unknown>) => ({
  target: 'stripe',
  intent_type: 'http_call',
  parameters,
});

const call = (over: Partial<{
  service: string; method: string; url: string; query: Record<string, string>;
  headers: Record<string, string>; body: unknown;
}> = {}) => ({
  service: 'stripe',
  method: 'POST',
  url: 'https://api.stripe.com/v1/customers',
  ...over,
});

describe('approval shape comparison', () => {
  it('admits the call the approval described', () => {
    const m = compareApprovedShape(
      approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers' }),
      call(),
    );
    expect(m).toBeNull();
  });

  it('REFUSES a different endpoint on the same host', () => {
    // The old comparator checked host only, so an approval for /v1/customers
    // admitted /v1/transfers — a money-moving endpoint.
    const m = compareApprovedShape(
      approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers' }),
      call({ url: 'https://api.stripe.com/v1/transfers' }),
    );
    expect(m?.field).toBe('url_path');
  });

    it('refuses a different host', () => {
    const m = compareApprovedShape(
      approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers' }),
      call({ url: 'https://attacker.example.com/v1/customers' }),
    );
      expect(m?.field).toBe('url_host');
    });

    it('refuses a different URL scheme', () => {
      const m = compareApprovedShape(
        approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers' }),
        call({ url: 'http://api.stripe.com/v1/customers' }),
      );
      expect(m?.field).toBe('url_scheme');
    });

  it('refuses a different method', () => {
    const m = compareApprovedShape(
      approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers' }),
      call({ method: 'DELETE' }),
    );
    expect(m?.field).toBe('method');
  });

  it('refuses a different service', () => {
    const m = compareApprovedShape(
      approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers' }),
      call({ service: 'resend' }),
    );
    expect(m?.field).toBe('target');
  });

  describe('fails closed on an omitted dimension', () => {
    it('refuses when the approval declares no method', () => {
      // Previously: `approvedMethod !== undefined &&` — omitting it skipped
      // the check entirely, so ANY method was admitted.
      const m = compareApprovedShape(approved({ url: 'https://api.stripe.com/v1/customers' }), call());
      expect(m?.field).toBe('method');
      expect(String(m?.expected)).toContain('parameters.method');
    });

    it('refuses when the approval declares no url', () => {
      const m = compareApprovedShape(approved({ method: 'POST' }), call());
      expect(m?.field).toBe('url');
      expect(String(m?.expected)).toContain('parameters.url');
    });

    it('refuses when the approval declares neither', () => {
      expect(compareApprovedShape(approved({}), call())).not.toBeNull();
    });

    it('refuses an unparseable approved url rather than ignoring it', () => {
      const m = compareApprovedShape(approved({ method: 'POST', url: 'not a url' }), call());
      expect(m?.field).toBe('url');
    });
  });

  describe('path and method normalisation', () => {
    it('treats a trailing slash as a different prepared endpoint', () => {
      const m = compareApprovedShape(
        approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers/' }),
        call({ url: 'https://api.stripe.com/v1/customers' }),
      );
      expect(m?.field).toBe('url_path');
    });

    it('compares method case-insensitively', () => {
      const m = compareApprovedShape(
        approved({ method: 'post', url: 'https://api.stripe.com/v1/customers' }),
        call({ method: 'POST' }),
      );
      expect(m).toBeNull();
    });

    it('binds the exact ordered query string', () => {
      const m = compareApprovedShape(
        approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers?a=1' }),
        call({ url: 'https://api.stripe.com/v1/customers?b=2' }),
      );
      expect(m?.field).toBe('url_query');
    });

    it('says only that the query differs, never a value or a hash of one', () => {
      const m = compareApprovedShape(
        approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers?email=ada@example.test' }),
        call({ url: 'https://api.stripe.com/v1/customers?email=grace@example.test' }),
      );
      expect(m).toEqual({ field: 'url_query', expected: 'the approved query', actual: 'a different query' });
    });

    it('includes appended query parameters in the approved URL comparison', () => {
      expect(compareApprovedShape(
        approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers?limit=10' }),
        call({ url: 'https://api.stripe.com/v1/customers', query: { limit: '10' } }),
      )).toBeNull();
    });
  });

  describe('body', () => {
    const withBody = { method: 'POST', url: 'https://api.stripe.com/v1/customers', body: { amount: 100, currency: 'usd' } };

    it('admits the approved body', () => {
      const m = compareApprovedShape(approved(withBody), call({ body: { amount: 100, currency: 'usd' } }));
      expect(m).toBeNull();
    });

    it('admits the same body with keys in a different order', () => {
      const m = compareApprovedShape(approved(withBody), call({ body: { currency: 'usd', amount: 100 } }));
      expect(m).toBeNull();
    });

    it('REFUSES a changed value', () => {
      const m = compareApprovedShape(approved(withBody), call({ body: { amount: 999999, currency: 'usd' } }));
      expect(m?.field).toBe('body');
    });

    it('refuses an added field', () => {
      const m = compareApprovedShape(
        approved(withBody),
        call({ body: { amount: 100, currency: 'usd', destination: 'acct_attacker' } }),
      );
      expect(m?.field).toBe('body');
    });

    it('never puts body values in the mismatch, only hashes', () => {
      const m = compareApprovedShape(approved(withBody), call({ body: { amount: 999999, currency: 'usd' } }));
      const rendered = JSON.stringify(m);
      expect(rendered).not.toContain('999999');
      expect(rendered).toContain('sha256:');
    });

    it('does not compare a body the approval never pinned', () => {
      const m = compareApprovedShape(
        approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers' }),
        call({ body: { anything: true } }),
      );
      expect(m).toBeNull();
    });

    it('refuses an array that collides with the old object-entry representation', () => {
      const m = compareApprovedShape(
        approved({
          method: 'POST', url: 'https://api.stripe.com/v1/customers', body: { x: 1 },
        }),
        call({ body: [['x', 1]] }),
      );
      expect(m?.field).toBe('body');
    });

    it('refuses nested object-array representation collisions', () => {
      const m = compareApprovedShape(
        approved({
          method: 'POST', url: 'https://api.stripe.com/v1/customers', body: { x: { y: 1 } },
        }),
        call({ body: [['x', [['y', 1]]]] }),
      );
      expect(m?.field).toBe('body');
    });

    it('distinguishes a pinned null body from an absent body', () => {
      const m = compareApprovedShape(
        approved({ method: 'POST', url: 'https://api.stripe.com/v1/customers', body: null }),
        call(),
      );
      expect(m?.field).toBe('body');
    });
  });

  describe('pinned headers', () => {
    it('treats case-only header names as equivalent', () => {
      const m = compareApprovedShape(
        approved({
          method: 'POST', url: 'https://api.stripe.com/v1/customers', headers: { 'Stripe-Account': 'acct_one' },
        }),
        call({ headers: { 'stripe-account': 'acct_one' } }),
      );
      expect(m).toBeNull();
    });

    it('refuses a changed pinned header value', () => {
      const m = compareApprovedShape(
        approved({
          method: 'POST', url: 'https://api.stripe.com/v1/customers', headers: { 'stripe-account': 'acct_one' },
        }),
        call({ headers: { 'stripe-account': 'acct_two' } }),
      );
      expect(m?.field).toBe('headers');
    });

    it('refuses ambiguous case-duplicate headers', () => {
      const m = compareApprovedShape(
        approved({
          method: 'POST', url: 'https://api.stripe.com/v1/customers', headers: { 'stripe-account': 'acct_one' },
        }),
        call({ headers: { 'Stripe-Account': 'acct_one', 'stripe-account': 'acct_two' } }),
      );
      expect(m?.field).toBe('headers');
    });
  });
});

describe('canonicalBodyHash', () => {
  it('is order-independent', () => {
    expect(canonicalBodyHash({ a: 1, b: 2 })).toBe(canonicalBodyHash({ b: 2, a: 1 }));
  });

  it('is order-DEPENDENT for arrays, where order is meaning', () => {
    expect(canonicalBodyHash([1, 2])).not.toBe(canonicalBodyHash([2, 1]));
  });

  it('distinguishes null from absent', () => {
    expect(canonicalBodyHash({ a: null })).not.toBe(canonicalBodyHash({}));
  });

  it('distinguishes objects from arrays that contain the same entry tuples', () => {
    expect(canonicalBodyHash({ x: 1 })).not.toBe(canonicalBodyHash([['x', 1]]));
  });

  it('distinguishes empty objects, empty arrays, null and absent bodies', () => {
    const hashes = [
      canonicalBodyHash({}), canonicalBodyHash([]), canonicalBodyHash(null), canonicalBodyHash(undefined),
    ];
    expect(new Set(hashes)).toHaveLength(4);
  });

  it('distinguishes nested object and array representations', () => {
    expect(canonicalBodyHash({ x: { y: 1 } }))
      .not.toBe(canonicalBodyHash([['x', [['y', 1]]]]));
  });
});
