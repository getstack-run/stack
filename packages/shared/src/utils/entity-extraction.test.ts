import { describe, it, expect } from 'vitest';
import { extractEntities } from './entity-extraction.js';

describe('extractEntities', () => {
  it('extracts emails (lowercased)', () => {
    const result = extractEntities({ to: 'Alice@Example.COM' });
    expect(result).toContainEqual(
      expect.objectContaining({ entity: 'alice@example.com', entity_type: 'email' }),
    );
  });

  it('extracts URL host + path as separate entities', () => {
    const result = extractEntities({ url: 'https://API.Stripe.COM/v1/charges' });
    const hosts = result.filter((r) => r.entity_type === 'url_host');
    const paths = result.filter((r) => r.entity_type === 'url_path');
    expect(hosts.some((r) => r.entity === 'api.stripe.com')).toBe(true);
    expect(paths.some((r) => r.entity === '/v1/charges')).toBe(true);
  });

  it('extracts Stripe-style account ids', () => {
    const result = extractEntities({ charge_id: 'ch_3O1abcDef2GhIjKl' });
    expect(result).toContainEqual(
      expect.objectContaining({ entity_type: 'account_id' }),
    );
  });

  it('extracts AWS ARNs intact (case preserved)', () => {
    const result = extractEntities({ resource: 'arn:aws:s3:::My-Bucket-Name/path/to/key' });
    const arns = result.filter((r) => r.entity_type === 'arn');
    expect(arns.length).toBe(1);
    expect(arns[0]!.entity).toBe('arn:aws:s3:::My-Bucket-Name/path/to/key');
  });

  it('extracts IPv4 addresses', () => {
    const result = extractEntities({ remote_addr: '203.0.113.42' });
    expect(result).toContainEqual(
      expect.objectContaining({ entity: '203.0.113.42', entity_type: 'ip_address' }),
    );
  });

  it('extracts phone numbers in E.164 form', () => {
    const result = extractEntities({ phone: '+14155550123' });
    expect(result).toContainEqual(
      expect.objectContaining({ entity: '+14155550123', entity_type: 'phone' }),
    );
  });

  it('dedupes the same entity across nested fields', () => {
    const result = extractEntities({
      a: { b: { c: 'admin@example.com' } },
      d: 'admin@example.com',
    });
    const emails = result.filter((r) => r.entity_type === 'email');
    expect(emails.length).toBe(1);
  });

  it('respects maxDepth (stops walking past the limit)', () => {
    // Email at depth 6 — past default depth 4
    const result = extractEntities(
      { l1: { l2: { l3: { l4: { l5: { deep: 'too@deep.com' } } } } } },
      { maxDepth: 4 },
    );
    expect(result.every((r) => r.entity !== 'too@deep.com')).toBe(true);
  });

  it('respects maxEntities cap', () => {
    const inputs = Array.from({ length: 100 }, (_, i) => `user${i}@example.com`);
    const result = extractEntities({ list: inputs }, { maxEntities: 10 });
    expect(result.length).toBeLessThanOrEqual(10);
  });

  it('walks arrays', () => {
    const result = extractEntities([
      'https://one.example.com',
      'https://two.example.com',
    ]);
    const hosts = result.filter((r) => r.entity_type === 'url_host');
    expect(hosts.length).toBe(2);
  });

  it('returns empty for input with no matches', () => {
    const result = extractEntities({ greeting: 'hello world', n: 42 });
    expect(result).toEqual([]);
  });

  it('handles null / undefined / empty input gracefully', () => {
    expect(extractEntities(null)).toEqual([]);
    expect(extractEntities(undefined)).toEqual([]);
    expect(extractEntities({})).toEqual([]);
    expect(extractEntities('')).toEqual([]);
  });

  it('source_path reflects nested location', () => {
    const result = extractEntities({ outer: { inner: 'mailto-test@example.com' } });
    const email = result.find((r) => r.entity_type === 'email');
    expect(email?.source_path).toContain('outer.inner');
  });
});
