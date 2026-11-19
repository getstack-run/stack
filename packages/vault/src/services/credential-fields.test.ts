import { describe, expect, it } from 'vitest';
import {
  decodeStoredCredential,
  interpolate,
  parseCredentialObject,
  proxyFieldsFromCredential,
  templateFieldsFromCredential,
} from './credential-fields.js';

const OBJECT = JSON.stringify({ api_key: 'synthetic-key', base_url: 'https://api.example.test' });

describe('parseCredentialObject', () => {
  it('returns the fields of a valid JSON object', () => {
    expect(parseCredentialObject(OBJECT)).toEqual({
      api_key: 'synthetic-key',
      base_url: 'https://api.example.test',
    });
  });

  it('returns null for JSON that is not an object', () => {
    for (const raw of ['[1,2]', '"a string"', '42', 'true', 'null']) {
      expect(parseCredentialObject(raw)).toBeNull();
    }
  });

  it('returns null for invalid JSON', () => {
    expect(parseCredentialObject('{"api_key": ')).toBeNull();
    expect(parseCredentialObject('')).toBeNull();
  });

  it('returns null for a raw string credential', () => {
    expect(parseCredentialObject('sk_synthetic_token')).toBeNull();
  });
});

describe('decodeStoredCredential', () => {
  it('returns the field map for a JSON object', () => {
    expect(decodeStoredCredential(OBJECT)).toEqual(JSON.parse(OBJECT));
  });

  it('returns the string itself for everything else', () => {
    for (const raw of ['sk_synthetic_token', '[1,2]', '42', 'null', '{"broken"']) {
      expect(decodeStoredCredential(raw)).toBe(raw);
    }
  });
});

describe('templateFieldsFromCredential', () => {
  const templateFields = [
    { key: 'note', required: false },
    { key: 'api_key', required: true },
    { key: 'region', required: true },
  ];

  it('uses the field map of a JSON object as it is', () => {
    expect(templateFieldsFromCredential(OBJECT, templateFields)).toEqual(JSON.parse(OBJECT));
  });

  it('maps a raw string onto the first required field', () => {
    expect(templateFieldsFromCredential('sk_synthetic_token', templateFields)).toEqual({
      api_key: 'sk_synthetic_token',
    });
  });

  it('maps JSON that is not an object, and invalid JSON, the same way', () => {
    expect(templateFieldsFromCredential('[1]', templateFields)).toEqual({ api_key: '[1]' });
    expect(templateFieldsFromCredential('{"broken"', templateFields)).toEqual({
      api_key: '{"broken"',
    });
  });

  it('yields no fields when the template has no required field', () => {
    expect(templateFieldsFromCredential('sk_synthetic_token', [{ key: 'note' }])).toEqual({});
  });
});

describe('proxyFieldsFromCredential', () => {
  it('marks a JSON object as structured', () => {
    expect(proxyFieldsFromCredential(OBJECT)).toEqual({ fields: JSON.parse(OBJECT), structured: true });
  });

  it('offers a raw string as both api_key and token, unstructured', () => {
    expect(proxyFieldsFromCredential('sk_synthetic_token')).toEqual({
      fields: { api_key: 'sk_synthetic_token', token: 'sk_synthetic_token' },
      structured: false,
    });
  });

  it('treats JSON that is not an object, and invalid JSON, as a raw string', () => {
    expect(proxyFieldsFromCredential('["a"]').structured).toBe(false);
    expect(proxyFieldsFromCredential('{"broken"').structured).toBe(false);
  });
});

describe('interpolate', () => {
  it('replaces known placeholders and blanks unknown ones', () => {
    expect(interpolate('{{instance_url}}/v1/{{missing}}x', { instance_url: 'https://acme.test' })).toBe(
      'https://acme.test/v1/x',
    );
  });

  it('leaves text without placeholders alone', () => {
    expect(interpolate('https://api.example.test/v1', {})).toBe('https://api.example.test/v1');
  });
});
