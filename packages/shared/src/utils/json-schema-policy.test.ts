import { describe, expect, it } from 'vitest';
import {
  JSON_SCHEMA_LIMITS,
  assertBoundedJsonValue,
  assertSafeJsonSchema,
} from './json-schema-policy.js';

describe('safe JSON Schema policy', () => {
  it('accepts and bounds the supported structural subset', () => {
    expect(() => assertSafeJsonSchema({
      $schema: 'http://json-schema.org/draft-07/schema#',
      type: 'object',
      properties: {
        name: { type: 'string', maxLength: 64, pattern: '^[a-z0-9_-]+$' },
        count: { type: 'integer', minimum: 0, maximum: 100 },
        tags: { type: 'array', maxItems: 10, items: { type: 'string', maxLength: 32 } },
      },
      required: ['name'],
      additionalProperties: false,
    })).not.toThrow();
  });

  it.each(['$ref', 'anyOf', 'oneOf', 'allOf', 'not', 'patternProperties']) (
    'rejects the unbounded keyword %s',
    (keyword) => {
      expect(() => assertSafeJsonSchema({ type: 'object', [keyword]: [] }))
        .toThrow("safe JSON Schema subset");
    },
  );

  it('rejects excessive nesting and node counts', () => {
    let deep: Record<string, unknown> = { type: 'string' };
    for (let i = 0; i <= JSON_SCHEMA_LIMITS.maxSchemaDepth; i++) {
      deep = { type: 'array', items: deep };
    }
    expect(() => assertSafeJsonSchema(deep)).toThrow('depth limit');

    const properties = Object.fromEntries(
      Array.from({ length: JSON_SCHEMA_LIMITS.maxPropertiesPerObject + 1 }, (_, i) => [
        `field_${i}`,
        { type: 'string' },
      ]),
    );
    expect(() => assertSafeJsonSchema({ type: 'object', properties })).toThrow('property limit');
  });

  it('rejects regex features that can create pathological match work', () => {
    expect(() => assertSafeJsonSchema({
      type: 'string',
      maxLength: 4096,
      pattern: '^(a+)+$',
    })).toThrow('unsupported regular-expression features');
    expect(() => assertSafeJsonSchema({ type: 'string', pattern: '^a+$' }))
      .toThrow('requires maxLength');
  });

  it('rejects oversized schemas', () => {
    expect(() => assertSafeJsonSchema({
      type: 'object',
      description: 'x'.repeat(JSON_SCHEMA_LIMITS.maxSchemaBytes),
    })).toThrow('byte limit');
  });
});

describe('bounded JSON values', () => {
  it('accepts ordinary JSON and rejects cycles and excessive depth', () => {
    expect(() => assertBoundedJsonValue({ value: ['synthetic', 1, true, null] })).not.toThrow();

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => assertBoundedJsonValue(cyclic)).toThrow('acyclic');

    let deep: Record<string, unknown> = {};
    for (let i = 0; i <= JSON_SCHEMA_LIMITS.maxInstanceDepth; i++) deep = { child: deep };
    expect(() => assertBoundedJsonValue(deep)).toThrow('depth limit');
  });

  it('rejects values over the byte ceiling', () => {
    expect(() => assertBoundedJsonValue({ value: 'x'.repeat(JSON_SCHEMA_LIMITS.maxInstanceBytes) }))
      .toThrow('byte limit');
  });
});
