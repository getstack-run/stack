/**
 * Resource limits for customer-authored JSON Schemas and the values checked
 * against them. The accepted dialect is deliberately small: it contains the
 * structural and scalar constraints STACK needs, without references,
 * conditionals or combinators that can create unbounded compilation work.
 */
export const JSON_SCHEMA_LIMITS = Object.freeze({
  maxSchemaBytes: 32_768,
  maxSchemaDepth: 12,
  maxSchemaNodes: 512,
  maxPropertiesPerObject: 128,
  maxRequiredProperties: 128,
  maxEnumValues: 100,
  maxPatternLength: 128,
  maxPatterns: 32,
  maxPatternInputLength: 4_096,
  maxInstanceBytes: 1_048_576,
  maxInstanceDepth: 32,
  maxInstanceNodes: 100_000,
});

export class JsonSchemaPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JsonSchemaPolicyError';
  }
}

const ALLOWED_KEYWORDS = new Set([
  '$schema', '$id', 'title', 'description', 'type', 'properties', 'required',
  'additionalProperties', 'items', 'minProperties', 'maxProperties',
  'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'pattern',
  'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum',
  'multipleOf', 'enum', 'const', 'default', 'examples', 'readOnly', 'writeOnly',
]);

const STRING_KEYWORDS = new Set(['$schema', '$id', 'title', 'description']);
const NON_NEGATIVE_INTEGER_KEYWORDS = new Set([
  'minProperties', 'maxProperties', 'minItems', 'maxItems', 'minLength', 'maxLength',
]);
const FINITE_NUMBER_KEYWORDS = new Set([
  'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf',
]);
const BOOLEAN_KEYWORDS = new Set(['uniqueItems', 'readOnly', 'writeOnly']);
const JSON_TYPES = new Set(['object', 'array', 'string', 'number', 'integer', 'boolean', 'null']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function jsonByteLength(value: unknown, label: string): number {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new JsonSchemaPolicyError(`${label} must be acyclic JSON`);
  }
  if (serialized === undefined) throw new JsonSchemaPolicyError(`${label} must be JSON-serializable`);
  return new TextEncoder().encode(serialized).byteLength;
}

function assertJsonLiteral(value: unknown, path: string): void {
  const stack: Array<{ value: unknown; path: string }> = [{ value, path }];
  const seen = new Set<object>();
  while (stack.length > 0) {
    const current = stack.pop()!;
    const item = current.value;
    if (item === null || typeof item === 'string' || typeof item === 'boolean') continue;
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new JsonSchemaPolicyError(`${current.path} must contain finite numbers`);
      continue;
    }
    if (typeof item !== 'object') throw new JsonSchemaPolicyError(`${current.path} must contain JSON values only`);
    if (seen.has(item)) throw new JsonSchemaPolicyError(`${current.path} must be acyclic JSON`);
    seen.add(item);
    if (Array.isArray(item)) {
      for (let i = 0; i < item.length; i++) stack.push({ value: item[i], path: `${current.path}[${i}]` });
    } else if (isPlainObject(item)) {
      for (const [key, child] of Object.entries(item)) {
        stack.push({ value: child, path: `${current.path}.${key}` });
      }
    } else {
      throw new JsonSchemaPolicyError(`${current.path} must contain plain JSON objects only`);
    }
  }
}

function assertSafePattern(pattern: unknown, schema: Record<string, unknown>, path: string): void {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    throw new JsonSchemaPolicyError(`${path}.pattern must be a non-empty string`);
  }
  if (pattern.length > JSON_SCHEMA_LIMITS.maxPatternLength) {
    throw new JsonSchemaPolicyError(`${path}.pattern exceeds the ${JSON_SCHEMA_LIMITS.maxPatternLength}-character limit`);
  }
  // Parenthesized groups, alternation, backreferences and counted quantifiers
  // are excluded. The remaining regular-language subset is linear to match.
  if (/[()|{}]/.test(pattern) || /\\[1-9]/.test(pattern)) {
    throw new JsonSchemaPolicyError(`${path}.pattern uses unsupported regular-expression features`);
  }
  if (
    typeof schema.maxLength !== 'number' ||
    !Number.isInteger(schema.maxLength) ||
    schema.maxLength < 0 ||
    schema.maxLength > JSON_SCHEMA_LIMITS.maxPatternInputLength
  ) {
    throw new JsonSchemaPolicyError(
      `${path}.pattern requires maxLength at most ${JSON_SCHEMA_LIMITS.maxPatternInputLength}`,
    );
  }
  try {
    new RegExp(pattern, 'u');
  } catch {
    throw new JsonSchemaPolicyError(`${path}.pattern is not a valid regular expression`);
  }
}

export function assertSafeJsonSchema(schema: Record<string, unknown>): void {
  if (!isPlainObject(schema)) throw new JsonSchemaPolicyError('Schema must be a plain JSON object');
  assertJsonLiteral(schema, 'Schema');
  if (jsonByteLength(schema, 'Schema') > JSON_SCHEMA_LIMITS.maxSchemaBytes) {
    throw new JsonSchemaPolicyError(`Schema exceeds the ${JSON_SCHEMA_LIMITS.maxSchemaBytes}-byte limit`);
  }

  let nodes = 0;
  let patterns = 0;
  const stack: Array<{ schema: Record<string, unknown>; depth: number; path: string }> = [
    { schema, depth: 0, path: '$' },
  ];
  while (stack.length > 0) {
    const current = stack.pop()!;
    nodes++;
    if (nodes > JSON_SCHEMA_LIMITS.maxSchemaNodes) {
      throw new JsonSchemaPolicyError(`Schema exceeds the ${JSON_SCHEMA_LIMITS.maxSchemaNodes}-node limit`);
    }
    if (current.depth > JSON_SCHEMA_LIMITS.maxSchemaDepth) {
      throw new JsonSchemaPolicyError(`Schema exceeds the depth limit of ${JSON_SCHEMA_LIMITS.maxSchemaDepth}`);
    }

    for (const [keyword, value] of Object.entries(current.schema)) {
      if (!ALLOWED_KEYWORDS.has(keyword)) {
        throw new JsonSchemaPolicyError(`${current.path}.${keyword} is not in STACK's safe JSON Schema subset`);
      }
      if (STRING_KEYWORDS.has(keyword) && typeof value !== 'string') {
        throw new JsonSchemaPolicyError(`${current.path}.${keyword} must be a string`);
      }
      if (keyword === '$schema' && value !== 'http://json-schema.org/draft-07/schema#') {
        throw new JsonSchemaPolicyError(`${current.path}.$schema must select JSON Schema draft-07`);
      }
      if (NON_NEGATIVE_INTEGER_KEYWORDS.has(keyword) && (!Number.isInteger(value) || (value as number) < 0)) {
        throw new JsonSchemaPolicyError(`${current.path}.${keyword} must be a non-negative integer`);
      }
      if (FINITE_NUMBER_KEYWORDS.has(keyword) && (typeof value !== 'number' || !Number.isFinite(value))) {
        throw new JsonSchemaPolicyError(`${current.path}.${keyword} must be a finite number`);
      }
      if (keyword === 'multipleOf' && (value as number) <= 0) {
        throw new JsonSchemaPolicyError(`${current.path}.multipleOf must be greater than zero`);
      }
      if (BOOLEAN_KEYWORDS.has(keyword) && typeof value !== 'boolean') {
        throw new JsonSchemaPolicyError(`${current.path}.${keyword} must be boolean`);
      }
      if (keyword === 'type' && (typeof value !== 'string' || !JSON_TYPES.has(value))) {
        throw new JsonSchemaPolicyError(`${current.path}.type must name one supported JSON type`);
      }
      if (keyword === 'required') {
        if (!Array.isArray(value) || value.length > JSON_SCHEMA_LIMITS.maxRequiredProperties ||
            value.some((item) => typeof item !== 'string') || new Set(value).size !== value.length) {
          throw new JsonSchemaPolicyError(`${current.path}.required must be a unique bounded string array`);
        }
      }
      if (keyword === 'enum') {
        if (!Array.isArray(value) || value.length === 0 || value.length > JSON_SCHEMA_LIMITS.maxEnumValues) {
          throw new JsonSchemaPolicyError(`${current.path}.enum must contain 1-${JSON_SCHEMA_LIMITS.maxEnumValues} values`);
        }
      }
      if (keyword === 'properties') {
        if (!isPlainObject(value)) throw new JsonSchemaPolicyError(`${current.path}.properties must be an object`);
        const entries = Object.entries(value);
        if (entries.length > JSON_SCHEMA_LIMITS.maxPropertiesPerObject) {
          throw new JsonSchemaPolicyError(`${current.path}.properties exceeds the property limit`);
        }
        for (const [name, child] of entries) {
          if (!isPlainObject(child)) throw new JsonSchemaPolicyError(`${current.path}.properties.${name} must be a schema object`);
          stack.push({ schema: child, depth: current.depth + 1, path: `${current.path}.properties.${name}` });
        }
      }
      if (keyword === 'items') {
        if (!isPlainObject(value)) throw new JsonSchemaPolicyError(`${current.path}.items must be one schema object`);
        stack.push({ schema: value, depth: current.depth + 1, path: `${current.path}.items` });
      }
      if (keyword === 'additionalProperties' && typeof value !== 'boolean') {
        if (!isPlainObject(value)) throw new JsonSchemaPolicyError(`${current.path}.additionalProperties must be boolean or a schema`);
        stack.push({ schema: value, depth: current.depth + 1, path: `${current.path}.additionalProperties` });
      }
      if (keyword === 'pattern') {
        patterns++;
        if (patterns > JSON_SCHEMA_LIMITS.maxPatterns) {
          throw new JsonSchemaPolicyError(`Schema exceeds the ${JSON_SCHEMA_LIMITS.maxPatterns}-pattern limit`);
        }
        assertSafePattern(value, current.schema, current.path);
      }
    }
  }
}

export function assertBoundedJsonValue(value: unknown): void {
  let nodes = 0;
  const seen = new Set<object>();
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  while (stack.length > 0) {
    const current = stack.pop()!;
    nodes++;
    if (nodes > JSON_SCHEMA_LIMITS.maxInstanceNodes) {
      throw new JsonSchemaPolicyError(`JSON value exceeds the ${JSON_SCHEMA_LIMITS.maxInstanceNodes}-node limit`);
    }
    if (current.depth > JSON_SCHEMA_LIMITS.maxInstanceDepth) {
      throw new JsonSchemaPolicyError(`JSON value exceeds the depth limit of ${JSON_SCHEMA_LIMITS.maxInstanceDepth}`);
    }
    const item = current.value;
    if (item === null || typeof item === 'string' || typeof item === 'boolean') continue;
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new JsonSchemaPolicyError('JSON value contains a non-finite number');
      continue;
    }
    if (typeof item !== 'object') throw new JsonSchemaPolicyError('Value contains a non-JSON type');
    if (seen.has(item)) throw new JsonSchemaPolicyError('JSON value must be acyclic');
    seen.add(item);
    const children = Array.isArray(item) ? item : isPlainObject(item) ? Object.values(item) : null;
    if (!children) throw new JsonSchemaPolicyError('JSON value contains a non-plain object');
    for (const child of children) stack.push({ value: child, depth: current.depth + 1 });
  }
  if (jsonByteLength(value, 'JSON value') > JSON_SCHEMA_LIMITS.maxInstanceBytes) {
    throw new JsonSchemaPolicyError(`JSON value exceeds the ${JSON_SCHEMA_LIMITS.maxInstanceBytes}-byte limit`);
  }
}
