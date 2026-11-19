/** JSON-schema matching for pinned domain-profile actions. */
import Ajv, { type ValidateFunction } from 'ajv';
import { ForbiddenError, canonicalize } from '@stack/shared';

export const domainAjv = new (Ajv as unknown as typeof Ajv.default)({
  allErrors: true,
  strict: true,
  validateSchema: true,
});

export const domainSchemaCache = new Map<string, ValidateFunction>();

export function compileDomainSchema(schemaValue: unknown): ValidateFunction {
  if (!schemaValue || typeof schemaValue !== 'object' || Array.isArray(schemaValue)) {
    throw new ForbiddenError('domain action request schema is invalid');
  }
  const encoded = canonicalize(schemaValue);
  if (Buffer.byteLength(encoded, 'utf8') > 65_536) {
    throw new ForbiddenError('domain action request schema exceeds the bounded profile limit');
  }
  let nodes = 0;
  let branches = 0;
  const walk = (value: unknown, depth: number): void => {
    if (++nodes > 1_024 || depth > 32) {
      throw new ForbiddenError('domain action request schema exceeds the bounded profile limit');
    }
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      branches += value.length;
      if (branches > 128)
        throw new ForbiddenError('domain action request schema has too many branches');
      value.forEach((item) => walk(item, depth + 1));
      return;
    }
    const record = value as Record<string, unknown>;
    for (const forbidden of [
      'pattern',
      'patternProperties',
      '$ref',
      '$dynamicRef',
      'contentSchema',
    ]) {
      if (Object.prototype.hasOwnProperty.call(record, forbidden)) {
        throw new ForbiddenError('domain action request schema uses an unsupported unsafe keyword');
      }
    }
    Object.values(record).forEach((item) => walk(item, depth + 1));
  };
  walk(schemaValue, 0);
  const key = encoded;
  const cached = domainSchemaCache.get(key);
  if (cached) return cached;
  try {
    const validate = domainAjv.compile(schemaValue);
    if (domainSchemaCache.size >= 1024)
      domainSchemaCache.delete(domainSchemaCache.keys().next().value!);
    domainSchemaCache.set(key, validate);
    return validate;
  } catch {
    throw new ForbiddenError('domain action request schema is invalid or unsupported');
  }
}

export function jsonSchemaMatches(schemaValue: unknown, value: unknown): boolean {
  return compileDomainSchema(schemaValue)(value) === true;
}
