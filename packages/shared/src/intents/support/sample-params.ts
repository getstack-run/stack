// Best-effort sample params for catalog intents. Used by the intent smoke and
// effect-classification tests, and at runtime by the send-bound check
// (utils/send-bounds.ts) to learn which method and path each send intent
// binds. It lives in a subdirectory so the registry-completeness test never
// mistakes it for a provider catalogue.
//
// Params generation is best-effort. For intents whose params have bespoke
// regex constraints (e.g., github requires "owner/repo"), an override map
// provides a known-good sample. Everything else is walked generically from
// the zod definition.

import type { z } from 'zod';
import type { Intent } from '../types.js';

// Overrides for intents where the auto-generator can't produce valid
// params because the schema uses complex regex / custom validation.
// Key is intent name; value is the params object.
export const SAMPLE_PARAM_OVERRIDES: Record<string, Record<string, unknown>> = {
  'github.create_issue':      { repo: 'acme/foo' },
  'github.comment_issue':     { repo: 'acme/foo' },
  'github.create_pr':         { repo: 'acme/foo' },
  'github.merge_pr':          { repo: 'acme/foo' },
  'github.read_repo':         { repo: 'acme/foo' },
};

// Recursively synthesize a minimal value that satisfies a zod schema.
// Returns undefined when it can't — caller decides whether to skip.
export function minimalValue(schema: z.ZodTypeAny): unknown {
  const def = (schema as { _def: { typeName?: string } })._def;
  const typeName = def.typeName;

  switch (typeName) {
    case 'ZodString': {
      // Handle string modifiers: min length, regex, etc.
      const checks = (def as { checks?: Array<{ kind: string; value?: unknown; regex?: RegExp }> }).checks ?? [];
      const minCheck = checks.find((c) => c.kind === 'min');
      const min = (minCheck?.value as number | undefined) ?? 1;
      const regexCheck = checks.find((c) => c.kind === 'regex') as { regex: RegExp } | undefined;
      if (regexCheck) {
        // Try a battery of candidate strings covering the most common
        // patterns across the catalog. First match wins.
        const candidates = [
          'x', 'foo', 'foo-bar', 'foo_bar', 'abc123',
          'owner/repo', 'acme/foo', 'acme/foo-bar',
          'workspace/repo-slug',
          'appXXXXXXXXXXXXXX', 'tblXXXXXXXXXXXXXX', 'recXXXXXXXXXXXXXX',
          'C01234567', 'U01234567',
          '123', '12345', '1234567890',
          '12345678901', '123456789012345', '1234567890123456', '12345678901234567890',
          'user@example.com', 'example.com',
          'cus_1234567890', 'pi_1234567890', 'ch_1234567890',
          '00000000-0000-4000-8000-000000000000',
          '01234567-89ab-cdef-0123-456789abcdef',
          '+14155550123', '+447700900123',
          'us-east-1', 'eu-west-1',
          // Cloudflare zone / account / object IDs: 32-char lowercase hex
          '0123456789abcdef0123456789abcdef',
          // PagerDuty: P + 6 alphanumeric uppercase
          'PABC123', 'PXYZ789',
          // Generic 16/24/32-char alphanumerics, uppercase variants
          'ABCDEF1234567890',
          'ABCDEF1234567890ABCDEF12',
          // NanoID-style
          'V1StGXR8_Z5jdHi6B-myT',
          // Coinbase product_id: BASE-QUOTE (e.g., BTC-USD)
          'BTC-USD', 'ETH-USD', 'BTC-EUR',
          // Shopify shop host: <shop>.myshopify.com
          'acme.myshopify.com', 'foo-bar.myshopify.com',
        ];
        for (const c of candidates) {
          if (regexCheck.regex.test(c) && c.length >= min) return c;
        }
        return undefined;
      }
      return 'x'.repeat(Math.max(min, 1));
    }
    case 'ZodNumber':
      return 1;
    case 'ZodBoolean':
      return false;
    case 'ZodLiteral':
      return (def as { value: unknown }).value;
    case 'ZodEnum': {
      const values = (def as { values: readonly string[] }).values;
      return values[0];
    }
    case 'ZodOptional':
    case 'ZodNullable':
    case 'ZodDefault': {
      const inner = (def as { innerType: z.ZodTypeAny }).innerType;
      return minimalValue(inner);
    }
    case 'ZodArray': {
      const inner = (def as { type: z.ZodTypeAny; minLength?: { value: number } }).type;
      const minLen = (def as { minLength?: { value: number } }).minLength?.value ?? 0;
      const count = Math.max(minLen, 1);
      const item = minimalValue(inner);
      if (item === undefined) return undefined;
      return Array(count).fill(item);
    }
    case 'ZodObject': {
      const shape = (def as { shape: () => Record<string, z.ZodTypeAny> }).shape();
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(shape)) {
        const val = minimalValue(v);
        if (val !== undefined) out[k] = val;
        // Don't add keys that we couldn't synthesize for - optional
        // fields are fine to omit; required fields will fail safeParse
        // which the caller catches.
      }
      return out;
    }
    case 'ZodUnion': {
      const options = (def as { options: z.ZodTypeAny[] }).options;
      for (const opt of options) {
        const v = minimalValue(opt);
        if (v !== undefined) return v;
      }
      return undefined;
    }
    case 'ZodRecord':
      return {};
    case 'ZodTuple': {
      const items = (def as { items: z.ZodTypeAny[] }).items;
      const out: unknown[] = [];
      for (const item of items) {
        const v = minimalValue(item);
        if (v === undefined) return undefined;
        out.push(v);
      }
      return out;
    }
    case 'ZodEffects': {
      const inner = (def as { schema: z.ZodTypeAny }).schema;
      return minimalValue(inner);
    }
    case 'ZodAny':
    case 'ZodUnknown':
      return 'x';
    default:
      return undefined;
  }
}

/** Sample params for an intent that pass its own schema, or undefined. */
export function sampleParams(intent: Intent): Record<string, unknown> | undefined {
  const params = SAMPLE_PARAM_OVERRIDES[intent.name]
    ?? (minimalValue(intent.params as z.ZodTypeAny) as Record<string, unknown> | undefined);
  if (params === undefined) return undefined;
  return intent.params.safeParse(params).success ? params : undefined;
}
