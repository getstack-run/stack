/**
 * How a stored credential string becomes fields.
 *
 * A credential is stored as one string. A multi-field credential (an OAuth
 * token response, an API key plus a base URL) is a JSON object; a single-token
 * credential is the bare token. Every reader of a stored credential has to tell
 * the two apart, and what each reader does with a bare token differs on
 * purpose:
 *
 *   - the retrieval path hands a bare token back as the string it is;
 *   - template verification maps it onto the template's first required field;
 *   - proxy header injection treats it as both `api_key` and `token`;
 *   - proxy URL interpolation leaves the URL untouched, because a bare token
 *     carries no host or instance fields.
 *
 * `parseCredentialObject` is the one place that decides what counts as "fields":
 * a JSON object, and only a JSON object. Each named function below is one
 * reader's treatment of everything else.
 */

/** Replace `{{field}}` placeholders in a template string with values from a record. */
export function interpolate(template: string, fields: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => fields[key] ?? '');
}

/**
 * The credential's fields when it is a JSON object, otherwise null. A JSON
 * array, a JSON scalar, `null`, malformed JSON and a bare token all return null.
 * Values are not checked: the caller names the shape it expects with `T`.
 */
export function parseCredentialObject<T extends object = Record<string, unknown>>(
  raw: string,
): T | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      return parsed as T;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Retrieval: the field map for a JSON-object credential, the string itself for
 * anything else.
 */
export function decodeStoredCredential(raw: string): string | Record<string, string> {
  return parseCredentialObject<Record<string, string>>(raw) ?? raw;
}

/**
 * Template verification: the field map for a JSON-object credential. Anything
 * else is a single token, mapped onto the template's first required field (or
 * no fields at all when the template has none).
 */
export function templateFieldsFromCredential(
  raw: string,
  templateFields: ReadonlyArray<{ key: string; required?: boolean }>,
): Record<string, string> {
  const fields = parseCredentialObject<Record<string, string>>(raw);
  if (fields) return fields;
  const firstRequired = templateFields.find((field) => field.required);
  return firstRequired ? { [firstRequired.key]: raw } : {};
}

/**
 * Proxy header injection: the field map for a JSON-object credential, flagged
 * `structured`. A single token is offered under both `api_key` and `token`, and
 * is not structured.
 */
export function proxyFieldsFromCredential(raw: string): {
  fields: Record<string, string>;
  structured: boolean;
} {
  const fields = parseCredentialObject<Record<string, string>>(raw);
  return fields
    ? { fields, structured: true }
    : { fields: { api_key: raw, token: raw }, structured: false };
}

/**
 * Whether a credential template speaks for this credential. Most templates are
 * the only shape a provider's credential takes. A template marked
 * `own_fields_only` is the key path of a service that is also connected through
 * an OAuth app, so it applies only to a credential carrying every required
 * field of its own; an OAuth token response, or a legacy bare token, for the
 * same provider is read the way it always was.
 */
export function templateApplies(
  template: { fields: ReadonlyArray<{ key: string; required?: boolean }>; own_fields_only?: boolean },
  credential: { fields: Record<string, string>; structured: boolean },
): boolean {
  if (!template.own_fields_only) return true;
  if (!credential.structured) return false;
  return template.fields
    .filter((field) => field.required)
    .every((field) => typeof credential.fields[field.key] === 'string' && credential.fields[field.key] !== '');
}
