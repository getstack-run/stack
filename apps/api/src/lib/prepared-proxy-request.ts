import { StackError, canonicalize, sha256 } from '@stack/shared';
import type { ProxyRequestInput } from '@stack/shared';

const AUTH_HEADER_NAMES = new Set(['authorization', 'x-api-key', 'api-key']);
const HOP_BY_HOP_HEADER_NAMES = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);
/** Explicit URL-template semantics. UI field type "text" is not a security classification. */
const DESTINATION_FIELDS_BY_PROVIDER: Readonly<Record<string, ReadonlySet<string>>> = {
  algolia: new Set(['app_id']),
  posthog: new Set(['host']),
  salesforce: new Set(['instance_url']),
  sentry: new Set(['organization']),
  supabase: new Set(['url']),
  twilio: new Set(['account_sid']),
};

export interface ProxyOperationBinding {
  operatorId: string;
  agentId: string;
  passportJti: string;
  authorityUseId: string | null;
  approvalId: string | null;
  connectionId: string;
  credentialVersion: number;
  destinationConfigHash: `sha256:${string}`;
}

export interface PreparedProxyRequest {
  version: 1;
  service: string;
  method: ProxyRequestInput['method'];
  finalUrl: string;
  headers: Record<string, string>;
  bodyBytes: string | null;
  bodyKind: 'absent' | 'text' | 'json';
  requestHash: `sha256:${string}`;
  persistence: {
    origin: string;
    pathnameHash: `sha256:${string}`;
    queryHash: `sha256:${string}`;
    destinationConfigHash: `sha256:${string}`;
    headerNames: string[];
    headersHash: `sha256:${string}`;
    bodyHash: `sha256:${string}` | null;
    bodyBytes: number;
  };
}

/**
 * Identify the external effect independently of operation, Passport,
 * authority and approval identifiers. This is used only to stop a fresh
 * handle from silently repeating an unresolved write. Provider idempotency
 * headers are excluded because changing one must not bypass that guard.
 */
export function proxyEffectCorrelationHash(
  prepared: PreparedProxyRequest,
  binding: Pick<ProxyOperationBinding, 'connectionId' | 'destinationConfigHash'>,
): `sha256:${string}` {
  const headers = Object.entries(prepared.headers)
    .filter(([name]) => name !== 'idempotency-key')
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  return `sha256:${sha256(canonicalize({
    version: 1,
    service_connection_id: binding.connectionId,
    destination_config_hash: binding.destinationConfigHash,
    service: prepared.service,
    method: prepared.method,
    final_url: prepared.finalUrl,
    headers,
    body_kind: prepared.bodyKind,
    body_bytes: prepared.bodyBytes,
  }))}`;
}

function invalidRequest(message: string): never {
  throw new StackError(message, 'INVALID_REQUEST', 400);
}

function stableJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) invalidRequest('Proxy body must contain valid JSON numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableJson(entryValue)}`).join(',')}}`;
  }
  invalidRequest('Proxy body must be a JSON value or a serialized string');
}

function normalizeCallerHeaders(input: Record<string, string> | undefined, hasBody: boolean) {
  const normalized = new Map<string, string>();
  const nominated = new Set<string>();

  for (const [rawName, value] of Object.entries(input ?? {})) {
    const name = rawName.trim().toLowerCase();
    if (!name) invalidRequest('Proxy header names cannot be empty');
    const prior = normalized.get(name);
    if (prior !== undefined && prior !== value) {
      invalidRequest(`Proxy request contains conflicting duplicate header ${name}`);
    }
    normalized.set(name, value);
    if (name === 'connection') {
      for (const nominatedName of value.split(',')) {
        const candidate = nominatedName.trim().toLowerCase();
        if (candidate) nominated.add(candidate);
      }
    }
  }

  for (const name of [...AUTH_HEADER_NAMES, ...HOP_BY_HOP_HEADER_NAMES, ...nominated]) {
    normalized.delete(name);
  }
  if (hasBody && !normalized.has('content-type')) {
    normalized.set('content-type', 'application/json');
  }

  return Object.fromEntries(
    [...normalized.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0),
  );
}

function mergeQuery(url: string, query: Record<string, string> | undefined): string {
  const parsed = new URL(url);
  for (const [key, value] of Object.entries(query ?? {})) {
    parsed.searchParams.set(key, value);
  }
  return parsed.toString();
}

function credentialFields(rawCredential: string): Record<string, string> {
  try {
    const parsed = JSON.parse(rawCredential);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      const fields: Record<string, string> = {};
      for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof value === 'string') fields[key] = value;
      }
      return fields;
    }
  } catch {
    // A single opaque token has no destination fields.
  }
  return {};
}

/**
 * Resolve only credential fields with an explicit destination semantic.
 * Form widget types are deliberately ignored: a visible identifier can still
 * be credential material (for example an AWS access-key id). Custom providers
 * have no destination schema and therefore must use an explicit URL.
 */
export function resolveProxyDestination(
  service: string,
  template: string,
  rawCredential: string,
): string {
  const fields = credentialFields(rawCredential);
  const allowedFields = DESTINATION_FIELDS_BY_PROVIDER[service];

  return template.replace(/\{\{(\w+)\}\}/g, (_match, key: string) => {
    if (!allowedFields?.has(key)) {
      invalidRequest(`Credential field ${key} cannot be interpolated into a proxy URL`);
    }
    const value = fields[key];
    if (value === undefined || value.length === 0) {
      invalidRequest(`Proxy URL requires credential destination field ${key}`);
    }
    return value;
  });
}

export function prepareProxyRequest(
  input: ProxyRequestInput,
  resolvedUrl: string,
  binding: ProxyOperationBinding,
): PreparedProxyRequest {
  const finalUrl = mergeQuery(resolvedUrl, input.query);
  const bodyKind = input.body === undefined
    ? 'absent'
    : typeof input.body === 'string'
      ? 'text'
      : 'json';
  const bodyBytes = bodyKind === 'absent'
    ? null
    : bodyKind === 'text'
      ? input.body as string
      : stableJson(input.body);
  const headers = normalizeCallerHeaders(input.headers, bodyBytes !== null);
  const headerEntries = Object.entries(headers);
  const parsed = new URL(finalUrl);
  const queryPairs = [...parsed.searchParams.entries()];
  const bodyHash = bodyBytes === null ? null : `sha256:${sha256(bodyBytes)}` as const;

  const identity = {
    version: 1,
    operator_id: binding.operatorId,
    agent_id: binding.agentId,
    passport_jti: binding.passportJti,
    authority_use_id: binding.authorityUseId,
    approval_id: binding.approvalId,
    service_connection_id: binding.connectionId,
    credential_version: binding.credentialVersion,
    destination_config_hash: binding.destinationConfigHash,
    service: input.service,
    method: input.method,
    origin: parsed.origin,
    pathname: parsed.pathname,
    query_pairs: queryPairs,
    headers: headerEntries,
    body_kind: bodyKind,
    body_bytes: bodyBytes,
  };

  return {
    version: 1,
    service: input.service,
    method: input.method,
    finalUrl,
    headers,
    bodyBytes,
    bodyKind,
    requestHash: `sha256:${sha256(canonicalize(identity))}`,
    persistence: {
      origin: parsed.origin,
      pathnameHash: `sha256:${sha256(parsed.pathname)}`,
      queryHash: `sha256:${sha256(canonicalize(queryPairs))}`,
      destinationConfigHash: binding.destinationConfigHash,
      headerNames: headerEntries.map(([name]) => name),
      headersHash: `sha256:${sha256(canonicalize(headerEntries))}`,
      bodyHash,
      bodyBytes: bodyBytes === null ? 0 : Buffer.byteLength(bodyBytes, 'utf8'),
    },
  };
}
