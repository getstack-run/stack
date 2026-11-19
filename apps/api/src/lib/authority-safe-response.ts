// Defense in depth at the HTTP boundary. Authority services return safe views,
// but a future repository refactor must not accidentally serialize a ciphertext
// envelope or resolved fact simply because it appeared on a returned object.
const FORBIDDEN_WIRE_KEYS = new Set([
  'assertion_encrypted',
  'payload_encrypted',
  'native_evidence',
  'native_evidence_encrypted',
  'normalized_request',
  'signed_decision',
  'signed_callback',
  'signed_request',
  'signed_receipt',
  'passport',
  'evidence_encrypted',
  'ciphertext',
  'plaintext',
  'personal_number',
  'national_id',
  'full_name',
  'date_of_birth',
  'credential_encrypted',
  'private_key',
]);

export function assertSafeAuthorityResponse(value: unknown): void {
  visit(value, new Set<object>());
}

function visit(value: unknown, seen: Set<object>): void {
  if (value === null || typeof value !== 'object') return;
  if (seen.has(value)) return;
  seen.add(value);

  if (Array.isArray(value)) {
    for (const item of value) visit(item, seen);
    return;
  }

  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_WIRE_KEYS.has(key) || key.endsWith('_encrypted')) {
      // Fail closed without naming the sensitive field in the wire response.
      throw new Error('Authority response could not be safely projected');
    }
    visit(nested, seen);
  }
}

export function safeAuthorityResponse<T>(value: T): T {
  assertSafeAuthorityResponse(value);
  return value;
}
