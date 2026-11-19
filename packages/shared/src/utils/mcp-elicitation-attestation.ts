// Chat confirmation of a governance approval (MCP elicitation).
//
// The hosted MCP server asks the person in the chat client to confirm a
// pending governance approval through MCP elicitation. The model cannot
// answer an elicitation: the client renders it to the person and returns the
// person's choice to the MCP server, never to the model. After an accept, the
// MCP server signs this attestation with a key that only the MCP server and
// the API hold, and the API records the decision only when the signature, the
// approval, its payload hash, the MCP session, the signed-in principal and the
// one-time elicitation id all match.
//
// The trust boundary is the hosted MCP server process. It is client-attested:
// STACK cannot prove that a person, rather than the chat application, pressed
// the button. See the governance step-up design, Decision 6.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const MCP_ELICITATION_ATTESTATION_VERSION = 'stack-mcp-elicitation-v1';
/** Maximum age, and future skew, of an attestation when the API checks it. */
export const MCP_ELICITATION_ATTESTATION_MAX_AGE_SECONDS = 120;
/** Minimum length of the shared attestation key. */
export const MCP_ELICITATION_ATTESTATION_KEY_MIN_LENGTH = 32;

export interface McpElicitationAttestationFields {
  approvalId: string;
  payloadHash: string;
  /** hashMcpSessionId(session id) — the raw session id never leaves the MCP server. */
  mcpSessionHash: string;
  /** `operator:<id>` or `member:<id>`, as reported by /v1/auth/context. */
  principal: string;
  /** Random id the MCP server generated for this one elicitation. */
  elicitationId: string;
  decision: 'approve' | 'reject';
  /** Unix seconds at which the person answered. */
  issuedAt: number;
}

const APPROVAL_ID = /^gvr_[A-Za-z0-9_-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const PRINCIPAL = /^(operator|member):[A-Za-z0-9_-]{1,128}$/;
const ELICITATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Domain-separated hash of an MCP session id. */
export function hashMcpSessionId(sessionId: string): string {
  return createHash('sha256').update(`stack-mcp-session-v1\n${sessionId}`).digest('hex');
}

/** True when the configured key is long enough to use. */
export function isUsableMcpElicitationAttestationKey(key: string | undefined | null): key is string {
  return typeof key === 'string' && key.trim().length >= MCP_ELICITATION_ATTESTATION_KEY_MIN_LENGTH;
}

function assertFields(fields: McpElicitationAttestationFields): void {
  if (
    !APPROVAL_ID.test(fields.approvalId)
    || !HEX64.test(fields.payloadHash)
    || !HEX64.test(fields.mcpSessionHash)
    || !PRINCIPAL.test(fields.principal)
    || !ELICITATION_ID.test(fields.elicitationId)
    || (fields.decision !== 'approve' && fields.decision !== 'reject')
    || !Number.isSafeInteger(fields.issuedAt)
    || fields.issuedAt <= 0
  ) {
    throw new Error('invalid MCP elicitation attestation fields');
  }
}

/** The exact signed message. Every field is format-checked, so none contains a newline. */
export function mcpElicitationAttestationMessage(fields: McpElicitationAttestationFields): string {
  assertFields(fields);
  return [
    MCP_ELICITATION_ATTESTATION_VERSION,
    fields.approvalId,
    fields.payloadHash,
    fields.mcpSessionHash,
    fields.principal,
    fields.elicitationId,
    fields.decision,
    String(fields.issuedAt),
  ].join('\n');
}

export function signMcpElicitationAttestation(key: string, fields: McpElicitationAttestationFields): string {
  if (!isUsableMcpElicitationAttestationKey(key)) throw new Error('MCP elicitation attestation key is not configured');
  return createHmac('sha256', key.trim()).update(mcpElicitationAttestationMessage(fields)).digest('hex');
}

/**
 * Constant-time check of an attestation. Returns false (never throws) for a
 * malformed field, a bad signature, or an attestation outside the age window.
 */
export function verifyMcpElicitationAttestation(
  key: string,
  fields: McpElicitationAttestationFields,
  attestation: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
  if (!isUsableMcpElicitationAttestationKey(key)) return false;
  if (typeof attestation !== 'string' || !HEX64.test(attestation)) return false;
  let expected: string;
  try {
    expected = signMcpElicitationAttestation(key, fields);
  } catch {
    return false;
  }
  if (Math.abs(nowSeconds - fields.issuedAt) > MCP_ELICITATION_ATTESTATION_MAX_AGE_SECONDS) return false;
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(attestation, 'hex'));
}
