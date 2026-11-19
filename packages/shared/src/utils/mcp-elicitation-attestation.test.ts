import { describe, expect, it } from 'vitest';
import {
  MCP_ELICITATION_ATTESTATION_KEY_MIN_LENGTH,
  MCP_ELICITATION_ATTESTATION_MAX_AGE_SECONDS,
  hashMcpSessionId,
  isUsableMcpElicitationAttestationKey,
  mcpElicitationAttestationMessage,
  signMcpElicitationAttestation,
  verifyMcpElicitationAttestation,
  type McpElicitationAttestationFields,
} from './mcp-elicitation-attestation.js';

const KEY = 'k'.repeat(40);
const NOW = 1_790_000_000;

function fields(overrides: Partial<McpElicitationAttestationFields> = {}): McpElicitationAttestationFields {
  return {
    approvalId: 'gvr_abc123',
    payloadHash: 'a'.repeat(64),
    mcpSessionHash: hashMcpSessionId('session-1'),
    principal: 'operator:op_1',
    elicitationId: '3f2c1a4e-0b7d-4c55-9a1e-2d6f8b9c0a11',
    decision: 'approve',
    issuedAt: NOW,
    ...overrides,
  };
}

describe('MCP elicitation attestation', () => {
  it('verifies an attestation it signed', () => {
    const signed = signMcpElicitationAttestation(KEY, fields());
    expect(verifyMcpElicitationAttestation(KEY, fields(), signed, NOW)).toBe(true);
  });

  it('refuses a forged attestation and one signed with another key', () => {
    expect(verifyMcpElicitationAttestation(KEY, fields(), 'f'.repeat(64), NOW)).toBe(false);
    const other = signMcpElicitationAttestation('z'.repeat(40), fields());
    expect(verifyMcpElicitationAttestation(KEY, fields(), other, NOW)).toBe(false);
  });

  it('binds every field: any change to the signed message fails', () => {
    const signed = signMcpElicitationAttestation(KEY, fields());
    const changes: Array<Partial<McpElicitationAttestationFields>> = [
      { approvalId: 'gvr_other' },
      { payloadHash: 'b'.repeat(64) },
      { mcpSessionHash: hashMcpSessionId('session-2') },
      { principal: 'member:mem_9' },
      { elicitationId: '3f2c1a4e-0b7d-4c55-9a1e-2d6f8b9c0a12' },
      { decision: 'reject' },
      { issuedAt: NOW + 1 },
    ];
    for (const change of changes) {
      expect(verifyMcpElicitationAttestation(KEY, fields(change), signed, NOW)).toBe(false);
    }
  });

  it('refuses an attestation outside the age window, in either direction', () => {
    const signed = signMcpElicitationAttestation(KEY, fields());
    const edge = MCP_ELICITATION_ATTESTATION_MAX_AGE_SECONDS;
    expect(verifyMcpElicitationAttestation(KEY, fields(), signed, NOW + edge)).toBe(true);
    expect(verifyMcpElicitationAttestation(KEY, fields(), signed, NOW + edge + 1)).toBe(false);
    expect(verifyMcpElicitationAttestation(KEY, fields(), signed, NOW - edge - 1)).toBe(false);
  });

  it('never throws for malformed input, it refuses', () => {
    expect(verifyMcpElicitationAttestation(KEY, fields({ approvalId: 'not an id' }), 'a'.repeat(64), NOW)).toBe(false);
    expect(verifyMcpElicitationAttestation(KEY, fields(), 'short', NOW)).toBe(false);
    expect(verifyMcpElicitationAttestation(KEY, fields(), 12 as unknown as string, NOW)).toBe(false);
  });

  it('is unusable without a key of at least 32 characters', () => {
    expect(MCP_ELICITATION_ATTESTATION_KEY_MIN_LENGTH).toBe(32);
    expect(isUsableMcpElicitationAttestationKey(undefined)).toBe(false);
    expect(isUsableMcpElicitationAttestationKey('')).toBe(false);
    expect(isUsableMcpElicitationAttestationKey('x'.repeat(31))).toBe(false);
    expect(isUsableMcpElicitationAttestationKey(` ${'x'.repeat(31)} `)).toBe(false);
    expect(isUsableMcpElicitationAttestationKey('x'.repeat(32))).toBe(true);
    expect(() => signMcpElicitationAttestation('short', fields())).toThrow();
    expect(verifyMcpElicitationAttestation('short', fields(), 'a'.repeat(64), NOW)).toBe(false);
  });

  it('keeps the raw session id out of the signed message', () => {
    const message = mcpElicitationAttestationMessage(fields());
    expect(message).not.toContain('session-1');
    expect(message.split('\n')).toHaveLength(8);
  });
});
