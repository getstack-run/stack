// The reference verifier of a claim signed with an agent's key, and the TypeScript SDK's signer, run the
// `agent-keys` suites; and the suites fail verifiers and signers that each have one deliberate defect.

import { createPublicKey, verify as edVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { signClaimEnvelope } from '@getstackrun/sdk';
import { formatReport, runAgentClaimSignerSuite, runAgentClaimVerifierSuite } from '../src/index.mjs';
import { decode, encode } from '../src/cbor.mjs';
import { verifyAgentClaim } from './agent-claim-reference.mjs';

const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);

describe('agent claim signer: the TypeScript SDK', () => {
  it('passes the signer suite', async () => {
    const report = await runAgentClaimSignerSuite({
      sign: ({ envelope, privateJwk, agentId, alg }) => signClaimEnvelope(envelope, { privateKey: privateJwk, agentId, ...(alg ? { alg } : {}) }),
    });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  });

  it('fails a signer that signs under another key id, one that signs over the wrong structure, and one that falls back to EdDSA', async () => {
    const real = ({ envelope, privateJwk, agentId, alg }) => signClaimEnvelope(envelope, { privateKey: privateJwk, agentId, ...(alg ? { alg } : {}) });
    const otherKid = await runAgentClaimSignerSuite({ sign: ({ envelope, privateJwk, agentId }) => signClaimEnvelope(envelope, { privateKey: privateJwk, agentId: `${agentId}x` }) });
    expect(mustFailedIds(otherKid)).toEqual(expect.arrayContaining(['CS02', 'CS05']));
    const noRefusal = await runAgentClaimSignerSuite({ sign: ({ envelope, privateJwk, agentId }) => real({ envelope, privateJwk, agentId }) });
    expect(mustFailedIds(noRefusal)).toEqual(['CS06']);
    const wrongStructure = await runAgentClaimSignerSuite({
      sign: async (input) => {
        const parts = decode(Buffer.from(await real(input), 'base64url'));
        parts[3] = Buffer.alloc(64, 1);
        return encode(parts).toString('base64url');
      },
    });
    expect(mustFailedIds(wrongStructure)).toContain('CS04');
  });
});

describe('agent claim verifier', () => {
  it('passes the reference verifier', async () => {
    const report = await runAgentClaimVerifierSuite({ verify: (message, context) => verifyAgentClaim(message, context) });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  });

  it('fails a verifier that accepts every message, and one that accepts none', async () => {
    const all = await runAgentClaimVerifierSuite({ verify: async () => ({ valid: true }) });
    expect(all.conforms).toBe(false);
    const none = await runAgentClaimVerifierSuite({ verify: async () => ({ valid: false }) });
    expect(mustFailedIds(none)).toEqual(expect.arrayContaining(['CV01', 'CV03', 'CV11', 'CV12']));
  });

  it('fails a verifier that does not pin the key id to the agent', async () => {
    // It looks the kid up in whatever key set it is given, which is the mistake the specification warns of.
    const lax = (message, { jwks }) => {
      const parts = decode(Buffer.from(message, 'base64url'));
      const header = decode(parts[0]);
      const inner = header.value ?? header;
      const kid = Buffer.from(inner.get(4)).toString('utf8');
      const key = jwks.keys.find((k) => k.kid === kid);
      if (!key) return { valid: false };
      const toBeSigned = encode(['Signature1', parts[0], Buffer.alloc(0), parts[2]]);
      return { valid: edVerify(null, toBeSigned, createPublicKey({ key, format: 'jwk' }), parts[3]) };
    };
    const report = await runAgentClaimVerifierSuite({ verify: lax });
    expect(mustFailedIds(report)).toContain('CV06');
  });

  it('fails a verifier that re-encodes the payload instead of checking the bytes on the wire', async () => {
    const reencoding = (message, context) => {
      const parts = decode(Buffer.from(message, 'base64url'));
      // Rebuild the message from its decoded payload: the length prefix and the double timestamp change.
      const payload = decode(parts[2]);
      parts[2] = encode(payload);
      return verifyAgentClaim(encode(parts).toString('base64url'), context);
    };
    const report = await runAgentClaimVerifierSuite({ verify: reencoding });
    expect(mustFailedIds(report)).toContain('CV03');
  });
});
