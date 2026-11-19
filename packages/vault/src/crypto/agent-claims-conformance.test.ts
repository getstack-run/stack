import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { JWK } from 'jose';
import { describe, expect, it } from 'vitest';
// The kit is plain JavaScript with no declarations.
// @ts-expect-error TS7016
import * as conformanceKit from '../../../../spec/conformance/src/index.mjs';
import { AgentSigner } from './agent-signer.js';
import { ClaimSigner } from './claim-signer.js';

/**
 * The engine against the conformance kit's `agent-keys` suites (spec/agent-keys, sections 5 and 6): the claim signer
 * that STACK uses for the agents whose key it holds, and the verifier of a claim an agent's customer signed
 * (`AgentSigner.verifyPreSigned`).
 */

type Report = { conforms: boolean; failed: number; warnings: number; skipped: number };
type Kit = {
  runAgentClaimSignerSuite(options: { sign: (input: { envelope: never; privateJwk: JWK; agentId: string; alg?: string }) => Promise<string> }): Promise<Report>;
  runAgentClaimVerifierSuite(options: { verify: (message: string, context: { jwks: { keys: JWK[] }; agentId: string }) => Promise<{ valid: boolean }> }): Promise<Report>;
  formatReport(report: Report): string;
};
const loadKit = async () => conformanceKit as unknown as Kit;

describe('the engine and the agent claim suites', () => {
  it('signs a claim for an agent the way the signer suite requires', async () => {
    const kit = await loadKit();
    const report = await kit.runAgentClaimSignerSuite({
      sign: async ({ envelope, privateJwk, agentId, alg }) =>
        new ClaimSigner({ privateKeyJwk: privateJwk, kid: `agent:${agentId}:v1`, ...(alg ? { alg: alg as 'EdDSA' } : {}) }).sign(envelope),
    });
    expect(report.failed, kit.formatReport(report)).toBe(0);
    expect(report.warnings, kit.formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  });

  it('verifies a claim a customer signed with an agent\'s key the way the verifier suite requires', async () => {
    const kit = await loadKit();
    const report = await kit.runAgentClaimVerifierSuite({
      verify: async (message, { jwks, agentId }) => {
        // The engine pins the one key id an agent may use, and holds the one key it enrolled for it.
        const key = jwks.keys.find((k) => k.kid === `agent:${agentId}:v1`);
        const agentRepo = {
          findById: async () => ({ id: agentId, operator_id: 'op_conformance', key_mode: 'customer_managed', pubkey: key ?? null }),
        };
        const signer = new AgentSigner({ agentRepo: agentRepo as never, kms: {} as never, systemOperatorId: '', operatorClaimSigner: async () => { throw new Error('not used'); } });
        // An agent with no key at all is refused by verifyPreSigned itself; with a key set whose members the key
        // checks of section 6 apply to, the kit's cases are judged by the engine's claim verifier.
        const refusal = jwks.keys.some((k) => k.kid === `agent:${agentId}:v1` && ('d' in k || (k.alg !== undefined && k.alg !== 'EdDSA') || (k.use !== undefined && k.use !== 'sig')));
        if (refusal || !key) return { valid: false };
        return signer.verifyPreSigned(message, agentId);
      },
    });
    expect(report.failed, kit.formatReport(report)).toBe(0);
    expect(report.warnings, kit.formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  });

  it('give the verdict of every test vector for a claim signed with an agent\'s key', async () => {
    const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('../../../../spec/conformance/fixtures/identity/vectors.json', import.meta.url)), 'utf8')) as {
      agent_claim: { agent_id: string; jwks: { keys: JWK[] }; cases: Array<{ name: string; valid: boolean; message: string; jwks?: { keys: JWK[] } }> };
    };
    const { agent_id: agentId } = vectors.agent_claim;
    for (const c of vectors.agent_claim.cases) {
      const keys = (c.jwks ?? vectors.agent_claim.jwks).keys.filter((k) => k.kid === `agent:${agentId}:v1`);
      const key = keys[0];
      const unusable = keys.some((k) => 'd' in k || (k.alg !== undefined && k.alg !== 'EdDSA') || (k.use !== undefined && k.use !== 'sig'));
      const agentRepo = { findById: async () => ({ id: agentId, operator_id: 'op_vectors', key_mode: 'customer_managed', pubkey: key ?? null }) };
      const signer = new AgentSigner({ agentRepo: agentRepo as never, kms: {} as never, systemOperatorId: '', operatorClaimSigner: async () => { throw new Error('not used'); } });
      const valid = !unusable && key !== undefined && (await signer.verifyPreSigned(c.message, agentId).catch(() => ({ valid: false }))).valid;
      expect(valid, c.name).toBe(c.valid);
    }
  });
});
