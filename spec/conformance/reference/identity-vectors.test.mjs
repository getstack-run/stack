// The test vectors of fixtures/identity/vectors.json (built from the specifications by
// scripts/build-identity-vectors.mjs) are judged by the reference implementations of this repository.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { createAgentJwtVerifier } from './agent-jwt-reference.mjs';
import { verifyAgentClaim } from './agent-claim-reference.mjs';
import { isMetadataClientId, validate } from './oauth-client-metadata-reference.mjs';
import { accept } from './workload-token-reference.mjs';

const vectors = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'identity', 'vectors.json'), 'utf8'));

describe('identity test vectors', () => {
  it('give the agent JWT verdicts of the specification, with the tokens presented in order', async () => {
    const verify = createAgentJwtVerifier({ now: () => vectors.agent_jwt.now });
    for (const c of vectors.agent_jwt.cases) {
      let accepted;
      try {
        await verify(c.token_parts.join('.'), { agentId: vectors.agent_jwt.agent_id, publicJwk: vectors.agent_jwt.public_jwk });
        accepted = true;
      } catch {
        accepted = false;
      }
      expect(accepted, c.name).toBe(c.valid);
    }
  });

  it('give the agent claim verdicts of the specification', () => {
    for (const c of vectors.agent_claim.cases) {
      const result = verifyAgentClaim(c.message, { jwks: c.jwks ?? vectors.agent_claim.jwks, agentId: vectors.agent_claim.agent_id });
      expect(result.valid, c.name).toBe(c.valid);
    }
  });

  it('give the workload token verdicts and reasons of the specification', async () => {
    for (const c of vectors.workload_token.cases) {
      let outcome;
      try {
        await accept({ kind: c.kind, token: c.token_parts.join('.'), config: c.config, jwks: c.jwks, now: () => vectors.workload_token.now });
        outcome = { valid: true };
      } catch (error) {
        outcome = { valid: false, reason: error.code };
      }
      expect(outcome.valid, c.name).toBe(c.valid);
      if (c.reason) expect(outcome.reason, c.name).toBe(c.reason);
    }
  });

  it('give the client metadata verdicts of the specification', () => {
    for (const c of vectors.client_metadata.cases) {
      let valid;
      try {
        validate(c.client_id, c.document);
        valid = true;
      } catch {
        valid = false;
      }
      expect(valid, c.name).toBe(c.valid);
    }
    for (const c of vectors.client_metadata.client_ids) expect(isMetadataClientId(c.client_id), c.client_id).toBe(c.metadata_document_url);
  });
});
