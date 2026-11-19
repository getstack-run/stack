import type { FastifyInstance } from 'fastify';
import { SigningKeyUnavailableError } from '@stack/shared';
import type { Services } from '../config/services.js';

/**
 * Public JWKS endpoint for per-agent signing keys.
 *
 * of the Signed Primitive epic.
 * ADR Design Decision 15.
 *
 * Each agent has its own Ed25519 signing keypair (added
 * via the agents table columns; lazy-provisioned by AgentSigner
 * for stack_managed and co_signed modes). This
 * endpoint exposes the agent's pubkey(s) so external verifiers can
 * validate COSE_Sign1 envelopes signed by that agent's key.
 *
 * **URL shape:** `GET /v1/agents/:id/.well-known/jwks.json`
 *
 * **Security posture:** PUBLIC, no auth. Same posture as the operator
 * JWKS at `/v1/.well-known/jwks.json` — pubkeys are by definition
 * public material. The kid in a COSE protected header tells the
 * verifier WHICH key to use; this endpoint resolves the kid to the
 * pubkey bytes. Without a public lookup, external SCITT verifiers
 * couldn't independently verify STACK-signed claims.
 *
 * **Shape forward-compatible with key rotation.** Returns
 * `{ keys: [...] }` where each entry is a JWK plus optional
 * `not_before` / `not_after` timestamps (unix ms) marking the
 * validity window. Today every agent has exactly one key (no
 * rotation primitive shipped yet); the response carries one entry
 * with `not_before = enrolled_at` and `not_after = null` (= current).
 *
 * When rotation ships (separate change, later), each
 * rotation appends a new key entry; the previous entry's
 * `not_after` flips to the rotation timestamp. Verifier picks the
 * key by kid (kids are unique per generation: `agent:{id}:v1`,
 * `:v2`, etc.) — the not_before/not_after metadata is informational
 * for the verifier, not load-bearing for the verification math.
 *
 * **404 vs empty response:** an agent that does not exist OR exists
 * in customer_managed mode without an SDK-enrolled pubkey OR exists
 * in stack_managed mode but has never signed (no AgentSigner
 * provisioning yet) returns 404. A 200 with `{ keys: [] }` would
 * mislead external verifiers into caching an empty result; better
 * to fail-loud so the caller retries when the key actually exists.
 *
 * **Verification flow:** a verifier seeing a COSE_Sign1 with kid
 * `agent:ag_xyz:v1` constructs `https://api.getstack.run/v1/agents/
 * ag_xyz/.well-known/jwks.json`, fetches, finds the matching kid in
 * the keys array, imports the pubkey, verifies the signature.
 */
export function registerAgentJwksRoute(app: FastifyInstance, services: Services) {
  app.get<{ Params: { id: string } }>(
    '/v1/agents/:id/.well-known/jwks.json',
    async (request, reply) => {
      const { id } = request.params;

      const info = await services.agent.getPublicSigningInfo(id);
      if (!info) {
        // 404 for both "agent not found" and "agent has no key" —
        // see file docstring for the rationale (avoid misleading
        // verifier caches with empty keys arrays).
        throw new SigningKeyUnavailableError('agent', id);
      }

      return reply.status(200).send({
        keys: [
          {
            // Standard JWK fields (RFC 7517).
            kty: info.pubkey.kty,
            crv: info.pubkey.crv,
            x: info.pubkey.x,
            kid: info.kid,
            alg: 'EdDSA',
            use: 'sig',
            // Validity window. Non-standard JWK fields (custom
            // extension) — JWKS readers that don't recognise these
            // fields ignore them per RFC 7517 §4.1. Future rotation
            // populates not_after with the rotation timestamp on the
            // retired key.
            not_before: info.enrolled_at?.getTime() ?? null,
            not_after: null,
          },
        ],
      });
    },
  );
}
