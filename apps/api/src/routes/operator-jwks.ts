import type { FastifyInstance } from 'fastify';
import { SigningKeyUnavailableError } from '@stack/shared';
import type { Services } from '../config/services.js';

/**
 * Public JWKS endpoint for per-operator claim-signing keys.
 *
 * Part of the Signed Primitive epic. Mirror of
 * `/v1/agents/:id/.well-known/jwks.json` (agent-jwks.ts) — operator keys
 * sign COSE_Sign1 claim envelopes attached to passports owned by that
 * operator. The kid in the COSE protected header tells the verifier which
 * key to use; this endpoint resolves it.
 *
 * **URL shape:** `GET /v1/operators/:operator_id/jwks.json`
 *
 * **Security posture:** PUBLIC, no auth. Same posture as
 * `/v1/.well-known/jwks.json` and `/v1/agents/:id/.well-known/jwks.json` —
 * pubkeys are by definition public material. The data layer carve-out for
 * `op_stack_system` (no row in `operator_signing_keys`) is what enforces
 * the 404 for the system operator.
 *
 * **Shape:** returns `{ keys: [...] }` with one entry per non-revoked
 * signing key for that operator (active + retired). Each entry carries
 * kid, alg, use, not_before, not_after. Retired keys have not_after set
 * to their `retired_at` timestamp; active keys have not_after = null.
 *
 * **404 vs empty response:** an operator with no active or retired keys
 * returns 404. Empty `{ keys: [] }` would mislead JWKS readers into
 * caching an empty result; fail-loud so the caller retries when the key
 * actually exists. The system operator falls through to 404 by virtue
 * of the data-layer carve-out (the service refuses to insert rows for
 * `op_stack_system`).
 *
 * **Verification flow:** a verifier seeing a COSE_Sign1 with kid
 * `op_abc:claim:v1` constructs
 * `https://api.getstack.run/v1/operators/op_abc/jwks.json`, fetches,
 * finds the matching kid in the keys array, imports the pubkey, verifies
 * the signature.
 */
export function registerOperatorJwksRoute(app: FastifyInstance, services: Services) {
  app.get<{ Params: { operator_id: string } }>(
    '/v1/operators/:operator_id/jwks.json',
    async (request, reply) => {
      const { operator_id } = request.params;

      const keys = await services.operatorSigningKey.getPublicJwksForOperator(operator_id);
      if (keys.length === 0) {
        throw new SigningKeyUnavailableError('operator', operator_id);
      }

      return reply.status(200).send({ keys });
    },
  );
}
