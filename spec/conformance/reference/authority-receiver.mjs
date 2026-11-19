// A reference authority receiver: the smallest correct implementation of the
// receiver side of spec/authority-receiver/SPEC.md. It signs the two receiver
// JWS of a presentation request, signs receipts, builds the origin document,
// and opens presentations with every check of section 7.2. It uses node:crypto
// and the kit's JOSE helpers; start a receiver of your own from it.
//
// `createReceiver(config)` is the function the `authority` suite takes
// (`stack-conformance authority --module ./authority-receiver.mjs`). The
// functions are pure with respect to the clock: `now` is passed in.

import { randomBytes } from 'node:crypto';
import { canonicalize } from '../src/canonical.mjs';
import { decodeJws, decryptJwe, digest, privateKeyFromJwk, signJws, verifyJwsSignature } from '../src/authority-jose.mjs';

const STACK_ALGORITHMS = ['EdDSA'];
const MAX_PRESENTATION_SECONDS = 120;

export function createReceiver(config) {
  const requestKey = privateKeyFromJwk(config.requestKey.privateJwk);
  const receiptKey = privateKeyFromJwk(config.receiptKey.privateJwk);
  const encryptionKey = privateKeyFromJwk(config.encryptionKey.privateJwk);
  const seen = new Set();
  const jti = () => randomBytes(18).toString('base64url');

  /** Claims every receiver-signed JWS shares (section 4.3). */
  const claims = (audience, now, lifetime, extra) => ({
    iss: config.receiverId, sub: config.receiverId, aud: audience, jti: jti(), iat: now, exp: now + lifetime, ...extra,
  });
  const sign = (key, material, payload) => signJws({ alg: material.alg, kid: material.kid, typ: 'JWT' }, payload, key, material.alg);

  return {
    /** The value of the Authorization header for one call (section 5). */
    authorization({ method, path, body, now }) {
      const [bare] = path.split('?', 1);
      const payload = claims(`${config.stackOrigin}${bare}`, now, 30, {
        htm: method.toUpperCase(),
        htu: bare,
        body_hash: digest(body === undefined ? '' : canonicalize(body)),
      });
      return `STACK-Receiver ${sign(requestKey, config.requestKey, payload)}`;
    },

    /** The signed_request of a presentation request body (section 6.2). */
    signPresentationRequest(fields, { now }) {
      const repeated = ['authority_ref', 'receiver_profile_version_id', 'receiver_request_id', 'mission_id', 'action_uri', 'resource_hash', 'request_hash', 'requested_facts', 'nonce', 'issued_at', 'expires_at', 'normalized_request'];
      const payload = {
        ...Object.fromEntries(repeated.map((name) => [name, fields[name]])),
        passport_hash: digest(fields.passport),
        agent_proof_hash: digest(fields.agent_proof),
        ...claims(`${config.stackOrigin}/v1/authority/presentation-requests`, fields.issued_at ?? now, 0, {}),
      };
      payload.exp = fields.expires_at;
      return sign(requestKey, config.requestKey, payload);
    },

    /** A receipt for a presentation the receiver took in (section 9). */
    signReceipt({ presentationId, presentation, outcome, result, externalTransactionRef, now }) {
      const commitmentNonce = randomBytes(18).toString('base64url');
      const payload = claims(`${config.stackOrigin}/v1/authority/presentations/${presentationId}/receipts`, now, 30, {
        receiver_id: config.receiverId,
        presentation_id: presentationId,
        authority_use_id: presentation.authority_use_id,
        presentation_payload_hash: digest(canonicalize(presentation)),
        request_hash: presentation.request_hash,
        action_uri: presentation.action_uri,
        outcome,
        result,
        result_commitment_nonce: commitmentNonce,
        result_hash: digest(canonicalize({ value: result, commitment_nonce: commitmentNonce })),
        ...(externalTransactionRef === undefined ? {} : { external_transaction_ref: externalTransactionRef }),
      });
      return sign(receiptKey, config.receiptKey, payload);
    },

    /**
     * Decrypt and verify one presentation (section 7.2). Resolves with the
     * claims; throws on anything it must refuse.
     */
    openPresentation(compactJwe, { now, expected }) {
      const { header, plaintext } = decryptJwe(compactJwe, encryptionKey);
      if (header.kid !== config.encryptionKey.kid) throw new Error('the JWE is not addressed to this receiver key');
      const decoded = decodeJws(plaintext);
      if (!decoded) throw new Error('the plaintext is not a compact JWS');
      const { header: jwsHeader, payload } = decoded;
      if (!STACK_ALGORITHMS.includes(jwsHeader.alg)) throw new Error('the presentation algorithm is not accepted');
      for (const member of ['jku', 'x5u', 'jwk', 'crit']) if (member in jwsHeader) throw new Error(`the header carries ${member}`);
      const key = config.stackKeys.keys.find((candidate) => candidate.kid === jwsHeader.kid);
      if (!key || !verifyJwsSignature(decoded, key, jwsHeader.alg)) throw new Error('the presentation is not signed by a STACK key this receiver trusts');
      if (payload.iss !== config.presentationIssuer) throw new Error('wrong issuer');
      if (payload.aud !== config.audience) throw new Error('wrong audience');
      if (payload.receiver_id !== config.receiverId || payload.receiver_profile_version_id !== config.receiverProfileVersionId) throw new Error('the presentation is for another receiver');
      if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) throw new Error('iat and exp must be integers');
      if (payload.iat > now + 5 || payload.exp <= now - 5 || payload.exp <= payload.iat || payload.exp - payload.iat > MAX_PRESENTATION_SECONDS) throw new Error('the presentation is not live');
      if (typeof payload.jti !== 'string' || payload.jti === '') throw new Error('no jti');
      if (payload.nonce !== expected.nonce) throw new Error('the nonce is not the one this receiver sent');
      if (payload.request_hash !== expected.requestHash) throw new Error('the presentation is for another transaction');
      if (seen.has(payload.jti)) throw new Error('the presentation was already taken in');
      seen.add(payload.jti);
      return payload;
    },

    /** The document served at /.well-known/stack-receiver.json while the origin is being verified (section 3.3). */
    verificationDocument({ challengeId, challenge, now }) {
      const payload = claims(config.stackOrigin, now, 120, { challenge_id: challengeId, challenge });
      return {
        origin: config.origin ?? 'https://receiver.stack-conformance.test',
        key_id: config.requestKey.kid,
        signed_challenge: sign(requestKey, config.requestKey, payload),
      };
    },
  };
}

export default createReceiver;
