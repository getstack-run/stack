/** Verification of the agent's proof of possession carried by a presentation request. */
import {
  ConflictError,
  ForbiddenError,
  canonicalize,
  type ReceiverChallengeInput,
} from '@stack/shared';
import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import type { AuthorityBindingRecord } from './records.js';
import type { AuthorityRepositoryPort } from './port.js';
import { AUTHORITY_CLOCK_TOLERANCE_SECONDS, assertBoundedJwtLifetime } from './receiver-validation.js';
import { sha256 } from './digest.js';

/**
 * Checks that the agent signed this exact receiver request with the key its
 * binding pins, within the request's lifetime, and records the proof's
 * identifier so it cannot be replayed.
 */
export async function verifyPresentationAgentProof(
  repo: AuthorityRepositoryPort,
  input: {
    binding: AuthorityBindingRecord;
    currentAgentKey: { thumbprint: string; active: boolean; publicJwk: JWK };
    receiverId: string;
    input: ReceiverChallengeInput;
    requestMaximumAge: number;
    now: Date;
  },
): Promise<void> {
  const header = decodeProtectedHeader(input.input.agent_proof);
  if (
    header.jku ||
    header.x5u ||
    header.jwk ||
    header.alg !== 'EdDSA' ||
    header.kid !== input.currentAgentKey.thumbprint
  ) {
    throw new ForbiddenError('agent proof uses an untrusted key or algorithm');
  }
  const verified = await jwtVerify(
    input.input.agent_proof,
    await importJWK(input.currentAgentKey.publicJwk, 'EdDSA'),
    {
      algorithms: ['EdDSA'],
      issuer: input.binding.agent_id,
      subject: input.binding.agent_id,
      audience: input.receiverId,
      currentDate: input.now,
      clockTolerance: AUTHORITY_CLOCK_TOLERANCE_SECONDS,
    },
  );
  const payload = verified.payload as Record<string, unknown>;
  const bound = {
    receiver_request_id: input.input.receiver_request_id,
    authority_ref: input.input.authority_ref,
    passport_hash: sha256(input.input.passport),
    mission_id: input.input.mission_id,
    action_uri: input.input.action_uri,
    resource_hash: input.input.resource_hash,
    request_hash: input.input.request_hash,
    nonce: input.input.nonce,
  };
  for (const [keyName, expected] of Object.entries(bound)) {
    if (canonicalize(payload[keyName]) !== canonicalize(expected)) {
      throw new ForbiddenError(`agent proof signed payload mismatch for ${keyName}`);
    }
  }
  const issuedAt = Number(payload.iat);
  const expiresAt = Number(payload.exp);
  const jti = String(payload.jti ?? '');
  if (!jti || issuedAt !== input.input.issued_at || expiresAt !== input.input.expires_at) {
    throw new ForbiddenError('agent proof protected lifetime does not match the receiver request');
  }
  assertBoundedJwtLifetime(issuedAt, expiresAt, input.now, input.requestMaximumAge, 'agent proof');
  if (
    !(await repo.consumeAuthorityJti({
      operatorId: input.binding.operator_id,
      namespace: `agent-proof:${input.receiverId}`,
      jtiHash: sha256(jti),
      expiresAt: new Date(expiresAt * 1000),
    }))
  ) {
    throw new ConflictError('agent proof replay detected');
  }
}
