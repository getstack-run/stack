/** Receivers and their keys: registration, verification and request authentication. */
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  generateId,
  type AddAuthorityReceiverKeyInput,
  type CreateAuthorityReceiverInput,
} from '@stack/shared';
import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { isIP } from 'node:net';
import { randomBytes } from 'node:crypto';
import type { AuthorityPresentationProtocol } from './presentation-protocol.js';
import type {
  AuthorityReceiverAuthContext,
  AuthorityReceiverProfileRecord,
  AuthorityReceiverRecord,
} from './records.js';
import type { AuthorityServiceDeps } from './contracts.js';
import { AuthorityCore } from './core.js';
import {
  assertPublicReceiverJwk,
  assertReceiverKeyUsable,
  receiverJwkThumbprint,
  validatePublicHttpsEndpoint,
  AUTHORITY_CLOCK_TOLERANCE_SECONDS,
  AUTHORITY_VERIFICATION_CHALLENGE_SECONDS,
} from './receiver-validation.js';
import { safeReceiver } from './redaction.js';
import { sha256 } from './digest.js';

export class ReceiverService {
  private readonly deps: AuthorityServiceDeps;
  private readonly now: () => Date;

  constructor(private readonly core: AuthorityCore) {
    this.deps = core.deps;
    this.now = core.now;
  }

  async createReceiver(
    operatorId: string,
    input: CreateAuthorityReceiverInput,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      'receiver.create',
      idempotencyKey,
      input,
      async (repo) => {
        let canonicalIdentifier = input.canonical_identifier;
        if (input.mode === 'native') {
          const checked = await validatePublicHttpsEndpoint(input.canonical_identifier);
          const url = new URL(checked.normalized);
          if (
            isIP(url.hostname) ||
            url.pathname !== '/' ||
            url.search ||
            url.hash ||
            input.canonical_identifier !== url.origin
          ) {
            throw new ForbiddenError(
              'native receiver identifier must be a normalized public HTTPS origin',
            );
          }
          canonicalIdentifier = url.origin;
        } else if (input.mode === 'internal') {
          if (!(await repo.isOwnedInternalReceiver(operatorId, canonicalIdentifier)))
            throw new ForbiddenError();
        } else if (
          !input.proxy_service_connection_id ||
          !(await repo.isOwnedActiveServiceConnection(
            operatorId,
            input.proxy_service_connection_id,
          ))
        ) {
          throw new ForbiddenError(
            'proxy receiver must reference an owned active service connection',
          );
        }
        const duplicate =
          input.mode === 'native'
            ? (await repo.findNativeReceiversByCanonicalId(canonicalIdentifier))[0]
            : await repo.findManagedReceiverByCanonicalId(operatorId, canonicalIdentifier);
        if (duplicate)
          throw new ConflictError('authority receiver canonical identifier already exists');
        const now = this.now();
        const row = await repo.insertReceiver({
          id: generateId('rcv'),
          managed_by_operator_id: operatorId,
          mode: input.mode,
          canonical_identifier: canonicalIdentifier,
          display_name: input.display_name,
          proxy_service_connection_id: input.proxy_service_connection_id ?? null,
          current_profile_version_id: null,
          status: 'pending',
          created_at: now,
          verified_at: input.mode !== 'native' ? now : null,
        });
        return safeReceiver(row);
      },
      201,
    );
  }

  async listReceivers(operatorId: string) {
    return (await this.deps.repo.listReceivers(operatorId)).map(safeReceiver);
  }

  async getReceiver(operatorId: string, receiverId: string) {
    const row = await this.deps.repo.findReceiver(operatorId, receiverId);
    if (!row) throw new NotFoundError('AuthorityReceiver', receiverId);
    return safeReceiver(row);
  }

  async createReceiverVerificationChallenge(
    operatorId: string,
    receiverId: string,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `receiver.verify.challenge:${receiverId}`,
      idempotencyKey,
      {},
      async (repo) => {
        const receiver = await repo.findReceiver(operatorId, receiverId);
        if (!receiver || receiver.status === 'revoked')
          throw new NotFoundError('AuthorityReceiver', receiverId);
        const challengeId = generateId('rvc');
        const challenge = randomBytes(32).toString('base64url');
        const expiresAt = new Date(this.now().getTime() + AUTHORITY_VERIFICATION_CHALLENGE_SECONDS * 1000);
        if (
          !(await repo.createReceiverVerificationChallenge({
            operatorId,
            receiverId,
            challengeId,
            challengeHash: sha256(challenge),
            expiresAt,
          }))
        )
          throw new ConflictError('receiver verification challenge could not be created');
        return {
          challenge_id: challengeId,
          challenge,
          audience: this.deps.receiverRequestAudience,
          expires_at: expiresAt.toISOString(),
        };
      },
    );
  }

  async verifyReceiver(operatorId: string, receiverId: string, idempotencyKey: string) {
    return this.core.idempotent(
      operatorId,
      `receiver.verify:${receiverId}`,
      idempotencyKey,
      {},
      async (repo) => {
        const receiver = await repo.findReceiver(operatorId, receiverId);
        if (!receiver || receiver.status === 'revoked')
          throw new NotFoundError('AuthorityReceiver', receiverId);
        if (receiver.mode !== 'native')
          throw new ForbiddenError('proxy receivers are verified through their owned connection');
        const wellKnownUrl = `${receiver.canonical_identifier}/.well-known/stack-receiver.json`;
        const checked = await validatePublicHttpsEndpoint(wellKnownUrl);
        const fetched = await this.deps.receiverOriginVerifier.fetchWellKnown({
          url: checked.normalized,
          resolvedAddresses: checked.addresses,
          redirect: 'manual',
        });
        if (fetched.status !== 200 || fetched.location || fetched.body.length > 1_000_000) {
          throw new ForbiddenError(
            'receiver origin verification document is unavailable or redirected',
          );
        }
        let document: Record<string, unknown>;
        try {
          document = JSON.parse(fetched.body) as Record<string, unknown>;
        } catch {
          throw new ForbiddenError('receiver origin verification document is invalid');
        }
        const keyId = String(document.key_id ?? '');
        const signedChallenge = String(document.signed_challenge ?? '');
        if (document.origin !== receiver.canonical_identifier || !keyId || !signedChallenge) {
          throw new ForbiddenError(
            'receiver origin verification document does not match the registered origin',
          );
        }
        const header = decodeProtectedHeader(signedChallenge);
        if (
          header.jku ||
          header.x5u ||
          header.jwk ||
          header.kid !== keyId ||
          !['EdDSA', 'ES256'].includes(String(header.alg))
        ) {
          throw new ForbiddenError('receiver verification uses an untrusted key or algorithm');
        }
        const key = await repo.findReceiverKey(receiverId, keyId, 'request_signing');
        const now = this.now();
        assertReceiverKeyUsable(key, now, String(header.alg));
        const verified = await jwtVerify(
          signedChallenge,
          await importJWK(key!.public_jwk, key!.algorithm),
          {
            algorithms: [key!.algorithm],
            issuer: receiver.id,
            subject: receiver.id,
            audience: this.deps.receiverRequestAudience,
            currentDate: now,
            clockTolerance: AUTHORITY_CLOCK_TOLERANCE_SECONDS,
          },
        );
        const challengeId = String(verified.payload.challenge_id ?? '');
        const challenge = String(verified.payload.challenge ?? '');
        if (
          !challengeId ||
          !challenge ||
          !(await repo.consumeReceiverVerificationChallenge({
            operatorId,
            receiverId,
            challengeId,
            challengeHash: sha256(challenge),
            now,
          }))
        )
          throw new ForbiddenError(
            'receiver verification challenge is invalid, expired, or replayed',
          );
        const row = await repo.markReceiverVerified(operatorId, receiverId, now);
        if (!row) throw new ConflictError('receiver verification transition failed');
        return safeReceiver(row);
      },
    );
  }

  async addReceiverKey(
    operatorId: string,
    receiverId: string,
    input: AddAuthorityReceiverKeyInput,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `receiver.key.add:${receiverId}`,
      idempotencyKey,
      input,
      async (repo) => {
        const receiver = await repo.findReceiver(operatorId, receiverId);
        if (!receiver || receiver.status === 'revoked')
          throw new NotFoundError('AuthorityReceiver', receiverId);
        assertPublicReceiverJwk(input);
        const thumbprint = receiverJwkThumbprint(input.public_jwk as JWK);
        const row = await repo.insertReceiverKey({
          id: generateId('rky'),
          receiver_id: receiverId,
          key_id: input.key_id,
          use: input.use,
          algorithm: input.algorithm,
          public_jwk: input.public_jwk as JWK,
          thumbprint,
          status: 'active',
          valid_from: input.valid_from,
          valid_until: input.valid_until ?? null,
          created_at: this.now(),
          revoked_at: null,
        });
        return { ...row, public_jwk: undefined };
      },
      201,
    );
  }

  async revokeReceiverKey(
    operatorId: string,
    receiverId: string,
    keyId: string,
    reason: string,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `receiver.key.revoke:${receiverId}:${keyId}`,
      idempotencyKey,
      { reason },
      async (repo) => {
        const row = await repo.revokeReceiverKey(operatorId, receiverId, keyId, reason, this.now());
        if (!row) throw new NotFoundError('AuthorityReceiverKey', keyId);
        return {
          id: row.id,
          key_id: row.key_id,
          use: row.use,
          status: row.status,
          revoked_at: this.now().toISOString(),
        };
      },
    );
  }

  async authenticateReceiverRequest(input: {
    compactJws: string;
    method: string;
    normalizedPath: string;
    bodyHash: string;
    now?: Date;
  }): Promise<AuthorityReceiverAuthContext> {
    const now = input.now ?? this.now();
    const candidates: Array<{
      protocol: AuthorityPresentationProtocol;
      receiver: AuthorityReceiverRecord;
      profile: AuthorityReceiverProfileRecord;
      route: { receiverId: string; keyId: string; algorithm: string };
    }> = [];
    for (const protocol of this.core.presentationProtocols.values()) {
      let route: { receiverId: string; keyId: string; algorithm: string };
      try {
        route = protocol.peekReceiverRequest(input.compactJws);
      } catch {
        continue;
      }
      const receiver = await this.deps.repo.findReceiverById(route.receiverId);
      if (
        !receiver ||
        receiver.mode !== 'native' ||
        receiver.status !== 'active' ||
        !receiver.current_profile_version_id
      )
        continue;
      const profile = await this.deps.repo.findReceiverProfile(
        receiver.managed_by_operator_id,
        receiver.current_profile_version_id,
      );
      if (
        !profile ||
        profile.status !== 'active' ||
        this.core.presentationProtocolForConfig(profile.config_json) !== protocol
      )
        continue;
      candidates.push({ protocol, receiver, profile, route });
    }
    if (candidates.length !== 1)
      throw new ForbiddenError('receiver request protocol or routing is unavailable');
    const { protocol, receiver, profile, route } = candidates[0]!;
    const key = await this.deps.repo.findReceiverKey(receiver.id, route.keyId, 'request_signing');
    assertReceiverKeyUsable(key, now, route.algorithm);
    const authenticated = await protocol.authenticateReceiverRequest({
      compactRequest: input.compactJws,
      receiver,
      profile,
      key,
      audience: `${this.deps.receiverRequestAudience.replace(/\/$/, '')}${input.normalizedPath}`,
      method: input.method,
      normalizedPath: input.normalizedPath,
      bodyHash: input.bodyHash,
      now,
    });
    if (
      !(await this.deps.repo.consumeReceiverJti({
        receiverId: receiver.id,
        jtiHash: sha256(authenticated.jti),
        expiresAt: authenticated.expiresAt,
      }))
    ) {
      throw new ConflictError('receiver request replay detected');
    }
    return {
      receiverId: receiver.id,
      keyId: key.key_id,
      jti: authenticated.jti,
      expiresAt: authenticated.expiresAt,
      payload: authenticated.payload,
    };
  }
}
