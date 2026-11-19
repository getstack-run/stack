/** The STACK direct-post JWT presentation protocol. */
import { CompactEncrypt, decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { ForbiddenError, canonicalize } from '@stack/shared';
import type {
  AuthorityPresentationProtocol,
  AuthorityPresentationSigner,
  AuthorityPresentationTransport,
} from './presentation-protocol.js';
import type {
  AuthorityReceiverKeyRecord,
  AuthorityReceiverProfileRecord,
  AuthorityReceiverRecord,
} from './records.js';
import {
  STACK_DIRECT_POST_PROTOCOL_KEY,
  STACK_DIRECT_POST_PROTOCOL_VERSION,
  assertStackDirectPostProfile,
} from './profile-validators.js';
import {
  AUTHORITY_ASSERTION_MAX_SECONDS,
  AUTHORITY_CLOCK_TOLERANCE_SECONDS,
  assertBoundedJwtLifetime,
} from './receiver-validation.js';
import { sha256 } from './digest.js';

export class StackDirectPostJwtV1Protocol implements AuthorityPresentationProtocol {
  readonly key = STACK_DIRECT_POST_PROTOCOL_KEY;
  readonly version = STACK_DIRECT_POST_PROTOCOL_VERSION;

  constructor(
    private signer: AuthorityPresentationSigner,
    private transport: AuthorityPresentationTransport,
  ) {}

  validateProfile(config: Record<string, unknown>): void {
    assertStackDirectPostProfile(config);
  }

  peekReceiverRequest(compactRequest: string) {
    const header = decodeProtectedHeader(compactRequest);
    if (
      header.jku ||
      header.x5u ||
      header.jwk ||
      !header.kid ||
      !['EdDSA', 'ES256'].includes(String(header.alg))
    ) {
      throw new ForbiddenError('receiver request uses untrusted key discovery or algorithm');
    }
    const payload = decodeJwt(compactRequest);
    const receiverId = String(payload.iss ?? '');
    if (!/^rcv_[\w-]+$/.test(receiverId) || payload.sub !== receiverId) {
      throw new ForbiddenError('receiver request issuer/subject mismatch');
    }
    return { receiverId, keyId: header.kid, algorithm: String(header.alg) };
  }

  async authenticateReceiverRequest(input: {
    compactRequest: string;
    receiver: AuthorityReceiverRecord;
    profile: AuthorityReceiverProfileRecord;
    key: AuthorityReceiverKeyRecord;
    audience: string;
    method: string;
    normalizedPath: string;
    bodyHash: string;
    now: Date;
  }) {
    this.validateProfile(input.profile.config_json);
    const authConfig = input.profile.config_json.request_authentication as Record<string, unknown>;
    const route = this.peekReceiverRequest(input.compactRequest);
    if (
      route.receiverId !== input.receiver.id ||
      route.keyId !== input.key.key_id ||
      !((authConfig.signing_key_ids as string[]) ?? []).includes(route.keyId) ||
      !((authConfig.allowed_algs as string[]) ?? []).includes(route.algorithm)
    ) {
      throw new ForbiddenError('receiver request key is not permitted by the active profile');
    }
    const verified = await jwtVerify(
      input.compactRequest,
      await importJWK(input.key.public_jwk, input.key.algorithm),
      {
        algorithms: [input.key.algorithm],
        issuer: input.receiver.id,
        subject: input.receiver.id,
        audience: input.audience,
        currentDate: input.now,
        clockTolerance: AUTHORITY_CLOCK_TOLERANCE_SECONDS,
      },
    );
    const payload = verified.payload as Record<string, unknown>;
    const issuedAt = Number(payload.iat);
    const expires = Number(payload.exp);
    const jti = String(payload.jti ?? '');
    if (!jti) throw new ForbiddenError('receiver request lifetime is invalid');
    assertBoundedJwtLifetime(
      issuedAt,
      expires,
      input.now,
      Math.min(Number(authConfig.maximum_age_seconds ?? AUTHORITY_ASSERTION_MAX_SECONDS), AUTHORITY_ASSERTION_MAX_SECONDS),
      'receiver request',
    );
    if (
      payload.htm !== input.method.toUpperCase() ||
      payload.htu !== input.normalizedPath ||
      payload.body_hash !== input.bodyHash
    ) {
      throw new ForbiddenError('receiver request is not bound to this HTTP request');
    }
    return { payload, jti, expiresAt: new Date(expires * 1000) };
  }

  async verifyPresentationRequest(input: {
    compactRequest: string;
    receiver: AuthorityReceiverRecord;
    profile: AuthorityReceiverProfileRecord;
    key: AuthorityReceiverKeyRecord;
    audience: string;
    now: Date;
  }) {
    this.validateProfile(input.profile.config_json);
    const route = this.peekReceiverRequest(input.compactRequest);
    const authConfig = input.profile.config_json.request_authentication as Record<string, unknown>;
    if (
      !((authConfig.signing_key_ids as string[]) ?? []).includes(route.keyId) ||
      !((authConfig.allowed_algs as string[]) ?? []).includes(route.algorithm)
    ) {
      throw new ForbiddenError('receiver challenge key is not permitted by the active profile');
    }
    const verified = await jwtVerify(
      input.compactRequest,
      await importJWK(input.key.public_jwk, input.key.algorithm),
      {
        algorithms: [input.key.algorithm],
        issuer: input.receiver.id,
        subject: input.receiver.id,
        audience: input.audience,
        currentDate: input.now,
        clockTolerance: AUTHORITY_CLOCK_TOLERANCE_SECONDS,
      },
    );
    return { payload: verified.payload as Record<string, unknown> };
  }

  async verifyReceipt(input: {
    compactReceipt: string;
    receiver: AuthorityReceiverRecord;
    profile: AuthorityReceiverProfileRecord;
    key: AuthorityReceiverKeyRecord;
    audience: string;
    now: Date;
  }) {
    this.validateProfile(input.profile.config_json);
    const verified = await jwtVerify(
      input.compactReceipt,
      await importJWK(input.key.public_jwk, input.key.algorithm),
      {
        algorithms: [input.key.algorithm],
        issuer: input.receiver.id,
        subject: input.receiver.id,
        audience: input.audience,
        currentDate: input.now,
        clockTolerance: AUTHORITY_CLOCK_TOLERANCE_SECONDS,
      },
    );
    return { payload: verified.payload as Record<string, unknown> };
  }

  async signEncryptAndDeliver(input: {
    payload: Record<string, unknown>;
    receiverKey: AuthorityReceiverKeyRecord;
    endpoint: string;
    resolvedAddresses: string[];
    audience: string;
    presentationId: string;
  }): Promise<{
    payloadHash: string;
    deliveredAt: Date;
    signingKeyId: string;
    compactJweHash: string;
  }> {
    if (
      input.receiverKey.use !== 'response_encryption' ||
      input.receiverKey.algorithm !== 'ECDH-ES+A256KW'
    ) {
      throw new ForbiddenError(
        'receiver response-encryption key is incompatible with the active protocol',
      );
    }
    const signed = await this.signer.sign(input.payload);
    const publicKey = await importJWK(input.receiverKey.public_jwk, input.receiverKey.algorithm);
    const compactJwe = await new CompactEncrypt(Buffer.from(signed, 'utf8'))
      .setProtectedHeader({
        alg: 'ECDH-ES+A256KW',
        enc: 'A256GCM',
        cty: 'JWT',
        kid: input.receiverKey.key_id,
      })
      .encrypt(publicKey);
    const delivered = await this.transport.deliver({
      endpoint: input.endpoint,
      resolvedAddresses: input.resolvedAddresses,
      audience: input.audience,
      compactJwe,
      presentationId: input.presentationId,
    });
    return {
      payloadHash: sha256(canonicalize(input.payload)),
      deliveredAt: delivered.deliveredAt,
      signingKeyId: this.signer.keyId,
      compactJweHash: sha256(compactJwe),
    };
  }
}
