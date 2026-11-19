/** Contract between the authority service and a presentation wire protocol. */
import type {
  AuthorityReceiverKeyRecord,
  AuthorityReceiverProfileRecord,
  AuthorityReceiverRecord,
} from './records.js';

export interface AuthorityPresentationSigner {
  keyId: string;
  algorithm: 'EdDSA';
  sign(payload: Record<string, unknown>): Promise<string>;
}

export interface AuthorityPresentationTransport {
  deliver(input: {
    endpoint: string;
    /** The transport must connect only to one of these resolved addresses. */
    resolvedAddresses: string[];
    audience: string;
    compactJwe: string;
    presentationId: string;
  }): Promise<{ deliveredAt: Date; responseHash?: string }>;
}

export interface AuthorityPresentationProtocol {
  readonly key: string;
  readonly version: string;
  validateProfile(config: Record<string, unknown>): void;
  peekReceiverRequest(compactRequest: string): {
    receiverId: string;
    keyId: string;
    algorithm: string;
  };
  authenticateReceiverRequest(input: {
    compactRequest: string;
    receiver: AuthorityReceiverRecord;
    profile: AuthorityReceiverProfileRecord;
    key: AuthorityReceiverKeyRecord;
    audience: string;
    method: string;
    normalizedPath: string;
    bodyHash: string;
    now: Date;
  }): Promise<{ payload: Record<string, unknown>; jti: string; expiresAt: Date }>;
  verifyPresentationRequest(input: {
    compactRequest: string;
    receiver: AuthorityReceiverRecord;
    profile: AuthorityReceiverProfileRecord;
    key: AuthorityReceiverKeyRecord;
    audience: string;
    now: Date;
  }): Promise<{ payload: Record<string, unknown> }>;
  verifyReceipt(input: {
    compactReceipt: string;
    receiver: AuthorityReceiverRecord;
    profile: AuthorityReceiverProfileRecord;
    key: AuthorityReceiverKeyRecord;
    audience: string;
    now: Date;
  }): Promise<{ payload: Record<string, unknown> }>;
  signEncryptAndDeliver(input: {
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
  }>;
}
