// Pure helpers the network's formats are defined by (see `schemas/network.ts`).
// Node's crypto only, so the API, the vault and the public specification share one definition.

import { createHash } from 'node:crypto';
import type { InstallPublicJwk } from '../schemas/network.js';

/** RFC 7638 thumbprint of an Ed25519 public JWK: base64url SHA-256 of the canonical member set. */
export function installKeyThumbprint(jwk: Pick<InstallPublicJwk, 'x'>): string {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`;
  return createHash('sha256').update(canonical).digest('base64url');
}

/** The digest a countersignature binds: base64url SHA-256 of the passport's compact serialisation, byte for byte as issued. */
export function passportDigest(passportCompact: string): string {
  return createHash('sha256').update(passportCompact, 'utf8').digest('base64url');
}

/** The `sub` of a "STACK-verified" statement about a passport. */
export function verifiedSubjectForPassport(digest: string): string {
  return `passport:${digest}`;
}

/** The `sub` of a "STACK-verified" statement about an agent of an install. */
export function verifiedSubjectForAgent(installId: string, agent: string): string {
  return `agent:${installId}:${agent}`;
}
