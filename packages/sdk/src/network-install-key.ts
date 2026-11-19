import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, exportJWK, exportPKCS8, generateKeyPair, importPKCS8 } from 'jose';

// An install's key, and the two things it signs: the proof of possession that
// registers it, and the single-use request (the "install proof") that every
// call from the install to the network carries as its bearer value. Formats:
// `packages/shared/src/schemas/network.ts` in the STACK repository, and
// the network contract.

/** Who an install's signed requests are addressed to. */
export const NETWORK_AUDIENCE = 'stack:network';
export const NETWORK_INSTALL_PROOF_TYP = 'stack-install+jwt';
export const NETWORK_INSTALL_POP_TYP = 'stack-install-pop+jwt';

/** A proof lives this long by default, in seconds; the API accepts at most 120. */
export const INSTALL_PROOF_LIFETIME_SECONDS = 60;

/** An Ed25519 public key as the API takes it: these three members and nothing else. */
export interface InstallPublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
}

/** What an install asks for. */
export type NetworkProofAction = 'rules' | 'classify' | 'countersign' | 'revoke';

/** RFC 7638 thumbprint of an Ed25519 public key: the key's id everywhere in the network. */
export function installKeyThumbprint(jwk: Pick<InstallPublicJwk, 'x'>): string {
  return createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`).digest('base64url');
}

/** The digest a countersignature binds: base64url SHA-256 of the passport's compact serialisation, byte for byte as issued. */
export function passportDigest(passport: string): string {
  return createHash('sha256').update(passport, 'utf8').digest('base64url');
}

type PrivateKey = Awaited<ReturnType<typeof importPKCS8>>;

/**
 * An install's signing key. Create one with {@link InstallKey.generate}, keep the
 * private half in a file only the install can read ({@link InstallKey.toPem}), and
 * register the public half with `stack.network.installs.registerKey`.
 */
export class InstallKey {
  private constructor(
    private readonly privateKey: PrivateKey,
    /** The public key, as the API takes it. */
    readonly publicJwk: InstallPublicJwk,
    /** The key's thumbprint: its id in the network. */
    readonly kid: string,
  ) {}

  /** A new key pair. The private half exists only in the returned object: write it out with `toPem()`. */
  static async generate(): Promise<InstallKey> {
    const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    return InstallKey.fromPrivate(privateKey as PrivateKey);
  }

  /** Load a key from its PKCS#8 PEM, as written by `toPem()`. */
  static async fromPem(pem: string): Promise<InstallKey> {
    return InstallKey.fromPrivate(await importPKCS8(pem, 'EdDSA', { extractable: true }));
  }

  private static async fromPrivate(privateKey: PrivateKey): Promise<InstallKey> {
    const jwk = await exportJWK(privateKey);
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
      throw new Error('An install key is an Ed25519 key');
    }
    const publicJwk: InstallPublicJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
    return new InstallKey(privateKey, publicJwk, installKeyThumbprint(publicJwk));
  }

  /** The private key as PKCS#8 PEM. Secret: write it to a file with mode 0600 and never log it. */
  async toPem(): Promise<string> {
    return exportPKCS8(this.privateKey);
  }

  /**
   * The proof of possession that registers this key: a JWS over the challenge STACK
   * issued, signed with the key being registered.
   */
  async signKeyProof(installId: string, nonce: string, options: { now?: Date } = {}): Promise<string> {
    const iat = Math.floor((options.now ?? new Date()).getTime() / 1000);
    return new SignJWT({ install: installId, nonce })
      .setProtectedHeader({ alg: 'EdDSA', typ: NETWORK_INSTALL_POP_TYP, kid: this.kid })
      .setIssuer(this.kid)
      .setAudience(NETWORK_AUDIENCE)
      .setIssuedAt(iat)
      .setExpirationTime(iat + 120)
      .sign(this.privateKey);
  }

  /**
   * One signed request: a fresh `jti` every time, so a proof is good for exactly one
   * call. `claims` carries `act` and the fields that action needs.
   */
  async signProof(
    installId: string,
    claims: { act: NetworkProofAction } & Record<string, unknown>,
    options: { now?: Date; lifetimeSeconds?: number } = {},
  ): Promise<string> {
    const iat = Math.floor((options.now ?? new Date()).getTime() / 1000);
    return new SignJWT({ ...claims })
      .setProtectedHeader({ alg: 'EdDSA', typ: NETWORK_INSTALL_PROOF_TYP, kid: this.kid })
      .setIssuer(installId)
      .setSubject(installId)
      .setAudience(NETWORK_AUDIENCE)
      .setIssuedAt(iat)
      .setExpirationTime(iat + (options.lifetimeSeconds ?? INSTALL_PROOF_LIFETIME_SECONDS))
      .setJti(randomBytes(18).toString('base64url'))
      .sign(this.privateKey);
  }
}

