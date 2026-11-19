import type { HttpClient } from '../client.js';
import { InstallKey, type InstallPublicJwk } from '../network-install-key.js';
import { verifyRevocationList, type NetworkKeySource, type RevocationList } from '../verify-network.js';

// The STACK network, the owner's side and the public checks.
//
// An install is a self-hosted STACK you registered. It signs its own requests
// with a key, so it holds no account credential: see `InstallClient` for what
// an install calls. Here you register installs and their keys, stop a key or
// an install at once, publish a revocation, follow other companies'
// revocations, and check countersigned passports.
//
// Every change is an owner or admin decision, never available to an agent.
// Registering a key lets an install have passports countersigned in your name,
// so it takes a person in a browser: without a dashboard session,
// `requestKeyChallenge` first throws `GovernanceApprovalRequiredError`; once a
// person approves at its link, send the same call again with its `approvalId`.
// Revoking never needs approval. None of it is metered.

export type NetworkRevocationKind = 'passport' | 'agent' | 'key' | 'install';
export type NetworkRevocationReason =
  | 'unspecified'
  | 'key_compromise'
  | 'agent_decommissioned'
  | 'superseded'
  | 'policy_violation'
  | 'owner_request';

export interface NetworkInstallKey {
  id: string;
  /** The key's thumbprint: its id in the network. */
  kid: string;
  status: 'active' | 'revoked';
  /** When a rolled-over key stops working; null for the newest. */
  valid_until: string | null;
  /** True when the key can sign a request right now. */
  usable: boolean;
  created_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
  public_jwk: InstallPublicJwk;
}

export interface NetworkInstall {
  id: string;
  name: string;
  status: 'active' | 'revoked';
  created_at: string;
  revoked_at: string | null;
  keys: NetworkInstallKey[];
}

export interface NetworkKeyChallenge {
  nonce: string;
  expires_at: string;
  audience: 'stack:network';
  install: string;
}

export interface NetworkRevocation {
  id: string;
  seq: number;
  kind: NetworkRevocationKind;
  subject: string;
  /** The install the subject belongs to: every revocation names one. */
  install: string;
  reason: NetworkRevocationReason;
  by: 'install' | 'owner' | 'stack';
  at: string;
}

export interface PublishNetworkRevocationInput {
  kind: NetworkRevocationKind;
  /** passport: its digest; agent: its id; key: its thumbprint; install: its id. */
  subject: string;
  /**
   * The install the subject belongs to: required for every kind. An install is itself, a key is one of its keys,
   * a passport digest is one STACK countersigned for it, and an agent is a name STACK countersigned for it; anything else is `NOT_FOUND`.
   */
  install: string;
  reason?: NetworkRevocationReason;
}

export interface NetworkSubscription {
  id: string;
  url: string;
  /** The installs followed, or null for every revocation. */
  installs: string[] | null;
  status: 'active' | 'failing' | 'paused';
  last_delivered_seq: number;
  last_error: string | null;
  /** False for a subscription made before deliveries were signed: rotate its secret to start signing them. */
  signed: boolean;
  created_at: string;
}

/** A new subscription: the signing secret is returned once, here. An OAuth sign-in gets `null` and a note. */
export interface CreatedNetworkSubscription extends NetworkSubscription {
  signing_secret: string | null;
  signing_secret_note?: string;
}

export interface NetworkSubscriptionSecretRotation {
  /** The new secret, returned once. */
  signing_secret: string;
  /** The previous secret keeps signing beside the new one until then (null when there was none). */
  previous_valid_until: string | null;
}

export interface CreateNetworkSubscriptionInput {
  /** Where STACK posts each new revocation: https, publicly reachable. */
  url: string;
  /** Follow only these installs. */
  installs?: string[];
}

/** A licence key your account revoked. The key itself is never kept or returned. */
export interface NetworkLicenceRevocation {
  /** The key's id: what the network checks on every request. */
  jti: string;
  customer: string;
  reason: NetworkRevocationReason;
  /** When the key would have expired; the entry is dropped some time after. */
  expires_at: string;
  revoked_at: string;
}

export interface NetworkVerifyResult {
  valid: boolean;
  /** Why not, as short codes, when `valid` is false. */
  reasons: string[];
  checked_at: string;
  install: string | null;
  owner: string | null;
  passport_digest: string | null;
  countersignature_expires_at: string | null;
  revoked: { kind: string; at: string; reason: string } | null;
}

export interface NetworkVerifiedStatus {
  status: 'live' | 'expired' | 'revoked';
  /** A compact JWS signed by STACK; check it with `verifyVerifiedStatement`. */
  statement: string;
}

export interface NetworkGovernedOptions {
  /** The approval id from `GovernanceApprovalRequiredError`, once a person approved it. Call again with the same input. */
  governanceApprovalId?: string;
}

const seg = encodeURIComponent;

function governed(options?: NetworkGovernedOptions): { headers: Record<string, string> } | undefined {
  return options?.governanceApprovalId ? { headers: { 'X-Governance-Approval': options.governanceApprovalId } } : undefined;
}

/** Your installs and their keys. */
export class NetworkInstallsService {
  constructor(private readonly client: HttpClient) {}

  /** Register an install. It can sign nothing until it has a key. */
  async register(name: string): Promise<NetworkInstall> {
    return this.client.post<NetworkInstall>('/v1/network/installs', { name });
  }

  async list(): Promise<NetworkInstall[]> {
    return (await this.client.get<{ installs: NetworkInstall[] }>('/v1/network/installs')).installs;
  }

  async get(id: string): Promise<NetworkInstall> {
    return this.client.get<NetworkInstall>(`/v1/network/installs/${seg(id)}`);
  }

  /**
   * Ask for the challenge the install signs with the key it is registering. A
   * governance action: see the note at the top of this file. The challenge is
   * single use and good for five minutes.
   */
  async requestKeyChallenge(id: string, options?: NetworkGovernedOptions): Promise<NetworkKeyChallenge> {
    return this.client.post<NetworkKeyChallenge>(`/v1/network/installs/${seg(id)}/key-challenges`, {}, governed(options));
  }

  /**
   * Register a key from its challenge answer (`InstallKey.signKeyProof`). The
   * install's other keys keep working for `rolloverSeconds` (24 hours when omitted,
   * at most 7 days, 0 for none), then stop; at most three keys are live at once.
   */
  async addKey(
    id: string,
    input: { publicJwk: InstallPublicJwk; proof: string; rolloverSeconds?: number },
  ): Promise<NetworkInstall> {
    return this.client.post<NetworkInstall>(`/v1/network/installs/${seg(id)}/keys`, {
      public_jwk: input.publicJwk,
      proof: input.proof,
      ...(input.rolloverSeconds !== undefined ? { rollover_seconds: input.rolloverSeconds } : {}),
    });
  }

  /**
   * Register a key end to end: ask for a challenge, answer it with the key and
   * register it. The challenge is the governance step; pass the approval id on the
   * second call, as for `requestKeyChallenge`.
   */
  async registerKey(
    id: string,
    key: InstallKey,
    options: NetworkGovernedOptions & { rolloverSeconds?: number } = {},
  ): Promise<NetworkInstall> {
    const challenge = await this.requestKeyChallenge(id, options);
    return this.addKey(id, {
      publicJwk: key.publicJwk,
      proof: await key.signKeyProof(id, challenge.nonce),
      ...(options.rolloverSeconds !== undefined ? { rolloverSeconds: options.rolloverSeconds } : {}),
    });
  }

  /** Stop one key at once and publish it. Every countersignature made under it stops being live. Never needs approval. */
  async revokeKey(id: string, keyId: string, reason?: NetworkRevocationReason): Promise<NetworkInstall> {
    return this.client.post<NetworkInstall>(`/v1/network/installs/${seg(id)}/keys/${seg(keyId)}/revoke`, reason ? { reason } : {});
  }

  /** Stop an install and all its keys at once and publish it. Never needs approval. */
  async revoke(id: string, reason?: NetworkRevocationReason): Promise<NetworkInstall> {
    return this.client.post<NetworkInstall>(`/v1/network/installs/${seg(id)}/revoke`, reason ? { reason } : {});
  }
}

/** Counterparty subscriptions: where STACK posts each new revocation. */
export class NetworkSubscriptionsService {
  constructor(private readonly client: HttpClient) {}

  /**
   * STACK posts `{ "type": "stack.network.revocations", "list": "<signed list>" }` to
   * the address, in order and at least once. The list is signed with STACK's key:
   * check it with `verifyRevocationList`. The request is signed as a Standard Webhooks
   * message with the `signing_secret` this call returns once: check it with
   * `verifyWebhook`, which refuses a forged or stale request.
   */
  async create(input: CreateNetworkSubscriptionInput): Promise<CreatedNetworkSubscription> {
    return this.client.post<CreatedNetworkSubscription>('/v1/network/subscriptions', {
      url: input.url,
      ...(input.installs ? { installs: input.installs } : {}),
    });
  }

  async list(): Promise<NetworkSubscription[]> {
    return (await this.client.get<{ subscriptions: NetworkSubscription[] }>('/v1/network/subscriptions')).subscriptions;
  }

  async delete(id: string): Promise<void> {
    await this.client.delete(`/v1/network/subscriptions/${seg(id)}`);
  }

  /**
   * A fresh signing secret, returned once, for an API key or a dashboard session. The one it
   * replaces keeps signing beside it for 24 hours, so the receiver can switch without a gap.
   */
  async rotateSecret(id: string): Promise<NetworkSubscriptionSecretRotation> {
    return this.client.post<NetworkSubscriptionSecretRotation>(`/v1/network/subscriptions/${seg(id)}/rotate-secret`, {});
  }

  /** Put a paused or failing subscription back to work; it is sent what it missed. */
  async resume(id: string): Promise<NetworkSubscription> {
    return this.client.post<NetworkSubscription>(`/v1/network/subscriptions/${seg(id)}/resume`, {});
  }
}

/**
 * The licence keys STACK issued to your account. A key is accepted by the network
 * as your account's credential for live detection rules and the hosted
 * classifier, so one that leaks costs you money until it expires: revoke it here.
 */
export class NetworkLicencesService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Revoke a licence key before it expires. The key is the proof it is yours: its
   * claims, signed by STACK, name your account and carry the key's id. From the
   * next call the network refuses it, on every machine. Revoking a key again
   * returns the first revocation. A key that is not yours, that STACK did not
   * sign or that carries no id answers `LICENCE_NOT_REVOCABLE` (400). An owner or
   * admin decision, never available to an agent; never needs approval, never charged.
   */
  async revoke(licenceKey: string, reason?: NetworkRevocationReason): Promise<NetworkLicenceRevocation> {
    return this.client.post<NetworkLicenceRevocation>('/v1/network/licences/revoke', {
      licence_key: licenceKey,
      ...(reason ? { reason } : {}),
    });
  }

  /** The keys your account revoked, newest first. */
  async list(): Promise<NetworkLicenceRevocation[]> {
    return (await this.client.get<{ revoked: NetworkLicenceRevocation[] }>('/v1/network/licences/revoked')).revoked;
  }
}

/**
 * The STACK network.
 *
 * @example
 * ```ts
 * const install = await stack.network.installs.register('office');
 * const key = await InstallKey.generate();
 * await stack.network.installs.registerKey(install.id, key); // a person approves the key in a browser
 * const verdict = await stack.network.verify({ countersignature, passport });
 * ```
 */
export class NetworkService {
  readonly installs: NetworkInstallsService;
  readonly subscriptions: NetworkSubscriptionsService;
  readonly licences: NetworkLicencesService;

  constructor(private readonly client: HttpClient) {
    this.installs = new NetworkInstallsService(client);
    this.subscriptions = new NetworkSubscriptionsService(client);
    this.licences = new NetworkLicencesService(client);
  }

  /** Publish a revocation of something that is yours. Never metered. */
  async publishRevocation(input: PublishNetworkRevocationInput): Promise<NetworkRevocation> {
    return this.client.post<NetworkRevocation>('/v1/network/revocations', {
      kind: input.kind,
      subject: input.subject,
      install: input.install,
      ...(input.reason ? { reason: input.reason } : {}),
    });
  }

  /** STACK's public keys, current and retired, for checking every signed object of the network. */
  async jwks(): Promise<{ keys: import('jose').JWK[] }> {
    return this.client.publicRequest('GET', '/v1/network/jwks.json');
  }

  /**
   * The signed list of revocations after a cursor, as STACK serves it. Check it
   * with `verifyRevocationList` or use `revocations`, which does.
   */
  async signedRevocations(query: { after?: number; limit?: number; install?: string } = {}): Promise<{ list: string }> {
    return this.client.publicRequest('GET', '/v1/network/revocations', {
      query: {
        after: query.after !== undefined ? String(query.after) : undefined,
        limit: query.limit !== undefined ? String(query.limit) : undefined,
        install: query.install,
      },
    });
  }

  /**
   * The revocations after a cursor, with the list's signature checked against
   * STACK's published keys (or the keys you pin with `keys`). Resume from
   * `resumeFrom`.
   */
  async revocations(query: { after?: number; limit?: number; install?: string; keys?: NetworkKeySource; now?: Date } = {}): Promise<RevocationList> {
    const { list } = await this.signedRevocations(query);
    return verifyRevocationList(list, { ...(query.keys ?? { jwks: await this.jwks() }), ...(query.now ? { now: query.now } : {}) });
  }

  /**
   * Check a countersignature now, revocation included: STACK's signature, whether
   * the key, install, agent or passport was revoked, and with `passport` that it
   * is the passport the countersignature covers and the install signed it.
   */
  async verify(input: { countersignature: string; passport?: string }): Promise<NetworkVerifyResult> {
    return this.client.publicRequest('POST', '/v1/network/verify', { body: input });
  }

  /**
   * The signed "STACK-verified" statement for a passport (by its digest) or for an
   * install's agent: a five-minute snapshot of whether it is countersigned and live.
   * Rejects with a 404 when STACK never countersigned it. Check the statement with
   * `verifyVerifiedStatement`.
   */
  async verified(query: { passportDigest: string } | { install: string; agent: string }): Promise<NetworkVerifiedStatus> {
    return this.client.publicRequest('GET', '/v1/network/verified', {
      query: 'passportDigest' in query
        ? { passport_digest: query.passportDigest }
        : { install: query.install, agent: query.agent },
    });
  }
}
