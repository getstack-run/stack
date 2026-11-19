import { ForbiddenError } from '@stack/shared';
import { OAuthLifecycleError, type CredentialFields, type ReconnectReason } from '../oauth-token-lifecycle.js';
import type { PlanLimitsReader } from '../entitlements/plan-limits.js';

/** Refuses a grant change for an agent a fleet runs outside STACK. */
export type ExternalAgentGuard = (operatorId: string, agentId: string) => Promise<void>;

/** The OAuth application a managed connection renews its token through. */
export type OAuthClientResolver = (
  operatorId: string,
  fields: CredentialFields,
  connection: {
    serviceId: string;
    provider: string;
    tokenUrl: string;
  },
) => Promise<{ clientId: string; clientSecret: string; tenant?: string }>;

/** The app a managed connection was made through. */
export type OAuthAppBinding = NonNullable<CredentialFields['oauth_app_binding']>;

/**
 * Whether the app a connection was made through is one STACK no longer runs,
 * so the connection cannot renew and must be reconnected with a key or the
 * customer's own app. Answered without a lookup: the binding names its owner.
 */
export type OAuthAppRetiredCheck = (binding: OAuthAppBinding) => boolean;

/**
 * Whether a connection holds scopes that the app it was made through may not
 * ask for (an app whose allowed scopes do not cover what the connection holds).
 * Such a connection cannot renew: renewing keeps the token's scopes, so
 * it would go on holding what the app is not allowed to request. Answered
 * without a lookup, from the binding and the scopes the connection records.
 */
export type OAuthAppScopesCheck = (
  binding: OAuthAppBinding,
  connectionProvider: string,
  scopes: readonly string[],
) => boolean;

/**
 * Called, best effort, after a connection was closed or marked reconnect-required
 * with the credential it held, so the deployment can end the grant at the
 * provider (a refresh token the provider would go on honouring). It decides for
 * itself whether the grant is one to end; it never fails the caller, and the
 * credential is never logged.
 */
export type GrantDroppedHandler = (
  connection: { id: string; provider: string; scopes: readonly string[] },
  credential: CredentialFields,
  /** Asked only when the handler is about to end the grant: whether the operator holds another live connection through the same app, whose token ending the grant could also end. */
  context: { sharesGrant(): Promise<boolean> },
) => Promise<void>;

/** Tells the operator that a stored credential can no longer renew and must be reconnected. */
export type ReconnectRequiredHandler = (event: {
  operatorId: string;
  connectionId: string;
  provider: string;
  credentialVersion: number;
  eventId: string;
  /** Set when the cause is more than a failed renewal (the app STACK used is retired). */
  reason?: ReconnectReason;
}) => Promise<void>;

/** A connection as a lifecycle hook sees it: who holds it, which provider it is for and, on request, the credential it holds. */
export interface ConnectionLifecycleEvent {
  operatorId: string;
  connection: { id: string; provider: string; service_id: string };
  /** The credential as stored, decrypted in memory for this call. Never log it. */
  credential(): Promise<string>;
}

/**
 * Told, after a connection is made and before the caller is answered, so the deployment can set up what a provider needs beside the
 * key (STACK registers where RentAHuman delivers the account's events). It decides for itself whether the provider is one it acts
 * for. A hook that throws removes the connection and the error reaches the caller: the connection did not work. A hook may answer a
 * `notice` for the caller to be told (the connection works, but something it set up is not ready yet): it is returned with the connection.
 */
export type ConnectionOpenedHook = (event: ConnectionLifecycleEvent) => Promise<void | { notice: string }>;

/**
 * Told before a connection is closed, so the deployment can end what it set up at the provider (delete an endpoint, revoke the key). A
 * hook that throws refuses the disconnect: the connection stays as it is, and the key is not left good at the provider by a connection
 * that says it is gone.
 */
export type ConnectionClosingHook = (event: ConnectionLifecycleEvent) => Promise<void>;

/**
 * What ServiceConnectionService needs from the rest of the system. All three
 * are required: the service cannot be constructed without them, so a grant
 * change cannot skip the fleet check and a credential that stops renewing
 * cannot go unreported.
 *
 * Each is a function, so the composition root can hand over one that reaches a
 * collaborator built later (the fleet service, the OAuth connect service and
 * the notification service all depend on this service).
 */
export interface ServiceConnectionHooks {
  externalAgentGuard: ExternalAgentGuard;
  oauthClientResolver: OAuthClientResolver;
  reconnectRequired: ReconnectRequiredHandler;
  /** Absent: no app is retired. */
  oauthAppRetired?: OAuthAppRetiredCheck;
  /** Absent: no app is held to a list. */
  oauthAppScopesExceeded?: OAuthAppScopesCheck;
  /**
   * Whether an app (by its provider) serves a service (by its provider): a Google app serves every Google service.
   * Lets the shared-grant check skip, without decrypting, a connection of a service the app can never have made.
   * Absent: every OAuth connection of the operator is read.
   */
  oauthAppServes?: (appProvider: string, serviceProvider: string) => boolean;
  /** Absent: nothing is set up beside a new connection. */
  connectionOpened?: ConnectionOpenedHook;
  /** Absent: nothing is ended at the provider when a connection is disconnected. */
  connectionClosing?: ConnectionClosingHook;
  /** Absent: a closed connection's grant is left at the provider. */
  grantDropped?: GrantDroppedHandler;
  /** Told, with the connection's id and provider only, when a grant could not be ended; the deployment reports it. Absent: only the log line. */
  grantReleaseFailed?: (connection: { connectionId: string; provider: string }) => void;
  /** How many connections a tier may hold. Absent, the contract plan's: no cap. */
  planLimits?: PlanLimitsReader;
  /**
   * Operators whose decrypted credentials may be cached in process memory (a traffic simulator that decrypts the same
   * sentinel values thousands of times a day). Absent: none, every decryption goes to the KMS.
   */
  cachedDecryptOperatorIds?: readonly string[];
}

/**
 * Hooks for a process that reads and maintains stored credentials but runs no
 * fleet, no hosted OAuth connect flow and no notification channel (the worker,
 * operator scripts). Each one fails closed or says so; none allows anything.
 *
 *   - grant changes for agents are refused, since this process cannot tell
 *     whether a fleet runs the agent;
 *   - a managed OAuth connection cannot find its application, which is the
 *     same reconnect-required outcome an unreachable application produces;
 *   - a reconnect-required credential is logged by connection id only.
 */
export const standaloneServiceConnectionHooks: ServiceConnectionHooks = {
  externalAgentGuard: async () => {
    throw new ForbiddenError('Agent grants are not managed by this process');
  },
  oauthClientResolver: async () => {
    throw new OAuthLifecycleError(true);
  },
  reconnectRequired: async (event) => {
    console.warn(
      '[service-connection] connection must be reconnected:', event.connectionId, event.provider, 'This process has no notifier.',
    );
  },
};

/** Fail at construction, not at the first request that needs a missing hook. */
export function assertServiceConnectionHooks(hooks: ServiceConnectionHooks): void {
  for (const key of ['externalAgentGuard', 'oauthClientResolver', 'reconnectRequired'] as const) {
    if (typeof hooks?.[key] !== 'function') {
      throw new Error(`ServiceConnectionService requires its ${key} hook at construction`);
    }
  }
}
