import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from 'fastify';
import { ForbiddenError, InvalidApiKeyError, type OperatorTier } from '@stack/shared';
import type { BrowserDecisionSession, DbTransaction, MemberService, OperatorService, PassportSigner } from '@stack/vault';

/**
 * Browser (Console) sessions, as the engine sees them. A governance decision
 * (approving a step-up, deciding an authority request, reconciling a proxy
 * operation) is made by a person in a signed-in browser, never by a bearer
 * credential; the engine needs to read that proof but not to know who minted
 * it. STACK's Console mints these sessions, so a deployment without the
 * Console has none: no browser can decide anything there, and those routes
 * refuse every request.
 */

/** A verified session token (the signer's own answer). */
export type VerifiedBrowserSession = Awaited<ReturnType<PassportSigner['verifyAccessOrSession']>>;

/** Who a browser session is for, rechecked against the account. */
export interface BrowserSessionIdentity {
  operator: Awaited<ReturnType<OperatorService['getById']>>;
  member: Awaited<ReturnType<MemberService['findById']>> | null;
}

export interface BrowserSessions {
  /** The session token a request's Cookie header carries, or null when there is none or it is ambiguous. */
  extractCookie(cookieHeader: string | undefined): string | null;
  /** Recheck the mailbox whose proof minted the session; throws 401 when it no longer holds. */
  identity(session: VerifiedBrowserSession, currentOperator?: BrowserSessionIdentity['operator']): Promise<BrowserSessionIdentity>;
  /** The verified proof of the session, preserved as the decision's evidence. */
  decisionSession(session: VerifiedBrowserSession): BrowserDecisionSession;
  /** The session is still live (not signed out, not revoked). */
  assertActive(session: VerifiedBrowserSession): Promise<void>;
  /** The same check inside the transaction that records the decision, so a sign-out cannot interleave. */
  assertActiveInTransaction(tx: DbTransaction, session: VerifiedBrowserSession): Promise<void>;
}

/** A deployment with no Console: no session is ever live. */
export const NO_BROWSER_SESSIONS: BrowserSessions = {
  extractCookie: () => null,
  identity: () => Promise.reject(new InvalidApiKeyError()),
  decisionSession: () => {
    throw new InvalidApiKeyError();
  },
  assertActive: () => Promise.reject(new InvalidApiKeyError()),
  assertActiveInTransaction: () => Promise.reject(new InvalidApiKeyError()),
};

/** Who a request acts for on a connect link: the caller as the Console's server vouched for it. */
export interface ConnectLinkPrincipal {
  operatorId: string;
  operatorTier: OperatorTier;
  memberId?: string;
  memberRole?: string;
  allowedConnections?: string[];
}

/** What the engine reads of a connect link: which sign-in it is for, and the scopes it fixes. */
export interface ConnectLinkRef {
  id: string;
  method: string;
  provider: string;
  scopes: string[];
  /** What the connection the link makes is called; null when the link names none. */
  connection_name?: string | null;
}

/**
 * The Console's bridge for routes that act for a signed-in person on a link
 * (connect a service, from a chat). Absent on a deployment without a Console:
 * those routes then answer 404 NOT_CONFIGURED.
 */
export interface ConsoleBridge {
  proxyAuth(): preHandlerHookHandler;
  privateResponse(reply: FastifyReply): FastifyReply;
  connectLinkPrincipal(request: FastifyRequest): ConnectLinkPrincipal;
  /** The links a person opens to connect a service without the credential passing through a chat. */
  connectLinks: {
    /** The link for this person's session, opened by its token; throws when it is not theirs or no longer open. */
    resolveForSession(principal: ConnectLinkPrincipal, token: string): Promise<{ row: ConnectLinkRef }>;
    /** Marks a link used once its sign-in connected a service. */
    completeWithOAuth(operatorId: string, linkId: string, connectionId: string): Promise<unknown>;
  };
}

/**
 * The gate for a route only a person in a browser may call: a Console session
 * the auth middleware recognised, and no agent, platform passport or
 * OAuth client behind it.
 */
export function requireBrowserSession(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  reply.header('Cache-Control', 'private, no-store');
  if (request.isDashboardSession !== true || request.agentId || request.platformPassport || request.oauthClientId) {
    throw new ForbiddenError('Dashboard browser session required');
  }
  // Fastify treats a two-argument hook as promise-style. Returning undefined
  // leaves the hook runner waiting forever even though this gate is otherwise
  // synchronous.
  return Promise.resolve();
}

export const NO_CONSOLE_BRIDGE: ConsoleBridge | null = null;
