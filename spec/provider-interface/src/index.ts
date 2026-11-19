// The provider interface: what a provider adapter implements so that STACK can
// open, find and close one piece of an agent account at a provider (an inbox, a
// phone number, a model key, a workspace, a browser, a card, a wallet).
//
// This file is the written contract of spec/provider-interface/SPEC.md. It has
// no dependencies. STACK's own adapters implement the same shapes, and the
// conformance kit in spec/conformance runs any adapter through them; its
// reference adapter (spec/conformance/reference/reference-adapter.mjs) is a fake
// that implements them.
//
// An adapter reports every outcome other than success by throwing one of four
// errors. The caller (the provisioner) treats each the same way for every
// provider:
//
//   RetryablePieceError      a transient provider failure (5xx, timeout). The
//                            attempt counts; after the attempt limit the piece
//                            fails. Closing a piece retries without a limit.
//   PermanentPieceError      no retry can fix it (the provider refused the
//                            request, the open request lacks an input). The
//                            piece fails at once.
//   AwaitingCustomerError    the piece waits on a step only the customer can
//                            take (become the wallet's owner, add a card). It
//                            stays pending with the code and public details
//                            (such as the link to act on) and is rechecked on a
//                            schedule without consuming attempts.
//   PieceNotConfiguredError  the operator's own side of the provider is not set
//                            up on this deployment. The piece stays pending and
//                            is rechecked without consuming attempts.
//
// Any other error is treated as permanent: its `code` (when it has a safe one)
// is recorded, never its message.

/** The kinds of piece an account can hold. */
export const ACCOUNT_PIECE_KINDS = [
  'passport',
  'inbox',
  'phone',
  'models',
  'tools',
  'browser',
  'card',
  'wallet',
  'making',
  'workspace',
] as const;
export type AccountPieceKind = (typeof ACCOUNT_PIECE_KINDS)[number];

/**
 * The request that opened the account, as validated by the caller. Its shape is
 * `schemas/OpenAgentAccountInput.json`. Adapters read the parts that concern
 * their piece (an inbox adapter reads `inbox`, a phone adapter `phone`) and
 * ignore the rest. Typed loosely here so that this package needs nothing else;
 * an implementation that has the request type narrows it with the type
 * parameter.
 */
export type AccountOpenRequest = {
  name: string;
  description?: string;
  monthly_budget_cents?: number;
  [piece: string]: unknown;
};

/** What every call to an adapter is told about the piece it works on. */
export interface PieceContext<TRequest = AccountOpenRequest> {
  operatorId: string;
  accountId: string;
  agentId: string;
  /** Stable for the life of the piece. The adapter derives the provider's idempotency keys and names from it. */
  pieceId: string;
  /** The validated request that opened the account. */
  request: TRequest;
}

export interface PieceOpenResult {
  /** The provider's id for the resource. Non-empty. Written before the piece is marked ready. */
  providerResourceId: string;
  /**
   * Public, non-secret facts the agent may see (an address, a number, a wallet
   * address). A plain JSON object. It MUST NOT contain a credential, a token or
   * a key.
   */
  details: Record<string, unknown>;
}

export interface AccountPieceAdapter<TRequest = AccountOpenRequest> {
  readonly kind: AccountPieceKind;
  /** The provider's name, a short stable identifier. */
  readonly provider: string;
  /**
   * Find a resource already created for this piece, or null. Called before
   * every open attempt, so a crash between the provider call and the database
   * write never leaves a second resource at the provider. May throw
   * AwaitingCustomerError when the resource exists but still waits on the
   * customer. MUST have no side effect at the provider.
   */
  find(ctx: PieceContext<TRequest>): Promise<PieceOpenResult | null>;
  /** Create the resource. The caller has already called `find` and got null. */
  open(ctx: PieceContext<TRequest>): Promise<PieceOpenResult>;
  /** Close the resource at the provider. MUST succeed when it is already gone. */
  close(ctx: PieceContext<TRequest> & { providerResourceId: string }): Promise<void>;
  /**
   * Runs after the piece is marked closed, for clean-up that depends on no
   * piece being left open (closing the customer's provider account). MUST be
   * idempotent and MUST NOT throw: the piece is already closed.
   */
  afterClose?(ctx: PieceContext<TRequest>): Promise<void>;
}

abstract class PieceError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

/** A failure worth retrying (provider 5xx, timeout). */
export class RetryablePieceError extends PieceError {}

/** A failure no retry fixes (missing input, refused by the provider). The piece fails. */
export class PermanentPieceError extends PieceError {}

/**
 * The piece cannot open until the customer does something only the customer
 * can do. The piece stays pending with `code` as its last error and `details`
 * merged into its public details. When the provider already holds a resource
 * for the piece (a card vault waiting for a card), `providerResourceId` is
 * recorded so a close can release it.
 */
export class AwaitingCustomerError extends PieceError {
  constructor(
    code: string,
    message: string,
    readonly details: Record<string, unknown>,
    readonly providerResourceId: string | null = null,
  ) {
    super(code, message);
  }
}

/** The code a piece waits under when the operator's side of the provider is not configured. */
export const PROVIDER_NOT_CONFIGURED = 'provider_not_configured';

/** The operator's own side of the provider is not configured on this deployment. The piece waits. */
export class PieceNotConfiguredError extends PieceError {
  constructor(code: string = PROVIDER_NOT_CONFIGURED, message = 'The provider for this piece is not configured') {
    super(code, message);
  }
}

export type PieceErrorKind = 'retryable' | 'permanent' | 'awaiting_customer' | 'not_configured' | 'unclassified';

/**
 * How the caller treats an error. Recognises the classes above by identity and
 * by name, so an error thrown by a copy of this module (another package version
 * in the same process) is classified the same way.
 */
export function classifyPieceError(error: unknown): PieceErrorKind {
  if (error instanceof RetryablePieceError) return 'retryable';
  if (error instanceof PermanentPieceError) return 'permanent';
  if (error instanceof AwaitingCustomerError) return 'awaiting_customer';
  if (error instanceof PieceNotConfiguredError) return 'not_configured';
  switch ((error as { name?: unknown } | null)?.name) {
    case 'RetryablePieceError': return 'retryable';
    case 'PermanentPieceError': return 'permanent';
    case 'AwaitingCustomerError': return 'awaiting_customer';
    case 'PieceNotConfiguredError': return 'not_configured';
    default: return 'unclassified';
  }
}

/** A code safe to store on a piece row: letters, digits, `_`, `.` and `-`, starting with a letter or digit, at most 64 characters. */
export const PIECE_ERROR_CODE_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,63}$/i;
