import type { ZodTypeAny } from 'zod';
import type { DecisionReachedHook, OAuthScope } from '@stack/shared';
import { ENGINE_ROUTE_SCOPES } from '../middleware/oauth-scope.js';
import { ENGINE_MEMBER_ACTION_ALLOWLIST } from '../middleware/member-floor.js';
import type {
  ArchiveErasePrefix,
  AuditContext,
  CmekMigrationStep,
  DbTransaction,
  ErasureStep,
  InboundDeliveryHandler,
  InboundManagedEnd,
  InboundWebhookExtractor,
  OperatorDeleteStep,
  EntitlementAccount,
  ReceiverDirectory,
} from '@stack/vault';
import type { OutputDelivery } from '../routes/llm-gateway/openrouter/delivery.js';
export type { ArchiveErasePrefix, OperatorDeleteStep, ReceiverDirectory };

/**
 * Where a deployment adds to the engine. The engine owns each registry and its
 * defaults; the extension fills them before any route exists; `seal()` runs
 * before the server listens, and a later `register` throws, so what a request
 * can reach never changes while it is serving.
 */

const sealedMessage = (name: string) => `The ${name} registry is sealed: it is filled before the server starts and never changed after`;

/** Named entries, one per key; a key registered twice is a wiring mistake. */
export class SealedMap<V> {
  private readonly entries = new Map<string, V>();
  private isSealed = false;

  constructor(private readonly name: string, initial: Iterable<readonly [string, V]> = []) {
    for (const [key, value] of initial) this.entries.set(key, value);
  }

  register(key: string, value: V): void {
    if (this.isSealed) throw new Error(sealedMessage(this.name));
    if (this.entries.has(key)) throw new Error(`The ${this.name} registry already has ${key}`);
    this.entries.set(key, value);
  }

  get(key: string): V | undefined {
    return this.entries.get(key);
  }

  has(key: string): boolean {
    return this.entries.has(key);
  }

  keys(): readonly string[] {
    return [...this.entries.keys()];
  }

  values(): readonly V[] {
    return [...this.entries.values()];
  }

  seal(): void {
    this.isSealed = true;
  }

  get sealed(): boolean {
    return this.isSealed;
  }
}

/** Ordered entries; the order of registration is the order of use. */
export class SealedList<T> {
  private readonly items: T[] = [];
  private isSealed = false;

  constructor(private readonly name: string) {}

  register(item: T): void {
    if (this.isSealed) throw new Error(sealedMessage(this.name));
    this.items.push(item);
  }

  list(): readonly T[] {
    return [...this.items];
  }

  seal(): void {
    this.isSealed = true;
  }

  get sealed(): boolean {
    return this.isSealed;
  }
}

/** A governance action a person confirms in the browser, with the shape of what it carries. */
export interface GovernanceActionSpec {
  payload: ZodTypeAny;
  /** What the person is shown of the payload, kept beside the approval. Called with the parsed payload. */
  preview?: (payload: unknown) => Record<string, unknown>;
  /** Never approved from a chat: only a signed-in browser may decide it. */
  browserOnly?: boolean;
}

/** A store of ciphertext the customer-managed-key migration re-encrypts for an operator, beside the engine's own. */
export type CmekStep = CmekMigrationStep;

/** Reads the recipients of an outbound message from a request the engine could not read them from. */
export type RequestRecipientExtractor = (request: unknown) => { recipients: string[] } | undefined;

/** Something a drop-off carries beside its payload (the agent drive's files). */
export interface DropoffAttachmentHandler {
  /** The request-body field it arrives in. */
  field: string;
  schema: ZodTypeAny;
  attach(input: {
    operatorId: string;
    dropoffId: string;
    fromAgentId: string;
    toAgentId: string;
    value: unknown;
    /** The Mission and Passport the deposit was admitted under, for the attachment's own checks and record. */
    missionId: string | null;
    passportJti: string | null;
    /** The context of the deposit's audit row. */
    audit: AuditContext;
    transaction: DbTransaction;
  }): Promise<void>;
  complete(input: {
    dropoffId: string;
    agentId: string;
    operatorId: string;
    transaction: DbTransaction;
  }): Promise<readonly unknown[]>;
}

/**
 * Told once a deposit has committed: the work is there to collect. A deployment uses it for what happens when an agent
 * is handed something (STACK wakes the agents it names). A hook that throws is logged and never fails the deposit.
 */
export type DropoffDepositedHook = (event: {
  operatorId: string;
  dropoffId: string;
  fromAgentId: string;
  /** Every agent the drop-off names, in the order named. */
  toAgentIds: readonly string[];
}) => Promise<void>;

/**
 * Who wrote a message an agent received, for a Mission or a send that replies to them (`reply_to_message`). Answers the
 * sender's addresses or numbers, `unverified` for a message whose sender could not be verified (an email its receiving
 * server did not vouch for), or null when this agent has no such message it may reply to (unknown, someone else's,
 * withheld). The engine has no messages of its own, so a deployment that has them registers one.
 */
export type MessageSenderResolver = (input: {
  operatorId: string;
  agentId: string;
  messageId: string;
}) => Promise<{ recipients: string[] } | { unverified: true } | null>;

/** What a gate sees of a request: the route it matched and the billing account it is billed to. */
export interface AccessRequest {
  method: string;
  /** The matched route pattern (`/v1/operators/me`), never the concrete URL. */
  route: string;
  account: EntitlementAccount;
}

/** Throws to refuse. Runs after authentication and before any handler, on every route that authenticates. */
export type AccessGate = (request: AccessRequest) => void | Promise<void>;

export class EngineRegistries {
  /**
   * Route -> OAuth scope (`METHOD /path` -> scope, or null for a route another protocol authenticates). It starts
   * with the engine's own routes; a deployment adds its routes' and may not change one the engine has.
   */
  readonly routeScopes = new SealedMap<OAuthScope | null>('route scopes', Object.entries(ENGINE_ROUTE_SCOPES));
  /**
   * Routes a read-only team member may call although the route changes something (`METHOD /route` -> the reason it is here:
   * it only reads through a POST, or it acts on the member's own sign-in and nothing of the account's). Every other
   * POST, PUT, PATCH and DELETE is refused to a read-only member by the one gate after authentication
   * (`middleware/member-floor.ts`). It starts with the engine's own routes; a deployment adds its routes' and may not change one the engine has.
   */
  readonly memberActionAllowlist = new SealedMap<string>('member action allowlist', Object.entries(ENGINE_MEMBER_ACTION_ALLOWLIST));
  readonly governanceActions = new SealedMap<GovernanceActionSpec>('governance actions');
  /** Erasure steps that run before the operator's rows go, and fail the erasure closed. */
  readonly erasureBefore = new SealedList<ErasureStep>('erasure steps');
  /** A deployment's own delete statements, each at its named point of `OperatorRepository.deleteById`. */
  readonly operatorDeleteSlots = new SealedList<OperatorDeleteStep>('operator delete slots');
  readonly archiveErasePrefixes = new SealedList<ArchiveErasePrefix>('archive erase prefixes');
  readonly cmekSteps = new SealedList<CmekStep>('CMEK steps');
  /** Per-call stores of ciphertext the deployment adds; they age out under the old key, so nothing is backfilled. */
  readonly cmekEphemeralStores = new SealedList<string>('CMEK ephemeral stores');
  readonly receiverDirectories = new SealedList<ReceiverDirectory>('receiver directories');
  readonly inboundExtractors = new SealedMap<InboundWebhookExtractor>('inbound extractors');
  /**
   * What the deployment does with a verified delivery of a provider it takes the deliveries of itself (in place of forwarding it); such a
   * provider's rows are made and ended by the deployment, never by a customer. The engine has none.
   */
  readonly inboundDeliveries = new SealedMap<InboundDeliveryHandler>('inbound deliveries');
  /** What ends such a provider's side of one of its rows when the owner revokes it (an endpoint registered at the provider). The engine has none. */
  readonly inboundManagedEnds = new SealedMap<InboundManagedEnd>('inbound managed ends');
  readonly requestRecipientExtractors = new SealedList<RequestRecipientExtractor>('request recipient extractors');
  readonly dropoffAttachments = new SealedMap<DropoffAttachmentHandler>('drop-off attachments');
  readonly dropoffDeposited = new SealedList<DropoffDepositedHook>('drop-off deposit hooks');
  /**
   * Told when a pending item an agent waited on ends (an intent approval, a fleet or control review, an authority
   * request, a proxy operation, a drop-off, a Mission review): `announceDecision` runs each after the end is stored.
   * The engine has none; STACK's deployment registers its `decision` wake-up.
   */
  readonly decisionReached = new SealedList<DecisionReachedHook>('decision hooks');
  /** Finds who wrote a message an agent received, for a Mission that replies to them. */
  readonly messageSenders = new SealedList<MessageSenderResolver>('message sender resolvers');
  /**
   * Run for every authenticated request once the billing account is known, before the route: a gate throws to
   * refuse the request. The engine has none; a deployment that sells access adds its rule here, in one place.
   */
  readonly accessGates = new SealedList<AccessGate>('access gates');
  /**
   * Where an OpenRouter answer can be saved instead of returned, by the name a caller sends in `X-Stack-Save-Output`. The engine
   * has none (the header is then refused, never ignored); a deployment with an agent drive registers `drive`.
   */
  readonly outputDeliveries = new SealedMap<OutputDelivery>('output deliveries');

  private all(): ReadonlyArray<{ seal(): void; readonly sealed: boolean }> {
    return [
      this.routeScopes,
      this.memberActionAllowlist,
      this.governanceActions,
      this.erasureBefore,
      this.operatorDeleteSlots,
      this.archiveErasePrefixes,
      this.cmekSteps,
      this.cmekEphemeralStores,
      this.receiverDirectories,
      this.inboundExtractors,
      this.inboundDeliveries,
      this.inboundManagedEnds,
      this.requestRecipientExtractors,
      this.dropoffAttachments,
      this.dropoffDeposited,
      this.decisionReached,
      this.messageSenders,
      this.accessGates,
      this.outputDeliveries,
    ];
  }

  /** Called once, before the server listens. */
  seal(): void {
    for (const registry of this.all()) registry.seal();
  }

  get sealed(): boolean {
    return this.all().every((registry) => registry.sealed);
  }
}
