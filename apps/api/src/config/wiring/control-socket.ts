// The control socket: who decides for a customer, and where their record goes.
// Built after billing (a hosted check is charged through the wallet) and the
// audit trail (every audit row is offered to the events outbox in its own
// transaction).
//
// The customer's socket, the posture every hosted check reads and the policies
// are built earlier (`createControlCore`), because the wallet's holds, the
// detectors and the data trail read them before the decision engine exists.

import {
  ControlEventsDelivery,
  ControlEventsSink,
  ControlPolicyRepository,
  ControlPolicyService,
  ControlPosture,
  ControlReviewRepository,
  ControlReviewService,
  ControlSocketRepository,
  ControlSocketService,
  MissionRecipientPinReader,
  PassportLineageReader,
  PassportRepository,
  MissionRepository,
  type AuditService,
  type GovernanceApprovalService,
  type ActionLimitCounter,
  type EntitlementResolver,
  type HeldPaymentChat,
  type KmsService,
  type NotificationService,
} from '@stack/vault';
import type { Database, DecisionReachedHook } from '@stack/shared';
import { ControlDecisionEngine } from '../../lib/control-socket/engine.js';
import { HostedDecider, NoneDecider } from '../../lib/control-socket/deciders.js';
import { PolicyHostedCheck } from '../../lib/control-socket/policy-check.js';
import { RemoteDecider } from '../../lib/control-socket/remote-decider.js';
import { ConcurrencyLimiter } from '../../lib/control-policy/concurrency-limiter.js';
import type { ActionMeter } from '../../lib/action-meter.js';
import type { RedisClient } from './infra.js';

/** One Redis channel tells every API machine to drop its cached view of a customer's socket. */
export const CONTROL_SOCKET_CHANNEL = 'stack:control-socket-invalidated';
/** One tells every API machine to drop its cached policies of a customer, so a tightening applies at once. */
export const CONTROL_POLICY_CHANNEL = 'stack:control-policy-invalidated';
/** One tells every API machine to drop what it read of a Mission's recipient pins once the owner added some ("<operator> <mission>"). */
export const MISSION_PINS_CHANNEL = 'stack:mission-pins-invalidated';

/**
 * The parts of the control layer other services read: the customer's socket,
 * the posture that says which hosted checks apply to a kind of action, and the
 * policies. No network, no subscriptions: `createControlSocketServices` starts those.
 */
export function createControlCore(deps: {
  db: Database;
  redis: RedisClient;
  kms: KmsService;
  entitlements: Pick<EntitlementResolver, 'controlsEnabled'>;
  /** Builds the policy repository; absent, the engine's, which knows no agent accounts. */
  policyRepository?: (db: Database) => ControlPolicyRepository;
}) {
  const { db, redis, kms, entitlements } = deps;
  const controlSocketRepo = new ControlSocketRepository(db);
  const controlSocket = new ControlSocketService({
    repo: controlSocketRepo,
    kms,
    publishInvalidation: async (operatorId) => {
      await redis.publish(CONTROL_SOCKET_CHANNEL, operatorId);
    },
  });
  const controlPosture = new ControlPosture({ sockets: controlSocket, controls: entitlements });
  const controlPolicyRepo = deps.policyRepository?.(db) ?? new ControlPolicyRepository(db);
  const controlPolicies = new ControlPolicyService({
    repo: controlPolicyRepo,
    controls: entitlements,
    publishInvalidation: async (operatorId) => {
      await redis.publish(CONTROL_POLICY_CHANNEL, operatorId);
    },
  });
  return { controlSocketRepo, controlSocket, controlPosture, controlPolicyRepo, controlPolicies };
}

export type ControlCore = ReturnType<typeof createControlCore>;

/** The notification event the owner's rules subscribe to when delivery of their record pauses. */
export const CONTROL_EVENTS_FAILING_EVENT = 'control.events_failing';

/**
 * Tell the owner, through their own notification rules, that the address their
 * record is streamed to has not accepted a delivery for 72 hours and delivery
 * has paused. Verifying the address again resumes it and announces what was skipped.
 */
export async function notifyEventsFailing(
  notification: Pick<NotificationService, 'publishEvent'>,
  operatorId: string,
): Promise<void> {
  await notification.publishEvent({
    operatorId,
    eventType: CONTROL_EVENTS_FAILING_EVENT,
    severity: 'warning',
    payload: {
      message: 'Your events address has not accepted a delivery for 72 hours, so STACK paused sending your record to it. Fix the address and verify it again to resume; what was skipped is announced with one gap marker.',
      status: 'paused',
    },
  });
}

export async function createControlSocketServices(deps: {
  db: Database;
  redis: RedisClient;
  audit: AuditService;
  entitlements: Pick<EntitlementResolver, 'controlsEnabled'>;
  /** Charges a decision STACK's own hosted check made, and one the customer's own server made (at its own, lower price). */
  meter: Pick<ActionMeter, 'recordCheck' | 'recordDecision'>;
  /** The counters of an agent account's action and cents windows. */
  limits: ActionLimitCounter;
  governanceApprovals: GovernanceApprovalService;
  /** Tells the owner when delivery of their record pauses. */
  notification: Pick<NotificationService, 'publishEvent'>;
  core: ControlCore;
  /** Offers a held payment to the owner's chat identities when their limits allow it. Absent: held payments are decided on the approval page only. */
  chat?: HeldPaymentChat | null;
  /** Told when a held action's review ends, so the agent waiting on it hears how it ended. */
  onDecision?: DecisionReachedHook;
  /** Test builds put their own transport in front of the customer's servers; production leaves it unset. */
  transport?: {
    fetchFn?: (url: string, init: RequestInit) => Promise<Response>;
    urlGuard?: (url: string) => Promise<unknown> | unknown;
  };
}) {
  const { db, redis, audit, entitlements, meter, limits, governanceApprovals, notification, core, transport, chat } = deps;
  const { controlSocketRepo: repo, controlSocket, controlPosture, controlPolicies, controlPolicyRepo } = core;
  // A development build may reach a plain-http address; production never does.
  const allowHttp = process.env['NODE_ENV'] !== 'production';
  // The events stream is the record. Hosted controls need the subscription; a customer whose decider is their own server
  // (the control socket's remote mode) streams without one. Anyone else without controls has nothing enqueued.
  const sink = new ControlEventsSink(repo, {
    controlsEnabled: (operatorId) => entitlements.controlsEnabled(operatorId),
    decidesRemotely: async (operatorId) => (await controlSocket.runtime(operatorId)).modeSetting === 'remote',
  });
  controlSocket.onInvalidate((operatorId) => sink.forget(operatorId));
  audit.setOutboxSink((tx, row) => sink.write(tx, row));

  const missionPins = new MissionRecipientPinReader(new MissionRepository(db));
  const subscriber = redis.duplicate();
  await subscriber.subscribe(CONTROL_SOCKET_CHANNEL, CONTROL_POLICY_CHANNEL, MISSION_PINS_CHANNEL);
  subscriber.on('message', (channel: string, message: string) => {
    if (!message) return;
    if (channel === CONTROL_SOCKET_CHANNEL) controlSocket.invalidateLocal(message);
    else if (channel === CONTROL_POLICY_CHANNEL) controlPolicies.invalidateLocal(message);
    else if (channel === MISSION_PINS_CHANNEL) {
      const [operatorId, missionId] = message.split(' ');
      if (operatorId && missionId) missionPins.forget(operatorId, missionId);
    }
  });

  const remote = new RemoteDecider({
    sockets: controlSocket,
    allowHttp,
    ...(transport?.fetchFn ? { fetchFn: transport.fetchFn } : {}),
    ...(transport?.urlGuard ? { urlGuard: transport.urlGuard } : {}),
  });

  const controlReviews = new ControlReviewService({
    repo: new ControlReviewRepository(db),
    governance: governanceApprovals,
    ...(deps.onDecision ? { onDecision: deps.onDecision } : {}),
  });
  const concurrency = new ConcurrencyLimiter(redis);
  const controlDecisions = new ControlDecisionEngine({
    sockets: controlSocket,
    repo,
    controls: entitlements,
    posture: controlPosture,
    audit,
    none: new NoneDecider(),
    // The customer's policy is the hosted check: rules, held actions, counters and concurrency.
    hosted: new HostedDecider([
      new PolicyHostedCheck({
        policies: controlPolicies,
        reviews: controlReviews,
        limits,
        concurrency,
        missions: missionPins,
        lineage: new PassportLineageReader(new PassportRepository(db)),
        ...(chat ? { chat } : {}),
      }),
    ]),
    remote,
    charge: async (operatorId) => {
      await meter.recordCheck(operatorId, 1);
    },
    chargeDecision: async (operatorId) => {
      await meter.recordDecision(operatorId, 1);
    },
  });
  const controlEvents = new ControlEventsDelivery({
    repo,
    sockets: controlSocket,
    allowHttp,
    onFailing: (operatorId) => notifyEventsFailing(notification, operatorId),
    ...(transport?.fetchFn ? { fetchFn: transport.fetchFn as typeof globalThis.fetch } : {}),
    ...(transport?.urlGuard ? { urlGuard: transport.urlGuard } : {}),
  });

  return {
    controlDecisions,
    controlRemote: remote,
    controlEvents,
    controlReviews,
    /** The counters it was handed; the deployment's own service types them (services.ts). */
    agentLimits: limits,
    controlPolicyRepo,
    /** Stop listening for invalidations (shutdown and tests). */
    stop: () => subscriber.disconnect(),
  };
}

export type ControlSocketServices = Awaited<ReturnType<typeof createControlSocketServices>>;
