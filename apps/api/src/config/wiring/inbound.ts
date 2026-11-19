import { type Database } from '@stack/shared';
import {
  InboundWebhookRepository,
  InboundWebhookReceiptsRepository,
  InboundWebhookService,
  type AgentService,
  type AuditService,
  type DetectorService,
  type EntitlementResolver,
  type InboundDeliverySource,
  type InboundManagedEndSource,
  type InboundExtractorSource,
  type KmsService,
} from '@stack/vault';
import { env } from '../env.js';
import type { ActionMeter } from '../../lib/action-meter.js';
import type { CoreRepositories } from './repositories.js';

type InboundMeterAction = ConstructorParameters<typeof InboundWebhookService>[0]['meterAction'];

/**
 * Meters one inbound webhook receive. POST /v1/inbound/:provider/:slug is public
 * and unauthenticated, so the operator is only known once the service has
 * resolved it from the slug; this closure is how the route-layer meter reaches a
 * route that has no request.operatorId.
 */
function createInboundMeterAction(meter: ActionMeter): InboundMeterAction {
  return async (operatorId: string, eventKey: string, accountingDate: Date) => {
    let commitMeter: (() => Promise<void>) | undefined;
    await meter.enforce(operatorId, 'action', undefined, undefined, {
      key: eventKey,
      accountingDate,
      onCommit: (commit) => {
        commitMeter = commit;
      },
    });
    await commitMeter?.();
  };
}

export interface InboundServices {
  /**
   * Inbound webhook receiver. An operator creates a webhook row and gets
   * back a URL plus an HMAC secret; providers POST inbound to
   * /v1/inbound/:provider/:slug; STACK verifies the signature, runs the
   * detector, writes a security_event on block, and forwards to the operator's
   * configured downstream URL on clean. Service connectors only cover
   * agent-initiated calls; this covers server-initiated push.
   */
  inboundWebhooks: InboundWebhookService;
}

export function createInboundServices(deps: {
  db: Database;
  kms: KmsService;
  repos: Pick<CoreRepositories, 'agentRepo' | 'operatorRepo'>;
  agent: AgentService;
  detector: DetectorService;
  audit: AuditService;
  /** Counts one action per received event; the deployment decides what counting means. */
  meter: ActionMeter;
  /** The plan an operator's endpoint count is capped by. */
  entitlements: Pick<EntitlementResolver, 'resolve'>;
  /** The providers the deployment adds to the engine's. */
  extractors: InboundExtractorSource;
  /** The providers whose deliveries the deployment takes itself. */
  deliveries: InboundDeliverySource;
  /** What ends such a provider's side of a row the owner revokes. */
  managedEnds: InboundManagedEndSource;
}): InboundServices {
  const { db, kms, repos, agent, detector, audit, meter, entitlements, extractors, deliveries, managedEnds } = deps;
  const inboundWebhookRepo = new InboundWebhookRepository(db);
  const inboundWebhookReceiptsRepo = new InboundWebhookReceiptsRepository(db);
  const inboundWebhooks = new InboundWebhookService({
    repo: inboundWebhookRepo,
    receiptsRepo: inboundWebhookReceiptsRepo,
    agentRepo: repos.agentRepo,
    operatorRepo: repos.operatorRepo,
    detector,
    audit,
    kms,
    entitlements,
    extractors,
    deliveries,
    managedEnds,
    baseUrl: env.STACK_API_BASE_URL,
    meterAction: createInboundMeterAction(meter),
  });

  // Cascade-block: an agent referenced by an active inbound webhook cannot be
  // deleted until the webhook is revoked. The DB FK is ON DELETE SET NULL
  // (orphans the attribution rather than blocking the delete); this
  // service-layer guard surfaces the conflict before the FK fires.
  agent.registerDeletePreconditionCheck(async (agentId, operatorId) => {
    const webhooks = await inboundWebhookRepo.listByOperator(operatorId);
    const active = webhooks.filter((w) => w.agent_id === agentId && w.revoked_at === null);
    if (active.length === 0) return [];
    return active.map(
      (w) =>
        `inbound webhook ${w.id} (${w.provider}, slug=${w.slug.slice(0, 4)}...${w.slug.slice(-4)})`,
    );
  });

  return { inboundWebhooks };
}
