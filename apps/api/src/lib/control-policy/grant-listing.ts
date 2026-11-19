import {
  connectionNeedsListing,
  expandGrantRules,
  normalizePolicy,
  policyDigest,
  safeErrorSummary,
  type GrantAgentAccessInput,
  type PolicyDefinition,
} from '@stack/shared';
import type { FastifyRequest } from 'fastify';
import type { PolicyPlan } from '@stack/vault';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';
import { GOVERNANCE_APPROVAL_HEADER } from '../../middleware/governance-stepup.js';
import { buildGrantPreview } from '../grant-preview.js';
import { policyActor } from './policy-actor.js';

/** What an approval of a grant widening also covers when the agent's policy has to list the connection. */
export interface GrantPolicyListing {
  plan: PolicyPlan;
  /** Bound into the grant's approval payload: the policy, the revision it was judged at and the exact result. */
  ref: { policy_id: string; expected_revision: number; definition_digest: string };
}

/**
 * Where controls are on and the agent has a policy of its own that lists connections without this one, widening
 * the agent's grant leaves it uncallable until a revision of the policy lists the connection, which is a second
 * loosening and a second approval. This plans that revision, so the person approves the grant and its listing
 * once: the grant's approval payload carries the exact policy change, and the approval card says so.
 *
 * Only a policy of the agent's own is changed here. The customer's default policy governs other agents too and is
 * never edited as a side effect of one agent's grant. Null when there is nothing to list (controls off, no policy,
 * a policy that does not list connections or already has a rule for the connection) and whenever the policy cannot
 * be planned: the grant then goes ahead on its own and answers with the notice that says what is still needed.
 */
export async function planGrantListing(
  services: Pick<Services, 'entitlements' | 'controlPolicies' | 'controlPolicyRepo'>,
  operatorId: string,
  input: GrantAgentAccessInput,
): Promise<GrantPolicyListing | null> {
  try {
    if (!(await services.entitlements.controlsEnabled(operatorId))) return null;
    if (!(await services.controlPolicyRepo.accountOfAgent(operatorId, input.agent_id))) return null;
    const row = await services.controlPolicies.get(operatorId, input.agent_id);
    if (!row) return null;
    const current = (await services.controlPolicies.effective(operatorId, input.agent_id));
    if (!current || current.source !== 'agent' || current.id !== row.id) return null;
    if (!connectionNeedsListing(current.definition, input.service_connection_id)) return null;

    // The rule the grant itself implies: the connection, within the constraints the grant already carries.
    const constraints = expandGrantRules(input).slice(0, 32);
    const taken = new Set(current.definition.connections.rules.map((rule) => rule.id));
    let n = current.definition.connections.rules.length + 1;
    while (taken.has(`connection-${n}`)) n += 1;
    const next: PolicyDefinition = normalizePolicy({
      ...current.definition,
      connections: {
        ...current.definition.connections,
        rules: [
          ...current.definition.connections.rules,
          { id: `connection-${n}`, effect: 'allow', access: { connection_id: input.service_connection_id, intents: [], constraints } },
        ],
      },
    });
    // The combined approval may be confirmed in the chat only because this adds ONE rule for the connection and
    // changes nothing else of the policy: not its spend, review or block rules, recipients, surfaces or limits.
    // Hold the plan to that, whatever the builder above did.
    const withoutRules = (definition: PolicyDefinition) =>
      policyDigest(normalizePolicy({ ...definition, connections: { ...definition.connections, rules: [] } }));
    const before = current.definition.connections.rules;
    const after = next.connections.rules;
    if (
      withoutRules(next) !== withoutRules(current.definition)
      || after.length !== before.length + 1
      || before.some((rule, index) => JSON.stringify(rule) !== JSON.stringify(after[index]))
    ) {
      return null;
    }
    const plan = await services.controlPolicies.planSet({
      operatorId,
      agentId: input.agent_id,
      definition: next,
      expectedRevision: current.revision,
    });
    if (plan.change === 'unchanged' || !plan.next) return null;
    return {
      plan,
      ref: { policy_id: current.id, expected_revision: current.revision, definition_digest: policyDigest(plan.next) },
    };
  } catch (error) {
    console.error('[CONTROL] planning the policy listing for a grant failed', safeErrorSummary(error));
    return null;
  }
}

/**
 * The service a grant is about, by name, and the connection by the name its owner gave it, for the card and the
 * confirmation; the id for the service and no name when they cannot be read.
 */
export async function grantServiceName(
  services: Pick<Services, 'serviceConnection'>,
  request: Pick<FastifyRequest, 'operatorId' | 'allowedConnections'>,
  input: GrantAgentAccessInput,
): Promise<{ service: string; connectionName: string | null }> {
  try {
    const named = await services.serviceConnection.checkSetup(
      request.operatorId,
      { grants: [{ service_connection_id: input.service_connection_id, scopes: input.scopes }], allowed_hosts: [] },
      request.allowedConnections,
    );
    const connection = named.get(input.service_connection_id);
    return { service: connection?.provider ?? input.service_connection_id, connectionName: connection?.name ?? null };
  } catch {
    // The grant itself refuses what is wrong with it; the name is only for the card.
    return { service: input.service_connection_id, connectionName: null };
  }
}

/**
 * What the approval of a widened grant is made of: the payload it binds (the grant, and the exact policy change
 * when the same approval lists the service in the agent's policy), the one-line summary and the preview that lists
 * every part, in the Console and in the chat.
 */
export function grantApproval(
  input: GrantAgentAccessInput,
  serviceName: string,
  listing: GrantPolicyListing | null,
  connectionName?: string | null,
) {
  return {
    payload: listing ? { ...input, policy_listing: listing.ref } : input,
    summary: listing
      ? "Expand this agent service grant and list the service in the agent's policy"
      : 'Expand this agent service grant',
    preview: buildGrantPreview(
      input,
      serviceName,
      listing ? { policy_id: listing.ref.policy_id, expected_revision: listing.ref.expected_revision } : null,
      connectionName,
    ),
  };
}

/**
 * Apply the policy change the grant's approval covered, after the grant is made. The grant stands whatever happens
 * here: a policy that moved since it was planned, or any failure, leaves the connection unlisted and the caller
 * answers with the notice that says what the policy still needs. Returns what was listed.
 */
export async function applyGrantListing(
  services: Pick<Services, 'controlPolicies' | 'audit'>,
  request: FastifyRequest,
  listing: GrantPolicyListing,
  input: GrantAgentAccessInput,
  start: number,
): Promise<{ policy_id: string; revision: number } | null> {
  try {
    const approvalHeader = request.headers[GOVERNANCE_APPROVAL_HEADER];
    const applied = await services.controlPolicies.apply(listing.plan, {
      actor: policyActor(request),
      approvalId: typeof approvalHeader === 'string' ? approvalHeader : null,
      // The person approved this exact change with the grant (or is the person, in their own session).
      authorized: true,
    });
    if (!applied) return null;
    await services.audit.write({
      ctx: auditCtx(request, { agent_id: input.agent_id }),
      layer: 'vault',
      action: `control_policy.${listing.plan.change}`,
      outcome: 'success',
      duration_ms: Date.now() - start,
      payload_hash: listing.ref.definition_digest,
    });
    return { policy_id: applied.id, revision: applied.revision };
  } catch (error) {
    console.error('[CONTROL] listing a new grant in the agent policy failed', safeErrorSummary(error));
    return null;
  }
}
