import { expandIntents, type AccessAlternative, type GrantAgentAccessInput } from '@stack/shared';

/** One rule of a grant as the approval shows it: the named actions and every constraint it holds once they are expanded. */
export function describeAlternative(rule: AccessAlternative): { intents: string[]; constraints: Array<{ path: string; op: string; value: unknown }> } {
  const constraints = [...(rule.intents ? expandIntents(rule.intents) : []), ...(rule.constraints ?? [])];
  return {
    intents: (rule.intents ?? []).map((ref) => ref.name),
    constraints: constraints.map((c) => ({ path: c.path, op: c.op, value: c.value })),
  };
}

/**
 * What the approval of a widened grant shows, in the Console and in the chat confirmation: the agent, the service
 * (by name, not only by id, and the connection by the name its owner gave it), every scope, every constraint, the named actions, the data flow, and the policy
 * listing the same approval carries when there is one. Derived from the request and the customer's own
 * connection, never from anything the caller wrote about it. Display only: the approval binds the request by its
 * payload hash.
 */
export function buildGrantPreview(
  input: GrantAgentAccessInput,
  service: string,
  listing: { policy_id: string; expected_revision: number } | null,
  connectionName?: string | null,
): Record<string, unknown> {
  return {
    agent_id: input.agent_id,
    service_connection_id: input.service_connection_id,
    ...(connectionName ? { connection_name: connectionName } : {}),
    service,
    scopes: input.scopes,
    constraints: (input.constraints ?? []).map((c) => ({ path: c.path, op: c.op, value: c.value })),
    intents: (input.intents ?? []).map((ref) => ref.name),
    ...(input.alternatives && input.alternatives.length > 0 ? { alternatives: input.alternatives.map(describeAlternative) } : {}),
    allow_data_from: input.allow_data_from ?? [],
    ...(listing ? { policy_listing: { policy_id: listing.policy_id, expected_revision: listing.expected_revision } } : {}),
  };
}
