import { describeOtherAgentFields, type AgentSetupInput, type AgentSetupPreview } from '@stack/shared';
import { describeAlternative } from './grant-preview.js';

/**
 * What the approval card of an agent setup lists: the agent's posture as it will be registered (the defaults
 * filled in, so "nothing said" is shown as what it means), every grant with its constraints in full, and every
 * host list. Derived from the request and the customer's own connections, never from anything the caller wrote
 * about it. Display only: the approval binds the request by its payload hash.
 */
export function buildSetupPreview(
  input: AgentSetupInput,
  connections: ReadonlyMap<string, { id: string; provider: string; name?: string }>,
): AgentSetupPreview {
  const service = (connectionId: string) => connections.get(connectionId)?.provider ?? connectionId;
  // The connection's own name, read now, stored with the preview the approval is bound to: what is shown is what was asked.
  const named = (connectionId: string) => {
    const name = connections.get(connectionId)?.name;
    return name ? { connection_name: name } : {};
  };
  const agent = input.agent;
  return {
    agent: {
      name: agent.name,
      description: agent.description ?? null,
      accountability_mode: agent.accountability_mode ?? 'logged',
      on_warning: agent.on_warning ?? 'notify',
      on_critical: agent.on_critical ?? 'notify',
      credential_access: agent.credential_access ?? 'proxy_only',
      eval_traffic: agent.eval_traffic === true,
      other_fields: describeOtherAgentFields(agent),
    },
    grants: input.grants.map((grant) => ({
      service_connection_id: grant.service_connection_id,
      ...named(grant.service_connection_id),
      service: service(grant.service_connection_id),
      scopes: grant.scopes,
      constraints: (grant.constraints ?? []).map((c) => ({ path: c.path, op: c.op, value: c.value })),
      intents: (grant.intents ?? []).map((ref) => ref.name),
      ...(grant.alternatives && grant.alternatives.length > 0 ? { alternatives: grant.alternatives.map(describeAlternative) } : {}),
      allow_data_from: grant.allow_data_from ?? [],
    })),
    allowed_hosts: input.allowed_hosts.map((entry) => ({
      service_connection_id: entry.service_connection_id,
      ...named(entry.service_connection_id),
      service: service(entry.service_connection_id),
      hosts: entry.allowed_hosts,
    })),
  };
}

/** The one line the approval carries beside the card. */
export function setupSummary(input: AgentSetupInput): string {
  const parts = ['register it'];
  if (input.grants.length > 0) parts.push(`${input.grants.length} service ${input.grants.length === 1 ? 'grant' : 'grants'}`);
  if (input.allowed_hosts.length > 0) parts.push(`${input.allowed_hosts.length} host ${input.allowed_hosts.length === 1 ? 'list' : 'lists'}`);
  return `Set up agent ${input.agent.name}: ${parts.join(', ')}`;
}
