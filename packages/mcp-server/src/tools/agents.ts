import { z } from 'zod';
import { AccessAlternative, Constraint, IntentRef } from '@stack/shared';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson, approvalFlow } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const AGENTS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Agents
  stack_register_agent: hint.write('Register agent'),
  stack_setup_agent: hint.write('Set up agent with grants and hosts'),
  stack_update_agent: hint.destructive('Update agent'),
  stack_unblock_agent: hint.write('Unblock agent'),
  stack_allow_skill: hint.write('Allow skill for agent'),
  stack_disallow_skill: hint.destructive('Disallow skill for agent'),
  stack_list_agents: hint.read('List agents'),
  stack_retire_agent: hint.destructive('Retire agent'),
  stack_dismiss_agent_warnings: hint.destructive('Dismiss agent warnings'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const AGENTS_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_setup_agent:
    'Gives a new agent grants on the account\'s connections and changes where their credentials may be sent, in one approval. The directory profile serves registration and the single grant tools, not this combined one.',
  stack_retire_agent: 'Retires an agent for good, or closes its agent account. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_dismiss_agent_warnings: 'Resolves an agent\'s open warnings and hides repeats of them for a day, after the person confirms it. Kept out of the directory profile, whose reviewed tool set does not change.',
};

/** Agent registration, updates, unblocking and per-agent skill allow lists. */
export function registerAgentsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  server.tool(
    'stack_register_agent',
    `Register a new agent with STACK and return its record. Registering an agent needs no approval: it names a principal that has no access to any connected service yet, and giving it access (a grant, the hosts a credential may go to, a signing key) is asked of the person separately, whatever settings the agent starts with. Agents never receive raw credentials; credential_access only controls proxy posture. accountability_mode controls monitoring, skill access defaults to none, and key_mode selects the signing-key model.`,
    {
      name: z.string().describe('Agent name (lowercase, letters/digits/hyphens/underscores)'),
      description: z.string().optional().describe('Optional description'),
      profile: z
        .enum(['proxied-llm-bot'])
        .optional()
        .describe(
          "Registration preset. 'proxied-llm-bot' = a bot that just runs: calls an LLM through the STACK gateway and holds no provider key on its box. Expands to credential_access: proxy_only + accountability_mode: logged + key_mode: stack_managed so the first call works immediately. Explicit fields below override the preset. Omit for the base posture (logged + proxy_only).",
        ),
      accountability_mode: z
        .enum(['enforced', 'logged', 'standard'])
        .optional()
        .describe(
          "Accountability mode (default: logged, or per profile). 'logged' records every call and needs no per-call approval; 'enforced' holds every call for a person's approval and is the owner's choice.",
        ),
      on_warning: z
        .enum(['notify', 'block'])
        .optional()
        .describe('Action on warning flags (default: notify)'),
      on_critical: z
        .enum(['notify', 'block'])
        .optional()
        .describe('Action on critical flags (default: notify)'),
      credential_access: z
        .enum(['direct', 'proxy_preferred', 'proxy_only'])
        .optional()
        .describe(
          "Credential proxy posture (default: proxy_only, or per profile). Agents never receive raw credentials. 'proxy_only' requires STACK proxy use; legacy direct/proxy_preferred values do not grant raw-secret retrieval.",
        ),
      key_mode: z
        .enum(['stack_managed', 'customer_managed', 'co_signed'])
        .optional()
        .describe(
          "Signing-key model (default: stack_managed). 'stack_managed' = STACK generates + KMS-wraps the keypair and provisions it automatically on the agent's first sign — NO enrollment step is needed or possible. 'customer_managed' = you hold the private key and enroll the public key (the only mode that uses the enrollment flow). 'co_signed' = stack_managed primary plus a co-signature.",
        ),
      icon_url: z
        .string()
        .optional()
        .describe('Icon URL for the agent (data URL or external URL, max 100KB)'),
      skill_access_mode: z
        .enum(['none', 'custom', 'all'])
        .optional()
        .describe(
          "Skill access policy. 'none' (default) blocks all skill invocation. 'custom' uses the allowed_skills list. 'all' permits any active skill.",
        ),
      allowed_skills: z
        .array(z.string())
        .optional()
        .describe(
          'List of skill IDs the agent can invoke when skill_access_mode is "custom". Ignored in other modes but kept as memory across mode changes.',
        ),
      llm_inject_system_prompt: z
        .boolean()
        .optional()
        .describe(
          'Accepted and ignored: it has no effect. STACK adds no system prompt to gateway calls.',
        ),
      llm_redact_pii: z
        .boolean()
        .optional()
        .describe(
          'Scan user-role messages and redact PII before forwarding to the LLM provider (default: true). false sends user content to the provider unredacted — an explicit operator choice.',
        ),
      eval_traffic: z
        .boolean()
        .optional()
        .describe(
          'Mark this agent as test or benchmark traffic (default: false). Detection stays on and events stay visible, but warnings arrive already resolved and send no notification; criticals stay live. true mutes the alerts of the owner for the agent.',
        ),
      governance_approval_id: z.string().optional().describe(
        'Deprecated and ignored: registering an agent no longer asks for an approval. Kept so existing callers keep working.',
      ),
    },
    async ({
      name,
      description,
      profile,
      accountability_mode,
      on_warning,
      on_critical,
      credential_access,
      key_mode,
      icon_url,
      skill_access_mode,
      allowed_skills,
      llm_inject_system_prompt,
      llm_redact_pii,
      eval_traffic,
    }) => {
      const result = await api(
        'POST',
        '/v1/agents/register',
        {
          name, description, profile, accountability_mode, on_warning, on_critical,
          credential_access, key_mode, icon_url, skill_access_mode, allowed_skills,
          llm_inject_system_prompt, llm_redact_pii, eval_traffic,
        },
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_update_agent',
    `Update a registered agent. Tightening controls or suspending the agent applies immediately. Reactivation, added authority, or weaker safeguards (turning eval_traffic on included) require human approval; changing which skills the agent may use does not. ${approvalFlow} Agents never receive raw credentials. key_mode cannot be changed after registration.`,
    {
      agent_id: z.string().describe('The agent id (agt_*) to update'),
      status: z
        .enum(['active', 'suspended'])
        .optional()
        .describe('Suspend or reactivate the agent'),
      accountability_mode: z
        .enum(['enforced', 'logged', 'standard'])
        .optional()
        .describe('New accountability mode'),
      on_warning: z.enum(['notify', 'block']).optional().describe('New action on warning flags'),
      on_critical: z.enum(['notify', 'block']).optional().describe('New action on critical flags'),
      credential_access: z
        .enum(['direct', 'proxy_preferred', 'proxy_only'])
        .optional()
        .describe(
          "New credential proxy posture. Agents never receive raw credentials; proxy_only requires all credential use through STACK's proxy boundary.",
        ),
      skill_access_mode: z
        .enum(['none', 'custom', 'all'])
        .optional()
        .describe('New skill access policy'),
      allowed_skills: z
        .array(z.string())
        .optional()
        .describe('New allowed-skills list (used when skill_access_mode is "custom")'),
      llm_inject_system_prompt: z
        .boolean()
        .optional()
        .describe(
          'Accepted and ignored: it has no effect. STACK adds no system prompt to gateway calls.',
        ),
      llm_redact_pii: z
        .boolean()
        .optional()
        .describe(
          'Toggle PII redaction of user messages before forwarding to the LLM provider (default: true). false sends user content unredacted — an explicit operator choice.',
        ),
      eval_traffic: z
        .boolean()
        .optional()
        .describe(
          'Mark or unmark this agent as test or benchmark traffic. true needs human approval; false applies immediately. Detection stays on either way; warnings of a marked agent arrive already resolved and send no notification, and criticals stay live.',
        ),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a prior 403, after human approval in the dashboard',
      ),
    },
    async ({ agent_id, governance_approval_id, ...patch }) => {
      const result = await api(
        'PATCH',
        `/v1/agents/${encodeURIComponent(agent_id)}`,
        patch,
        governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_unblock_agent',
    `Clear an agent's passport_blocked state so Passports can be issued to it again. STACK blocks an agent automatically when a critical security event fires while its on_critical policy is 'block'. A blocked agent cannot unblock itself. Calls from MCP and API-key sessions require human approval. ${approvalFlow}`,
    {
      agent_id: z.string().describe('The agent id (agt_*) to unblock'),
      governance_approval_id: z
        .string()
        .optional()
        .describe('Approval id (gvr_*) from a prior 403, after human approval in the dashboard'),
    },
    async ({ agent_id, governance_approval_id }) => {
      const result = await api(
        'POST',
        `/v1/agents/${encodeURIComponent(agent_id)}/unblock`,
        {},
        governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_allow_skill',
    "Add a skill to an agent's allowed_skills list. It needs no approval: the account's own session or key does it directly, and a read-only member may not. It lets the agent invoke that skill when its skill_access_mode is custom.",
    {
      agent_id: z.string().describe('Agent ID'),
      skill_id: z.string().describe('Skill ID to allow'),
      governance_approval_id: z.string().optional().describe(
        'Deprecated and ignored: allowing a skill no longer asks for an approval. Kept so existing callers keep working.',
      ),
    },
    async ({ agent_id, skill_id }) => {
      const result = await api(
        'POST',
        `/v1/agents/${encodeURIComponent(agent_id)}/allowed-skills`,
        { skill_id },
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_disallow_skill',
    "Remove a skill from an agent's allowed_skills list. Removing a skill that is not on the list succeeds without change.",
    {
      agent_id: z.string().describe('Agent ID'),
      skill_id: z.string().describe('Skill ID to remove'),
    },
    async ({ agent_id, skill_id }) => {
      const result = await api('DELETE', `/v1/agents/${encodeURIComponent(agent_id)}/allowed-skills/${encodeURIComponent(skill_id)}`);
      return toolJson(result);
    },
  );

  server.tool('stack_list_agents', 'List the registered agents of the account.', {}, async () => {
    const result = await api('GET', '/v1/agents');
    return toolJson(result);
  });

  server.tool(
    'stack_setup_agent',
    `Set an agent up in one step: register it, give it its first grants on connections the account already holds, and declare the hosts those connections' credentials may be sent to. All of it is one human approval whose card lists every part, instead of one approval for each grant and one for each host list. The person confirms it in the chat, and the confirmation lists every part. ${approvalFlow} Use stack_register_agent to register an agent alone and stack_grant_agent_access to change a grant later. The service connections must already exist (stack_list_connected_services). A setup that cannot succeed, for example a scope the connection does not hold or an agent name already in use, is refused before anyone is asked. Returns the agent, the grants made and the host lists set.`,
    {
      name: z.string().describe('Agent name (lowercase, letters/digits/hyphens/underscores)'),
      description: z.string().optional().describe('Optional description'),
      accountability_mode: z
        .enum(['enforced', 'logged', 'standard'])
        .optional()
        .describe("Accountability mode (default: logged). 'enforced' holds every call for a person's approval."),
      on_warning: z.enum(['notify', 'block']).optional().describe('Action on warning flags (default: notify)'),
      on_critical: z.enum(['notify', 'block']).optional().describe('Action on critical flags (default: notify)'),
      credential_access: z
        .enum(['direct', 'proxy_preferred', 'proxy_only'])
        .optional()
        .describe('Credential proxy posture (default: proxy_only). Agents never receive raw credentials.'),
      eval_traffic: z
        .boolean()
        .optional()
        .describe('Mark this agent as test or benchmark traffic (default: false). It is part of the same approval.'),
      grants: z
        .array(
          z.object({
            service_connection_id: z.string().describe('Service connection ID (scon_*)'),
            scopes: z.array(z.string()).min(1).describe('Scopes, a subset of the connection scopes'),
            constraints: z
              .array(Constraint)
              .max(32)
              .optional()
              .describe('Raw parameter-level constraints, each { path, op, value }, as in stack_grant_agent_access'),
            intents: z.array(IntentRef).max(32).optional().describe('Named intents that expand to constraints'),
            alternatives: z
              .array(AccessAlternative)
              .min(1)
              .max(16)
              .optional()
              .describe('Several rules, any one of which allows a call, as in stack_grant_agent_access'),
            allow_data_from: z
              .array(z.string().min(1).max(128))
              .max(32)
              .optional()
              .describe('Sources whose content may flow into this one: a service, or one connection of a service written service@<connection id>, as in stack_grant_agent_access'),
          }),
        )
        .optional()
        .describe("The agent's first grants, one per connection."),
      allowed_hosts: z
        .array(
          z.object({
            service_connection_id: z.string().describe('Service connection ID (scon_*)'),
            allowed_hosts: z
              .array(z.string().min(1).max(253))
              .min(1)
              .describe('Hosts the credential may be sent to, such as api.example.com or .example.com'),
          }),
        )
        .optional()
        .describe("The hosts each named connection's credential may be sent to. A host the connection does not already allow is part of this approval."),
      governance_approval_id: z
        .string()
        .optional()
        .describe('Approval id (gvr_*) from the first call, after a person approved it'),
    },
    async ({ governance_approval_id, grants, allowed_hosts, ...agent }) => {
      const result = await api(
        'POST',
        '/v1/agents/setup',
        { agent, grants: grants ?? [], allowed_hosts: allowed_hosts ?? [] },
        governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_retire_agent',
    'Retire an agent for good: it is marked revoked, its Passports are revoked and it can never be issued another. Its name is free to register again and its audit history is kept. Refused while other records, such as inbound webhooks, still name the agent. An agent that has an open agent account is retired by closing the account (owner or admin only), which also ends its Mission, grants and pieces. To stop an agent for a while and bring it back, use stack_update_agent with status suspended.',
    {
      agent_id: z.string().regex(/^agt_[\w-]+$/).describe('Agent id (agt_*) from stack_list_agents'),
    },
    async ({ agent_id }) => toolJson(await api('DELETE', `/v1/agents/${encodeURIComponent(agent_id)}`)),
  );

  server.tool(
    'stack_dismiss_agent_warnings',
    `Dismiss every open warning and info security event of one agent in one step, and hide new events of the same kinds for that agent for 24 hours, so the same notice does not come back. A critical event is never dismissed or hidden by this. Notifications already sent are not recalled. One audit entry names who dismissed, how many and which kinds. Returns agent_id, dismissed, by_signal_type and repeats_hidden_for_seconds.`,
    {
      agent_id: z.string().regex(/^agt_[\w-]+$/).describe('Agent id (agt_*) from stack_list_agents'),
      governance_approval_id: z.string().optional().describe(
        'Deprecated and ignored: dismissing warnings no longer asks for an approval. Kept so existing callers keep working.',
      ),
    },
    async ({ agent_id }) => toolJson(await api(
      'POST',
      `/v1/agents/${encodeURIComponent(agent_id)}/dismiss-warnings`,
      {},
    )),
  );
}
