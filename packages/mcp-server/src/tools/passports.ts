import { z } from 'zod';
import { Constraint, IntentRef, DelegatePassportInput } from '@stack/shared';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const PASSPORTS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  stack_get_agent_permissions: hint.read('Get agent permissions'),
  // Passports
  stack_issue_passport: hint.write('Issue Passport'),
  stack_verify_passport: hint.read('Verify Passport'),
  stack_revoke_passport: hint.destructive('Revoke Passport'),
  stack_refresh_passport: hint.write('Refresh Passport'),
  stack_delegate_passport: hint.write('Delegate Passport'),
  stack_list_active_passports: hint.read('List active Passports'),
  stack_revoke_agent_passports: hint.destructive('Revoke all Passports for agent'),
  stack_revoke_session: hint.destructive('Revoke Passport session'),
  stack_revoke_all_passports: hint.destructive('Revoke all Passports'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const PASSPORTS_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_verify_passport: 'Requires a Passport bearer token as input.',
  stack_refresh_passport: 'Requires a Passport bearer token as input and returns a new one.',
  stack_delegate_passport: 'Requires a Passport bearer token as input and returns a new one.',
  stack_issue_passport: 'Returns a Passport bearer token into the conversation.',
};

/** Passport issue, verify, refresh, delegate and revoke, plus agent permission lookup. */
export function registerPassportsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  server.tool(
    'stack_issue_passport',
    'Issue a signed Passport for an agent and return the token, jti and expiry. mission_ids holds exactly one live Mission (ms_*) assigned to this agent or unassigned; stack_open_mission opens one, and stack_start_mission opens a Mission and issues its Passport in one call. The Passport never outlives its Mission, and completing or revoking the Mission revokes it. Enforced and logged agents require an intent summary and services. Enforced agents receive a short TTL that checkpoints extend. authority_binding_ids attaches up to eight active, opaque authority binding references. scope_overrides narrows per-connection OAuth scopes and adds parameter-level constraints or intents on top of the grant baseline; it never loosens the grant.',
    {
      agent_id: z.string().describe('Agent ID'),
      mission_ids: z
        .array(z.string().regex(/^ms_[\w-]+$/))
        .length(1)
        .describe(
          'Exactly one Mission id (ms_*) the Passport is issued for, from stack_open_mission.',
        ),
      ttl_seconds: z
        .number()
        .optional()
        .describe('TTL in seconds (overridden by checkpoint interval for enforced agents)'),
      intent_summary: z
        .string()
        .optional()
        .describe('What the agent will do (required for enforced/logged agents)'),
      intent_services: z
        .array(z.string())
        .optional()
        .describe('Services the agent plans to use (required for enforced/logged agents)'),
      will_delegate: z
        .boolean()
        .optional()
        .describe('Whether the agent will delegate to other agents'),
      estimated_duration: z
        .string()
        .optional()
        .describe('Estimated mission duration, e.g. "30m", "2h"'),
      checkpoint_interval: z
        .string()
        .optional()
        .describe('Checkpoint interval for enforced mode, e.g. "5m", "15m", "1h"'),
      identity_claim_ids: z
        .array(z.string())
        .optional()
        .describe(
          'Opt-in: only embed these identity claim IDs. When omitted, all valid claims are embedded.',
        ),
      authority_binding_ids: z
        .array(z.string().regex(/^abn_[\w-]+$/))
        .max(8)
        .optional()
        .describe('Exact active authority bindings assigned to this agent. Maximum eight.'),
      scope_overrides: z
        .array(
          z.object({
            service_connection_id: z.string(),
            scopes: z.array(z.string()).describe('Subset of the grant scopes'),
            constraints: z.array(Constraint).max(32).optional(),
            intents: z.array(IntentRef).max(32).optional(),
            allow_data_from: z
              .array(z.string().min(1).max(128))
              .max(32)
              .optional()
              .describe(
                "Data-flow declaration for this scope: the sources whose content may flow INTO it. Each entry is a service, or one connection of a service written service@<connection id>. The scope wall refuses cross-service movement (e.g. reading a guestbook and mailing the names out) unless declared here, and content read through one connection of a service needs an entry before it may go out through another connection of the same service. Must be a subset of the grant's allow_data_from ceiling — issue can narrow it, never add a flow the grant lacked.",
              ),
          }),
        )
        .optional()
        .describe(
          "Per-connection overrides. Lets this specific passport tighten scope and/or add constraints on top of the grant baseline, and declare which sources' content (a service, or service@<connection id>) may flow into each (allow_data_from). Constraints and intents expand + merge into a superset of the grant baseline; allow_data_from narrows within the grant ceiling.",
        ),
    },
    async ({
      agent_id,
      mission_ids,
      ttl_seconds,
      intent_summary,
      intent_services,
      will_delegate,
      estimated_duration,
      checkpoint_interval,
      identity_claim_ids,
      authority_binding_ids,
      scope_overrides,
    }) => {
      // Parse duration strings to seconds
      const parseDuration = (s?: string): number | undefined => {
        if (!s) return undefined;
        const match = s.match(/^(\d+)(s|m|h)$/);
        if (!match) return parseInt(s, 10) || undefined;
        const [, num, unit] = match;
        const multiplier = { s: 1, m: 60, h: 3600 }[unit!] ?? 1;
        return parseInt(num!, 10) * multiplier;
      };

      const body: Record<string, unknown> = { agent_id, mission_ids };
      if (ttl_seconds !== undefined) body.ttl_seconds = ttl_seconds;
      if (intent_summary || intent_services) {
        body.intent = {
          summary: intent_summary ?? '',
          services: intent_services ?? [],
          will_delegate: will_delegate ?? false,
          estimated_duration_seconds: parseDuration(estimated_duration),
        };
      }
      const cpInterval = parseDuration(checkpoint_interval);
      if (cpInterval) body.checkpoint_interval_seconds = cpInterval;
      if (identity_claim_ids?.length) body.identity_claim_ids = identity_claim_ids;
      if (authority_binding_ids?.length) body.authority_binding_ids = authority_binding_ids;
      if (scope_overrides?.length) body.scopes = scope_overrides;

      const result = await api('POST', '/v1/passports/issue', body);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_verify_passport',
    'Verify a Passport token, including a live revocation check. Returns the agent identity and scopes when the token is valid.',
    {
      token: z.string().describe('Passport JWT token'),
    },
    async ({ token }) => {
      const result = await api('POST', '/v1/passports/verify', { token });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_revoke_passport',
    'Revoke a Passport by jti. STACK-verified calls reject it from the next call onward.',
    {
      jti: z.string().describe('Passport JTI to revoke'),
      reason: z.string().optional().describe('Reason'),
    },
    async ({ jti, reason }) => {
      const result = await api('POST', '/v1/passports/revoke', { jti, reason });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_refresh_passport',
    'Refresh a Passport and return a new token. Accepts a token that is still valid or one that expired less than 24 hours ago. The new Passport keeps the session and delegation chain and reflects current permissions.',
    {
      token: z.string().describe('The Passport JWT to refresh'),
      ttl_seconds: z.number().optional().describe('TTL for new passport (default 900, max 3600)'),
    },
    async ({ token, ttl_seconds }) => {
      const result = await api('POST', '/v1/passports/refresh', { token, ttl_seconds });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_delegate_passport',
    "Delegate a Passport to a child agent and return the child Passport. Takes the parent token and the exact connection scopes for the child. STACK checks the parent authority and permits only narrower access.",
    {
      parent_passport_token: z.string().describe('The parent passport JWT to delegate from'),
      child_agent_id: z
        .string()
        .describe('The child agent id (agt_*) receiving the delegated passport'),
        scopes: DelegatePassportInput.shape.scopes,
      ttl_seconds: z
        .number()
        .optional()
        .describe('TTL for the child passport (<= parent remaining TTL)'),
    },
    async ({ parent_passport_token, child_agent_id, scopes, ttl_seconds }) => {
      const result = await api('POST', '/v1/passports/delegate', {
        parent_passport_token,
        child_agent_id,
        scopes,
        ttl_seconds,
      });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_active_passports',
    'List active (unexpired, unrevoked) Passports, optionally filtered by agent or session.',
    {
      agent_id: z.string().optional().describe('Filter by agent ID'),
      session_id: z.string().optional().describe('Filter by session ID'),
    },
    async ({ agent_id, session_id }) => {
      const params = new URLSearchParams();
      if (agent_id) params.set('agent_id', agent_id);
      if (session_id) params.set('session_id', session_id);
      const qs = params.toString();
      const result = await api('GET', `/v1/passports/active${qs ? `?${qs}` : ''}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_revoke_agent_passports',
    'Revoke every active Passport held by one agent. The agent cannot act through STACK until a new Passport is issued.',
    {
      agent_id: z.string().describe('Agent ID to revoke all passports for'),
      reason: z.string().optional().describe('Reason for revocation'),
    },
    async ({ agent_id, reason }) => {
      const result = await api('POST', `/v1/passports/revoke-agent/${encodeURIComponent(agent_id)}`, { reason });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_revoke_session',
    'Revoke a session chain: the root Passport and every Passport delegated from it in that session.',
    {
      session_id: z.string().describe('Session ID to revoke'),
      reason: z.string().optional().describe('Reason for revocation'),
    },
    async ({ session_id, reason }) => {
      const result = await api('POST', `/v1/passports/revoke-session/${encodeURIComponent(session_id)}`, { reason });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_revoke_all_passports',
    'Revoke every active Passport across all agents of the account. Requires confirm: true. Intended for security incidents.',
    {
      confirm: z.literal(true).describe('Must be true — safety confirmation'),
      reason: z.string().optional().describe('Reason for emergency revocation'),
    },
    async ({ confirm, reason }) => {
      const result = await api('POST', '/v1/passports/revoke-all', { confirm, reason });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_agent_permissions',
    'Get the service grants and scopes held by an agent.',
    {
      agent_id: z.string().describe('Agent ID'),
    },
    async ({ agent_id }) => {
      const result = await api('GET', `/v1/agents/${encodeURIComponent(agent_id)}/permissions`);
      return toolJson(result);
    },
  );
}
