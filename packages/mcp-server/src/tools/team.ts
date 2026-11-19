import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const TEAM_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Team
  stack_invite_member: hint.write('Invite team member', true),
  stack_list_members: hint.read('List team members'),
  stack_revoke_member: hint.destructive('Revoke team member'),
  stack_update_member: hint.destructive('Update team member'),
  stack_clear_member_sso_binding: hint.destructive('Forget single sign-on identity'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const TEAM_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  // OAuth scope withheld from directory tokens (OAUTH_DIRECTORY_SCOPES). Each
  // scope also authorizes writes that no human approval gates, so the tools
  // that need it stay on /mcp rather than widening the directory ceiling.
  stack_invite_member: 'Needs team:write, withheld from directory tokens: it adds, changes and removes team members without approval.',
  stack_update_member: 'Needs team:write, withheld from directory tokens: it adds, changes and removes team members without approval.',
  stack_revoke_member: 'Needs team:write, withheld from directory tokens: it adds, changes and removes team members without approval.',
  stack_clear_member_sso_binding: 'Needs team:write, withheld from directory tokens: it changes who a member of the team is bound to at the identity provider.',
};

/** Team member invitation and management. */
export function registerTeamTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Team Management Tools ──────────────────────────────────────

  server.tool(
    'stack_invite_member',
    'Invite a team member. STACK emails the person a sign-in link to their scoped account. Requires an owner or admin session.',
    {
      email: z.string().describe('Member email address'),
      name: z.string().describe('Member display name'),
      role: z
        .enum(['readonly', 'standard', 'admin'])
        .optional()
        .describe(
          'Role (default: standard). readonly=view only, standard=connect services, admin=full access',
        ),
      allowed_connections: z
        .array(z.string())
        .optional()
        .describe('Service connection IDs this member can access'),
    },
    async ({ email, name, role, allowed_connections }) => {
      const result = await api('POST', '/v1/team/members', {
        email,
        name,
        role,
        allowed_connections,
      });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_members',
    'List team members with their status, role and allowed connections.',
    {},
    async () => {
      const result = await api('GET', '/v1/team/members');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_revoke_member',
    'Revoke a team member, ending their access and live OAuth sessions.',
    {
      member_id: z.string().describe('Member ID to revoke'),
    },
    async ({ member_id }) => {
      const result = await api('DELETE', `/v1/team/members/${encodeURIComponent(member_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_update_member',
    "Update a team member's role or allowed service connections.",
    {
      member_id: z.string().describe('Member ID to update'),
      role: z
        .enum(['readonly', 'standard', 'admin'])
        .optional()
        .describe('New role: readonly, standard, or admin'),
      allowed_connections: z
        .array(z.string())
        .optional()
        .describe('Updated list of allowed service connection IDs'),
    },
    async ({ member_id, role, allowed_connections }) => {
      const body: Record<string, unknown> = {};
      if (role !== undefined) body.role = role;
      if (allowed_connections !== undefined) body.allowed_connections = allowed_connections;
      const result = await api('PATCH', `/v1/team/members/${encodeURIComponent(member_id)}`, body);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_clear_member_sso_binding',
    `Forget the single sign-on identity of one team member (member_id) or of every member who signed in through one identity provider (issuer, the iss of the provider that was replaced; send exactly one). A member is bound to the provider's own name for them on their first sign-in, and is refused under a new provider until the binding is cleared; after it, the next sign-in the provider confirms with their address binds them again, so whoever the provider says holds that address takes the seat. Needs an owner or admin session. A person approves it in a browser: the call fails first with approval_id and approval_url and the chat never approves it. Send the same arguments with governance_approval_id once they have. The role, status and sessions of a member are unchanged. Returns cleared: the members whose binding was forgotten, each with id, email and the issuer it was bound to (empty when nobody had one).`,
    {
      member_id: z.string().min(1).max(128).optional().describe('One member to clear'),
      issuer: z.string().min(1).max(2048).optional().describe('Clear every member bound to this issuer (the iss of the provider that was replaced)'),
      governance_approval_id: z
        .string()
        .optional()
        .describe('Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, once the person approved it in their browser'),
    },
    async ({ member_id, issuer, governance_approval_id }) => {
      if ((member_id === undefined) === (issuer === undefined)) {
        throw new Error('Send exactly one of member_id and issuer.');
      }
      const headers = governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined;
      const result = await api('POST', '/v1/team/sso-bindings/clear', member_id !== undefined ? { member_id } : { issuer }, headers);
      return toolJson(result);
    },
  );
}
