import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const AUTHORITY_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  stack_request_authority: hint.write('Request authority approval'),
  stack_get_authority_request: hint.read('Get authority request'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const AUTHORITY_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_request_authority: 'Needs authority:write, withheld from directory tokens: it also covers authority proof import, erasure and receiver keys.',
};

/** Authority requests. */
export function registerAuthorityTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  server.tool(
    'stack_request_authority',
    'Create a pending request for an owner or admin to approve one exact job for an agent. Returns the request id and a human approval URL; it grants no access by itself. The approver reviews the terms and verifies through the OpenID Connect provider configured under Security and sign-in.',
    {
      organisation_name: z.string().min(1).max(256).describe('Organisation the agent will act for.'),
      role_name: z.string().min(1).max(256).describe('Human-readable role required to approve the request.'),
      role_claim_path: z.string().min(1).max(256).describe('OIDC claim path that records the approver role, such as roles.'),
      role_claim_value: z.string().min(1).max(512).describe('Required value in the configured OIDC role claim.'),
      agent_id: z.string().regex(/^(ag|agt)_[\w-]+$/),
      mission_id: z.string().regex(/^ms_[\w-]+$/).optional(),
      service_connection_id: z.string().regex(/^scon_[\w-]+$/),
      provider: z.string().min(1).max(128).describe('Connected system, such as stripe.'),
      purpose: z.string().min(1).max(1024).describe('Plain-language reason this access is needed.'),
      http_method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
      resource_path: z.string().min(1).max(1024).startsWith('/'),
      constraints: z.array(z.object({
        path: z.string().min(1).max(256),
        op: z.enum(['eq', 'not_eq', 'in', 'not_in', 'lt', 'lte', 'gt', 'gte', 'exists', 'not_exists']),
        value: z.union([
          z.string().max(2048),
          z.number(),
          z.boolean(),
          z.array(z.union([z.string().max(2048), z.number(), z.boolean()])).max(256),
        ]).optional(),
        value_ref: z.string().min(1).max(512).optional(),
      }).strict()).max(16).optional(),
      expires_at: z.string().datetime().describe('ISO timestamp within the next 60 minutes.'),
      idempotency_key: z.string().min(1).max(128).describe('Stable key for this exact request. A repeated call with the same key returns the same request.'),
    },
    async ({ idempotency_key, ...request }) => {
      const result = await api(
        'POST',
        '/v1/authority/enterprise-oidc/requests',
        request,
        { 'Idempotency-Key': idempotency_key },
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_authority_request',
    'Get the status of an Authority request: pending, completed, rejected or expired. After approval the result includes the opaque binding reference. Identity-provider tokens and evidence are never returned.',
    {
      request_id: z.string().regex(/^aor_[a-f0-9]{32}$/),
    },
    async ({ request_id }) => {
      const result = await api(
        'GET',
        `/v1/authority/enterprise-oidc/requests/${encodeURIComponent(request_id)}`,
      );
      return toolJson(result);
    },
  );
}
