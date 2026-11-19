import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const CREDENTIALS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  stack_list_credential_templates: hint.read('List credential templates'),
  stack_verify_connection: hint.write('Verify service connection', true),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const CREDENTIALS_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_list_credential_templates: 'Lists the secret fields a custom connection needs, which invites pasting credentials into the conversation.',
};

/** Credential templates and connection verification. */
export function registerCredentialsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Credential Template Tools ────────────────────────────────────

  server.tool(
    'stack_list_credential_templates',
    'List credential templates. Each template names the fields a custom service connection needs. Returns field names only, never credential values.',
    {},
    async () => {
      const result = await api('GET', '/v1/services/templates');
      return toolJson(result);
    },
  );

  // ─── Connection Verification Tools ──────────────────────────────

  server.tool(
    'stack_verify_connection',
    "Test a service connection's stored credential against the provider API and record the resulting connection status. Returns whether the connection is healthy.",
    {
      connection_id: z.string().describe('Service connection ID to verify'),
    },
    async ({ connection_id }) => {
      const result = await api('POST', `/v1/services/${encodeURIComponent(connection_id)}/verify`);
      return toolJson(result);
    },
  );
}
