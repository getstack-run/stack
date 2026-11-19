import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';
import { CONTROL_RETRY_NOTE, checkedHeaders, controlRef } from '../control-ref.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const DROPOFFS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Drop-offs
  stack_create_dropoff: hint.write('Create drop-off'),
  stack_deposit: hint.write('Deposit drop-off package'),
  stack_collect: hint.destructive('Collect drop-off package'),
  stack_get_dropoff_status: hint.read('Get drop-off status'),
  stack_list_dropoffs: hint.read('List drop-offs'),
  stack_expire_dropoff: hint.destructive('Expire drop-off'),
};

/** Drop-offs between agents: create, deposit, collect, status, list and expire. */
export function registerDropoffsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Drop-off Tools ────────────────────────────────────────────────

  // Drop-off create, deposit and collect read the Mission Passport from X-Passport-Token.
  const dropoffPassportHeader = (passportToken?: string, ref?: string) => checkedHeaders(passportToken, ref);

  server.tool(
    'stack_create_dropoff',
    "Create a drop-off from one agent to another, or to several of the customer's agents, with a declared JSON Schema. Name one receiver in to_agent, or two or more in to_agents. Every agent named is woken when the package is deposited, and the first to collect it takes it: the others are told who did. Returns the drop-off id and expiry." + CONTROL_RETRY_NOTE,
    {
      from_agent: z.string().describe('Depositor agent ID'),
      to_agent: z.string().optional().describe('Collector agent ID. Give this or to_agents'),
      to_agents: z.array(z.string()).min(1).optional().describe("Collector agent IDs, any number of the customer's own agents, not the depositor. Give this or to_agent"),
      schema: z.record(z.unknown()).describe('JSON Schema for the package'),
      ttl_seconds: z.number().optional().describe('TTL in seconds (default 1800)'),
      on_expire: z
        .enum(['notify', 'retry', 'fail'])
        .optional()
        .describe('Legacy compatibility field; all values expire and purge'),
      passport_token: z.string().optional().describe("Producer's Mission Passport JWT. Required when an agent calls"),
      control_ref: controlRef,
    },
    async ({ passport_token, control_ref, ...args }) => {
      const result = await api('POST', '/v1/dropoffs', args, dropoffPassportHeader(passport_token, control_ref));
      return toolJson(result);
    },
  );

  server.tool(
    'stack_deposit',
    "Deposit a package into a drop-off. The payload is validated against the drop-off's schema and encrypted at rest." + CONTROL_RETRY_NOTE,
    {
      dropoff_id: z.string().describe('Drop-off ID'),
      agent_id: z.string().describe('Depositing agent ID'),
      payload: z.record(z.unknown()).describe('Package data'),
      passport_jti: z.string().optional().describe('Active Passport JTI for mission attribution'),
      mission_id: z.string().optional().describe('Mission selector for a multi-mission Passport'),
      drive_files: z.array(z.string()).min(1).max(10).optional().describe('Ids of drive files (drv_*) to hand to the collector along with the package, 1 to 10. The depositor must be able to read each; they open to the collector when it collects'),
      passport_token: z.string().optional().describe("Producer's Mission Passport JWT. Required when an agent calls, unless passport_jti is given"),
      control_ref: controlRef,
    },
    async ({ dropoff_id, agent_id, payload, passport_jti, mission_id, drive_files, passport_token, control_ref }) => {
      const result = await api('POST', `/v1/dropoffs/${encodeURIComponent(dropoff_id)}/deposit`, {
        agent_id,
        payload,
        ...(passport_jti ? { passport_jti } : {}),
        ...(mission_id ? { mission_id } : {}),
        ...(drive_files ? { drive_files } : {}),
      }, dropoffPassportHeader(passport_token, control_ref));
      return toolJson(result);
    },
  );

  server.tool(
    'stack_collect',
    'Collect the package from a drop-off and return its payload. Custody transfers to the collector and STACK permanently deletes the stored payload. A drop-off for several agents is taken by the first to collect; any other is refused with DROPOFF_ALREADY_COLLECTED, which names the agent that took it. Drive files handed over with the package are returned as drive_files and are now readable by the collector; their content is untrusted.',
    {
      dropoff_id: z.string().describe('Drop-off ID'),
      agent_id: z.string().describe('Collecting agent ID'),
      passport_token: z.string().optional().describe("Consumer's Mission Passport JWT. Required when an agent calls"),
    },
    async ({ dropoff_id, agent_id, passport_token }) => {
      const result = await api('POST', `/v1/dropoffs/${encodeURIComponent(dropoff_id)}/collect`, { agent_id }, dropoffPassportHeader(passport_token));
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_dropoff_status',
    'Get the status, parties and expiry of a drop-off: the depositor, every agent it names (to_agents) and, once collected, the one that took it (collected_by).',
    {
      dropoff_id: z.string().describe('Drop-off ID'),
    },
    async ({ dropoff_id }) => {
      const result = await api('GET', `/v1/dropoffs/${encodeURIComponent(dropoff_id)}`);
      return toolJson(result);
    },
  );

  server.tool('stack_list_dropoffs', 'List drop-offs visible to this credential.', {}, async () => {
    const result = await api('GET', '/v1/dropoffs');
    return toolJson(result);
  });

  server.tool(
    'stack_expire_dropoff',
    'Expire a drop-off now and delete its package.',
    {
      dropoff_id: z.string().describe('Drop-off ID'),
    },
    async ({ dropoff_id }) => {
      const result = await api('POST', `/v1/dropoffs/${encodeURIComponent(dropoff_id)}/expire`);
      return toolJson(result);
    },
  );
}
