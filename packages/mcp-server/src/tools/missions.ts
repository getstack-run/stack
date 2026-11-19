import { createHash } from 'node:crypto';
import { z } from 'zod';
import { FleetMissionStartInput } from '@stack/shared';
import { throwApiError } from '../api-client.js';
import type { ToolContext, ToolRegistrar } from './context.js';
import { missionSpecShape } from './mission-spec.js';
import { toolJson, controlsFeature } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const MISSIONS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Missions and records
  stack_open_mission: hint.write('Open Mission'),
  stack_complete_mission: hint.destructive('Complete Mission'),
  stack_revoke_mission: hint.destructive('Revoke Mission'),
  stack_get_mission: hint.read('Get Mission'),
  stack_list_missions: hint.read('List Missions'),
  stack_view_mission_activity: hint.read('View Mission activity'),
  stack_list_mission_operator_reviews: hint.read('List Mission operator reviews'),
  stack_download_mission_operator_review: hint.read('Download Mission operator review'),
  stack_review_paused_mission: hint.write('Review paused Mission'),
  stack_set_mission_making_allowance: hint.write('Set Mission making allowance'),
  stack_add_mission_recipients: hint.write('Add Mission recipients'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const MISSIONS_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_download_mission_operator_review: 'Owner download of a signed review. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_review_paused_mission: 'The owner\'s decision on a Mission a cap paused. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_set_mission_making_allowance: 'The owner\'s pre-approval of spending. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_add_mission_recipients: 'The owner widens who a running Mission may send to. Kept out of the directory profile, whose reviewed tool set does not change.',
};

/** Mission lifecycle, activity replay and operator reviews. */
export function registerMissionsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api, apiRaw } = ctx;
  // ─── Mission tools ─────────────────────────────────────────────────
  server.tool(
    'stack_open_mission',
    "Open a Mission with the access and limits needed for a job and return its mission_id (ms_*). Every Passport is issued for exactly one Mission, named at issuance as mission_ids: [mission_id]. agent_id assigns the Mission to one agent. A fleet agent supplies its fleet policy and requested access instead. Completing or revoking the Mission revokes every Passport bound to it. recipients, recipient_pins and reply_to_message set who the Mission may send to, for a policy rule that leaves recipients to each Mission; an agent woken by an incoming message passes that message's id as reply_to_message to reply to its sender and no one else. The agent cannot change them; only the owner can add to them. Opening a Mission is not metered; issuing its Passport is.",
    {
      ...FleetMissionStartInput.innerType().partial().omit({ intent_summary: true, expected_output_shape: true }).shape,
      ...missionSpecShape,
      agent_id: z
        .string()
        .regex(/^agt_[\w-]+$/)
        .optional()
        .describe('Agent the Mission is assigned to (agt_*). Only that agent can be issued a Passport for it. An agent caller is always assigned itself.'),
    },
    async (input) => {
      const result = await api('POST', '/v1/missions', input);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_complete_mission',
    "Complete a Mission and submit its output. STACK checks any declared output schema before accepting successful completion, stores the output encrypted and signs its digest. Completing the Mission revokes every Passport bound to it.",
    {
      mission_id: z.string().describe('Mission id from stack_open_mission (ms_*).'),
      output: z
        .record(z.unknown())
        .optional()
        .describe(
          "Final output, checked against the Mission's declared output schema and stored encrypted.",
        ),
    },
    async ({ mission_id, output }) => {
      const body: Record<string, unknown> = {};
      if (output !== undefined) body.output = output;
      const result = await api(
        'POST',
        `/v1/missions/${encodeURIComponent(mission_id)}/complete`,
        body,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_revoke_mission',
    'Revoke a Mission. Every Passport bound to it is revoked in the same transaction, whatever the reason. reason records why: adversarial for suspected abuse, operator_initiated_clean for an ordinary stop. A second call returns the prior state with transitioned=false.',
    {
      mission_id: z.string().describe('Mission id from stack_open_mission (ms_*).'),
      reason: z
        .enum(['adversarial', 'operator_initiated_clean'])
        .describe('Why the Mission is revoked. Both reasons revoke its bound Passports.'),
      notes: z
        .string()
        .max(1000)
        .optional()
        .describe('Optional human-readable note attached to the revoke event.'),
    },
    async ({ mission_id, reason, notes }) => {
      const body: Record<string, unknown> = { reason };
      if (notes !== undefined) body.notes = notes;
      const result = await api(
        'POST',
        `/v1/missions/${encodeURIComponent(mission_id)}/revoke`,
        body,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_get_mission',
    'Get one Mission by id: lifecycle state (started_at, expires_at, completed_at, revoked_at, terminal_state), caps, cap_behavior, coverage_cap_period, cap_time_zone, paused_at and paused_cap, making_orders_up_to_cents, intent_services, expected_counterparties, recipient_pins (who the Mission may send to, or null) and the latest claim_id. Missions belonging to another account return 404.',
    {
      mission_id: z.string().describe('Mission id (ms_*).'),
    },
    async ({ mission_id }) => {
      const result = await api('GET', `/v1/missions/${encodeURIComponent(mission_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_missions',
    controlsFeature("List the account's Missions, newest first by started_at, optionally filtered by status (active, completed, revoked, paused) and paginated with page and limit."),
    {
      status: z
        .enum(['active', 'completed', 'revoked', 'paused'])
        .optional()
        .describe('Filter by lifecycle status; paused lists the Missions waiting for the owner\'s review.'),
      page: z.number().int().positive().optional().describe('1-indexed page number.'),
      limit: z
        .number()
        .int()
        .positive()
        .max(200)
        .optional()
        .describe('Page size. Default 50, max 200.'),
    },
    async ({ status, page, limit }) => {
      const params = new URLSearchParams();
      if (status) params.set('status', status);
      if (page !== undefined) params.set('page', String(page));
      if (limit !== undefined) params.set('limit', String(limit));
      const suffix = params.toString();
      const result = await api('GET', `/v1/missions${suffix ? `?${suffix}` : ''}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_review_paused_mission',
    "Decide a Mission one of its caps paused (stack_list_missions with status paused lists them). raise sets a new limit, above the old one, for the cap that paused it (paused_cap; for max_actions_per_service, the paused_service's limit) and lets the Mission go on; continue lets it go on with its limits as they are, so a cap that has no room left pauses it again; close ends it as completed_cap_breached, and its Passports with it. The agent the Mission was opened for is told the decision. The owner's or a member's own decision; an agent cannot decide its own pause. Answers MISSION_NOT_PAUSED for a Mission that is not paused. Not metered.",
    {
      mission_id: z.string().regex(/^ms_[\w-]+$/).describe('Mission id (ms_*).'),
      decision: z.enum(['raise', 'continue', 'close']).describe('raise, continue or close.'),
      limit: z.number().int().positive().optional().describe('With raise only: the new limit of the cap that paused the Mission, in that cap\'s unit (actions, cents, seconds or bytes).'),
    },
    async ({ mission_id, decision, limit }) => {
      const result = await api('POST', `/v1/missions/${encodeURIComponent(mission_id)}/review`, {
        decision,
        ...(limit !== undefined ? { limit } : {}),
      });
      return toolJson(result);
    },
  );

  server.tool(
    'stack_set_mission_making_allowance',
    "Set what the owner pre-approves of a running Mission's print-on-demand making orders, in cents across all of them (an agent account's standing Mission included). An order its agent places under the Mission that fits in what is left is approved without asking; one that does not waits for the owner as before. null removes the pre-approval. The owner or an admin only. Not metered. Returns the Mission.",
    {
      mission_id: z.string().regex(/^ms_[\w-]+$/).describe('Mission id (ms_*).'),
      making_orders_up_to_cents: z.number().int().nonnegative().nullable().describe('The amount in cents across the Mission\'s orders, or null for none.'),
    },
    async ({ mission_id, making_orders_up_to_cents }) => {
      const result = await api('PUT', `/v1/missions/${encodeURIComponent(mission_id)}/making-allowance`, { making_orders_up_to_cents });
      return toolJson(result);
    },
  );

  // Mission activity and Operator review tools.

  server.tool(
    'stack_view_mission_activity',
    'Get the recorded activity of a Mission: verified events in time order, behavioral differences, cap usage, Operator review events and twin divergence. The view is computed live, not read from a stored file. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.',
    {
      mission_id: z.string().describe('Mission id (ms_*).'),
    },
    async ({ mission_id }) => {
      const result = await api('GET', `/v1/missions/${encodeURIComponent(mission_id)}/replay`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_mission_operator_reviews',
    'List the signed Operator review revisions of a Mission, including older dossier claims. Returns an empty array when no review exists.',
    {
      mission_id: z.string().describe('Mission id (ms_*).'),
    },
    async ({ mission_id }) => {
      const result = await api(
        'GET',
        `/v1/missions/${encodeURIComponent(mission_id)}/operator-reviews`,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_download_mission_operator_review',
    "Download one signed Operator review of a Mission as its COSE_Sign1 bytes, base64-encoded, which can be checked offline against the account's signing key. Returns mission_id, claim_id, content_type, cose_base64 and sha256 of the bytes. Reading the record is a controls feature: without controls the API answers 402 CONTROLS_REQUIRED.",
    {
      mission_id: z.string().regex(/^ms_[\w-]+$/).describe('Mission id (ms_*)'),
      claim_id: z.string().regex(/^pc_[\w-]+$/).describe('Review claim id (pc_*) from stack_list_mission_operator_reviews'),
    },
    async ({ mission_id, claim_id }) => {
      const res = await apiRaw(
        'GET',
        `/v1/missions/${encodeURIComponent(mission_id)}/operator-reviews/${encodeURIComponent(claim_id)}/download`,
      );
      if (!res.ok) throwApiError(res);
      const bytes = res.bytes ?? new Uint8Array();
      if (bytes.length === 0) throw new Error('The review came back empty.');
      return toolJson({
        mission_id,
        claim_id,
        content_type: 'application/cose',
        cose_base64: Buffer.from(bytes).toString('base64'),
        sha256: createHash('sha256').update(bytes).digest('hex'),
      });
    },
  );

  server.tool(
    'stack_add_mission_recipients',
    'Add who a running Mission may send to, for a policy rule that leaves recipients to each Mission: recipients, recipient_pins and reply_to_message, the same as at open, merged into the pins the Mission has (a pin on a field it already pins adds its values). Nothing already pinned is taken away. The owner\'s call; an agent cannot add to its own Mission. Returns mission_id and the recipient_pins the Mission holds now. A Mission that has ended answers 409.',
    {
      mission_id: z.string().regex(/^ms_[\w-]+$/).describe('Mission id (ms_*).'),
      recipients: missionSpecShape.recipients,
      recipient_pins: missionSpecShape.recipient_pins,
      reply_to_message: missionSpecShape.reply_to_message,
    },
    async ({ mission_id, recipients, recipient_pins, reply_to_message }) => {
      if (recipients === undefined && recipient_pins === undefined && reply_to_message === undefined) {
        throw new Error('Name recipients, recipient_pins or reply_to_message.');
      }
      return toolJson(await api('POST', `/v1/missions/${encodeURIComponent(mission_id)}/recipients`, {
        ...(recipients !== undefined ? { recipients } : {}),
        ...(recipient_pins !== undefined ? { recipient_pins } : {}),
        ...(reply_to_message !== undefined ? { reply_to_message } : {}),
      }));
    },
  );
}
