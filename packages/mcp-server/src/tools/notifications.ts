import { z } from 'zod';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson, approvalFlow } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const NOTIFICATIONS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Notifications
  // Sends a verification code to the given email, SMS number or webhook URL.
  stack_add_delivery_method: hint.write('Add notification delivery method', true),
  stack_list_delivery_methods: hint.read('List notification delivery methods'),
  stack_delete_delivery_method: hint.destructive('Delete notification delivery method'),
  stack_send_verification_code: hint.write('Send delivery method verification code', true),
  stack_verify_delivery_method: hint.write('Verify notification delivery method'),
  stack_test_delivery_method: hint.write('Send test notification', true),
  stack_create_notification_rule: hint.write('Create notification rule'),
  stack_list_notification_rules: hint.read('List notification rules'),
  stack_update_notification_rule: hint.destructive('Update notification rule'),
  stack_delete_notification_rule: hint.destructive('Delete notification rule'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const NOTIFICATIONS_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_send_verification_code: 'One-time verification code flow.',
  stack_verify_delivery_method: 'Accepts a one-time verification code.',
};

/** Notification delivery methods and notification rules. */
export function registerNotificationsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Notification Delivery Methods ─────────────────────────────────

  server.tool(
    'stack_add_delivery_method',
    `Add a notification delivery method (email, SMS or webhook). Email, SMS and webhook are the channel types: a hosted account's plan can limit SMS and webhook (the API answers 403 when it does), and SMS needs a text provider configured on the deployment. An email address matching the account email is verified automatically. Every other destination, webhook included, is verified with a code; for a webhook STACK posts the code to the URL signed with the destination's HMAC secret. Nothing is delivered to an unverified destination. Calls from MCP and API-key sessions require human approval. ${approvalFlow} Returns the delivery method; for a webhook it returns a masked hint of the HMAC signing secret, never the secret itself.`,
    {
      channel_type: z.enum(['email', 'sms', 'webhook']).describe('Delivery method type'),
      destination: z.string().describe('Email address, phone number (+E.164), or webhook URL'),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a human approved it in the dashboard',
      ),
    },
    async ({ channel_type, destination, governance_approval_id }) => {
      const result = await api('POST', '/v1/notifications/destinations', {
        channel_type,
        destination,
      }, governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined) as Record<string, unknown>;
      // The REST response carries a webhook destination's HMAC signing secret
      // once. It never enters the assistant conversation: MCP returns the
      // destination metadata, a masked hint and where to obtain the secret.
      const { webhook_secret: secret, webhook_secret_encrypted: _encrypted, ...metadata } = result;
      const signing = typeof secret === 'string' && secret.length > 0
        ? {
            webhook_secret_returned: false,
            webhook_secret_hint: `…${secret.slice(-4)}`,
            webhook_secret_access: 'The signing secret is not returned through MCP. An owner or admin obtains a new one with POST /v1/notifications/destinations/{id}/rotate-secret through the REST API or SDK; see https://getstack.run/docs/api/notifications.',
          }
        : {};
      return toolJson({ ...metadata, ...signing });
    },
  );

  server.tool(
    'stack_list_delivery_methods',
    "List the account's notification delivery methods (email, SMS, webhook) and their verification status.",
    {},
    async () => {
      const result = await api('GET', '/v1/notifications/destinations');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_delete_delivery_method',
    `Delete a notification delivery method and remove it from the notification rules that reference it. Calls from MCP and API-key sessions require human approval. ${approvalFlow}`,
    {
      destination_id: z.string().describe('Delivery method ID to delete'),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a human approved it in the dashboard',
      ),
    },
    async ({ destination_id, governance_approval_id }) => {
      const result = await api('DELETE', `/v1/notifications/destinations/${encodeURIComponent(destination_id)}`, undefined, governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_send_verification_code',
    `Send a verification code to an unverified delivery method. Calls from MCP and API-key sessions require human approval. ${approvalFlow}`,
    {
      destination_id: z.string().describe('Delivery method ID to verify'),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a human approved it in the dashboard',
      ),
    },
    async ({ destination_id, governance_approval_id }) => {
      const result = await api(
        'POST',
        `/v1/notifications/destinations/${encodeURIComponent(destination_id)}/send-code`,
        undefined,
        governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined,
      );
      return toolJson(result);
    },
  );

  server.tool(
    'stack_verify_delivery_method',
    `Mark a delivery method verified when the supplied 6-digit code matches the code sent to it. Calls from MCP and API-key sessions require human approval. ${approvalFlow}`,
    {
      destination_id: z.string().describe('Delivery method ID'),
      code: z.string().describe('6-digit verification code'),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a human approved it in the dashboard',
      ),
    },
    async ({ destination_id, code, governance_approval_id }) => {
      const result = await api('POST', `/v1/notifications/destinations/${encodeURIComponent(destination_id)}/verify`, {
        code,
      }, governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_test_delivery_method',
    `Send a test notification to a verified delivery method. Calls from MCP and API-key sessions require human approval. ${approvalFlow}`,
    {
      destination_id: z.string().describe('Delivery method ID to test'),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a human approved it in the dashboard',
      ),
    },
    async ({ destination_id, governance_approval_id }) => {
      const result = await api('POST', `/v1/notifications/destinations/${encodeURIComponent(destination_id)}/test`, undefined, governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined);
      return toolJson(result);
    },
  );

  // ─── Notification Rules ───────────────────────────────────────────

  server.tool(
    'stack_create_notification_rule',
    `Create a notification rule: the event types and minimum severity that trigger a notification, and the delivery methods that receive it. One rule can target several delivery methods. Calls from MCP and API-key sessions require human approval. ${approvalFlow}`,
    {
      destination_ids: z.array(z.string()).min(1).describe('Delivery method IDs to notify'),
      events: z
        .array(z.string())
        .min(1)
        .describe('Event types to subscribe to (e.g. passport.flagged, agent.blocked)'),
      min_severity: z
        .enum(['info', 'warning', 'critical'])
        .optional()
        .describe('Minimum severity threshold (default: warning)'),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a human approved it in the dashboard',
      ),
    },
    async ({ destination_ids, events, min_severity, governance_approval_id }) => {
      const result = await api('POST', '/v1/notifications/channels', {
        destination_ids,
        events,
        min_severity,
      }, governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_notification_rules',
    "List the account's notification rules with their delivery methods.",
    {},
    async () => {
      const result = await api('GET', '/v1/notifications/channels');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_update_notification_rule',
    `Replace a notification rule's delivery methods, event types or minimum severity. Calls from MCP and API-key sessions require human approval. ${approvalFlow}`,
    {
      rule_id: z.string().describe('Notification rule ID (nch_...)'),
      destination_ids: z.array(z.string()).min(1).optional().describe('New delivery method IDs'),
      events: z.array(z.string()).min(1).optional().describe('New event types'),
      min_severity: z
        .enum(['info', 'warning', 'critical'])
        .optional()
        .describe('New minimum severity'),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a human approved it in the dashboard',
      ),
    },
    async ({ rule_id, destination_ids, events, min_severity, governance_approval_id }) => {
      const body: Record<string, unknown> = {};
      if (destination_ids) body.destination_ids = destination_ids;
      if (events) body.events = events;
      if (min_severity) body.min_severity = min_severity;
      const result = await api('PATCH', `/v1/notifications/channels/${encodeURIComponent(rule_id)}`, body, governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_delete_notification_rule',
    `Delete a notification rule. Calls from MCP and API-key sessions require human approval. ${approvalFlow}`,
    {
      rule_id: z.string().describe('Notification rule ID to delete'),
      governance_approval_id: z.string().optional().describe(
        'Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, after a human approved it in the dashboard',
      ),
    },
    async ({ rule_id, governance_approval_id }) => {
      const result = await api('DELETE', `/v1/notifications/channels/${encodeURIComponent(rule_id)}`, undefined, governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined);
      return toolJson(result);
    },
  );
}
