import { z } from 'zod';

/** The JSON text result every tool returns. */
export const toolJson = (result: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] });

// Governance step-up wording shared by every tool that can require approval.
export const approvalFlow = 'When human approval is required and the chat client supports MCP elicitation, the person is asked to confirm the exact change in the client; the change is applied only after they approve, and a rejection changes nothing. Otherwise it returns GOVERNANCE_APPROVAL_REQUIRED with approval_id and approval_url, the page for that one approval, and the same payload sent with governance_approval_id after approval applies the change. An approval is single-use, bound to the exact payload, and expires after 24 hours.';

/**
 * A tool whose endpoint is a controls feature (control policies and their reviews, PII redaction settings, detector settings
 * reads, Missions the customer opens and lists, fleets, pending intent checks): with controls off the API answers the same
 * 402 CONTROLS_REQUIRED as the audit record does, and its message says controls are off and where the owner switches them on.
 */
export const controlsFeature = (description: string): string =>
  `${description} A controls feature: with controls off the API answers 402 CONTROLS_REQUIRED, and the owner switches controls on in the Console, at the Billing page. A self-managed install has every controls feature.`;

/**
 * The most text one tool result carries. The hosted transport ends a session whose response passes 4 MB, so a
 * download longer than this is refused with the way to read it in smaller parts, never cut short.
 */
export const TOOL_RESULT_MAX_CHARS = 3 * 1024 * 1024;

export const AuthorityRequestId = z.string()
  .regex(/^[A-Za-z0-9_-]{22,256}$/, 'must be 22-256 base64url characters');

// Provisioning APIs have one-time credential fields. MCP returns an explicit
// metadata projection, including when the API adds new response properties.
export function safeProvisioningMetadata(result: unknown, keys: readonly string[]) {
  const input = result && typeof result === 'object' ? result as Record<string, unknown> : {};
  return Object.fromEntries(keys.flatMap((key) => {
    const value = input[key];
    return value === null || ['string', 'number', 'boolean'].includes(typeof value) ? [[key, value]] : [];
  }));
}
export const webhookMetadataKeys = ['id', 'provider', 'slug', 'webhook_url', 'agent_id', 'forward_url', 'created_at', 'signing_configured'] as const;
