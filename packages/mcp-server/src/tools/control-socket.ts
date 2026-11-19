import { z } from 'zod';
import {
  ControlSocketTarget,
  ListControlDecisionsQuery,
  SetControlCheckedTypesInput,
  SetControlOnUnavailableInput,
  SetControlDecisionAddressInput,
  SetControlEventsAddressInput,
  SetControlModeInput,
} from '@stack/shared';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

// An address change, a signing-secret rotation and anything that loosens the
// controls are governance step-ups decided only on the approval page in a
// signed-in browser. The chat never approves them, so the shared approvalFlow
// sentence (which describes chat confirmation) does not apply here.
const browserApproval = 'This needs the person to approve it in their browser, never in the chat: the call fails with GOVERNANCE_APPROVAL_REQUIRED, approval_id and approval_url, the page where they approve that one change, and the same call sent with governance_approval_id after approval applies it. An approval is single-use, bound to the exact request, and expires after 24 hours.';

const governanceApproval = z.string().optional().describe('Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, once the person approved it in their browser');
const approvalHeader = (approvalId: string | undefined) => (approvalId ? { 'X-Governance-Approval': approvalId } : undefined);
const target = ControlSocketTarget.describe('decision: the address that allows or refuses each checked action. events: the address that receives the record of what happened.');

// A signing secret never reaches the model. The API returns it only to a
// dashboard session or an API key; to this OAuth caller it answers `secret: null`
// and `secret_reveal`, a Console link where the person reads it once. Whatever a
// tool returns goes into the conversation, so any `secret` that comes back anyway
// is dropped here and never repeated.
const REVEAL_NOTE = 'A signing secret was created and is not returned here: it is never shown in a chat. Give the person the link in secret_reveal.url; they open it signed in to the Console and read the secret there once. Do not ask for it, and do not write it anywhere.';

function dropSecret(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(dropSecret);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([key]) => key !== 'secret')
      .map(([key, inner]) => [key, dropSecret(inner)]),
  );
}

function withoutSecret(result: unknown): unknown {
  if (!result || typeof result !== 'object') return result;
  const reveal = (result as { secret_reveal?: unknown }).secret_reveal;
  const stripped = dropSecret(result) as Record<string, unknown>;
  return reveal && typeof reveal === 'object' ? { secret_note: REVEAL_NOTE, ...stripped } : stripped;
}

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const CONTROL_SOCKET_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Control socket: where the account's agents' actions are decided and their
  // record goes. Set, verify and test send a signed request to the customer's
  // own server, so they are open-world; replacing or clearing configuration
  // loses the prior value.
  stack_get_control_socket: hint.read('Get control socket'),
  stack_set_control_decision_address: hint.destructive('Set control decision address', true),
  stack_set_control_events_address: hint.destructive('Set control events address', true),
  stack_clear_control_address: hint.destructive('Clear control address'),
  stack_verify_control_address: hint.write('Verify control address', true),
  stack_test_control_address: hint.write('Test control address', true),
  stack_rotate_control_secret: hint.destructive('Rotate control signing secret'),
  stack_set_control_mode: hint.destructive('Set control mode'),
  stack_set_control_checked_types: hint.destructive('Set checked action kinds'),
  stack_set_control_on_unavailable: hint.destructive('Set what happens when the decision server does not answer'),
  stack_list_control_decisions: hint.read('List control decisions'),
  stack_get_control_decision: hint.read('Get control decision'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const CONTROL_SOCKET_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_get_control_socket: "Needs accounts:manage, withheld from directory tokens: it shows where the account's agents' actions are decided and their record is sent.",
  stack_set_control_decision_address: "Needs accounts:manage, withheld from directory tokens: it moves where the account's agents' actions are decided.",
  stack_set_control_events_address: "Needs accounts:manage, withheld from directory tokens: it moves where the account's agents' record is sent.",
  stack_clear_control_address: "Needs accounts:manage, withheld from directory tokens: it removes a decision or events address and can loosen the controls.",
  stack_verify_control_address: "Needs accounts:manage, withheld from directory tokens: it puts a decision or events address into use.",
  stack_test_control_address: "Needs accounts:manage, withheld from directory tokens: it sends a signed test request to the customer's own server.",
  stack_rotate_control_secret: "Needs accounts:manage, withheld from directory tokens: it replaces the signing secret the customer's own server verifies with, and mints a link to read the new one in the Console.",
  stack_set_control_mode: "Needs accounts:manage, withheld from directory tokens: it can turn the account's controls off.",
  stack_set_control_checked_types: "Needs accounts:manage, withheld from directory tokens: it can leave action kinds unchecked.",
  stack_set_control_on_unavailable: "Needs accounts:manage, withheld from directory tokens: it can let actions through when the customer's own decision server does not answer.",
  stack_list_control_decisions: "Needs accounts:manage, withheld from directory tokens: decisions carry the targets of agent actions.",
  stack_get_control_decision: "Needs accounts:manage, withheld from directory tokens: a decision carries the target of an agent action.",
};

/**
 * The control socket: where the customer's agents' actions are decided and
 * where their record goes, and the decisions made. Operator only; an agent
 * context is refused, so an agent cannot change its own controls.
 */
export function registerControlSocketTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;

  server.tool(
    'stack_get_control_socket',
    "Get the control socket: who decides for the account's agents now (effective_mode none, hosted or remote), the mode setting, whether STACK's hosted controls are on, the decision and events addresses with their status, verified_at and whether a signing secret is set (never the secret), the events backlog, and the action kinds checked. Operator only.",
    {},
    async () => toolJson(await api('GET', '/v1/control-socket')),
  );

  server.tool(
    'stack_set_control_decision_address',
    `Set or change the address that decides the account's agents' checked actions: STACK posts each one, signed, to this address and the answer allows or refuses it. The address is not used until stack_verify_control_address passes. timeout_ms is how long STACK waits for an answer. The first set creates the signing secret. It is never returned in the chat: secret_reveal.url is a single-use Console link, good for an hour, where the person reads it once, signed in. Later calls create no secret and return secret_reveal null. Operator only. ${browserApproval} Returns the socket and secret_reveal.`,
    {
      ...SetControlDecisionAddressInput.shape,
      governance_approval_id: governanceApproval,
    },
    async ({ governance_approval_id, ...input }) =>
      toolJson(withoutSecret(await api('PUT', '/v1/control-socket/decision', input, approvalHeader(governance_approval_id)))),
  );

  server.tool(
    'stack_set_control_events_address',
    `Set or change the address that receives the account's agents' record: every action and its outcome, minimised and signed, in batches. The address is not used until stack_verify_control_address passes. The first set creates the signing secret. It is never returned in the chat: secret_reveal.url is a single-use Console link, good for an hour, where the person reads it once, signed in. Later calls create no secret and return secret_reveal null. Operator only. ${browserApproval} Returns the socket and secret_reveal.`,
    {
      ...SetControlEventsAddressInput.shape,
      governance_approval_id: governanceApproval,
    },
    async ({ governance_approval_id, ...input }) =>
      toolJson(withoutSecret(await api('PUT', '/v1/control-socket/events', input, approvalHeader(governance_approval_id)))),
  );

  server.tool(
    'stack_clear_control_address',
    `Remove the decision or the events address. Clearing the decision address while it is enforcing returns the account to STACK's hosted controls or none, which loosens the controls. Operator only. ${browserApproval} Returns the socket.`,
    {
      target,
      governance_approval_id: governanceApproval,
    },
    async ({ target: which, governance_approval_id }) =>
      toolJson(await api('DELETE', `/v1/control-socket/${encodeURIComponent(which)}`, undefined, approvalHeader(governance_approval_id))),
  );

  server.tool(
    'stack_verify_control_address',
    `Run the setup check on the decision or events address and, when it passes, put the address into use. A decision address must answer allow to a signed test request; an events address must accept a signed test batch. Switching from STACK's hosted controls to your own decision address loosens the controls. Operator only. ${browserApproval} Returns target, ok, latency_ms, verdict (decision only), cause when it failed, and activated.`,
    {
      target,
      governance_approval_id: governanceApproval,
    },
    async ({ target: which, governance_approval_id }) =>
      toolJson(await api('POST', `/v1/control-socket/${encodeURIComponent(which)}/verify`, undefined, approvalHeader(governance_approval_id))),
  );

  server.tool(
    'stack_test_control_address',
    "Send one signed test exchange to the decision or events address and report the result. Nothing changes: the address is not put into use and no action is checked. Operator only. Returns target, ok, latency_ms, verdict (decision only), cause when it failed, and activated false.",
    { target },
    async ({ target: which }) =>
      toolJson(await api('POST', `/v1/control-socket/${encodeURIComponent(which)}/test`)),
  );

  server.tool(
    'stack_rotate_control_secret',
    `Create a new signing secret for the decision or events address. The new secret is never returned in the chat: secret_reveal.url is a single-use Console link, good for an hour, where the person reads it once, signed in. The old one keeps verifying until previous_valid_until, 24 hours later. Operator only. ${browserApproval} Returns target, secret_reveal and previous_valid_until.`,
    {
      target,
      governance_approval_id: governanceApproval,
    },
    async ({ target: which, governance_approval_id }) =>
      toolJson(withoutSecret(await api('POST', `/v1/control-socket/${encodeURIComponent(which)}/secret/rotate`, undefined, approvalHeader(governance_approval_id)))),
  );

  server.tool(
    'stack_set_control_mode',
    `Choose who decides the account's agents' actions: hosted, STACK's hosted controls (needs controls on, else CONTROLS_NOT_ENABLED), or none, no check at all. Your own decision address is switched on by stack_verify_control_address. Choosing none always needs approval, also while controls are off (the choice outlives that state); so does leaving your own server for hosted. Switching from none to hosted applies at once. Operator only. ${browserApproval} Returns the socket.`,
    {
      ...SetControlModeInput.shape,
      governance_approval_id: governanceApproval,
    },
    async ({ governance_approval_id, ...input }) =>
      toolJson(await api('PUT', '/v1/control-socket/mode', input, approvalHeader(governance_approval_id))),
  );

  server.tool(
    'stack_set_control_on_unavailable',
    `Set what happens when your own decision server does not answer in time: refuse (default: the action is refused, 403 CONTROL_SOCKET_UNAVAILABLE) or allow (the action goes through, and the decision records why). Only an answer that never came follows it (no answer in time, unreachable, a non-200 answer, a busy server or an open breaker); a forged or garbled answer, a blocked address and a server that is not verified or paused are refused whatever it says. allow loosens a control and needs approval; refuse applies at once. Operator only. ${browserApproval} Returns the socket.`,
    {
      on_unavailable: SetControlOnUnavailableInput.shape.on_unavailable.describe('refuse or allow'),
      governance_approval_id: governanceApproval,
    },
    async ({ governance_approval_id, ...input }) =>
      toolJson(await api('PUT', '/v1/control-socket/on-unavailable', input, approvalHeader(governance_approval_id))),
  );

  server.tool(
    'stack_set_control_checked_types',
    `Set which action kinds are checked. types lists the kinds; null checks every kind, including kinds added later. Adding kinds applies at once; removing a kind that is checked now lets those actions through unchecked and needs approval. Operator only. ${browserApproval} Returns the socket.`,
    {
      types: SetControlCheckedTypesInput.shape.types.describe('Action kinds to check, e.g. email.send, card.checkout; null checks every kind'),
      governance_approval_id: governanceApproval,
    },
    async ({ governance_approval_id, ...input }) =>
      toolJson(await api('PUT', '/v1/control-socket/checked-types', input, approvalHeader(governance_approval_id))),
  );

  server.tool(
    'stack_list_control_decisions',
    "List the decisions made on the account's agents' actions, newest first: id, account_id, agent_id, action_type, decider (hosted or remote), verdict (allow, deny or unavailable), reason_code, cause, latency_ms, charged, request_digest, request (kept for a refusal or an unreachable server, within its retention), evidence (which rule of a hosted policy refused: policy, revision, section, rule and code, never a value from the call) and created_at. Page by passing the last created_at as before. Operator only.",
    {
      limit: z.number().int().min(1).max(200).optional().describe('Maximum decisions to return (1-200, default 50)'),
      account_id: ListControlDecisionsQuery.shape.account_id.describe('Only decisions on this agent account (acct_*)'),
      verdict: ListControlDecisionsQuery.shape.verdict.describe('Only this verdict: allow, deny or unavailable'),
      before: ListControlDecisionsQuery.shape.before.describe('Only decisions created before this ISO timestamp'),
    },
    async ({ limit, account_id, verdict, before }) => {
      const params = new URLSearchParams();
      if (limit !== undefined) params.set('limit', String(limit));
      if (account_id) params.set('account_id', account_id);
      if (verdict) params.set('verdict', verdict);
      if (before) params.set('before', before);
      const query = params.toString();
      return toolJson(await api('GET', `/v1/control-decisions${query ? `?${query}` : ''}`));
    },
  );

  server.tool(
    'stack_get_control_decision',
    'Get one decision by id (dec_*): the same fields as the list, with the request as sent when it was kept. Operator only.',
    { decision_id: z.string().describe('Decision id (dec_*) from the list') },
    async ({ decision_id }) =>
      toolJson(await api('GET', `/v1/control-decisions/${encodeURIComponent(decision_id)}`)),
  );
}
