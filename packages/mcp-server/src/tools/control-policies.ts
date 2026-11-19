import { z } from 'zod';
import {
  DeleteControlPolicyQuery,
  PolicyAgentParams,
  PolicyDefinition,
  SetControlPolicyInput,
  SimulateControlPolicyInput,
} from '@stack/shared';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson, controlsFeature } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

// A loosening and a deletion are governance step-ups decided only on the
// approval page in a signed-in browser. The chat never approves them, so the
// shared approvalFlow sentence (which describes chat confirmation) does not
// apply here.
const browserApproval = 'Tightening applies at once. Loosening a policy, and deleting one, needs the person to approve it in their browser, never in the chat: the call fails with GOVERNANCE_APPROVAL_REQUIRED, approval_id and approval_url, the page where they approve that one change, and the same call sent with governance_approval_id after approval applies it. The tool never waits or loops for the approval. An approval is single-use, bound to the exact request, and expires after 24 hours.';

const narrowsOnly = 'A policy only narrows what a connection grant already allows: it refuses, holds an action for a person, or limits it, and never opens anything.';

const governanceApproval = z.string().optional().describe('Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, once the person approved it in their browser');
const approvalHeader = (approvalId: string | undefined) => (approvalId ? { 'X-Governance-Approval': approvalId } : undefined);
const agentId = PolicyAgentParams.shape.agentId;
const policyId = z.string().regex(/^cpl_[\w-]+$/).describe('The policy id (cpl_*), from stack_list_control_policies or stack_get_control_policy');
const reviewId = z.string().regex(/^crv_[\w-]+$/).describe('The held action id (crv_*), from stack_list_control_reviews');
const optionalAgent = agentId.optional().describe('The agent (agt_*) whose own policy this is. Omit for the default policy, which applies to every agent account without a policy of its own.');
const expectedRevision = SetControlPolicyInput.shape.expected_revision.describe('The revision you read. Required to revise a policy; leave out to create one. A stale revision fails with a conflict.');

// What a refusal's rule evidence carries, stated once in the tools that show it.
const refusalEvidence = 'A refusal names the rule that stopped the action and nothing from the call: policy_id, policy_revision, section, rule, code and, for some rules, a detail holding the policy\'s own side of the comparison (a limit, the size of an allowed list), never a value the call carried.';

// The simulate input is a schema with a refinement, so its fields come from the
// object under it.
const simulateFields = SimulateControlPolicyInput.innerType().shape;

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const CONTROL_POLICIES_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Policies: the configuration behind hosted controls, kept by STACK. They
  // only narrow what a grant allows. Nothing here reaches outside the account.
  stack_list_control_policies: hint.read('List control policies'),
  stack_get_control_policy: hint.read('Get control policy'),
  stack_set_control_policy: hint.destructive('Set control policy'),
  stack_delete_control_policy: hint.destructive('Delete control policy'),
  stack_policy_start_from_current_access: hint.write('Start control policy from current access'),
  stack_list_control_policy_revisions: hint.read('List control policy revisions'),
  stack_simulate_control_policy: hint.read('Simulate control policy'),
  stack_list_control_reviews: hint.read('List held actions'),
  stack_get_control_review: hint.read('Get held action'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const CONTROL_POLICIES_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  // Policies state what the account's agents may do, and the held actions
  // carry what they tried. Their scope (accounts:manage) is withheld from
  // directory tokens.
  stack_list_control_policies: "Needs accounts:manage, withheld from directory tokens: policies state what the account's agents may and may not do.",
  stack_get_control_policy: "Needs accounts:manage, withheld from directory tokens: a policy states what an agent may and may not do.",
  stack_set_control_policy: "Needs accounts:manage, withheld from directory tokens: it changes what the account's agents may do, and a loosening needs a person's approval.",
  stack_delete_control_policy: "Needs accounts:manage, withheld from directory tokens: it removes a policy, which loosens the controls.",
  stack_policy_start_from_current_access: "Needs accounts:manage, withheld from directory tokens: it creates a policy for an agent.",
  stack_simulate_control_policy: "Needs accounts:manage, withheld from directory tokens: it shows how a policy would treat a call, and so what the policy contains.",
  stack_list_control_policy_revisions: "Needs accounts:manage, withheld from directory tokens: every revision carries the whole policy as it was, so it states what the account's agents may and may not do.",
  stack_list_control_reviews: "Needs accounts:manage, withheld from directory tokens: held actions carry what an agent tried to do and the page where a person decides.",
  stack_get_control_review: "Needs accounts:manage, withheld from directory tokens: a held action carries what an agent tried to do and the page where a person decides.",
};

/**
 * Policies: the configuration behind hosted controls, and the actions they hold
 * for a person. Operator only; an agent context is refused, so an agent cannot
 * read or change its own controls.
 */
export function registerControlPolicyTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;

  server.tool(
    'stack_list_control_policies',
    controlsFeature(`List every policy of the account and whether STACK's hosted controls are on (controls_enabled). Each policy has id, agent_id (null for the default), name, revision, definition, last_change, findings (sends it allows without naming who receives them) and timestamps. ${narrowsOnly} A policy is stored by STACK per agent, plus one default for the account, and is never put into a Passport. Operator only.`),
    {},
    async () => toolJson(await api('GET', '/v1/control-policies')),
  );

  server.tool(
    'stack_get_control_policy',
    controlsFeature(`Get one policy. With agent_id: that agent's own policy (null when it has none) and in_force, the policy that applies to it now (its own, else the default) with its id, revision and source, plus controls_enabled. Without agent_id: the default policy, or a not-found error when there is none. Operator only.`),
    { agent_id: optionalAgent },
    async ({ agent_id }) =>
      toolJson(
        agent_id
          ? await api('GET', `/v1/control-policies/agents/${encodeURIComponent(agent_id)}`)
          : await api('GET', '/v1/control-policies/default'),
      ),
  );

  server.tool(
    'stack_set_control_policy',
    `Create or revise a policy, for one agent or, without agent_id, the account's default. definition holds connections (which connections a call may use, with allow, review or deny rules), actions (a stance per action kind), recipients (allowed email addresses, texts and calls: each a list, or "per_mission"), spend (a ceiling per action, counters per day, month or Mission, and concurrency), review (hold above an amount) and surfaces (models, browser, card, wallet, workspace and tools). A section left out places no limit. ${narrowsOnly} Controls must be on, else CONTROLS_NOT_ENABLED. A rule that allows a send without naming who receives it fails with UNBOUNDED_SEND_RULE: bind the recipient fields in the rule, or set the rule's recipients to "per_mission" so each Mission names them. Recipients set per job: a connection rule with effect allow set to "per_mission" allows a send only in a Mission that names the recipients exactly (recipients, recipient_pins or reply_to_message when the Mission opens), and only to them. A Mission that does not name them is refused with recipients_not_pinned; a send to someone it did not name is refused with recipient_not_allowed. A delegated Passport carries the same Mission, so these rules apply to it too. The account's own recipients.email, recipients.sms and recipients.call may also be "per_mission": a send, text or call then names the stored message it answers (reply_to_message) and goes only to whoever wrote that message (a reply with reply_all also reaches the original's own To and Cc). One that names no message is refused with recipients_not_pinned, a recipient other than the sender with recipient_not_allowed, and an id that is not one of the account's received messages with NOT_FOUND. Changing a list to "per_mission", or back, is a loosening; setting "per_mission" where there was no rule is a tightening. Operator only. ${browserApproval} Returns change (create, tighten, loosen or unchanged) and the policy.`,
    {
      agent_id: optionalAgent,
      definition: PolicyDefinition,
      expected_revision: expectedRevision,
      governance_approval_id: governanceApproval,
    },
    async ({ agent_id, definition, expected_revision, governance_approval_id }) => {
      const body = { definition, ...(expected_revision !== undefined ? { expected_revision } : {}) };
      const headers = approvalHeader(governance_approval_id);
      return toolJson(
        agent_id
          ? await api('PUT', `/v1/control-policies/agents/${encodeURIComponent(agent_id)}`, body, headers)
          : await api('PUT', '/v1/control-policies/default', body, headers),
      );
    },
  );

  server.tool(
    'stack_delete_control_policy',
    `Delete a policy, for one agent or, without agent_id, the account's default. The agent then falls back to the default policy, or to no policy, which loosens the controls. Operator only. ${browserApproval} Returns change delete and policy null.`,
    {
      agent_id: optionalAgent,
      expected_revision: DeleteControlPolicyQuery.shape.expected_revision.describe('The revision you read; a stale revision fails with a conflict'),
      governance_approval_id: governanceApproval,
    },
    async ({ agent_id, expected_revision, governance_approval_id }) => {
      const query = expected_revision === undefined ? '' : `?expected_revision=${expected_revision}`;
      const headers = approvalHeader(governance_approval_id);
      return toolJson(
        agent_id
          ? await api('DELETE', `/v1/control-policies/agents/${encodeURIComponent(agent_id)}${query}`, undefined, headers)
          : await api('DELETE', `/v1/control-policies/default${query}`, undefined, headers),
      );
    },
  );

  server.tool(
    'stack_policy_start_from_current_access',
    `Create a policy for an agent that equals what its connection grants allow today, as the place to start narrowing. It changes no outcome until it is tightened. It fails with a conflict when the agent already has a policy, and with CONTROLS_NOT_ENABLED when controls are off. Starting one that allows more than the default policy now in force counts as a loosening. Operator only. ${browserApproval} Returns change and the policy.`,
    {
      agent_id: agentId.describe('The agent (agt_*) to start a policy for'),
      governance_approval_id: governanceApproval,
    },
    async ({ agent_id, governance_approval_id }) =>
      toolJson(await api('POST', `/v1/control-policies/agents/${encodeURIComponent(agent_id)}/start-from-current-access`, undefined, approvalHeader(governance_approval_id))),
  );

  server.tool(
    'stack_simulate_control_policy',
    controlsFeature(`Try one call against a policy to see the result before an agent makes it. Name agent_id to try the policy in force for that agent, or give a definition to try a draft instead. Nothing is counted, held or sent, and no money moves. ${refusalEvidence} Returns verdict (allow, review or deny), policy (id, revision and source: agent, default or draft), refusal, message, limits (each counter that applies with what is used and remaining), controls_enabled and checked (whether this action kind is checked). Operator only.`),
    {
      agent_id: simulateFields.agent_id.describe('The agent (agt_*) whose policy applies. Ignored when definition is given.'),
      definition: simulateFields.definition.describe('A draft policy to try instead of the stored one'),
      call: simulateFields.call.describe('The call to try: action (an action kind such as email.send or proxy.call), target as a decision request carries it, amount_cents, connection_id, and for proxy.call the request itself (method, url, body, query). mission_id (ms_*) tries the call inside that Mission, so the recipients it names count for a rule whose recipients are set per job. reply_to_message (amsg_*, or an incoming call) tries a send of the account itself (email.send, sms.send or call.start) as answering that stored message, as a live send does; it needs agent_id'),
    },
    async ({ agent_id, definition, call }) =>
      toolJson(await api('POST', '/v1/control-policies/simulate', {
        ...(agent_id ? { agent_id } : {}),
        ...(definition ? { definition } : {}),
        call,
      })),
  );

  server.tool(
    'stack_list_control_reviews',
    controlsFeature(`List the actions a policy held for a person, newest first: id, account_id, agent_id, policy_id, policy_revision, action_type, summary, status (pending, approved, consuming, consumed, rejected or expired), approval_id, approval_url and expires_at. A held action is decided by the person on its approval page; there is no tool to approve or reject it, and an approval never comes from the chat. After approval the agent has one hour to send the same action again with the ref it was given. Operator only.`),
    {
      status: z.enum(['pending', 'all']).optional().describe('pending (default) or all'),
      limit: z.number().int().min(1).max(200).optional().describe('Maximum reviews to return (1-200, default 50)'),
    },
    async ({ status, limit }) => {
      const params = new URLSearchParams();
      if (status) params.set('status', status);
      if (limit !== undefined) params.set('limit', String(limit));
      const query = params.size > 0 ? `?${params.toString()}` : '';
      return toolJson(await api('GET', `/v1/control-reviews${query}`));
    },
  );

  server.tool(
    'stack_get_control_review',
    controlsFeature(`Get one action a policy held for a person: id, account_id, agent_id, policy_id, policy_revision, action_type, summary, status (pending, approved, consuming, consumed, rejected or expired), approval_id, approval_url and expires_at. A held action is decided by the person on its approval page; there is no tool to approve or reject it, and an approval never comes from the chat. Not found when the id is not a held action of the account. Operator only.`),
    { review_id: reviewId },
    async ({ review_id }) => toolJson(await api('GET', `/v1/control-reviews/${encodeURIComponent(review_id)}`)),
  );

  server.tool(
    'stack_list_control_policy_revisions',
    controlsFeature(`List the revisions of one policy, newest first: revision, change (create, start_from_access, tighten, loosen, delete or unchanged), actor, approval_id (the governance approval that let a loosening through, else null), the definition as it was and created_at. Not found when the id is not a policy of the account. Operator only.`),
    { policy_id: policyId },
    async ({ policy_id }) => toolJson(await api('GET', `/v1/control-policies/${encodeURIComponent(policy_id)}/revisions`)),
  );
}
