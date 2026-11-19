import { z } from 'zod';
import { FleetPolicyInput, FleetMissionStartInput, FleetEnrollmentInput } from '@stack/shared';
import type { ToolContext, ToolRegistrar } from './context.js';
import { missionSpecShape, OperatorStartPassportInput } from './mission-spec.js';
import { toolJson, approvalFlow, controlsFeature } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const FLEETS_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Fleets
  stack_list_fleets: hint.read('List fleet policies'),
  stack_get_fleet: hint.read('Get fleet policy'),
  stack_get_fleet_membership: hint.read('Get agent fleet membership'),
  stack_activate_fleet: hint.write('Activate fleet policy'),
  stack_revise_fleet: hint.destructive('Replace fleet policy'),
  stack_list_fleet_members: hint.read('List fleet members'),
  stack_revoke_fleet_member: hint.destructive('Revoke fleet member'),
  stack_revoke_fleet: hint.destructive('Revoke fleet policy'),
  stack_fleet_enrollment_challenge: hint.write('Create fleet enrollment challenge'),
  stack_enroll_fleet_agent: hint.write('Enroll fleet agent'),
  stack_start_mission: hint.write('Start Mission and issue Passport'),
  stack_renew_mission: hint.write('Renew Mission Passport'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const FLEETS_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_start_mission: 'Returns a Passport bearer token into the conversation.',
  stack_renew_mission: 'Agent-principal only and returns a Passport bearer token. A directory OAuth session is never an agent.',
  stack_fleet_enrollment_challenge: 'Agent-principal only. A directory OAuth session is never an agent.',
  stack_enroll_fleet_agent: 'Agent-principal only. A directory OAuth session is never an agent.',
};

/** Fleet policies, fleet membership and enrollment, and the fleet-agent Mission start and renew calls. */
export function registerFleetsTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  const fleetPage = { page: z.number().int().min(1).max(100000).optional(), limit: z.number().int().min(1).max(100).optional() };
  const pageQuery = ({ page, limit }: { page?: number; limit?: number }) => page === undefined && limit === undefined ? '' : `?page=${page ?? 1}&limit=${limit ?? 20}`;
  server.tool('stack_list_fleets', controlsFeature("List fleet policies and their current limits."), fleetPage, async input => toolJson(await api('GET', `/v1/fleets${pageQuery(input)}`)));
  server.tool('stack_get_fleet', controlsFeature('Read one fleet policy and its shared usage.'), { policy_id: z.string() }, async ({ policy_id }) =>
    toolJson(await api('GET', `/v1/fleets/${encodeURIComponent(policy_id)}`)));
  server.tool('stack_get_fleet_membership', controlsFeature('Read the fleet policy an agent belongs to.'), { agent_id: z.string() }, async ({ agent_id }) =>
    toolJson(await api('GET', `/v1/fleets/membership/${encodeURIComponent(agent_id)}`)));
  server.tool('stack_activate_fleet', controlsFeature(`Create a fleet policy that sets the connections, actions and limits a fleet may use. Activation requires operator approval. ${approvalFlow} A repeated call with the same idempotency key does not create a second policy.`), { policy: FleetPolicyInput, idempotency_key: z.string().min(8).max(128),
    governance_approval_id: z.string().optional() }, async ({ policy, idempotency_key, governance_approval_id }) =>
    toolJson(await api('POST', '/v1/fleets', policy, { 'Idempotency-Key': idempotency_key,
      ...(governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : {}) })));
  server.tool('stack_revise_fleet', controlsFeature(`Replace a fleet policy with a new revision. expected_revision must match the current revision. The change requires operator approval. ${approvalFlow} A repeated call with the same idempotency key applies the change once.`), { policy_id: z.string(), policy: FleetPolicyInput,
    expected_revision: z.number().int().positive(), idempotency_key: z.string().min(8).max(128),
    governance_approval_id: z.string().optional() }, async ({ policy_id, policy, governance_approval_id, expected_revision, idempotency_key }) =>
    toolJson(await api('PUT', `/v1/fleets/${encodeURIComponent(policy_id)}`, policy,
      { 'If-Match': String(expected_revision), 'Idempotency-Key': idempotency_key,
        ...(governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : {}) })));
  server.tool('stack_list_fleet_members', controlsFeature("List the agents enrolled under a fleet policy."), { policy_id: z.string(), ...fleetPage }, async ({ policy_id, ...input }) =>
    toolJson(await api('GET', `/v1/fleets/${encodeURIComponent(policy_id)}/members${pageQuery(input)}`)));
  server.tool('stack_revoke_fleet_member', controlsFeature("Revoke one agent's membership in a fleet."), { policy_id: z.string(), agent_id: z.string() }, async ({ policy_id, agent_id }) =>
    toolJson(await api('POST', `/v1/fleets/${encodeURIComponent(policy_id)}/members/${encodeURIComponent(agent_id)}/revoke`, {})));
  server.tool('stack_revoke_fleet', controlsFeature("Revoke a fleet policy. Its agents lose permission to continue work through STACK."), { policy_id: z.string() }, async ({ policy_id }) =>
    toolJson(await api('POST', `/v1/fleets/${encodeURIComponent(policy_id)}/revoke`, {})));
  server.tool('stack_fleet_enrollment_challenge', controlsFeature("Create an enrollment challenge for a new agent under an approved fleet policy. The new agent signs the challenge with its own private key. Requires a fleet provisioner agent session."), { policy_id: z.string() }, async ({ policy_id }) =>
    toolJson(await api('POST', `/v1/fleets/${encodeURIComponent(policy_id)}/enrollment-challenges`, {})));
  server.tool('stack_enroll_fleet_agent', controlsFeature("Enroll an agent using its public key and signed challenge. The caller must be an approved provisioner for this policy."), { policy_id: z.string(), request: FleetEnrollmentInput }, async ({ policy_id, request }) =>
    toolJson(await api('POST', `/v1/fleets/${encodeURIComponent(policy_id)}/enroll`, request)));
  server.tool('stack_start_mission',
    "Open a Mission and issue its Passport in one call. Two forms. Operator form: pass agent_id (agt_*), mission (intent_summary required, plus optional intent_services, caps, expires_in_seconds and, for a policy rule that leaves recipients to each Mission, recipients, recipient_pins or reply_to_message) and optional passport fields (scopes, ttl_seconds, intent, ...). Returns mission_id, claim_id, expires_at and passport { token, jti, expires_at }; if issuance fails the Mission is revoked. Fleet-agent form: request carries the fleet policy, requested access and limits; STACK checks them against the fleet policy, and a repeated request with the same idempotency key returns the same Mission. Completing or revoking the Mission revokes the Passport.",
    {
      request: FleetMissionStartInput.optional().describe('Fleet-agent form only. Omit for the operator form.'),
      agent_id: z.string().regex(/^agt_[\w-]+$/).optional().describe('Operator form: the agent the Mission and Passport are for (agt_*).'),
      mission: z.object(missionSpecShape).strict().optional().describe('Operator form: the Mission spec. intent_summary is required.'),
      passport: OperatorStartPassportInput.optional().describe('Operator form: optional Passport issue fields. The Passport is bound to the new Mission; do not pass agent_id or mission_ids. intent defaults to the Mission intent_summary and intent_services.'),
    },
    async ({ request, agent_id, mission, passport }) => {
      if (request !== undefined) {
        if (agent_id !== undefined || mission !== undefined || passport !== undefined) {
          throw new Error('Use one form: request (fleet agent) or agent_id + mission (+ passport) (operator).');
        }
        return toolJson(await api('POST', '/v1/missions/start', request));
      }
      if (agent_id === undefined || mission === undefined) {
        throw new Error('Operator form needs agent_id and mission. A fleet agent passes request instead.');
      }
      return toolJson(await api('POST', '/v1/missions/start', { agent_id, mission, ...(passport !== undefined ? { passport } : {}) }));
    });
  server.tool('stack_renew_mission', "Renew a fleet Mission's Passport and return the new Passport. The Mission keeps its original limits and usage. Requires a fleet agent session.", { mission_id: z.string() }, async ({ mission_id }) =>
    toolJson(await api('POST', `/v1/missions/${encodeURIComponent(mission_id)}/renew`, {})));
}
