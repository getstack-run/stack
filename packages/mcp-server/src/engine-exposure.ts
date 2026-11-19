import type { ModuleExposure } from './exposure.js';

// Who the engine's tools are for and which are rarely used (the MCP tool list design).
//
// The engine's tools belong to no account piece: they are the core (passports and
// Missions, connections and the proxy, the record, drop-offs) and the administration
// a person does (fleets, the team, notifications, the control socket, detector and
// PII settings). A module's default is the commonest case; a tool that differs
// says so. `both` is for a tool an agent uses and a person may need too; `owner` for
// a tool that sets or changes what an agent may do; `agent` for a tool that only an
// agent's own session can use. A rarely used tool is `deferred`.

export const ENGINE_EXPOSURE: Readonly<Record<string, ModuleExposure>> = {
  // Fleet policy is administration. Starting a Mission under a fleet policy and renewing it are the fleet
  // agent's own acts, listed to an agent that belongs to a fleet; enrolling is done by the agent's own credential
  // before it is a member, so those two are always listed to an agent.
  fleets: {
    audience: 'owner',
    deferred: true,
    tools: {
      stack_start_mission: { audience: 'both', piece: 'fleet', deferred: false },
      stack_renew_mission: { audience: 'agent', piece: 'fleet', deferred: false },
      stack_fleet_enrollment_challenge: { audience: 'agent' },
      stack_enroll_fleet_agent: { audience: 'agent' },
    },
  },
  agents: { audience: 'owner', deferred: true },
  // Connecting and granting are the person's; reading what is connected is the agent's.
  services: {
    audience: 'owner',
    tools: {
      stack_list_services: { audience: 'both', deferred: true },
      stack_list_connected_services: { audience: 'both' },
      stack_list_intents: { audience: 'both', deferred: true },
      stack_set_connection_proxy: { deferred: true },
      stack_rename_connection: { deferred: true },
      stack_list_service_configurations: { deferred: true },
      stack_save_service_configuration: { deferred: true },
      stack_delete_service_configuration: { deferred: true },
    },
  },
  passports: {
    audience: 'both',
    tools: {
      stack_list_active_passports: { audience: 'owner', deferred: true },
      stack_revoke_agent_passports: { audience: 'owner', deferred: true },
      stack_revoke_session: { audience: 'owner', deferred: true },
      stack_revoke_all_passports: { audience: 'owner', deferred: true },
      stack_delegate_passport: { deferred: true },
    },
  },
  credentials: { audience: 'owner', deferred: true },
  team: { audience: 'owner', deferred: true },
  identity: { audience: 'owner', deferred: true },
  dropoffs: { audience: 'both', deferred: true },
  accountability: {
    audience: 'both',
    tools: {
      stack_checkpoint: { audience: 'agent' },
      stack_checkout: { audience: 'agent' },
      stack_list_pending_reviews: { audience: 'owner', deferred: true },
      stack_decide_review: { audience: 'owner', deferred: true },
    },
  },
  proxy: {
    audience: 'both',
    tools: {
      // A connected service's own tools (RentAHuman's): found when an agent has such a connection, so not in the core list.
      stack_service_tools: { deferred: true },
      stack_service_call_tool: { deferred: true },
      stack_simulate_intent: { deferred: true },
      stack_get_intent_approval: { deferred: true },
      // Deciding what an agent submitted is the owner's; the API refuses an agent context on both.
      stack_list_pending_intents: { audience: 'owner', deferred: true },
      stack_decide_intent: { audience: 'owner', deferred: true },
    },
  },
  authority: { audience: 'both', deferred: true },
  missions: {
    audience: 'both',
    tools: {
      stack_list_mission_operator_reviews: { audience: 'owner', deferred: true },
      stack_download_mission_operator_review: { audience: 'owner', deferred: true },
      stack_review_paused_mission: { audience: 'owner', deferred: true },
      stack_set_mission_making_allowance: { audience: 'owner', deferred: true },
      stack_view_mission_activity: { deferred: true },
      stack_add_mission_recipients: { audience: 'owner', deferred: true },
    },
  },
  // The record: an agent and its owner read and check it; exporting a pack is the owner's.
  'signed-records': {
    audience: 'both',
    tools: { stack_export_signed_record: { audience: 'owner', deferred: true }, stack_download_signed_record: { deferred: true } },
  },
  // A scan of content is the agent's; the events, the detectors and the redaction settings are the owner's.
  security: {
    audience: 'owner',
    deferred: true,
    tools: { stack_scan: { audience: 'both', deferred: false }, stack_scan_usage: { audience: 'both' } },
  },
  'control-socket': { audience: 'owner', deferred: true },
  'control-policies': { audience: 'owner', deferred: true },
  // Installs and their revocations are the owner's; the two public checks are anyone's.
  network: {
    audience: 'owner',
    deferred: true,
    tools: { stack_verify_countersignature: { audience: 'both' }, stack_get_verified_status: { audience: 'both' } },
  },
  audit: { audience: 'owner', deferred: true },
  llm: { audience: 'owner', deferred: true },
  notifications: { audience: 'owner', deferred: true },
  webhooks: { audience: 'owner', deferred: true },
  partners: { audience: 'owner', deferred: true },
  // The API refuses an agent's context on every approval route, so an agent session never lists these.
  approvals: { audience: 'owner' },
};
