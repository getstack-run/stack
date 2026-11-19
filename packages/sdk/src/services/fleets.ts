import type { HttpClient } from '../client.js';
import type { IssuedPassport } from '../types.js';
import { prepareFleetEnrollmentKey } from '../agent-auth.js';

export interface FleetAccess {
  connection_id: string;
  scopes: string[];
  intents?: Array<{ name: string; params?: Record<string, unknown> }>;
  constraints?: unknown[];
  allow_data_from?: string[];
}
export interface FleetOperationAccess {
  producer: 'skill' | 'a2a' | 'dropoff';
  target_id: string;
  action: 'invoke' | 'tasks/send' | 'create' | 'deposit' | 'collect';
  constraints?: unknown[];
}
export interface FleetLimits {
  max_actions: number;
  max_concurrent_actions: number;
  max_duration_seconds: number;
  max_dropoff_bytes?: number;
  max_spend_cents?: number;
}
export interface FleetPolicyInput {
  name: string;
  rules?: Array<{ id: string; effect: 'allow' | 'review' | 'deny'; access: FleetAccess }>;
  operation_rules?: Array<{ id: string; effect: 'allow' | 'review' | 'deny'; access: FleetOperationAccess }>;
  limits: FleetLimits;
  window_seconds: number;
  max_members: number;
  max_enrollments_per_hour: number;
  identity_lease_seconds: number;
  provisioner_agent_ids?: string[];
  workload_trust?: Array<{ kind: 'spiffe' | 'wimse'; issuer: string; audience: string; subjects: string[] }>;
  allow_delegation?: boolean;
  expires_at: string;
}
export interface FleetPolicyRecord {
  id: string;
  operator_id: string;
  revision: number;
  status: string;
  definition: FleetPolicyInput;
  revoked_at: string | null;
  created_at: string;
}
export interface FleetEnrollmentInput {
  idempotency_key: string;
  name: string;
  public_key: { kty: 'OKP'; crv: 'Ed25519'; x: string };
  challenge_id: string;
  proof: string;
  previous_key_proof?: string;
}
export interface FleetPage<T> { items: T[]; page: number; limit: number; total: number; has_more: boolean }
export interface FleetMember { id: string; agent_id: string; agent_name: string; identity_expires_at: string; revoked_at: string | null }
export interface FleetMembershipSummary { policy_id: string; policy_name: string; revision: number; membership_id: string; identity_expires_at: string; revoked_at: string | null; policy_status: string; policy_expires_at: string }
export interface FleetPolicySummary {
  policy: FleetPolicyRecord;
  usage: { actions: number; concurrent_actions: number; reserved_spend_cents: number; dropoff_bytes: number; unknown_actions: number };
  window_started_at: string;
  window_seconds: number;
}
export interface FleetEnrollmentResult {
  agent_id: string;
  membership_id: string;
  identity_expires_at: string;
}
export interface FleetMissionStartInput {
  fleet_policy_id: string;
  idempotency_key: string;
  intent_summary: string;
  requested_access?: FleetAccess[];
  requested_operations?: FleetOperationAccess[];
  limits: FleetLimits;
  expected_output_shape?: Record<string, unknown>;
  authority_binding_ids?: string[];
}
export interface FleetMissionResult {
  mission_id: string;
  policy_id: string;
  policy_revision: number;
  passport: IssuedPassport;
}

export class FleetsService {
  constructor(private client: HttpClient) {}

  async workloadEnrollmentChallenge(policyId: string): Promise<{ challenge_id: string; challenge: string; expires_in: number }> {
    return this.client.post(`/v1/fleets/${encodeURIComponent(policyId)}/workload/enrollment-challenges`, {});
  }

  async enrollWorkload(policyId: string, input: FleetEnrollmentInput): Promise<FleetEnrollmentResult> {
    return this.client.post(`/v1/fleets/${encodeURIComponent(policyId)}/workload/enroll`, input);
  }

  async enrollWorkloadLocal(policyId: string, input: { name: string; idempotency_key: string }): Promise<FleetEnrollmentResult> {
    const key = await prepareFleetEnrollmentKey(policyId, input.idempotency_key);
    const challenge = await this.workloadEnrollmentChallenge(policyId);
    const result = await this.enrollWorkload(policyId, { ...input, public_key: key.publicKey,
      challenge_id: challenge.challenge_id, proof: key.sign(challenge.challenge) });
    await key.persist(result.agent_id);
    return result;
  }

  async session(fleetPolicyId?: string): Promise<{ access_token: string; token_type: 'Bearer'; expires_in: number; expires_at: string }> {
    return this.client.post('/v1/fleets/session', fleetPolicyId ? { fleet_policy_id: fleetPolicyId } : {});
  }

  async list(): Promise<FleetPolicyRecord[]> {
    return this.client.get('/v1/fleets');
  }

  async listPage(page = 1, limit = 20): Promise<FleetPage<FleetPolicyRecord>> {
    return this.client.get('/v1/fleets', { page: String(page), limit: String(limit) });
  }

  async get(policyId: string): Promise<FleetPolicySummary> {
    return this.client.get(`/v1/fleets/${encodeURIComponent(policyId)}`);
  }

  async membership(agentId: string): Promise<FleetMembershipSummary | null> {
    return this.client.get(`/v1/fleets/membership/${encodeURIComponent(agentId)}`);
  }

  async membersPage(policyId: string, page = 1, limit = 20): Promise<FleetPage<FleetMember>> {
    return this.client.get(`/v1/fleets/${encodeURIComponent(policyId)}/members`, { page: String(page), limit: String(limit) });
  }

  async activate(input: FleetPolicyInput, options: { idempotencyKey: string; governanceApprovalId?: string }): Promise<{ id: string; revision: number }> {
    return this.client.post('/v1/fleets', input, { headers: {
      'Idempotency-Key': options.idempotencyKey,
      ...(options.governanceApprovalId ? { 'X-Governance-Approval': options.governanceApprovalId } : {}),
    } });
  }

  async revise(policyId: string, input: FleetPolicyInput, options: { expectedRevision: number; idempotencyKey: string; governanceApprovalId?: string }): Promise<{ id: string; revision: number }> {
    return this.client.put(`/v1/fleets/${encodeURIComponent(policyId)}`, input,
      { headers: { 'If-Match': String(options.expectedRevision), 'Idempotency-Key': options.idempotencyKey,
        ...(options.governanceApprovalId ? { 'X-Governance-Approval': options.governanceApprovalId } : {}) } });
  }

  async members(policyId: string): Promise<FleetMember[]> {
    return this.client.get(`/v1/fleets/${encodeURIComponent(policyId)}/members`);
  }

  async revokeMember(policyId: string, agentId: string): Promise<{ success: boolean }> {
    return this.client.post(`/v1/fleets/${encodeURIComponent(policyId)}/members/${encodeURIComponent(agentId)}/revoke`, {});
  }

  async revoke(policyId: string): Promise<{ success: boolean }> {
    return this.client.post(`/v1/fleets/${encodeURIComponent(policyId)}/revoke`, {});
  }

  async enrollmentChallenge(policyId: string): Promise<{ challenge_id: string; challenge: string; expires_in: number }> {
    return this.client.post(`/v1/fleets/${encodeURIComponent(policyId)}/enrollment-challenges`, {});
  }

  async enroll(policyId: string, input: FleetEnrollmentInput): Promise<FleetEnrollmentResult> {
    return this.client.post(`/v1/fleets/${encodeURIComponent(policyId)}/enroll`, input);
  }

  async enrollLocal(policyId: string, input: { name: string; idempotency_key: string }): Promise<FleetEnrollmentResult> {
    const key = await prepareFleetEnrollmentKey(policyId, input.idempotency_key);
    const challenge = await this.enrollmentChallenge(policyId);
    const result = await this.enroll(policyId, { ...input, public_key: key.publicKey,
      challenge_id: challenge.challenge_id, proof: key.sign(challenge.challenge) });
    await key.persist(result.agent_id);
    return result;
  }
}
