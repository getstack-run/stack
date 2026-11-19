import { createHash, randomBytes } from 'node:crypto';
import { eq, getTableName, is, or, sql } from 'drizzle-orm';
import { PgTable } from 'drizzle-orm/pg-core';
import * as shared from '@stack/shared';
import {
  type Database,
  type AuditEntryHashInput,
  adminActions,
  agentServiceGrants,
  agents,
  auditArchiveSegments,
  auditLog,
  authorityApprovalDecisions,
  authorityApprovalRequests,
  authorityBindingProofs,
  authorityBindings,
  authorityIdempotencyKeys,
  authorityPresentations,
  authorityPrincipals,
  authorityProfileVersions,
  authorityProofDependencies,
  authorityProofs,
  authorityReceiverKeys,
  authorityReceivers,
  authorityUses,
  cmekMigrations,
  computeAuditEntryHash,
  connectLinks,
  controlDecisions,
  controlEventOutbox,
  controlPolicies,
  controlPolicyRevisions,
  controlReviews,
  controlSockets,
  dropoffRecipients,
  dropoffs,
  externalAnchors,
  fleetMemberships,
  fleetMissionStarts,
  fleetMissions,
  fleetOperations,
  fleetPolicies,
  fleetPolicyRevisions,
  governanceApprovals,
  identityClaims,
  identityProviders,
  identityVerificationSessions,
  inboundWebhookReceipts,
  inboundWebhooks,
  intentApprovals,
  llmUsage,
  magicLinkTokens,
  missions,
  notificationChannelVerifications,
  notificationChannels,
  notificationDestinations,
  oauthAuthorizationCodes,
  oauthClients,
  oauthDeviceCodes,
  oauthRefreshTokens,
  oidcIdpConfigs,
  operatorDecisionSources,
  operatorDecisions,
  operatorDetectorConfig,
  operatorEmailChanges,
  operatorEmailDeliveryJobs,
  operatorErasureJobs,
  operatorOauthApps,
  operatorPiiConfig,
  operatorSigningKeys,
  operators,
  partnerGrants,
  passportAuthorityBindings,
  passportCheckouts,
  passportCheckpoints,
  passportClaims,
  passportReviews,
  passports,
  receiverTransactionReceipts,
  securityEvents,
  serviceConfigurations,
  serviceConnections,
  serviceIdentityRequirements,
  services,
  spiffeTrustDomains,
  ssoVerifiedDomains,
  teamMembers,
  twinRuns,
  usageDaily,
  usageDailyByAction,
  usageMonthlyAllowances,
  wimseIssuers,
} from '@stack/shared';
import type { OperatorRepository } from './operator-repo.js';

/**
 * What the GDPR erasure tests seed and check, for the engine's own tables. `operator-repo.delete.test.ts` runs it
 * alone against the repository with no steps (what an install has); the hosted build's own test
 * seeds the hosted tables on top and runs the same deletion
 * with the hosted deployment's steps. Both seed a row in every table that references an operator, because the bug
 * these suites pin is a foreign-key bug that a fake `db` cannot observe.
 */

/** Names every row of one run carries, so repeated runs and suites running side by side never collide. */
export interface DeleteFixture {
  RUN: string;
  VICTIM: string;
  PUBLISHER: string;
  PARTNER: string;
  later: Date;
  id: (prefix: string) => string;
}

export function createDeleteFixture(): DeleteFixture {
  const RUN = `${Date.now().toString(36)}${randomBytes(2).toString('hex')}`;
  return {
    RUN,
    VICTIM: `op_del_victim_${RUN}`,
    PUBLISHER: `op_del_publisher_${RUN}`,
    PARTNER: `op_del_partner_${RUN}`,
    later: new Date(Date.now() + 3_600_000),
    id: (prefix) => `${prefix}_del_${RUN}`,
  };
}

/** The seed writes one row into every table that references an operator; on a busy shared database that outlasts the default. */
export const SEEDED_DB_TIMEOUT_MS = 60_000;

/**
 * Every foreign key of the engine's tables that references `operators`, as `table.column`. A new one forces a conscious
 * update of the seed and of `OperatorRepository.deleteById` (the test fails until both name it).
 */
export const ENGINE_OPERATOR_FOREIGN_KEYS: readonly string[] = [
  'admin_actions.admin_operator_id',
  'admin_actions.target_operator_id',
  'agents.operator_id',
  'audit_archive_segments.operator_id',
  'audit_log.operator_id',
  'authority_approval_decisions.operator_id',
  'authority_approval_requests.operator_id',
  'authority_bindings.operator_id',
  'authority_idempotency_keys.operator_id',
  'authority_presentations.operator_id',
  'authority_principals.operator_id',
  'authority_profile_versions.owner_operator_id',
  'authority_proofs.operator_id',
  'authority_receivers.managed_by_operator_id',
  'authority_uses.operator_id',
  'cmek_migrations.operator_id',
  'connect_links.operator_id',
  'control_decisions.operator_id',
  'control_event_outbox.operator_id',
  'control_policies.operator_id',
  'control_policy_revisions.operator_id',
  'control_reviews.operator_id',
  'control_sockets.operator_id',
  'dropoff_recipients.operator_id',
  'dropoffs.operator_id',
  'evidence_pack_artifacts.operator_id',
  'external_anchors.operator_id',
  'fleet_memberships.operator_id',
  'fleet_mission_starts.operator_id',
  'fleet_missions.operator_id',
  'fleet_operations.operator_id',
  'fleet_policies.operator_id',
  'governance_approvals.operator_id',
  'identity_claims.operator_id',
  'identity_verification_sessions.operator_id',
  'inbound_webhooks.operator_id',
  'intent_approvals.operator_id',
  'llm_usage.operator_id',
  'magic_link_tokens.operator_id',
  'missions.operator_id',
  'notification_channels.operator_id',
  'notification_destinations.operator_id',
  'oauth_authorization_codes.operator_id',
  'oauth_clients.operator_id',
  'oauth_device_codes.operator_id',
  'oauth_refresh_tokens.operator_id',
  'oidc_idp_configs.operator_id',
  'operator_decisions.operator_id',
  'operator_detector_config.operator_id',
  'operator_email_changes.operator_id',
  'operator_email_delivery_jobs.operator_id',
  'operator_erasure_jobs.operator_id',
  'operator_oauth_apps.operator_id',
  'operator_pii_config.operator_id',
  'operator_signing_keys.operator_id',
  'operators.parent_operator_id',
  'partner_grants.partner_operator_id',
  'partner_grants.user_operator_id',
  'passport_checkouts.operator_id',
  'passport_checkpoints.operator_id',
  'passport_claims.operator_id',
  'passport_reviews.operator_id',
  'passports.operator_id',
  'proxy_accounting_receipts.operator_id',
  'proxy_operation_replacement_acknowledgements.operator_id',
  'proxy_operations.operator_id',
  'receiver_transaction_receipts.operator_id',
  'security_events.operator_id',
  'service_configurations.operator_id',
  'service_connections.operator_id',
  'service_identity_requirements.operator_id',
  'services.operator_id',
  'spiffe_trust_domains.operator_id',
  'sso_verified_domains.operator_id',
  'team_members.operator_id',
  'usage_daily.operator_id',
  'usage_monthly_allowances.operator_id',
  'wimse_issuers.operator_id',
];

/** Every foreign key that references `operators` in the database under test, as `table.column`. */
export async function operatorForeignKeys(db: Database): Promise<string[]> {
  const rows = await db.execute(sql`
    SELECT src.relname AS child_table,
           (SELECT a.attname FROM unnest(con.conkey) AS ck(attnum)
              JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ck.attnum
              LIMIT 1) AS child_col
    FROM pg_constraint con
    JOIN pg_class src ON src.oid = con.conrelid
    JOIN pg_class tgt ON tgt.oid = con.confrelid
    WHERE con.contype = 'f' AND tgt.relname = 'operators'
  `);
  return (rows as unknown as Array<{ child_table: string; child_col: string }>).map(
    ({ child_table, child_col }) => `${child_table}.${child_col}`,
  );
}

/** The tables of the engine's own schema: a key from any other table is the deployment's. */
// Some exports are objects with no prototype, which `is` cannot read.
const isTable = (value: unknown): boolean => {
  try {
    return is(value, PgTable);
  } catch {
    return false;
  }
};
const ENGINE_TABLES = new Set(Object.values(shared).filter(isTable).map((table) => getTableName(table as PgTable)));

/** Whether any of these `table.column` keys belongs to a table the engine's schema does not have (a deployment's own). */
export function hasKeysOutsideTheEngine(keys: Iterable<string>): boolean {
  return [...keys].some((key) => !ENGINE_TABLES.has(key.split('.')[0]!));
}

/**
 * Seeds the victim operator with a row in every engine table that references `operators.id` (directly or through
 * agents, passports, connections, members and claims), plus the cross-operator rows that exercise the
 * sever-don't-delete paths.
 */
export async function seedEngineFixtures(db: Database, fixture: DeleteFixture) {
  const { RUN, VICTIM, PUBLISHER, PARTNER, later, id } = fixture;

  // ── Shared catalog rows (not operator-scoped) ────────────────────────
  await db.insert(services).values({
    id: id('svc'),
    provider: `deltest_${RUN}`,
    name: 'Delete Test Service',
    description: 'fixture',
    oauth_auth_url: 'https://example.invalid/auth',
    oauth_token_url: 'https://example.invalid/token',
    scopes_available: ['read'],
  });
  await db.insert(identityProviders).values({
    id: id('idp'),
    name: 'Delete Test IdP',
    provider_key: `deltest_${RUN}`,
    supported_layers: ['humanity'],
    claim_types: ['verified_human'],
    assurance_level: 'low',
    active: false,
  });
  // ── The three operators ──────────────────────────────────────────────
  await db.insert(operators).values([
    { id: VICTIM, email: `victim+${RUN}@example.invalid`, api_key_hash: `hash_victim_${RUN}` },
    { id: PUBLISHER, email: `publisher+${RUN}@example.invalid`, api_key_hash: `hash_pub_${RUN}` },
    {
      id: PARTNER,
      email: `partner+${RUN}@example.invalid`,
      api_key_hash: `hash_partner_${RUN}`,
      is_partner: true,
    },
  ]);
  // A child tenant under PARTNER — exercises the ON DELETE RESTRICT guard.
  await db.insert(operators).values({
    id: id('op_child'),
    email: `child+${RUN}@example.invalid`,
    api_key_hash: `hash_child_${RUN}`,
    parent_operator_id: PARTNER,
  });
  await db.insert(services).values({
    id: id('svc_custom'),
    operator_id: VICTIM,
    provider: `custom_deltest_${RUN}`,
    name: 'Delete Test Custom Service',
    description: 'operator-owned fixture',
    oauth_auth_url: 'https://example.invalid/custom/auth',
    oauth_token_url: 'https://example.invalid/custom/token',
    scopes_available: ['read'],
    available: false,
  });
  await db.insert(operatorPiiConfig).values({
    id: id('opc'),
    operator_id: VICTIM,
    enabled: true,
  });
  await db.insert(usageDaily).values({
    operator_id: VICTIM,
    day: '2026-08-09',
    actions: 3,
    actions_total: 5,
    agents_registered: 1,
  });
  await db.insert(usageDailyByAction).values({
    operator_id: VICTIM,
    day: '2026-08-09',
    action: 'passport.issue',
    count: 3,
  });
  await db.insert(usageMonthlyAllowances).values({
    operator_id: VICTIM,
    month: '2026-08-01',
    tier: 'free',
    actions_limit: 25_000,
  });
  await db.insert(operatorEmailChanges).values({
    id: id('oec'),
    operator_id: VICTIM,
    new_email: `new-victim+${RUN}@example.invalid`,
    old_email: `victim+${RUN}@example.invalid`,
    confirm_token_hash: `confirm_${RUN}`,
    cancel_token_hash: `cancel_${RUN}`,
    expires_at: later,
  });
  await db.insert(operatorEmailDeliveryJobs).values({
    id: id('oedj'),
    operator_id: VICTIM,
    email_change_id: id('oec'),
    kind: 'completion_notice',
  });
  await db.insert(auditArchiveSegments).values({
    id: id('aseg'),
    operator_id: VICTIM,
    from_timestamp: 1,
    to_timestamp: 2,
    row_count: 1,
    object_key: `audit/${VICTIM}/fixture.ndjson.gz`,
    byte_size: 1,
    content_hash: 'a'.repeat(64),
    first_entry_hash: 'b'.repeat(64),
    first_prev_entry_hash: null,
    last_entry_hash: 'c'.repeat(64),
  });
  await db.insert(operatorErasureJobs).values({
    operator_id: VICTIM,
  });
  await db.insert(magicLinkTokens).values([
    {
      id: id('mlt_linked'),
      email: `victim+${RUN}@example.invalid`,
      token_hash: `mlt_linked_hash_${RUN}`,
      intent: 'login',
      operator_id: VICTIM,
      expires_at: later,
    },
    {
      id: id('mlt_legacy'),
      email: `  VICTIM+${RUN}@EXAMPLE.INVALID  `,
      token_hash: `mlt_legacy_hash_${RUN}`,
      intent: 'login',
      operator_id: null,
      expires_at: later,
    },
  ]);
  // ── Agents ───────────────────────────────────────────────────────────
  await db.insert(agents).values([
    { id: id('agt'), operator_id: VICTIM, name: `agent-${RUN}` },
    { id: id('agt_fleet'), operator_id: VICTIM, name: `fleet-agent-${RUN}` },
    { id: id('agt_pub'), operator_id: PUBLISHER, name: `pub-agent-${RUN}` },
  ]);
  // ── Services + grants ────────────────────────────────────────────────
  await db.insert(serviceConnections).values({
    id: id('scon'),
    operator_id: VICTIM,
    service_id: id('svc'),
    provider: `deltest_${RUN}`,
    scopes: ['read'],
    credential_ref: 'ref',
    credential_encrypted: 'ciphertext',
  });
  await db.insert(serviceConfigurations).values({
    id: id('svcfg'),
    operator_id: VICTIM,
    service_id: id('svc'),
    provider: `deltest_${RUN}`,
    mode: 'shared',
  });
  await db.insert(serviceIdentityRequirements).values({
    id: id('svcreq'),
    operator_id: VICTIM,
    service_id: id('svc'),
    layer: 'humanity',
    requires_claim: 'verified_human',
    minimum_assurance: 'low',
    accepted_providers: [`deltest_${RUN}`],
  });
  await db.insert(agentServiceGrants).values({
    id: id('grant'),
    agent_id: id('agt'),
    service_connection_id: id('scon'),
    scopes: ['read'],
  });
  // ── Team members (must exist before the OAuth rows that point at them) ─
  await db.insert(teamMembers).values({
    id: id('mem'),
    operator_id: VICTIM,
    email: `member+${RUN}@example.invalid`,
    name: 'Member',
  });
  // ── Passports + claims graph ─────────────────────────────────────────
  await db.insert(passports).values({
    jti: id('pas'),
    operator_id: VICTIM,
    agent_id: id('agt'),
    session_id: id('ses'),
    expires_at: later,
  });
  await db.insert(passportClaims).values([
    // Bound to a passport → cascades when the passport goes.
    {
      claim_id: id('clm_bound'),
      passport_id: id('pas'),
      operator_id: VICTIM,
      type: 'intent_claim',
      body_json: {},
      claim_hash: 'h1',
      signature: 'sig1',
    },
    // Envelope-only, operator-scoped, passport_id NULL → NO cascade path.
    // This is the row that a naive "delete passports and let it cascade"
    // implementation leaves behind forever.
    {
      claim_id: id('clm_envelope'),
      operator_id: VICTIM,
      type: 'identity_claim',
      body_json: {},
      claim_hash: 'h2',
      signature: 'sig2',
    },
    // The mission claim (missions.claim_id is NOT NULL / NO ACTION).
    {
      claim_id: id('clm_mission'),
      operator_id: VICTIM,
      type: 'mission',
      body_json: {},
      claim_hash: 'h3',
      signature: 'sig3',
    },
    ...['proof', 'binding', 'use_intent', 'use_outcome', 'receipt'].map((kind, index) => ({
      claim_id: id(`clm_authority_${kind}`),
      operator_id: VICTIM,
      type: kind === 'proof' ? 'external_proof_verification'
        : kind === 'binding' ? 'authority_binding'
          : kind === 'receipt' ? 'receiver_transaction_receipt'
            : 'authority_use',
      body_json: {},
      claim_hash: `authority-hash-${index}`,
      signature: `authority-sig-${index}`,
    })),
  ]);
  await db.insert(passportCheckpoints).values({
    id: id('chk'),
    passport_jti: id('pas'),
    operator_id: VICTIM,
  });
  await db.insert(passportCheckouts).values({
    id: id('cout'),
    passport_jti: id('pas'),
    operator_id: VICTIM,
  });
  await db.insert(passportReviews).values({
    id: id('prev'),
    checkout_id: id('cout'),
    operator_id: VICTIM,
    agent_id: id('agt'),
    decision: 'approved',
  });
  await db.insert(intentApprovals).values({
    id: id('ia'),
    operator_id: VICTIM,
    agent_id: id('agt'),
    passport_jti: id('pas'),
    intent_claim_id: id('clm_bound'),
    status: 'pending',
    expires_at: later,
  });
  await db.insert(missions).values({
    mission_id: id('ms'),
    claim_id: id('clm_mission'),
    operator_id: VICTIM,
    intent_summary: 'fixture mission',
    expires_at: later,
  });
  // A complete Fleet graph exercises every new direct operator FK and the
  // policy/mission/agent dependencies that must be removed before its parents.
  const fleetLimits = { max_actions: 10, max_concurrent_actions: 2, max_duration_seconds: 60 };
  await db.insert(fleetPolicies).values({
    id: id('flp'), operator_id: VICTIM, root_agent_id: id('agt'), revision: 1,
  });
  await db.insert(fleetPolicyRevisions).values({
    policy_id: id('flp'), revision: 1, approved_by: VICTIM,
    definition: {
      name: 'Erasure fixture',
      rules: [{
        id: 'allow-read', effect: 'allow',
        access: { connection_id: id('scon'), scopes: ['read'], intents: [], constraints: [], allow_data_from: [] },
      }],
      operation_rules: [], limits: fleetLimits, window_seconds: 60,
      max_members: 1, max_enrollments_per_hour: 1, identity_lease_seconds: 60,
      provisioner_agent_ids: [id('agt')], workload_trust: [], allow_delegation: false,
      expires_at: later.toISOString(),
    },
  });
  await db.insert(fleetMemberships).values({
    id: id('flm'), policy_id: id('flp'), operator_id: VICTIM,
    agent_id: id('agt_fleet'), enrolled_by: VICTIM,
    enrollment_key_hash: id('fleet_key'), enrollment_payload_hash: id('fleet_payload'),
    identity_expires_at: later,
  });
  await db.insert(fleetMissions).values({
    mission_id: id('ms'), policy_id: id('flp'), policy_revision: 1,
    membership_id: id('flm'), operator_id: VICTIM, agent_id: id('agt_fleet'),
    access: [], operations: [], limits: fleetLimits, session_id: id('ses'),
  });
  await db.insert(fleetOperations).values({
    id: id('flo'), operator_id: VICTIM, policy_id: id('flp'), policy_revision: 1,
    mission_id: id('ms'), agent_id: id('agt_fleet'),
    operation_key_hash: id('operation_key'), request_hash: id('request_hash'),
    producer: 'skill', rule_id: 'allow-read', intent_claim_id: id('clm_bound'),
    window_start: new Date(),
  });
  await db.insert(fleetMissionStarts).values({
    id: id('fls'), operator_id: VICTIM, policy_id: id('flp'), agent_id: id('agt_fleet'),
    key_hash: id('start_key'), payload_hash: id('start_payload'), mission_id: id('ms'),
  });
  await db.insert(intentApprovals).values({
    id: id('ia_fleet'), operator_id: VICTIM, agent_id: id('agt_fleet'),
    passport_jti: id('pas'), intent_claim_id: id('clm_bound'),
    fleet_policy_id: id('flp'), fleet_policy_revision: 1, fleet_mission_id: id('ms'),
    fleet_request_hash: createHash('sha256').update(`fleet-request:${RUN}`).digest('hex'),
    fleet_review_key: createHash('sha256').update(`fleet-review:${RUN}`).digest('hex'),
    status: 'pending', expires_at: later,
  });
  await db.insert(operatorDecisions).values({
    id: id('odec'),
    claim_id: id('clm_bound'),
    operator_id: VICTIM,
    mission_id: id('ms'),
    idempotency_key: `idem_${RUN}`,
    action: 'checkout_approved',
    effect: 'checkout_released',
    effect_scope: 'mission',
    target_agent_id: id('agt'),
    author_kind: 'operator_owner',
  });
  await db.insert(operatorDecisionSources).values({
    decision_id: id('odec'),
    operator_id: VICTIM,
    source_type: 'checkout',
    source_id: id('cout'),
  });
  await db.insert(twinRuns).values({
    id: id('twr'),
    mission_id: id('ms'),
    real_passport_jti: id('pas'),
    twin_passport_jti: `${id('pas')}_twin`,
  });
  // ── Drop-offs ────────────────────────────────────────────────────────
  await db.insert(dropoffs).values({
    id: id('drp'),
    operator_id: VICTIM,
    from_agent_id: id('agt'),
    to_agent_id: id('agt'),
    schema: {},
    // Deposited under the victim's Mission: the key to missions must not block the erasure.
    mission_id: id('ms'),
    expires_at: later,
  });
  await db.insert(dropoffRecipients).values({
    dropoff_id: id('drp'),
    operator_id: VICTIM,
    agent_id: id('agt'),
    position: 0,
  });
  // ── Identity ─────────────────────────────────────────────────────────
  await db.insert(identityClaims).values({
    id: id('idc'),
    operator_id: VICTIM,
    provider_id: id('idp'),
    provider_key: `deltest_${RUN}`,
    layer: 'humanity',
    claim_type: 'verified_human',
    assurance_level: 'low',
    verified_at: new Date(),
    expires_at: later,
    assertion_encrypted: 'ciphertext',
  });
  await db.insert(identityVerificationSessions).values({
    id: id('ivs'),
    operator_id: VICTIM,
    provider_key: `deltest_${RUN}`,
    session_ref: 'ref',
    requested_claims: ['verified_human'],
    expires_at: later,
  });
  // ── BYOOA ────────────────────────────────────────────────────────────
  // Authority graph. Every table is populated so account deletion proves the
  // required leaf-to-root sweep instead of relying on operator cascades.
  const authorityHash = (label: string) =>
    `sha256:${createHash('sha256').update(`${label}:${RUN}`).digest('hex')}`;
  const authorityDigest = authorityHash('authority');
  await db.insert(authorityPrincipals).values({
    id: id('prn'), operator_id: VICTIM, kind: 'person', label_encrypted: 'principal-ciphertext',
  });
  await db.insert(authorityReceivers).values({
    id: id('rcv'), managed_by_operator_id: VICTIM, mode: 'native',
    canonical_identifier: `https://receiver-${RUN}.example.invalid`,
    display_name: 'Delete test receiver', status: 'active', verified_at: new Date(),
  });
  await db.insert(authorityProfileVersions).values([
    {
      id: id('apv_proof'), owner_operator_id: VICTIM, profile_kind: 'proof',
      profile_key: `delete-proof-${RUN}`, version: 1, schema_uri: 'urn:test:proof',
      schema_version: '1', adapter_key: 'delete-test', adapter_version: 1,
      config_json: {}, content_hash: authorityDigest, status: 'active', activated_at: new Date(),
    },
    {
      id: id('apv_domain'), owner_operator_id: VICTIM, profile_kind: 'domain',
      profile_key: `delete-domain-${RUN}`, version: 1, schema_uri: 'urn:test:domain',
      schema_version: '1', adapter_key: 'delete-test', adapter_version: 1,
      config_json: {}, content_hash: authorityHash('profile-agent'), status: 'active', activated_at: new Date(),
    },
    {
      id: id('apv_receiver'), owner_operator_id: VICTIM, profile_kind: 'receiver',
      profile_key: `delete-receiver-${RUN}`, version: 1, receiver_id: id('rcv'),
      schema_uri: 'urn:test:receiver', schema_version: '1', adapter_key: 'delete-test',
      adapter_version: 1, config_json: {}, content_hash: authorityHash('profile-receiver'),
      status: 'active', activated_at: new Date(),
    },
  ]);
  await db.update(authorityReceivers).set({ current_profile_version_id: id('apv_receiver') })
    .where(eq(authorityReceivers.id, id('rcv')));
  await db.insert(authorityReceiverKeys).values([
    {
      id: id('rky_request'), receiver_id: id('rcv'), key_id: `request-${RUN}`,
      use: 'request_signing', algorithm: 'EdDSA', public_jwk: { kty: 'OKP' },
      thumbprint: authorityHash('key-request'), valid_from: new Date(),
    },
    {
      id: id('rky_response'), receiver_id: id('rcv'), key_id: `response-${RUN}`,
      use: 'response_encryption', algorithm: 'ECDH-ES+A256KW', public_jwk: { kty: 'EC' },
      thumbprint: authorityHash('key-response'), valid_from: new Date(),
    },
    {
      id: id('rky_receipt'), receiver_id: id('rcv'), key_id: `receipt-${RUN}`,
      use: 'receipt_signing', algorithm: 'EdDSA', public_jwk: { kty: 'OKP' },
      thumbprint: authorityHash('key-receipt'), valid_from: new Date(),
    },
  ]);
  await db.insert(authorityProofs).values([
    {
      id: id('prf_identity'), version: 1, operator_id: VICTIM,
      subject_principal_id: id('prn'), profile_version_id: id('apv_proof'),
      proof_kind: 'identity', source_kind: 'external_native', issuer_identifier: 'urn:test:issuer',
      schema_uri: 'urn:test:proof', schema_version: '1', native_format: 'jwt',
      native_evidence_encrypted: 'proof-ciphertext', native_evidence_hash: authorityDigest,
      verification_method: 'signature', verifier_identifier: 'stack', verifier_version: '1',
      verified_at: new Date(), valid_from: new Date(), status: 'active',
      claim_id: id('clm_authority_proof'),
    },
    {
      id: id('prf_decision'), version: 1, operator_id: VICTIM,
      subject_principal_id: id('prn'), profile_version_id: id('apv_proof'),
      proof_kind: 'consent', source_kind: 'stack_derived', issuer_identifier: 'urn:test:issuer',
      schema_uri: 'urn:test:proof', schema_version: '1', native_format: 'cose',
      native_evidence_encrypted: 'decision-ciphertext', native_evidence_hash: authorityHash('evidence'),
      verification_method: 'signature', verifier_identifier: 'stack', verifier_version: '1',
      verified_at: new Date(), valid_from: new Date(), status: 'active',
    },
  ]);
  await db.insert(authorityProofDependencies).values({
    derived_proof_id: id('prf_decision'), derived_proof_version: 1, operator_id: VICTIM,
    source_proof_id: id('prf_identity'), source_proof_version: 1, relation: 'verified_from',
  });
  await db.insert(authorityBindings).values({
    id: id('abn'), version: 1, operator_id: VICTIM, principal_id: id('prn'),
    agent_id: id('agt'), agent_key_thumbprint: authorityDigest, receiver_id: id('rcv'),
    receiver_profile_version_id: id('apv_receiver'), domain_profile_version_id: id('apv_domain'),
    mission_ids: [id('ms')], lineage_root_id: id('abn'), lineage_root_version: 1,
    delegation_depth: 0, purpose_code: 'account.delete.test', purpose_hash: authorityDigest,
    purpose_statement_encrypted: 'purpose-ciphertext', scope_encrypted: 'scope-ciphertext',
    scope_hash: authorityDigest, approval_policy_encrypted: 'approval-ciphertext',
    approval_policy_hash: authorityDigest, disclosure_policy_encrypted: 'disclosure-ciphertext',
    disclosure_policy_hash: authorityDigest, delegation_policy: {}, delegation_policy_hash: authorityDigest,
    proof_set_hash: authorityDigest, valid_from: new Date(), expires_at: later, status: 'active',
    claim_id: id('clm_authority_binding'), activated_at: new Date(),
  });
  await db.insert(authorityBindingProofs).values({
    binding_id: id('abn'), binding_version: 1, proof_id: id('prf_identity'),
    proof_version: 1, operator_id: VICTIM, role: 'principal_identity',
    group_key: 'principal', weight: 1, required: true, ordinal: 0,
  });
  await db.insert(passportAuthorityBindings).values({
    passport_jti: id('pas'), operator_id: VICTIM, binding_id: id('abn'), binding_version: 1,
    binding_claim_id: id('clm_authority_binding'),
  });
  await db.insert(authorityUses).values({
    id: id('aus'), operator_id: VICTIM, binding_id: id('abn'), binding_version: 1,
    passport_jti: id('pas'), mission_id: id('ms'), agent_id: id('agt'),
    agent_key_thumbprint: authorityDigest, receiver_id: id('rcv'),
    receiver_profile_version_id: id('apv_receiver'), domain_profile_version_id: id('apv_domain'),
    receiver_request_id: `request-${RUN}-abcdefghijklmnop`, action_uri: 'urn:test:delete',
    request_hash: authorityDigest, effective_scope_hash: authorityDigest, proof_set_hash: authorityDigest,
    disclosure_manifest: [], verification_mode: 'native_receiver',
    proof_strength: 'native_stack_attestation', status: 'dispatched',
    intent_claim_id: id('clm_authority_use_intent'), outcome_claim_id: id('clm_authority_use_outcome'),
  });
  await db.insert(authorityApprovalRequests).values({
    id: id('apr'), operator_id: VICTIM, binding_id: id('abn'), binding_version: 1,
    authority_use_id: id('aus'), phase: 'action', group_key: 'principal',
    request_hash: authorityDigest, challenge_hash: authorityDigest, required_weight: 1,
    collected_weight: 1, reject_mode: 'any_reject', status: 'satisfied', expires_at: later,
  });
  await db.insert(authorityApprovalDecisions).values({
    id: id('apd'), operator_id: VICTIM, request_id: id('apr'),
    authoriser_principal_id: id('prn'), identity_proof_id: id('prf_identity'),
    identity_proof_version: 1, decision_proof_id: id('prf_decision'), decision_proof_version: 1,
    decision: 'approve', weight: 1, request_hash: authorityDigest, decided_at: new Date(),
  });
  await db.insert(authorityPresentations).values({
    id: id('prs'), operator_id: VICTIM, authority_use_id: id('aus'), binding_id: id('abn'),
    binding_version: 1, receiver_id: id('rcv'), receiver_profile_version_id: id('apv_receiver'),
    request_signing_key_id: id('rky_request'), response_encryption_key_id: id('rky_response'),
    nonce_hash: authorityDigest, signed_request_hash: authorityHash('signed-request'),
    request_payload_encrypted: 'request-ciphertext', requested_fact_ids: [],
    presentation_jti_hash: authorityHash('presentation-jti'), disclosure_manifest: [], proof_refs: [],
    status: 'delivered', expires_at: later,
  });
  await db.insert(receiverTransactionReceipts).values({
    id: id('rtr'), operator_id: VICTIM, authority_use_id: id('aus'), presentation_id: id('prs'),
    receiver_id: id('rcv'), receiver_profile_version_id: id('apv_receiver'),
    receiver_key_id: id('rky_receipt'), receipt_jti_hash: authorityHash('receipt-jti'),
    native_format: 'jwt', native_receipt_encrypted: 'receipt-ciphertext',
    receipt_hash: authorityHash('receipt'), request_hash: authorityDigest,
    outcome: 'accepted', verified_at: new Date(), claim_id: id('clm_authority_receipt'),
  });
  await db.insert(authorityIdempotencyKeys).values({
    id: id('aik'), operator_id: VICTIM, route_key: 'authority.delete.test',
    idempotency_key_hash: authorityDigest, request_hash: authorityDigest, state: 'completed',
    response_status: 200, response_body: { ok: true }, workflow_phase: 'completed',
    workflow_payload_encrypted: 'workflow-ciphertext', expires_at: later,
  });
  await db.insert(operatorOauthApps).values({
    id: id('oapp'),
    operator_id: VICTIM,
    provider: `deltest_${RUN}`,
    client_id: 'cid',
    client_secret_encrypted: 'ciphertext',
  });
  // ── Security + notifications ─────────────────────────────────────────
  await db.insert(securityEvents).values({
    id: id('sev'),
    operator_id: VICTIM,
    mission_id: id('ms'),
    agent_id: id('agt'),
    passport_jti: id('pas'),
    signal_type: 'prompt_injection',
    message: 'fixture',
    claim_id: id('clm_bound'),
  });
  await db.insert(notificationDestinations).values({
    id: id('ndst'),
    operator_id: VICTIM,
    channel_type: 'email',
    destination: `alerts+${RUN}@example.invalid`,
  });
  await db.insert(notificationChannels).values({
    id: id('nch'),
    operator_id: VICTIM,
    destination_id: id('ndst'),
    channel_type: 'email',
    destination: `alerts+${RUN}@example.invalid`,
    events: ['security_event'],
  });
  await db.insert(notificationChannelVerifications).values({
    id: id('nchv'),
    channel_id: id('nch'),
    destination_id: id('ndst'),
    code_hash: 's1:fixture:fixture',
    expires_at: later,
  });
  // ── OAuth 2.1 ────────────────────────────────────────────────────────
  await db.insert(oauthClients).values({
    id: id('ocl'),
    operator_id: VICTIM,
    client_type: 'public',
    client_name: 'fixture',
    redirect_uris: ['https://example.invalid/cb'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  });
  await db.insert(oauthAuthorizationCodes).values({
    code_hash: id('oac'),
    client_id: id('ocl'),
    operator_id: VICTIM,
    member_id: id('mem'),
    redirect_uri: 'https://example.invalid/cb',
    scope: 'openid',
    resource: 'stack:api',
    code_challenge: 'chal',
    expires_at: later,
  });
  await db.insert(oauthRefreshTokens).values({
    token_hash: createHash('sha256').update(id('ort')).digest('hex'),
    token_family_id: id('fam'),
    client_id: id('ocl'),
    operator_id: VICTIM,
    member_id: id('mem'),
    scope: 'openid',
    resource: 'stack:api',
    expires_at: later,
  });
  await db.insert(oauthDeviceCodes).values({
    device_code_hash: id('odc'),
    user_code: `UC${RUN.slice(-6)}`.toUpperCase(),
    client_id: id('ocl'),
    operator_id: VICTIM,
    member_id: id('mem'),
    scope: 'openid',
    resource: 'stack:api',
    expires_at: later,
  });
  // ── Platform / partner edges ─────────────────────────────────────────
  await db.insert(adminActions).values([
    { id: id('adm_by'), admin_operator_id: VICTIM, action: 'operator.suspend' },
    {
      id: id('adm_on'),
      admin_operator_id: PUBLISHER,
      target_operator_id: VICTIM,
      action: 'operator.comp',
    },
  ]);
  await db.insert(partnerGrants).values([
    {
      id: id('pgr_as_user'),
      partner_operator_id: PARTNER,
      user_operator_id: VICTIM,
      token_hash: `th_user_${RUN}`,
      scopes: ['proxy'],
      allowed_providers: [`deltest_${RUN}`],
      user_provisioned: true,
    },
    {
      id: id('pgr_as_partner'),
      partner_operator_id: VICTIM,
      user_operator_id: PUBLISHER,
      token_hash: `th_partner_${RUN}`,
      scopes: ['proxy'],
      allowed_providers: [`deltest_${RUN}`],
      user_provisioned: true,
    },
  ]);
  // ── Cascade-only tables (no explicit delete in deleteById) ───────────
  await db.insert(cmekMigrations).values({
    id: id('cmk'),
    operator_id: VICTIM,
    direction: 'enable',
    table_name: 'service_connections',
  });
  await db.insert(externalAnchors).values({
    id: id('anc'),
    operator_id: VICTIM,
    anchored_at_ms: Date.now(),
    chain_head_hash: 'a'.repeat(64),
    chain_head_at_audit_position: 1,
    registry: 'github:example-org/anchors',
    permalink: 'https://example.invalid/anchor',
    commit_sha: 'deadbeef',
    chain_head_signature: 'sig',
  });
  await db.insert(governanceApprovals).values({
    id: id('gvr'),
    operator_id: VICTIM,
    action: 'detector_config_upsert',
    resource_id: 'prompt_injection',
    payload_hash: 'ph',
    summary: 'fixture',
    requested_via: 'operator_key',
    expires_at: later,
  });
  await db.insert(connectLinks).values({
    id: id('cnl'),
    operator_id: VICTIM,
    token_hash: createHash('sha256').update(`connect-link-${RUN}`).digest('hex'),
    service_id: 'svc_fixture',
    provider: 'github',
    method: 'key',
    created_via: 'operator_key',
    expires_at: later,
  });
  await db.insert(controlSockets).values({ operator_id: VICTIM, socket_id: id('csk') });
  await db.insert(controlDecisions).values({
    id: id('dec'), operator_id: VICTIM, action_type: 'email.send', decider: 'hosted', verdict: 'allow', latency_ms: 1,
    request_digest: `sha256:${'d'.repeat(64)}`,
  });
  await db.insert(controlEventOutbox).values({ operator_id: VICTIM, seq: 1, entry_id: id('aud'), event: {} });
  const policy = id('cpl');
  await db.insert(controlPolicies).values({ id: policy, operator_id: VICTIM, name: 'Fixture', definition: { name: 'Fixture' }, definition_digest: 'd'.repeat(64) });
  await db.insert(controlPolicyRevisions).values({
    policy_id: policy, revision: 1, operator_id: VICTIM, definition: { name: 'Fixture' }, definition_digest: 'd'.repeat(64), change: 'create', actor: 'fixture',
  });
  await db.insert(controlReviews).values({
    id: id('crv'), operator_id: VICTIM, account_id: id('acct'), agent_id: id('agt'), policy_id: policy, policy_revision: 1,
    rule_section: 'review', rule_id: 'over_cents', action_type: 'card.checkout', call_digest: 'c'.repeat(64),
    summary: 'Fixture', governance_approval_id: id('gvr'), expires_at: later,
  });
  await db.insert(inboundWebhooks).values({
    id: id('iwh'),
    operator_id: VICTIM,
    provider: 'agentmail',
    slug: `slug_${RUN}`,
    webhook_secret_encrypted: 'ciphertext',
    agent_id: id('agt'),
  });
  await db.insert(inboundWebhookReceipts).values({
    webhook_id: id('iwh'),
    provider_message_id: `msg_${RUN}`,
  });
  await db.insert(llmUsage).values({
    id: id('usg'),
    operator_id: VICTIM,
    agent_id: id('agt'),
    passport_jti: id('pas'),
    provider: 'openrouter',
    model: 'anthropic/claude-haiku-4-5',
    prompt_tokens: 10,
    completion_tokens: 5,
    total_tokens: 15,
    wallet_fee_kind: 'sealed_execution',
    wallet_fee_microcents: 700_000,
    wallet_fee_microcents_remaining: 0,
    sealed_step_index: 0,
    streaming: false,
  });
  await db.insert(oidcIdpConfigs).values({
    id: id('oidc'),
    operator_id: VICTIM,
    issuer_uri: 'https://example.invalid',
    client_id: 'cid',
    client_secret_encrypted: 'ciphertext',
    redirect_uri: 'https://example.invalid/cb',
  });
  await db.insert(ssoVerifiedDomains).values({
    id: id('ssod'),
    operator_id: VICTIM,
    domain: `victim-${RUN}.example.invalid`,
    token: 'tok',
    status: 'verified',
    verified_at: new Date(),
    last_confirmed_at: new Date(),
  });
  await db.insert(operatorDetectorConfig).values({
    id: id('odc2'),
    operator_id: VICTIM,
    detector_key: 'prompt_injection',
  });
  await db.insert(operatorSigningKeys).values({
    kid: `${VICTIM}:claim:v1`,
    operator_id: VICTIM,
    private_key_wrapped: 'wrapped',
    public_jwk: { kty: 'OKP', crv: 'Ed25519', x: 'x' },
  });
  await db.insert(spiffeTrustDomains).values({
    id: id('std'),
    operator_id: VICTIM,
    trust_domain: `deltest-${RUN}`,
    jwks_uri: 'https://example.invalid/jwks',
    spiffe_id_mapping_policy_json: {},
  });
  await db.insert(wimseIssuers).values({
    id: id('wim'),
    operator_id: VICTIM,
    issuer_uri: 'https://example.invalid',
    jwks_uri: 'https://example.invalid/jwks',
    workload_id_mapping_policy_json: {},
  });
  // ── Audit chains (no FK — the policy sweep) ──────────────────────────
  const victimAuditRow = {
    hash_version: 2,
    entry_id: id('aud'),
    trace_id: 'tr',
    span_id: 'sp',
    timestamp: Date.now(),
    operator_id: VICTIM,
    agent_id: id('agt'),
    passport_jti: id('pas'),
    layer: 'vault',
    action: 'passport.issue',
    outcome: 'success',
    prev_entry_hash: 'GENESIS',
    claim_binding_status: 'no_active_claims',
  } satisfies AuditEntryHashInput;
  // The publisher's chain must be untouched — invariant #1 (per-operator
  // chain) is what makes deleting the victim's chain safe.
  const publisherAuditRow = {
    hash_version: 2,
    entry_id: id('aud_pub'),
    trace_id: 'tr',
    span_id: 'sp',
    timestamp: Date.now(),
    operator_id: PUBLISHER,
    agent_id: id('agt_pub'),
    passport_jti: 'none',
    layer: 'vault',
    action: 'passport.issue',
    outcome: 'success',
    prev_entry_hash: 'GENESIS',
    claim_binding_status: 'no_active_claims',
  } satisfies AuditEntryHashInput;
  await db.insert(auditLog).values([
    { ...victimAuditRow, entry_hash: computeAuditEntryHash(victimAuditRow) },
    { ...publisherAuditRow, entry_hash: computeAuditEntryHash(publisherAuditRow) },
  ]);

}

/** How many rows of the victim the engine's tables still hold (none, once it is erased). */
export async function countEngineRowsOfVictim(db: Database, fixture: DeleteFixture): Promise<number> {
  const { RUN, VICTIM } = fixture;
  const counts = await db.execute(sql`
    SELECT
      (SELECT count(*) FROM agents                         WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM passports                      WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM passport_claims                WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM passport_checkpoints           WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM passport_checkouts             WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM passport_reviews               WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM intent_approvals               WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM missions                       WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_decisions             WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_decision_sources      WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM dropoffs                       WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM dropoff_recipients             WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM service_connections            WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM service_configurations         WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM service_identity_requirements  WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM identity_claims                WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM identity_verification_sessions WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM team_members                   WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_oauth_apps            WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM security_events                WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM notification_destinations      WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM notification_channels          WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM oauth_clients                  WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM oauth_authorization_codes      WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM oauth_refresh_tokens           WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM oauth_device_codes             WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM admin_actions                  WHERE admin_operator_id = ${VICTIM} OR target_operator_id = ${VICTIM})
    + (SELECT count(*) FROM partner_grants                 WHERE partner_operator_id = ${VICTIM} OR user_operator_id = ${VICTIM})
    + (SELECT count(*) FROM cmek_migrations                WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM external_anchors               WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM governance_approvals           WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM connect_links                  WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM control_sockets                WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM control_decisions              WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM control_event_outbox           WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM control_policies               WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM control_policy_revisions       WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM control_reviews                WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM inbound_webhooks               WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM llm_usage                      WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM oidc_idp_configs               WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM sso_verified_domains           WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_detector_config       WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_signing_keys          WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM spiffe_trust_domains           WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM wimse_issuers                  WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_pii_config            WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM usage_daily                    WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM usage_daily_by_action          WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM usage_monthly_allowances       WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_email_changes         WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_email_delivery_jobs   WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM audit_archive_segments         WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM operator_erasure_jobs          WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM magic_link_tokens              WHERE operator_id = ${VICTIM} OR lower(trim(email)) = ${`victim+${RUN}@example.invalid`})
    + (SELECT count(*) FROM authority_principals           WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_receivers            WHERE managed_by_operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_profile_versions     WHERE owner_operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_proofs               WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_proof_dependencies   WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_bindings             WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_binding_proofs       WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_uses                 WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_approval_requests    WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_approval_decisions   WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_presentations        WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM receiver_transaction_receipts  WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM passport_authority_bindings    WHERE operator_id = ${VICTIM})
    + (SELECT count(*) FROM authority_idempotency_keys     WHERE operator_id = ${VICTIM})
    AS total
  `);
  return Number((counts[0] as { total: string }).total);
}

/** Best-effort removal of what the engine seed leaves behind by design (the other operators and the shared catalog rows). */
export async function tearDownEngineFixtures(db: Database, repo: OperatorRepository, fixture: DeleteFixture) {
  const { RUN, VICTIM, PUBLISHER, PARTNER } = fixture;
  await db.delete(operatorEmailDeliveryJobs).where(eq(operatorEmailDeliveryJobs.operator_id, VICTIM)).catch(() => {});
  await db.delete(operatorEmailChanges).where(eq(operatorEmailChanges.operator_id, VICTIM)).catch(() => {});
  await db.delete(usageDailyByAction).where(eq(usageDailyByAction.operator_id, VICTIM)).catch(() => {});
  await db.delete(usageDaily).where(eq(usageDaily.operator_id, VICTIM)).catch(() => {});
  await db.delete(usageMonthlyAllowances).where(eq(usageMonthlyAllowances.operator_id, VICTIM)).catch(() => {});
  await db.delete(operatorPiiConfig).where(eq(operatorPiiConfig.operator_id, VICTIM)).catch(() => {});
  await db.delete(auditArchiveSegments).where(eq(auditArchiveSegments.operator_id, VICTIM)).catch(() => {});
  await db.delete(operatorErasureJobs).where(eq(operatorErasureJobs.operator_id, VICTIM)).catch(() => {});
  await db
    .delete(magicLinkTokens)
    .where(sql`lower(trim(${magicLinkTokens.email})) = ${`victim+${RUN}@example.invalid`}`)
    .catch(() => {});
  await repo.deleteById(VICTIM).catch(() => {});
  await db
    .delete(partnerGrants)
    .where(or(eq(partnerGrants.partner_operator_id, PARTNER), eq(partnerGrants.user_operator_id, PUBLISHER)))
    .catch(() => {});
  await db.delete(operators).where(eq(operators.parent_operator_id, PARTNER)).catch(() => {});
  await db.delete(adminActions).where(eq(adminActions.admin_operator_id, PUBLISHER)).catch(() => {});
  await db.delete(auditLog).where(eq(auditLog.operator_id, PUBLISHER)).catch(() => {});
  await db.delete(agents).where(eq(agents.operator_id, PUBLISHER)).catch(() => {});
  await db.delete(operators).where(or(eq(operators.id, PUBLISHER), eq(operators.id, PARTNER))).catch(() => {});
  await db.delete(services).where(eq(services.id, `svc_del_${RUN}`)).catch(() => {});
  await db.delete(identityProviders).where(eq(identityProviders.id, `idp_del_${RUN}`)).catch(() => {});
}
