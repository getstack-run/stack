import {
  agents,
  authorityBindings,
  authorityPrincipals,
  authorityProfileVersions,
  authorityReceivers,
  authorityUses,
  createDb,
  intentApprovals,
  operators,
  passports,
  passportAuthorityBindings,
  passportClaims,
  proxyAccountingReceipts,
  proxyOperationAttempts,
  proxyOperationEvidence,
  proxyOperationReplacementAcknowledgements,
  proxyOperations,
  serviceConnections,
  services as serviceCatalog,
  sha256,
  type Database,
} from '@stack/shared';
import {
  AuthorityRepository,
  IntentApprovalRepository,
  ProxyOperationRepository,
  ProxyOperationService,
  type KmsService,
} from '@stack/vault';
import { eq, sql } from 'drizzle-orm';
import type { Services } from '../config/services.js';
import { isDedicatedStackTestDatabase } from '../test/dedicated-test-database.js';

export const proxyFixtureDatabaseUrl = process.env['DATABASE_URL'];

export function isDedicatedProxyFixtureDatabase(url = proxyFixtureDatabaseUrl): url is string {
  return isDedicatedStackTestDatabase(url);
}

class ContextBoundTestKms {
  private responseEncryptFailures = 0;
  private decryptAvailable = true;

  failNextResponseEncrypt() {
    this.responseEncryptFailures += 1;
  }

  revokeDecryptAccess() {
    this.decryptAvailable = false;
  }
  restoreDecryptAccess() {
    this.decryptAvailable = true;
  }

  async encrypt(plaintext: string, context?: Record<string, string>) {
    if (context?.['purpose'] === 'proxy_final_response' && this.responseEncryptFailures > 0) {
      this.responseEncryptFailures -= 1;
      throw new Error('simulated response KMS failure');
    }
    return {
      ciphertext: Buffer.from(JSON.stringify({ plaintext, context })).toString('base64'),
      keyRef: 'proxy-test-key',
    };
  }

  async decrypt(ciphertext: string, context?: Record<string, string>) {
    if (!this.decryptAvailable) throw new Error('CMEK decrypt access revoked');
    const envelope = JSON.parse(Buffer.from(ciphertext, 'base64').toString()) as {
      plaintext: string;
      context?: Record<string, string>;
    };
    if (JSON.stringify(envelope.context) !== JSON.stringify(context))
      throw new Error('AAD mismatch');
    return envelope.plaintext;
  }
}

export interface ProxyPostgresFixture {
  db: Database;
  repository: ProxyOperationRepository;
  operationService: ProxyOperationService;
  kms: ContextBoundTestKms;
  services: Services;
  ids: {
    operatorId: string;
    agentId: string;
    passportJti: string;
    serviceId: string;
    connectionId: string;
    provider: string;
    authorityBindingId: string;
    authorityBindingClaimId: string;
    authorityReceiverId: string;
    authorityReceiverProfileId: string;
  };
  upstreamAttempts: { count: number };
  upstreamResponse: { status: number; headers: Record<string, string>; body: unknown };
  close(): Promise<void>;
}

export async function createProxyPostgresFixture(): Promise<ProxyPostgresFixture> {
  const databaseUrl = proxyFixtureDatabaseUrl;
  if (!isDedicatedProxyFixtureDatabase(databaseUrl)) {
    throw new Error('A dedicated proxy fixture database is required');
  }
  const db = createDb(databaseUrl);
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const ids = {
    operatorId: `op_proxy_${suffix}`,
    agentId: `agt_proxy_${suffix}`,
    passportJti: `pas_proxy_${suffix}`,
    serviceId: `svc_proxy_${suffix}`,
    connectionId: `scon_proxy_${suffix}`,
    provider: `proxytest_${suffix}`,
    authorityBindingId: `abn_proxy_${suffix}`,
    authorityBindingClaimId: `pc_binding_proxy_${suffix}`,
    authorityReceiverId: `rcv_proxy_${suffix}`,
    authorityReceiverProfileId: `apv_proxy_${suffix}`,
  };
  await db.insert(operators).values({
    id: ids.operatorId,
    email: `${ids.operatorId}@test.invalid`,
    api_key_hash: `hash_${suffix}`,
  });
  await db
    .insert(agents)
    .values({ id: ids.agentId, operator_id: ids.operatorId, name: 'Proxy test agent' });
  await db.insert(serviceCatalog).values({
    id: ids.serviceId,
    provider: ids.provider,
    name: 'Proxy test provider',
    description: 'Transaction-safe proxy PostgreSQL fixture',
    oauth_auth_url: 'https://auth.example.invalid',
    oauth_token_url: 'https://token.example.invalid',
    scopes_available: ['write'],
  });
  await db.insert(serviceConnections).values({
    id: ids.connectionId,
    operator_id: ids.operatorId,
    service_id: ids.serviceId,
    provider: ids.provider,
    scopes: ['write'],
    credential_ref: 'proxy-test-key',
    credential_encrypted: 'not-a-real-credential',
    credential_version: 1,
    allowed_hosts: ['api.example.invalid'],
  });
  await db.insert(passports).values({
    jti: ids.passportJti,
    operator_id: ids.operatorId,
    agent_id: ids.agentId,
    session_id: `ses_${suffix}`,
    expires_at: new Date(Date.now() + 60 * 60 * 1000),
  });
  const authorityHash = (label: string) => `sha256:${sha256(`${label}:${suffix}`)}`;
  const authorityExpiry = new Date(Date.now() + 60 * 60 * 1000);
  await db.insert(passportClaims).values({
    claim_id: ids.authorityBindingClaimId,
    operator_id: ids.operatorId,
    type: 'authority_binding',
    body_json: { binding_id: ids.authorityBindingId, binding_version: 1, status: 'active' },
    claim_hash: authorityHash('binding-claim'),
    signature: 'proxy-fixture-signature',
  });
  await db.insert(authorityPrincipals).values({
    id: `prn_proxy_${suffix}`,
    operator_id: ids.operatorId,
    kind: 'person',
    label_encrypted: 'proxy-fixture-principal',
  });
  await db.insert(authorityReceivers).values({
    id: ids.authorityReceiverId,
    managed_by_operator_id: ids.operatorId,
    mode: 'proxy_bridge',
    canonical_identifier: `proxy-fixture:${suffix}`,
    display_name: 'Proxy fixture receiver',
    proxy_service_connection_id: ids.connectionId,
    status: 'active',
    verified_at: new Date(),
  });
  await db.insert(authorityProfileVersions).values({
    id: ids.authorityReceiverProfileId,
    owner_operator_id: ids.operatorId,
    profile_kind: 'receiver',
    profile_key: `proxy-fixture-${suffix}`,
    version: 1,
    receiver_id: ids.authorityReceiverId,
    schema_uri: 'urn:stack:test:proxy-receiver',
    schema_version: '1',
    adapter_key: 'stack.proxy.test',
    adapter_version: 1,
    config_json: {},
    content_hash: authorityHash('receiver-profile'),
    status: 'active',
    activated_at: new Date(),
  });
  await db
    .update(authorityReceivers)
    .set({ current_profile_version_id: ids.authorityReceiverProfileId })
    .where(eq(authorityReceivers.id, ids.authorityReceiverId));
  await db.insert(authorityBindings).values({
    id: ids.authorityBindingId,
    version: 1,
    operator_id: ids.operatorId,
    principal_id: `prn_proxy_${suffix}`,
    agent_id: ids.agentId,
    agent_key_thumbprint: authorityHash('agent-key'),
    receiver_id: ids.authorityReceiverId,
    receiver_profile_version_id: ids.authorityReceiverProfileId,
    mission_ids: [],
    lineage_root_id: ids.authorityBindingId,
    lineage_root_version: 1,
    delegation_depth: 0,
    purpose_code: 'test.proxy',
    purpose_statement_encrypted: 'proxy-fixture-purpose',
    purpose_hash: authorityHash('purpose'),
    scope_encrypted: 'proxy-fixture-scope',
    scope_hash: authorityHash('scope'),
    approval_policy_encrypted: 'proxy-fixture-approval',
    approval_policy_hash: authorityHash('approval'),
    disclosure_policy_encrypted: 'proxy-fixture-disclosure',
    disclosure_policy_hash: authorityHash('disclosure'),
    delegation_policy: { allow_further_delegation: false, max_delegation_depth: 0 },
    delegation_policy_hash: authorityHash('delegation'),
    proof_set_hash: authorityHash('proof-set'),
    valid_from: new Date(),
    expires_at: authorityExpiry,
    status: 'active',
    claim_id: ids.authorityBindingClaimId,
    activated_at: new Date(),
  });

  const repository = new ProxyOperationRepository(db);
  const approvalRepository = new IntentApprovalRepository(db);
  const authorityRepository = new AuthorityRepository(db);
  const kms = new ContextBoundTestKms();
  const operationService = new ProxyOperationService(repository, kms as unknown as KmsService);
  const upstreamAttempts = { count: 0 };
  const upstreamResponse = {
    status: 201,
    headers: { 'content-type': 'application/json' },
    body: { id: 'created_once' } as unknown,
  };
  const services = {
    proxyOperation: operationService,
    serviceConnection: {
      retrieveCredentialPinnedByConnectionId: async () => ({
        provider: ids.provider,
        service_id: ids.serviceId,
        connection_id: ids.connectionId,
        credential_version: 1,
        credential: 'test-secret',
        allowed_hosts: ['api.example.invalid'],
      }),
    },
    proxy: {
      validatePrepared: async () => null,
      resolveAuthHeaders: () => ({ authorization: 'Bearer test-secret' }),
      forwardPrepared: async () => {
        upstreamAttempts.count += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return {
          kind: 'response' as const,
          response: upstreamResponse,
        };
      },
    },
    detector: {
      scanOutput: async () => ({ match: null, redactedBody: null }),
    },
    approvalGate: {
      reserveForDispatch: async (approvalId: string, ownerHash: string, transaction: never) =>
        approvalRepository.markReserved(approvalId, ownerHash, transaction),
      markConsumed: async (approvalId: string, ownerHash: string, transaction: never) =>
        approvalRepository.markConsumed(approvalId, ownerHash, transaction),
    },
    authority: {
      claimRuntimeAuthorityDispatch: async (
        operatorId: string,
        useId: string,
        transaction: never,
      ) => {
        const claimed = await authorityRepository.claimAuthorityUseDispatched(
          operatorId,
          useId,
          new Date(),
          transaction,
        );
        if (!claimed) throw new Error('authority use dispatch ownership was not acquired');
      },
    },
  } as unknown as Services;

  return {
    db,
    repository,
    operationService,
    kms,
    services,
    ids,
    upstreamAttempts,
    upstreamResponse,
    async close() {
      await db.transaction(async (transaction) => {
        // This fixture is restricted to dedicated acceptance databases. Disable
        // append-only triggers only inside cleanup so its evidence can be removed.
        await transaction.execute(sql`set local session_replication_role = replica`);
        await transaction
          .delete(proxyOperationReplacementAcknowledgements)
          .where(eq(proxyOperationReplacementAcknowledgements.operator_id, ids.operatorId));
        await transaction
          .delete(proxyOperationEvidence)
          .where(eq(proxyOperationEvidence.operator_id, ids.operatorId));
        await transaction
          .delete(proxyOperationAttempts)
          .where(eq(proxyOperationAttempts.operator_id, ids.operatorId));
        await transaction
          .delete(proxyOperations)
          .where(eq(proxyOperations.operator_id, ids.operatorId));
      });
      await db
        .delete(proxyAccountingReceipts)
        .where(eq(proxyAccountingReceipts.operator_id, ids.operatorId));
      await db.transaction(async (transaction) => {
        await transaction.execute(
          sql`select set_config('stack.operator_erasure_id', ${ids.operatorId}, true)`,
        );
        await transaction
          .delete(intentApprovals)
          .where(eq(intentApprovals.operator_id, ids.operatorId));
        await transaction
          .delete(authorityUses)
          .where(eq(authorityUses.operator_id, ids.operatorId));
        await transaction
          .delete(passportAuthorityBindings)
          .where(eq(passportAuthorityBindings.operator_id, ids.operatorId));
        await transaction
          .delete(authorityBindings)
          .where(eq(authorityBindings.operator_id, ids.operatorId));
        await transaction
          .delete(authorityReceivers)
          .where(eq(authorityReceivers.managed_by_operator_id, ids.operatorId));
        await transaction
          .delete(authorityPrincipals)
          .where(eq(authorityPrincipals.operator_id, ids.operatorId));
      });
      await db.delete(passportClaims).where(eq(passportClaims.operator_id, ids.operatorId));
      await db.delete(passports).where(eq(passports.operator_id, ids.operatorId));
      await db.delete(serviceConnections).where(eq(serviceConnections.operator_id, ids.operatorId));
      await db.delete(agents).where(eq(agents.operator_id, ids.operatorId));
      await db.delete(operators).where(eq(operators.id, ids.operatorId));
      await db.delete(serviceCatalog).where(eq(serviceCatalog.id, ids.serviceId));
      await db.$client.end();
    },
  };
}

export type ProxyFixtureAccountabilityMode = 'standard' | 'logged' | 'enforced';

interface ProxyExecutionVariant {
  mode?: ProxyFixtureAccountabilityMode;
  passportJti?: string;
  authorityUseId?: string;
  authorityExecutionState?: string;
  authorityRefs?: unknown[];
  gate?: { skipped: boolean; approvalId?: string; replayOnly?: boolean };
}

export function proxyExecutionInput(
  fixture: ProxyPostgresFixture,
  operationKey: string,
  variant: ProxyExecutionVariant = {},
) {
  const evaluationCommitmentHash = `sha256:${sha256(`evaluation:${operationKey}`)}`;
  return {
    services: fixture.services,
    requestInput: {
      service: fixture.ids.provider,
      url: 'https://api.example.invalid/v1/write',
      method: 'POST' as const,
      headers: { 'content-type': 'application/json' },
      body: { amount: 100 },
    },
    operationKey,
    operatorId: fixture.ids.operatorId,
    agentId: fixture.ids.agentId,
    passportJti: variant.passportJti ?? fixture.ids.passportJti,
    ...(variant.authorityUseId ? { authorityUseId: variant.authorityUseId } : {}),
    ...(variant.authorityExecutionState
      ? { authorityExecutionState: variant.authorityExecutionState }
      : {}),
    gate: variant.gate ?? { skipped: true },
    connection: {
      provider: fixture.ids.provider,
      service_id: fixture.ids.serviceId,
      connection_id: fixture.ids.connectionId,
      credential_version: 1,
      proxy_enabled: true,
      allowed_hosts: ['api.example.invalid'],
    },
    scope: { scopes: ['write'] },
    intentServices: [fixture.ids.provider],
    discloseTo: [],
    authorityRefs: variant.authorityRefs ?? [],
    accounting: {
      operatorId: fixture.ids.operatorId,
      operationKey,
      evaluationCommitmentHash,
      period: '2099-12',
      cents: 0,
      obligationId: `obl_${sha256(operationKey).slice(0, 32)}`,
    },
    detectorContext: { accountabilityMode: variant.mode ?? 'standard' } as never,
    postResponse: {
      accountability: variant.mode ?? 'standard',
      missionIds: [],
      auditContext: {
        trace_id: `trace_${operationKey}`,
        span_id: `span_${operationKey}`,
        operator_id: fixture.ids.operatorId,
        agent_id: fixture.ids.agentId,
        passport_jti: variant.passportJti ?? fixture.ids.passportJti,
      },
      startedAt: Date.now(),
    },
  };
}

export async function createProxyConcurrencyScenario(
  fixture: ProxyPostgresFixture,
  operationKey: string,
  mode: ProxyFixtureAccountabilityMode,
  authorityBearing: boolean,
) {
  const caseSuffix = sha256(`${fixture.ids.operatorId}:${operationKey}`).slice(0, 24);
  const passportJti = `pas_proxy_case_${caseSuffix}`;
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
  await fixture.db.insert(passports).values({
    jti: passportJti,
    operator_id: fixture.ids.operatorId,
    agent_id: fixture.ids.agentId,
    session_id: `ses_proxy_case_${caseSuffix}`,
    expires_at: expiresAt,
  });

  let approvalId: string | undefined;
  if (mode === 'enforced') {
    const intentClaimId = `pc_intent_${caseSuffix}`;
    approvalId = `ia_proxy_${caseSuffix}`;
    await fixture.db.insert(passportClaims).values({
      claim_id: intentClaimId,
      passport_id: passportJti,
      operator_id: fixture.ids.operatorId,
      type: 'intent_claim',
      body_json: { accountability_mode: mode, services: [fixture.ids.provider] },
      claim_hash: `sha256:${sha256(`intent:${operationKey}`)}`,
      signature: 'proxy-fixture-signature',
    });
    await fixture.db.insert(intentApprovals).values({
      id: approvalId,
      operator_id: fixture.ids.operatorId,
      agent_id: fixture.ids.agentId,
      passport_jti: passportJti,
      intent_claim_id: intentClaimId,
      status: 'approved',
      expires_at: expiresAt,
    });
  }

  let authorityUseId: string | undefined;
  let authorityRefs: unknown[] = [];
  if (authorityBearing) {
    authorityUseId = `aus_proxy_${caseSuffix}`;
    await fixture.db.insert(passportAuthorityBindings).values({
      passport_jti: passportJti,
      operator_id: fixture.ids.operatorId,
      binding_id: fixture.ids.authorityBindingId,
      binding_version: 1,
      binding_claim_id: fixture.ids.authorityBindingClaimId,
    });
    await fixture.db.insert(authorityUses).values({
      id: authorityUseId,
      operator_id: fixture.ids.operatorId,
      binding_id: fixture.ids.authorityBindingId,
      binding_version: 1,
      passport_jti: passportJti,
      agent_id: fixture.ids.agentId,
      agent_key_thumbprint: `sha256:${sha256(`agent-key:${fixture.ids.agentId}`)}`,
      receiver_id: fixture.ids.authorityReceiverId,
      receiver_profile_version_id: fixture.ids.authorityReceiverProfileId,
      receiver_request_id: `proxy-request-${caseSuffix}`,
      action_uri: 'https://api.example.invalid/v1/write',
      resource_hash: `sha256:${sha256(`resource:${operationKey}`)}`,
      request_hash: `sha256:${sha256(`request:${operationKey}`)}`,
      effective_scope_hash: `sha256:${sha256(`scope:${operationKey}`)}`,
      proof_set_hash: `sha256:${sha256(`proof:${operationKey}`)}`,
      disclosure_manifest: [],
      verification_mode: 'proxy_mediated',
      proof_strength: 'proxy_stack_enforced',
      status: 'authorized',
      authorized_at: new Date(),
    });
    authorityRefs = [
      {
        binding_id: fixture.ids.authorityBindingId,
        binding_version: 1,
        binding_claim_id: fixture.ids.authorityBindingClaimId,
        binding_digest: `sha256:${sha256(`binding:${fixture.ids.authorityBindingId}`)}`,
        receiver_id: fixture.ids.authorityReceiverId,
        receiver_profile_version_id: fixture.ids.authorityReceiverProfileId,
        expires_at: Math.floor(expiresAt.getTime() / 1000),
      },
    ];
  }

  return {
    mode,
    authorityBearing,
    passportJti,
    approvalId,
    authorityUseId,
    input: proxyExecutionInput(fixture, operationKey, {
      mode,
      passportJti,
      authorityUseId,
      authorityExecutionState: authorityUseId ? 'authorized' : undefined,
      authorityRefs,
      gate: approvalId ? { skipped: false, approvalId } : { skipped: true },
    }),
  };
}
