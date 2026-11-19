import { afterAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, jwtVerify, SignJWT, type CryptoKey } from 'jose';
import { eq, sql } from 'drizzle-orm';
import {
  agents,
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
  canonicalize,
  createDb,
  operators,
  passportAuthorityBindings,
  passportClaims,
  passports,
  receiverTransactionReceipts,
  sha256 as rawSha256,
} from '@stack/shared';
import {
  AuthorityRepository,
  AuthorityService,
  authorityAgentKeyThumbprint,
  type AuthorityClaimIssuer,
  type AuthorityServiceDeps,
} from '../../../../packages/vault/src/index.js';
import type { AuthorityDbTransaction } from '../../../../packages/vault/src/services/authority-service.js';
import { createAuthorityModules } from '../../../../packages/vault/src/services/authority/modules.js';
import { isDedicatedStackTestDatabase } from '../test/dedicated-test-database.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const hasDedicatedDatabase = isDedicatedStackTestDatabase(DATABASE_URL);
const describeWithDedicatedDb = hasDedicatedDatabase ? describe : describe.skip;
const now = new Date('2026-08-21T18:30:00.000Z');
const expires = new Date('2099-08-21T18:30:00.000Z');
const digest = (value: string) => `sha256:${rawSha256(value)}`;

type Db = ReturnType<typeof createDb>;

function kms() {
  return {
    async encrypt(plaintext: string) {
      return { ciphertext: `test:${Buffer.from(plaintext).toString('base64url')}`, keyRef: 'test' };
    },
    async decrypt(ciphertext: string) {
      if (!ciphertext.startsWith('test:')) throw new Error('ciphertext is unavailable');
      return Buffer.from(ciphertext.slice(5), 'base64url').toString();
    },
  };
}

async function insertLegacyClaim(
  executor: Db | AuthorityDbTransaction,
  operatorId: string,
  claimId: string,
  type: string,
  body: Record<string, unknown>,
  passportId: string | null = null,
) {
  const signature = `fixture-signature:${claimId}`;
  await (executor as Db).insert(passportClaims).values({
    claim_id: claimId,
    passport_id: passportId,
    type,
    body_json: { type, ...body },
    claim_hash: digest(signature),
    signature,
    operator_id: operatorId,
  });
}

function signedTombstoneIssuer(
  db: Db,
  privateKey: CryptoKey,
  suffix: string,
): AuthorityClaimIssuer {
  let sequence = 0;
  return {
    registerAuthorityErasureTombstone: async ({ operatorId, tombstone, erasedAt }, transaction) => {
      const claimId = `pc_tomb_${suffix}_${++sequence}`;
      const payload = {
        type: 'authority_erasure_tombstone',
        target_kind: tombstone.target_kind,
        target_id: tombstone.target_id,
        target_version: tombstone.target_version,
        prior_artifact_digest: tombstone.prior_artifact_digest,
        prior_claim_digest: tombstone.prior_claim_digest,
        tombstone_digest: tombstone.tombstone_digest,
        erased_at: Math.floor(erasedAt.getTime() / 1000),
      };
      const token = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'EdDSA', kid: `erase-${suffix}` })
        .setIssuer(operatorId)
        .setSubject(`stack://operator/${operatorId}`)
        .setJti(claimId)
        .setIssuedAt(Math.floor(erasedAt.getTime() / 1000))
        .sign(privateKey);
      const executor = (transaction ?? db) as Db;
      await executor.insert(passportClaims).values({
        claim_id: claimId,
        passport_id: null,
        type: 'authority_erasure_tombstone',
        body_json: payload,
        claim_hash: digest(token),
        signature: token,
        operator_id: operatorId,
      });
      return { claimId, claimHash: digest(token) };
    },
  } as AuthorityClaimIssuer;
}

async function cleanup(db: Db, operatorId: string) {
  if (!hasDedicatedDatabase) throw new Error('Cleanup requires the isolated acceptance database');
  await db.transaction(async (tx) => {
    // Only fixture teardown bypasses append-only triggers; the tests run normally.
    await tx.execute(sql`set local session_replication_role = replica`);
    await tx.execute(
      sql`delete from receiver_transaction_receipts where operator_id=${operatorId}`,
    );
    await tx.execute(sql`delete from authority_presentations where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_approval_decisions where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_approval_requests where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_uses where operator_id=${operatorId}`);
    await tx.execute(sql`delete from passport_authority_bindings where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_binding_proofs where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_bindings where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_proof_dependencies where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_proofs where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_idempotency_keys where operator_id=${operatorId}`);
    await tx.execute(sql`delete from authority_receiver_keys where receiver_id in
      (select id from authority_receivers where managed_by_operator_id=${operatorId})`);
    await tx.execute(
      sql`delete from authority_profile_versions where owner_operator_id=${operatorId}`,
    );
    await tx.execute(
      sql`delete from authority_receivers where managed_by_operator_id=${operatorId}`,
    );
    await tx.execute(sql`delete from authority_principals where operator_id=${operatorId}`);
    await tx.execute(sql`delete from passport_claims where operator_id=${operatorId}`);
    await tx.execute(sql`delete from passports where operator_id=${operatorId}`);
    await tx.execute(sql`delete from agents where operator_id=${operatorId}`);
    await tx.delete(operators).where(eq(operators.id, operatorId));
  });
}

describeWithDedicatedDb('authority erasure PostgreSQL acceptance', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const operatorId = `op_erase_${suffix}`;
  const principalId = `prn_erase_${suffix}`;
  const receiverId = `rcv_erase_${suffix}`;
  const agentId = `agt_erase_${suffix}`;
  const profileId = `apv_proof_${suffix}`;
  const receiverProfileId = `apv_receiver_${suffix}`;
  const affected = {
    sourceProof: `prf_source_${suffix}`,
    derivedProof: `prf_derived_${suffix}`,
    binding: `abn_affected_${suffix}`,
    passport: `pas_affected_${suffix}`,
    use: `aus_affected_${suffix}`,
    presentation: `prs_affected_${suffix}`,
    receipt: `rtr_affected_${suffix}`,
  };
  const sibling = {
    proof: `prf_sibling_${suffix}`,
    binding: `abn_sibling_${suffix}`,
    passport: `pas_sibling_${suffix}`,
    use: `aus_sibling_${suffix}`,
    presentation: `prs_sibling_${suffix}`,
    receipt: `rtr_sibling_${suffix}`,
  };

  afterAll(async () => {
    await cleanup(db, operatorId);
  });

  it('scrubs the affected persisted graph, preserves signed non-PII tombstones, denies old retries, and leaves siblings usable', async () => {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA', {
      crv: 'Ed25519',
      extractable: true,
    });
    const publicJwk = (await exportJWK(publicKey)) as { kty: string; crv: string; x: string };
    const keyThumbprint = authorityAgentKeyThumbprint(publicJwk);
    await cleanup(db, operatorId);
    await db
      .insert(operators)
      .values({
        id: operatorId,
        email: `${operatorId}@test.invalid`,
        api_key_hash: `hash_${suffix}`,
      });
    await db
      .insert(agents)
      .values({ id: agentId, operator_id: operatorId, name: 'Erasure agent', pubkey: publicJwk });
    await db.insert(authorityPrincipals).values({
      id: principalId,
      operator_id: operatorId,
      kind: 'person',
      label_encrypted: 'test:personally-identifying-label',
      status: 'active',
    });
    await db.insert(authorityReceivers).values({
      id: receiverId,
      managed_by_operator_id: operatorId,
      mode: 'native',
      canonical_identifier: `https://${suffix}.receiver.invalid`,
      display_name: 'Erasure receiver',
      status: 'pending',
    });
    await db.insert(authorityProfileVersions).values([
      {
        id: profileId,
        owner_operator_id: operatorId,
        profile_kind: 'proof',
        profile_key: `proof-${suffix}`,
        version: 1,
        schema_uri: 'urn:test:proof',
        schema_version: '1',
        adapter_key: 'test',
        adapter_version: 1,
        config_json: {
          proof_kind: 'identity',
          accepted_native_formats: ['test+jws'],
          freshness: { maximum_age_seconds: 3600, live_status_required: false },
        },
        content_hash: digest(`proof-profile-${suffix}`),
        status: 'active',
        activated_at: now,
      },
      {
        id: receiverProfileId,
        owner_operator_id: operatorId,
        profile_kind: 'receiver',
        profile_key: `receiver-${suffix}`,
        version: 1,
        receiver_id: receiverId,
        schema_uri: 'urn:test:receiver',
        schema_version: '1',
        adapter_key: 'stack.direct_post.jwt',
        adapter_version: 1,
        config_json: {
          audience: 'https://receiver.invalid',
          delivery: { endpoint: 'https://receiver.invalid/callback' },
        },
        content_hash: digest(`receiver-profile-${suffix}`),
        status: 'active',
        activated_at: now,
      },
    ]);
    await db
      .update(authorityReceivers)
      .set({ status: 'active', current_profile_version_id: receiverProfileId, verified_at: now })
      .where(eq(authorityReceivers.id, receiverId));
    const receiptKeyId = `rky_receipt_${suffix}`;
    await db.insert(authorityReceiverKeys).values({
      id: receiptKeyId,
      receiver_id: receiverId,
      key_id: `receipt-${suffix}`,
      use: 'receipt_signing',
      algorithm: 'EdDSA',
      public_jwk: publicJwk,
      thumbprint: keyThumbprint,
      status: 'active',
      valid_from: now,
    });

    const proofClaimIds = [affected.sourceProof, affected.derivedProof, sibling.proof].map(
      (id) => `pc_${id}`,
    );
    for (let index = 0; index < proofClaimIds.length; index++) {
      await insertLegacyClaim(
        db,
        operatorId,
        proofClaimIds[index]!,
        'external_proof_verification',
        {
          proof_id: [affected.sourceProof, affected.derivedProof, sibling.proof][index],
          proof_version: 1,
          status: 'active',
        },
      );
    }
    const proofValue = (id: string, claimId: string) => ({
      id,
      version: 1,
      operator_id: operatorId,
      subject_principal_id: principalId,
      profile_version_id: profileId,
      proof_kind: 'identity',
      source_kind: 'external_native',
      issuer_identifier: 'issuer:test',
      issuer_key_thumbprint: digest('issuer-key'),
      schema_uri: 'urn:test:proof',
      schema_version: '1',
      native_format: 'test+jws',
      native_evidence_encrypted: `test:sensitive-native-${id}`,
      normalized_facts_encrypted: `test:sensitive-facts-${id}`,
      native_evidence_hash: digest(`native-${id}`),
      normalized_facts_hash: digest(`facts-${id}`),
      verification_method: 'jws',
      verifier_identifier: 'test',
      verifier_version: '1',
      verified_at: now,
      valid_from: now,
      expires_at: expires,
      last_status_result: 'valid',
      last_status_checked_at: now,
      status_fresh_until: expires,
      status: 'active',
      claim_id: claimId,
    });
    await db
      .insert(authorityProofs)
      .values([
        proofValue(affected.sourceProof, proofClaimIds[0]!),
        proofValue(affected.derivedProof, proofClaimIds[1]!),
        proofValue(sibling.proof, proofClaimIds[2]!),
      ]);
    await db.insert(authorityProofDependencies).values({
      derived_proof_id: affected.derivedProof,
      derived_proof_version: 1,
      operator_id: operatorId,
      source_proof_id: affected.sourceProof,
      source_proof_version: 1,
      relation: 'verified_from',
    });

    const bindingClaims = [`pc_${affected.binding}`, `pc_${sibling.binding}`];
    await insertLegacyClaim(db, operatorId, bindingClaims[0]!, 'authority_binding', {
      binding_id: affected.binding,
      binding_version: 1,
      status: 'active',
    });
    await insertLegacyClaim(db, operatorId, bindingClaims[1]!, 'authority_binding', {
      binding_id: sibling.binding,
      binding_version: 1,
      status: 'active',
    });
    const bindingValue = (id: string, claimId: string) => ({
      id,
      version: 1,
      operator_id: operatorId,
      principal_id: principalId,
      agent_id: agentId,
      agent_key_thumbprint: keyThumbprint,
      receiver_id: receiverId,
      receiver_profile_version_id: receiverProfileId,
      mission_ids: [],
      lineage_root_id: id,
      lineage_root_version: 1,
      delegation_depth: 0,
      purpose_code: 'test.erase',
      purpose_statement_encrypted: `test:sensitive-purpose-${id}`,
      purpose_hash: digest(`purpose-${id}`),
      scope_encrypted: `test:sensitive-scope-${id}`,
      scope_hash: digest(`scope-${id}`),
      approval_policy_encrypted: `test:sensitive-approval-${id}`,
      approval_policy_hash: digest(`approval-${id}`),
      disclosure_policy_encrypted: `test:sensitive-disclosure-${id}`,
      disclosure_policy_hash: digest(`disclosure-${id}`),
      delegation_policy: { allow_further_delegation: false, max_delegation_depth: 0 },
      delegation_policy_hash: digest(`delegation-${id}`),
      proof_set_hash: digest(`proof-set-${id}`),
      valid_from: now,
      expires_at: expires,
      status: 'active',
      claim_id: claimId,
      activated_at: now,
    });
    await db
      .insert(authorityBindings)
      .values([
        bindingValue(affected.binding, bindingClaims[0]!),
        bindingValue(sibling.binding, bindingClaims[1]!),
      ]);
    await db.insert(authorityBindingProofs).values([
      {
        binding_id: affected.binding,
        binding_version: 1,
        proof_id: affected.derivedProof,
        proof_version: 1,
        operator_id: operatorId,
        role: 'principal_identity',
        group_key: 'principal',
        required: true,
      },
      {
        binding_id: sibling.binding,
        binding_version: 1,
        proof_id: sibling.proof,
        proof_version: 1,
        operator_id: operatorId,
        role: 'principal_identity',
        group_key: 'principal',
        required: true,
      },
    ]);

    await db.insert(passports).values([
      {
        jti: affected.passport,
        operator_id: operatorId,
        agent_id: agentId,
        session_id: `ses_${suffix}_affected`,
        expires_at: expires,
      },
      {
        jti: sibling.passport,
        operator_id: operatorId,
        agent_id: agentId,
        session_id: `ses_${suffix}_sibling`,
        expires_at: expires,
      },
    ]);
    await db.insert(passportAuthorityBindings).values([
      {
        passport_jti: affected.passport,
        operator_id: operatorId,
        binding_id: affected.binding,
        binding_version: 1,
        binding_claim_id: bindingClaims[0]!,
      },
      {
        passport_jti: sibling.passport,
        operator_id: operatorId,
        binding_id: sibling.binding,
        binding_version: 1,
        binding_claim_id: bindingClaims[1]!,
      },
    ]);
    const useValue = (
      ids: typeof affected | typeof sibling,
      bindingId: string,
      passportJti: string,
    ) => ({
      id: ids.use,
      operator_id: operatorId,
      binding_id: bindingId,
      binding_version: 1,
      passport_jti: passportJti,
      agent_id: agentId,
      agent_key_thumbprint: keyThumbprint,
      receiver_id: receiverId,
      receiver_profile_version_id: receiverProfileId,
      receiver_request_id: `request-${ids.use}`,
      action_uri: 'urn:test:erase',
      request_hash: digest(`request-${ids.use}`),
      effective_scope_hash: digest(`scope-${ids.use}`),
      proof_set_hash: digest(`proof-${ids.use}`),
      disclosure_manifest: [],
      verification_mode: 'native_receiver',
      proof_strength: 'native_stack_attestation',
      status: 'dispatched',
      authorized_at: now,
      dispatched_at: now,
    });
    await db
      .insert(authorityUses)
      .values([
        useValue(affected, affected.binding, affected.passport),
        useValue(sibling, sibling.binding, sibling.passport),
      ]);
    await insertLegacyClaim(db, operatorId, `pc_use_${affected.use}`, 'authority_use', {
      authority_use_id: affected.use,
      binding_id: affected.binding,
      binding_version: 1,
      request_hash: digest(`request-${affected.use}`),
      action_uri: 'urn:test:erase',
      status: 'dispatched',
    });
    await insertLegacyClaim(db, operatorId, `pc_use_${sibling.use}`, 'authority_use', {
      authority_use_id: sibling.use,
      binding_id: sibling.binding,
      binding_version: 1,
      request_hash: digest(`request-${sibling.use}`),
      action_uri: 'urn:test:erase',
      status: 'dispatched',
    });
    const presentationValue = (ids: typeof affected | typeof sibling, bindingId: string) => ({
      id: ids.presentation,
      operator_id: operatorId,
      authority_use_id: ids.use,
      binding_id: bindingId,
      binding_version: 1,
      receiver_id: receiverId,
      receiver_profile_version_id: receiverProfileId,
      request_signing_key_id: receiptKeyId,
      response_encryption_key_id: receiptKeyId,
      nonce_hash: digest(`nonce-${ids.presentation}`),
      signed_request_hash: digest(`request-${ids.presentation}`),
      request_payload_encrypted: `test:sensitive-request-${ids.presentation}`,
      requested_fact_ids: ['private.fact'],
      presentation_jti_hash: digest(`jti-${ids.presentation}`),
      payload_hash: digest(`payload-${ids.presentation}`),
      disclosure_manifest: [{ fact_id: 'private.fact', mode: 'exact_private' }],
      proof_refs: [],
      status: 'delivered',
      expires_at: expires,
      prepared_at: now,
      delivered_at: now,
    });
    await db
      .insert(authorityPresentations)
      .values([
        presentationValue(affected, affected.binding),
        presentationValue(sibling, sibling.binding),
      ]);
    const receiptClaims = [`pc_${affected.receipt}`, `pc_${sibling.receipt}`];
    await insertLegacyClaim(db, operatorId, receiptClaims[0]!, 'receiver_transaction_receipt', {
      receipt_id: affected.receipt,
    });
    await insertLegacyClaim(db, operatorId, receiptClaims[1]!, 'receiver_transaction_receipt', {
      receipt_id: sibling.receipt,
    });
    const receiptValue = (ids: typeof affected | typeof sibling, claimId: string) => ({
      id: ids.receipt,
      operator_id: operatorId,
      authority_use_id: ids.use,
      presentation_id: ids.presentation,
      receiver_id: receiverId,
      receiver_profile_version_id: receiverProfileId,
      receiver_key_id: receiptKeyId,
      receipt_jti_hash: digest(`receipt-jti-${ids.receipt}`),
      native_format: 'application/jwt',
      native_receipt_encrypted: `test:sensitive-receipt-${ids.receipt}`,
      receipt_hash: digest(`receipt-${ids.receipt}`),
      request_hash: digest(`request-${ids.use}`),
      result_hash: digest(`result-${ids.use}`),
      outcome: 'accepted',
      verified_at: now,
      received_at: now,
      claim_id: claimId,
    });
    await db
      .insert(receiverTransactionReceipts)
      .values([
        receiptValue(affected, receiptClaims[0]!),
        receiptValue(sibling, receiptClaims[1]!),
      ]);
    await db.insert(authorityIdempotencyKeys).values({
      id: `aik_create_${suffix}`,
      operator_id: operatorId,
      route_key: 'proof.import',
      idempotency_key_hash: digest('original-key'),
      request_hash: digest('original-request'),
      state: 'completed',
      resource_type: 'proof',
      resource_id: affected.sourceProof,
      response_status: 201,
      response_body: { id: affected.sourceProof },
      workflow_phase: 'completed',
      workflow_payload_encrypted: 'test:sensitive-original-request',
      expires_at: expires,
    });

    const repo = new AuthorityRepository(db);
    const lockReceiptGraph = (presentationId: string) =>
      repo.atomic((transactionRepo) =>
        transactionRepo.lockReceiptAuthorityGraph(receiverId, presentationId, now),
      );
    await expect(lockReceiptGraph(affected.presentation)).resolves.toMatchObject({
      presentation: { id: affected.presentation },
      use: { id: affected.use },
      binding: { id: affected.binding },
    });
    await expect(lockReceiptGraph(sibling.presentation)).resolves.toMatchObject({
      presentation: { id: sibling.presentation },
      use: { id: sibling.use },
      binding: { id: sibling.binding },
    });

    const invalidApprovalId = `apr_invalid_${suffix}`;
    await db.insert(authorityApprovalRequests).values({
      id: invalidApprovalId,
      operator_id: operatorId,
      binding_id: affected.binding,
      binding_version: 1,
      authority_use_id: affected.use,
      phase: 'action',
      group_key: 'expired-approval',
      request_hash: digest(`request-${affected.use}`),
      challenge_hash: digest(`approval-${affected.use}`),
      required_weight: 1,
      collected_weight: 0,
      reject_mode: 'any_reject',
      status: 'pending',
      expires_at: now,
    });
    await expect(lockReceiptGraph(affected.presentation)).rejects.toThrow(
      'authority graph is no longer valid',
    );
    await expect(lockReceiptGraph(sibling.presentation)).resolves.toMatchObject({
      use: { id: sibling.use },
    });
    await db
      .delete(authorityApprovalRequests)
      .where(eq(authorityApprovalRequests.id, invalidApprovalId));

    await db
      .update(passports)
      .set({ revoked_at: now, revoked_reason: 'acceptance-test' })
      .where(eq(passports.jti, affected.passport));
    await expect(lockReceiptGraph(affected.presentation)).rejects.toThrow(
      'authority graph is no longer valid',
    );
    await expect(lockReceiptGraph(sibling.presentation)).resolves.toMatchObject({
      use: { id: sibling.use },
    });
    await db
      .update(passports)
      .set({ revoked_at: null, revoked_reason: null })
      .where(eq(passports.jti, affected.passport));

    await db
      .update(authorityPresentations)
      .set({ expires_at: now })
      .where(eq(authorityPresentations.id, affected.presentation));
    await expect(lockReceiptGraph(affected.presentation)).rejects.toThrow(
      'authority graph is no longer valid',
    );
    await expect(lockReceiptGraph(sibling.presentation)).resolves.toMatchObject({
      use: { id: sibling.use },
    });
    await db
      .update(authorityPresentations)
      .set({ expires_at: expires })
      .where(eq(authorityPresentations.id, affected.presentation));

    await db
      .update(authorityPresentations)
      .set({ status: 'accepted', request_payload_encrypted: null })
      .where(eq(authorityPresentations.id, affected.presentation));
    await expect(lockReceiptGraph(affected.presentation)).rejects.toThrow(
      'authority graph is no longer valid',
    );
    await expect(lockReceiptGraph(sibling.presentation)).resolves.toMatchObject({
      use: { id: sibling.use },
    });
    await db
      .update(authorityPresentations)
      .set({
        status: 'delivered',
        request_payload_encrypted: `test:sensitive-request-${affected.presentation}`,
      })
      .where(eq(authorityPresentations.id, affected.presentation));
    await expect(lockReceiptGraph(affected.presentation)).resolves.toMatchObject({
      use: { id: affected.use },
    });

    const publisher = { publishAuthorityRevocations: vi.fn(async () => undefined) };
    const serviceDeps: AuthorityServiceDeps = {
      repo,
      kms: kms(),
      claimIssuer: signedTombstoneIssuer(db, privateKey, suffix),
      receiverRequestAudience: 'https://api.test',
      passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
      approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
      receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
      passportRevocationPublisher: publisher,
      legacyIdentityResolver: {} as AuthorityServiceDeps['legacyIdentityResolver'],
      now: () => now,
    };
    const service = new AuthorityService(serviceDeps);
    const tombstone = await service.eraseProof(operatorId, affected.sourceProof, `erase-${suffix}`);
    expect(tombstone).toMatchObject({
      target_kind: 'proof',
      target_id: affected.sourceProof,
      tombstone_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    });
    expect(publisher.publishAuthorityRevocations).toHaveBeenCalledWith(
      [affected.passport],
      'authority_proof_erased',
    );

    const [
      proofRows,
      bindingRows,
      presentationRows,
      receiptRows,
      passportRows,
      ledgerRows,
      tombstoneRows,
    ] = await Promise.all([
      db.select().from(authorityProofs).where(eq(authorityProofs.operator_id, operatorId)),
      db.select().from(authorityBindings).where(eq(authorityBindings.operator_id, operatorId)),
      db
        .select()
        .from(authorityPresentations)
        .where(eq(authorityPresentations.operator_id, operatorId)),
      db
        .select()
        .from(receiverTransactionReceipts)
        .where(eq(receiverTransactionReceipts.operator_id, operatorId)),
      db.select().from(passports).where(eq(passports.operator_id, operatorId)),
      db
        .select()
        .from(authorityIdempotencyKeys)
        .where(eq(authorityIdempotencyKeys.operator_id, operatorId)),
      db
        .select()
        .from(passportClaims)
        .where(eq(passportClaims.type, 'authority_erasure_tombstone')),
    ]);
    for (const id of [affected.sourceProof, affected.derivedProof]) {
      expect(proofRows.find((row) => row.id === id)).toMatchObject({
        status: 'erased',
        native_evidence_encrypted: null,
        normalized_facts_encrypted: null,
        erased_at: now,
        tombstone_hash: expect.stringMatching(/^sha256:/),
        tombstone_claim_id: expect.any(String),
      });
    }
    expect(bindingRows.find((row) => row.id === affected.binding)).toMatchObject({
      status: 'erased',
      purpose_statement_encrypted: null,
      scope_encrypted: null,
      approval_policy_encrypted: null,
      disclosure_policy_encrypted: null,
    });
    expect(presentationRows.find((row) => row.id === affected.presentation)).toMatchObject({
      status: 'erased',
      request_payload_encrypted: null,
    });
    expect(receiptRows.find((row) => row.id === affected.receipt)).toMatchObject({
      native_receipt_encrypted: null,
      erased_at: now,
    });
    expect(passportRows.find((row) => row.jti === affected.passport)?.revoked_at).toEqual(now);
    expect(ledgerRows.find((row) => row.resource_id === affected.sourceProof)).toMatchObject({
      state: 'completed',
      workflow_phase: 'erased',
      workflow_payload_encrypted: null,
    });

    expect(proofRows.find((row) => row.id === sibling.proof)).toMatchObject({
      status: 'active',
      native_evidence_encrypted: `test:sensitive-native-${sibling.proof}`,
    });
    expect(bindingRows.find((row) => row.id === sibling.binding)).toMatchObject({
      status: 'active',
      scope_encrypted: `test:sensitive-scope-${sibling.binding}`,
    });
    expect(presentationRows.find((row) => row.id === sibling.presentation)).toMatchObject({
      status: 'delivered',
      request_payload_encrypted: `test:sensitive-request-${sibling.presentation}`,
    });
    expect(receiptRows.find((row) => row.id === sibling.receipt)).toMatchObject({
      erased_at: null,
      native_receipt_encrypted: `test:sensitive-receipt-${sibling.receipt}`,
    });
    expect(passportRows.find((row) => row.jti === sibling.passport)?.revoked_at).toBeNull();

    const publicKeyJwk = await exportJWK(publicKey);
    const graphTombstones = tombstoneRows.filter((row) =>
      String(row.body_json.target_id).includes(suffix),
    );
    expect(graphTombstones).toHaveLength(5);
    for (const row of graphTombstones) {
      const verified = await jwtVerify(row.signature, publicKeyJwk, {
        issuer: operatorId,
        subject: `stack://operator/${operatorId}`,
      });
      expect(verified.payload).toMatchObject(row.body_json);
      const serialized = canonicalize(row.body_json);
      expect(serialized).not.toMatch(/sensitive|personal|private\.fact/i);
      expect(row.claim_hash).toBe(digest(row.signature));
    }

    const erasedProof = proofRows.find((row) => row.id === affected.sourceProof)!;
    const { guards } = createAuthorityModules(serviceDeps);
    const decryptFacts = guards.decryptProofFacts.bind(guards);
    await expect(decryptFacts(erasedProof as never)).rejects.toThrow('facts are unavailable');
    await expect(
      repo.idempotent(
        {
          ledgerId: `aik_retry_${suffix}`,
          operatorId,
          operation: 'proof.import',
          idempotencyKey: 'original-key',
          payloadHash: digest('original-request'),
          workflowPayloadEncrypted: 'test:retry',
          responseStatus: 201,
          matchesExistingRequest: async () => true,
        },
        async () => ({ reopened: true }),
      ),
    ).rejects.toThrow('different payload');
  }, 120_000);

  it('rolls the database scrub and tombstone claim back when Redis revocation propagation fails', async () => {
    const failureSuffix = `${suffix}_redis_failure`;
    const failurePrincipal = `prn_${failureSuffix}`;
    const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    await db
      .insert(operators)
      .values({
        id: operatorId,
        email: `${operatorId}@test.invalid`,
        api_key_hash: `hash_${suffix}`,
      })
      .onConflictDoNothing();
    await db.insert(authorityPrincipals).values({
      id: failurePrincipal,
      operator_id: operatorId,
      kind: 'person',
      label_encrypted: 'test:must-survive-rollback',
      status: 'active',
    });
    const service = new AuthorityService({
      repo: new AuthorityRepository(db),
      kms: kms(),
      claimIssuer: signedTombstoneIssuer(db, privateKey, failureSuffix),
      receiverRequestAudience: 'https://api.test',
      passportVerifier: {} as AuthorityServiceDeps['passportVerifier'],
      approvalDecisionVerifier: {} as AuthorityServiceDeps['approvalDecisionVerifier'],
      receiverOriginVerifier: {} as AuthorityServiceDeps['receiverOriginVerifier'],
      passportRevocationPublisher: {
        publishAuthorityRevocations: vi.fn(async () => {
          throw new Error('redis unavailable');
        }),
      },
      legacyIdentityResolver: {} as AuthorityServiceDeps['legacyIdentityResolver'],
      now: () => now,
    });

    await expect(
      service.erasePrincipal(operatorId, failurePrincipal, `erase-${failureSuffix}`),
    ).rejects.toThrow('revocation propagation failed');
    const [principal] = await db
      .select()
      .from(authorityPrincipals)
      .where(eq(authorityPrincipals.id, failurePrincipal));
    expect(principal).toMatchObject({
      status: 'active',
      label_encrypted: 'test:must-survive-rollback',
      erased_at: null,
      tombstone_hash: null,
      tombstone_claim_id: null,
    });
    const tombstones = await db
      .select()
      .from(passportClaims)
      .where(eq(passportClaims.type, 'authority_erasure_tombstone'));
    expect(tombstones.some((row) => String(row.body_json.target_id) === failurePrincipal)).toBe(
      false,
    );
  }, 30_000);
});
