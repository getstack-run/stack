import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';
import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { eq, sql } from 'drizzle-orm';
import {
  spiffeTrustDomains,
  passportClaims,
  passports,
  auditLog,
  agents,
  operators,
  missions,
  ids,
  computePassportClaimHash,
  PASSPORT_DEFAULT_TTL_SECONDS,
} from '@stack/shared';
import { SpiffeSvidValidator, SpiffeWorkloadProvider, type FetchFn } from '@stack/vault';
import { createServices, type Services } from '../config/services.js';


const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

/**
 * P2 integration test — service-composition end-to-end for the SPIFFE
 * consumer. Exercises everything from P1.1 through P1.7 against real
 * Postgres + real Redis + real EdDSA crypto, with a tiny in-process
 * HTTP server publishing the test JWKS.
 *
 * Scope intentionally stops below the Fastify route layer:
 *   - Route wiring is verified by structural + unit tests (P1.7).
 *   - HTTP-surface end-to-end and real-SPIRE attestation are exercised
 *     in P3 (against Docker SPIRE).
 *
 * Local dev stack must be running (Postgres on :5433, Redis on :6380).
 */

const TEST_OPERATOR_ID = `op_p2sp_${Date.now()}`;
const TEST_AGENT_ID = `agt_p2sp_${Date.now()}`;
const TRUST_DOMAIN = 'p2.example';
const SPIFFE_ID = `spiffe://${TRUST_DOMAIN}/wl/orders`;

let services: Services;
let signingKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let publicJwk: JWK;
let jwksServer: Server;
let jwksUrl: string;
let trackedRequests = 0;
// every workload Passport is issued for one live Mission.
let testMissionId: string;

// We swap the validator's fetcher to point at our test JWKS server,
// instead of touching DNS for an external hostname.
let testFetcher: FetchFn;
const previousInsecureDevKmsOptIn = process.env['STACK_ALLOW_INSECURE_DEV_KMS'];

beforeAll(async () => {
  if (!DATABASE_URL) return;
  // This integration fixture intentionally uses the development KMS double.
  // Production still fails closed, and the opt-in is restored after the suite.
  process.env['STACK_ALLOW_INSECURE_DEV_KMS'] = 'true';
  services = await createServices(null);

  // ── Test issuer keypair + JWKS HTTP server ─────────────────────
  const kp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  signingKey = kp.privateKey;
  publicJwk = await exportJWK(kp.publicKey);
  publicJwk.kid = 'p2-test-key';
  publicJwk.use = 'sig';
  publicJwk.alg = 'EdDSA';

  jwksServer = createServer((req, res) => {
    if (req.url === '/jwks.json') {
      trackedRequests++;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys: [publicJwk] }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((resolve) => jwksServer.listen(0, '127.0.0.1', resolve));
  const port = (jwksServer.address() as AddressInfo).port;
  jwksUrl = `http://127.0.0.1:${port}/jwks.json`;

  testFetcher = (input, init) => fetch(input, init);

  // ── Test operator + agent (direct DB inserts to skip flow noise) ──
  await services.db.insert(operators).values({
    id: TEST_OPERATOR_ID,
    email: `${TEST_OPERATOR_ID}@test.local`,
    api_key_hash: `test-hash-${Date.now()}-${Math.random()}`,
  });
  await services.db.insert(agents).values({
    id: TEST_AGENT_ID,
    operator_id: TEST_OPERATOR_ID,
    name: 'p2-spiffe-agent',
    status: 'active',
  });
  testMissionId = (await services.mission.open({
    operatorId: TEST_OPERATOR_ID, intent_summary: 'p2 SPIFFE workload', expiresInSeconds: 3600,
  })).mission_id;
});

afterAll(async () => {
  try {
    await services.db.delete(passportClaims).where(
      sql`${passportClaims.passport_id} IN (SELECT jti FROM passports WHERE operator_id = ${TEST_OPERATOR_ID})`,
    );
    await services.db.delete(passports).where(eq(passports.operator_id, TEST_OPERATOR_ID));
    await services.db.delete(missions).where(eq(missions.operator_id, TEST_OPERATOR_ID));
    await services.db.delete(passportClaims).where(eq(passportClaims.operator_id, TEST_OPERATOR_ID));
    await services.db.delete(spiffeTrustDomains).where(eq(spiffeTrustDomains.operator_id, TEST_OPERATOR_ID));
    await services.db.delete(auditLog).where(eq(auditLog.operator_id, TEST_OPERATOR_ID));
    await services.db.delete(agents).where(eq(agents.id, TEST_AGENT_ID));
    await services.db.delete(operators).where(eq(operators.id, TEST_OPERATOR_ID));
  } catch {
    /* swallow — diagnostic only */
  }
  if (jwksServer) await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
  if (services) await services.redis.quit();
  if (previousInsecureDevKmsOptIn === undefined) {
    delete process.env['STACK_ALLOW_INSECURE_DEV_KMS'];
  } else {
    process.env['STACK_ALLOW_INSECURE_DEV_KMS'] = previousInsecureDevKmsOptIn;
  }
});

beforeEach(async () => {
  // Wipe Redis JWKS cache between tests so fresh-fetch behavior is
  // deterministic.
  const keys = await services.redis.keys('spiffe:jwks:*');
  if (keys.length > 0) await services.redis.del(...keys);
  const lockKeys = await services.redis.keys('spiffe:jwks-refreshing:*');
  if (lockKeys.length > 0) await services.redis.del(...lockKeys);
});

async function signTestSvid(opts: { exp?: number; aud?: string } = {}): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: 'p2-test-key' })
    .setIssuer(`https://spire.${TRUST_DOMAIN}`)
    .setSubject(SPIFFE_ID)
    .setAudience(opts.aud ?? 'https://api.getstack.run/v1/workload/passport')
    .setIssuedAt(nowSec)
    .setExpirationTime(opts.exp ?? nowSec + 600)
    .sign(signingKey);
}

async function ensureTrustDomainConfig() {
  const prior = await services.spiffeTrustDomainRepo.findByOperatorAndTrustDomain(
    TEST_OPERATOR_ID,
    TRUST_DOMAIN,
  );
  if (prior) await services.spiffeTrustDomainRepo.delete(prior.id);
  return services.spiffeTrustDomainRepo.create({
    id: ids.spiffeTrustDomain(),
    operator_id: TEST_OPERATOR_ID,
    trust_domain: TRUST_DOMAIN,
    jwks_uri: jwksUrl,
    audience: 'https://api.getstack.run/v1/workload/passport',
    jwks_cache_ttl_seconds: 300,
    spiffe_id_mapping_policy_json: { [SPIFFE_ID]: { agent_id: TEST_AGENT_ID } },
  });
}

/**
 * Build a SPIFFE provider with a fetcher that points at the test JWKS
 * server and a parse-only URL guard. Production keeps both globalThis.fetch
 * and the real DNS-backed SSRF guard; the test replaces them independently
 * so its local HTTP fixture cannot weaken production defaults.
 */
function buildTestProvider(): SpiffeWorkloadProvider {
  const validator = new SpiffeSvidValidator(
    services.redis,
    services.spiffeTrustDomainRepo,
    testFetcher,
    async (url) => new URL(url),
  );
  return new SpiffeWorkloadProvider(validator);
}

async function mintWorkloadPassport(provider: SpiffeWorkloadProvider, token: string) {
  const cfg = (await services.spiffeTrustDomainRepo.findByOperatorAndTrustDomain(
    TEST_OPERATOR_ID,
    TRUST_DOMAIN,
  ))!;
  const policy = cfg.spiffe_id_mapping_policy_json as Record<string, { agent_id: string }>;
  const accept = await provider.acceptSvid(token, {
    kind: 'spiffe',
    id: cfg.id,
    trust_domain: cfg.trust_domain,
    jwks_uri: cfg.jwks_uri,
    audience: cfg.audience,
    jwks_cache_ttl_seconds: cfg.jwks_cache_ttl_seconds,
    jwks_cached_jwks_json: null,
  });
  const nowSec = Math.floor(Date.now() / 1000);
  const remaining = accept.not_after - nowSec;
  const ttlSeconds = Math.min(remaining, PASSPORT_DEFAULT_TTL_SECONDS);
  const agentId = policy[accept.spiffe_id]!.agent_id;

  const signed = await services.passport.issue(TEST_OPERATOR_ID, {
    agent_id: agentId,
    mission_ids: [testMissionId],
    ttl_seconds: ttlSeconds,
    intent: { summary: `Workload via SPIFFE: ${accept.spiffe_id}`, services: [] },
  });
  const attached = await services.passport.attachClaim(signed.jti, accept.attestation_claim);

  await services.audit.write({
    ctx: {
      trace_id: `t_${signed.jti}`,
      span_id: signed.jti,
      operator_id: TEST_OPERATOR_ID,
      agent_id: agentId,
      passport_jti: signed.jti,
    },
    layer: 'vault',
    action: 'workload.passport.mint',
    outcome: 'success',
  });
  return { signed, attached, ttlSeconds, remaining };
}

// ── Tests ────────────────────────────────────────────────────────

describeWithDb('SPIFFE consumer integration (P2)', () => {
 it('end-to-end: SVID → passport mint + svid_attestation claim attached + audit row binds claim hash', async () => {
    await ensureTrustDomainConfig();
    const provider = buildTestProvider();
    const token = await signTestSvid();

    const { signed, attached, ttlSeconds } = await mintWorkloadPassport(provider, token);

    const passportRow = await services.db.query.passports.findFirst({
      where: eq(passports.jti, signed.jti),
    });
    expect(passportRow).toBeDefined();
    expect(passportRow?.operator_id).toBe(TEST_OPERATOR_ID);
    expect(passportRow?.agent_id).toBe(TEST_AGENT_ID);

    const claimRow = await services.passportClaimsRepo.findByClaimId(attached.claim_id);
    expect(claimRow).toBeDefined();
    expect(claimRow?.passport_id).toBe(signed.jti);
    expect(claimRow?.type).toBe('svid_attestation');
    expect(claimRow?.revoked_at).toBeNull();

    const expectedHash = computePassportClaimHash({
      passport_id: signed.jti,
      type: 'svid_attestation',
      body: claimRow!.body_json as Record<string, unknown>,
    });
    expect(claimRow?.claim_hash).toBe(expectedHash);

    const body = claimRow!.body_json as Record<string, unknown>;
    expect(body['spiffe_id']).toBe(SPIFFE_ID);
    expect(body['trust_domain']).toBe(TRUST_DOMAIN);
    expect(body['svid_format']).toBe('jwt-svid');

    // audit row binds the attached claim hash into the chain
    const mintAuditRow = await services.db.query.auditLog.findFirst({
      where: (log, { and, eq: dEq }) =>
        and(
          dEq(log.operator_id, TEST_OPERATOR_ID),
          dEq(log.passport_jti, signed.jti),
          dEq(log.action, 'workload.passport.mint'),
        ),
    });
    expect(mintAuditRow).toBeDefined();
    expect(mintAuditRow?.passport_claims_at_event).toEqual([attached.claim_hash]);

    // R5 — passport TTL aligns with SVID remaining
    const passportTtlSeconds = Math.floor(
      (passportRow!.expires_at.getTime() - passportRow!.issued_at.getTime()) / 1000,
    );
    expect(passportTtlSeconds).toBeLessThanOrEqual(ttlSeconds + 1);
  });

  it('verifyChain still validates after a chain entry binds an attached claim hash', async () => {
    await ensureTrustDomainConfig();
    const provider = buildTestProvider();
    const token = await signTestSvid();
    await mintWorkloadPassport(provider, token);

    const result = await services.audit.verifyChain(TEST_OPERATOR_ID);
    expect(result.valid).toBe(true);
    expect(result.first_break).toBeUndefined();
    expect(result.total_checked).toBeGreaterThan(0);
  });

 it('explicit: tampering passport_claims_at_event in DB invalidates the chain on verify', async () => {
    await ensureTrustDomainConfig();
    const provider = buildTestProvider();
    const token = await signTestSvid();
    const { signed } = await mintWorkloadPassport(provider, token);

    await services.db
      .update(auditLog)
      .set({ passport_claims_at_event: ['0'.repeat(64)] })
      .where(eq(auditLog.passport_jti, signed.jti));

    const result = await services.audit.verifyChain(TEST_OPERATOR_ID);
    expect(result.valid).toBe(false);
    expect(result.first_break?.reason).toBe('hash_mismatch');
  });

 it('cascade revoking the passport marks the attached claim revoked + writes claim.revoke audit row', async () => {
    await ensureTrustDomainConfig();
    const provider = buildTestProvider();
    const token = await signTestSvid();
    const { signed, attached } = await mintWorkloadPassport(provider, token);

    const revokeResult = await services.passport.revoke({
      jti: signed.jti,
      operatorId: TEST_OPERATOR_ID,
      reason: 'integration-test cascade',
    });

    expect(revokeResult.revoked_claims).toHaveLength(1);
    expect(revokeResult.revoked_claims[0]?.claim_id).toBe(attached.claim_id);
    expect(revokeResult.revoked_claims[0]?.claim_hash).toBe(attached.claim_hash);

    const claimRow = await services.passportClaimsRepo.findByClaimId(attached.claim_id);
    expect(claimRow?.revoked_at).not.toBeNull();
    expect(claimRow?.revoked_reason).toBe('passport_revoked');

    // Mirror what the route handler does on revoke: write per-claim audit rows.
    for (const cl of revokeResult.revoked_claims) {
      await services.audit.write({
        ctx: {
          trace_id: `t_${signed.jti}_revoke`,
          span_id: signed.jti,
          operator_id: TEST_OPERATOR_ID,
          agent_id: TEST_AGENT_ID,
          passport_jti: signed.jti,
        },
        layer: 'vault',
        action: 'claim.revoke',
        outcome: 'success',
        payload_hash: cl.claim_hash,
      });
    }

    const claimRevokeRow = await services.db.query.auditLog.findFirst({
      where: (log, { and, eq: dEq }) =>
        and(
          dEq(log.operator_id, TEST_OPERATOR_ID),
          dEq(log.action, 'claim.revoke'),
          dEq(log.payload_hash, attached.claim_hash),
        ),
    });
    expect(claimRevokeRow).toBeDefined();
  });

  it('R5 — passport TTL caps at SVID remaining when SVID expires sooner than default', async () => {
    await ensureTrustDomainConfig();
    const provider = buildTestProvider();

    const nowSec = Math.floor(Date.now() / 1000);
    const shortLivedSvid = await signTestSvid({ exp: nowSec + 120 });

    const { ttlSeconds, remaining } = await mintWorkloadPassport(provider, shortLivedSvid);
    expect(remaining).toBeLessThan(PASSPORT_DEFAULT_TTL_SECONDS);
    expect(ttlSeconds).toBeLessThanOrEqual(remaining);
    expect(ttlSeconds).toBe(Math.min(remaining, PASSPORT_DEFAULT_TTL_SECONDS));
  });

  it('R3 — JWKS fetch is cached: second mint within TTL does NOT re-fetch upstream', async () => {
    await ensureTrustDomainConfig();
    const provider = buildTestProvider();

    const before = trackedRequests;
    await mintWorkloadPassport(provider, await signTestSvid());
    const afterFirst = trackedRequests;
    expect(afterFirst).toBe(before + 1);

    await mintWorkloadPassport(provider, await signTestSvid());
    const afterSecond = trackedRequests;
    expect(afterSecond).toBe(afterFirst);
  });
});
