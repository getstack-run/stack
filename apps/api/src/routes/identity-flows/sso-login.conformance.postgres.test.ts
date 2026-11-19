import Fastify, { type FastifyInstance } from 'fastify';
import { eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { LICENCE_FEATURE_LABELS, LicenceRequiredError, SSO_DOMAIN_TRUST_SECONDS, hashApiKey, ids, operators, sha256, ssoDomainRecordName, ssoVerifiedDomains, teamMembers } from '@stack/shared';
import { DnsNameAbsentError, OidcIdpProvider, SsoDomainRepository, SsoDomainService, type DnsTxtResolver } from '@stack/vault';
// The kit is plain JavaScript with no declarations.
// @ts-expect-error TS7016
import * as conformanceKit from '../../../../../spec/conformance/src/index.mjs';
import { createServices, type Services } from '../../config/services.js';
import { hostedFeatureGate, type FeatureGate } from '../../config/licence-service.js';
import { createErrorHandler } from '../../middleware/error-handler.js';
import { isDedicatedStackTestDatabase } from '../../test/dedicated-test-database.js';
import { registerIdentityRoutes } from '../identity.js';

/**
 * The engine's single sign-on against the `sso-login` suite of the conformance kit (spec/sso-login/SPEC.md): the real
 * identity routes on a real Fastify server, the real OpenID provider class, the real repositories, a real Postgres and
 * a real Redis. The kit plays the browser and the customer's identity provider (an address on this machine, so the
 * provider class is given a guard that lets it through and a plain `fetch`: the one thing this test changes is the
 * guard against private addresses, which production applies). The connection is written to the table with the secret
 * wrapped by the install's own KMS, as `POST /v1/identity/oidc/config` would (that route insists on https).
 *
 * Needs a dedicated test database (DATABASE_URL, migrated) and Redis (REDIS_URL).
 */

const databaseUrl = process.env['DATABASE_URL'];
const redisUrl = process.env['REDIS_URL'] ?? process.env['STACK_TEST_REDIS_URL'];
const enabled = isDedicatedStackTestDatabase(databaseUrl) && Boolean(redisUrl);

/** A DNS the test publishes into: what a lookup of the proof record finds, with no name server involved. */
class FakeDns implements DnsTxtResolver {
  readonly records = new Map<string, string[][]>();
  async resolveTxt(name: string): Promise<string[][]> {
    const records = this.records.get(name);
    if (!records) throw new DnsNameAbsentError(name);
    return records;
  }
}

type Report = { results: Array<{ id: string; status: string; level: string; detail?: string }>; conforms: boolean };
type Kit = { runSsoLoginSuite(options: unknown): Promise<Report>; formatReport(report: unknown): string };

describe.runIf(enabled)('the engine single sign-on against the sso-login conformance suite', { timeout: 300_000 }, () => {
  const previousInsecureDevKmsOptIn = process.env['STACK_ALLOW_INSECURE_DEV_KMS'];
  const kit = conformanceKit as unknown as Kit;
  let services: Services;
  let app: FastifyInstance;
  let baseUrl: string;
  let gate: FeatureGate = hostedFeatureGate;
  const operatorId = ids.operator();
  // Another account of the same deployment, for a domain it has verified.
  const otherOperatorId = ids.operator();
  const dns = new FakeDns();

  /**
   * The provider class keeps a provider's discovery document and key set in the shared Redis for a day, keyed on the
   * issuer, and the kit's issuer is an address on this machine at a port the system picks: a document left by an earlier
   * run whose kit sat on the same port is served instead of fetched, and S10 (the deployment fetched both) fails. So the
   * test forgets what is cached for this run's issuer before it connects, and, to keep that honest, first leaves a stale
   * document there as an earlier run would have: the suite conforms only because the cache is cleared.
   */
  async function forgetWhatAnEarlierRunCached(issuer: string) {
    const jwksUri = `${issuer}/jwks`;
    await services.redis.set(`oidc:disc:${sha256(issuer)}`, JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: jwksUri }), 'EX', 3600);
    await services.redis.del(`oidc:disc:${sha256(issuer)}`, `oidc:jwks:${sha256(jwksUri)}`, `oidc:jwks-refetch:${sha256(jwksUri)}`);
  }

  async function connect(slug: string, over: { tier?: string; enabled?: boolean; issuer: string; client_id: string; client_secret: string; redirect_uri: string }) {
    await services.db.insert(operators).values({
      id: operatorId,
      email: `sso-conformance-${Date.now()}@corp.example`,
      api_key_hash: hashApiKey(`sk_live_${ids.operator()}`),
      tier: over.tier ?? 'enterprise',
      status: 'active',
    } as never);
    const { ciphertext } = await services.kms.encrypt(over.client_secret, { operator_id: operatorId, provider: 'oidc' });
    await services.oidcIdpConfigRepo.create({
      id: ids.oidcIdpConfig(),
      operator_id: operatorId,
      display_name: 'Conformance provider',
      issuer_uri: over.issuer,
      client_id: over.client_id,
      client_secret_encrypted: ciphertext,
      audience: null,
      redirect_uri: over.redirect_uri,
      scopes_json: ['openid', 'email', 'profile'],
      claim_mapping_policy_json: null,
      jwks_cache_ttl_seconds: 300,
      allowed_return_origins: null,
      sso_slug: slug,
      sso_login_enabled: over.enabled ?? true,
      default_member_role: 'standard',
      active: true,
    } as never);
  }

  beforeAll(async () => {
    // This fixture uses the development KMS double. Production still fails closed; the opt-in is restored below.
    process.env['STACK_ALLOW_INSECURE_DEV_KMS'] = 'true';
    services = await createServices(null);
    // The install's own gate reads a licence key; this run has the features the flow needs.
    (services as { features: FeatureGate }).features = { ...hostedFeatureGate, has: (feature) => gate.has(feature), require: (feature) => gate.require(feature) };
    // The verified domains run on the real repository and service; only the name server is the test's.
    (services as { ssoDomains: SsoDomainService }).ssoDomains = new SsoDomainService(new SsoDomainRepository(services.db), dns, services.audit);
    const provider = new OidcIdpProvider(services.redis, services.oidcIdpConfigRepo, services.kms, fetch, 'https://stack.corp.example', () => undefined);
    vi.spyOn(services.identity, 'getProvider').mockImplementation(((key: string) => (key === 'oidc' ? provider : undefined)) as never);
    app = Fastify();
    app.setErrorHandler(createErrorHandler());
    registerIdentityRoutes(app, services);
    await app.listen({ port: 0, host: '127.0.0.1' });
    baseUrl = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  }, 120_000);

  afterAll(async () => {
    await app?.close();
    if (services) {
      await services.db.delete(ssoVerifiedDomains).where(inArray(ssoVerifiedDomains.operator_id, [operatorId, otherOperatorId]));
      await services.db.delete(teamMembers).where(eq(teamMembers.operator_id, operatorId));
      await services.db.delete(operators).where(inArray(operators.id, [operatorId, otherOperatorId]));
      await services.redis.quit();
    }
    if (previousInsecureDevKmsOptIn === undefined) delete process.env['STACK_ALLOW_INSECURE_DEV_KMS'];
    else process.env['STACK_ALLOW_INSECURE_DEV_KMS'] = previousInsecureDevKmsOptIn;
  });

  /** Claim a domain for an account, publish its record and have the service verify it, as an administrator would. */
  async function verifyDomain(account: string, domain: string) {
    const { domain: claim } = await services.ssoDomains.add(account, domain);
    dns.records.set(ssoDomainRecordName(domain), [[claim.record.value]]);
    const result = await services.ssoDomains.verify(account, claim.id);
    expect(result.domain.status).toBe('verified');
  }

  it('conforms: a sign-in is the code flow with PKCE, an ID token checked by the profile, a state used once and bound to the browser, and a handoff reference at the end', async () => {
    const report = await kit.runSsoLoginSuite({
      baseUrl,
      configure: async (connection: { issuer: string; client_id: string; client_secret: string; redirect_uri: string; slug: string }) => {
        await forgetWhatAnEarlierRunCached(connection.issuer);
        await connect(connection.slug, connection);
      },
      domains: {
        verified: async ({ domain }: { domain: string }) => verifyDomain(operatorId, domain),
        verifiedElsewhere: async ({ domain }: { domain: string }) => {
          await services.db.insert(operators).values({
            id: otherOperatorId, email: `sso-conformance-other-${Date.now()}@corp.example`, api_key_hash: hashApiKey(`sk_live_${ids.operator()}`), tier: 'enterprise', status: 'active',
          } as never).onConflictDoNothing();
          await verifyDomain(otherOperatorId, domain);
        },
        // The record is gone, and the time the deployment trusts a cached check for has passed.
        recordRemoved: async ({ domain }: { domain: string }) => {
          dns.records.delete(ssoDomainRecordName(domain));
          const past = new Date(Date.now() - (SSO_DOMAIN_TRUST_SECONDS + 600) * 1000);
          await services.db.update(ssoVerifiedDomains).set({ last_confirmed_at: past, last_checked_at: past }).where(eq(ssoVerifiedDomains.domain, domain));
        },
      },
    });
    const notPassed = report.results.filter((r) => r.status !== 'pass');
    expect(notPassed, kit.formatReport(report)).toEqual([]);
    expect(report.results.length).toBe(24);
    expect(report.conforms).toBe(true);
  });

  it('created the people the sign-ins named, once each, at the connection\'s default role, active at once and with no API key', async () => {
    const people = await services.db.select().from(teamMembers).where(eq(teamMembers.operator_id, operatorId));
    expect(people.length).toBeGreaterThanOrEqual(8);
    for (const person of people) {
      expect(person.email).toBe(person.email.trim().toLowerCase());
      expect(person.email.endsWith('example.test')).toBe(true);
      expect(person.role).toBe('standard');
      expect(person.status).toBe('active');
      expect(person.api_key_hash).toBeNull();
      // Bound to the provider's own name for the person on the first sign-in (the kit's issuer is on this machine).
      expect(person.sso_issuer).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
      expect(person.sso_subject).toBeTruthy();
    }
    expect(new Set(people.map((p) => p.email)).size).toBe(people.length);
  });

  it('finds the person by the provider\'s subject within the account: another subject under the same address is refused, a removed person is refused and an unknown address is refused without the provisioning feature', async () => {
    const [existing] = await services.db.select().from(teamMembers).where(eq(teamMembers.operator_id, operatorId)).limit(1);
    const own = { operatorId, issuer: existing!.sso_issuer!, subject: existing!.sso_subject!, emailVerified: true, name: null, defaultRole: 'standard' };
    await expect(services.member.findOrProvisionForSso({ ...own, email: ` ${existing!.email.toUpperCase()} `, allowProvision: false })).resolves.toMatchObject({ provisioned: false, member: { id: existing!.id } });
    await expect(services.member.findOrProvisionForSso({ ...own, subject: 'someone-else', email: existing!.email, allowProvision: true })).rejects.toMatchObject({ code: 'SSO_LOGIN_FAILED' });
    await expect(services.member.findOrProvisionForSso({ ...own, subject: 'nobody', email: 'nobody@example.test', allowProvision: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await services.db.update(teamMembers).set({ status: 'revoked', revoked_at: new Date() }).where(eq(teamMembers.id, existing!.id));
    await expect(services.member.findOrProvisionForSso({ ...own, email: existing!.email, allowProvision: true })).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('turns a start away as the specification says when the licence lacks the feature and when the connection is switched off, and not for the plan', async () => {
    const binding = 'a'.repeat(64);
    const slug = (await services.oidcIdpConfigRepo.findActiveByOperator(operatorId))!.sso_slug!;
    const start = () => fetch(`${baseUrl}/v1/identity/sso/${slug}/start?browser_binding=${binding}`, { redirect: 'manual' });
    expect((await start()).status).toBe(302);

    const licensed = gate;
    gate = {
      ...hostedFeatureGate,
      has: () => false,
      require: (feature) => { throw new LicenceRequiredError(LICENCE_FEATURE_LABELS[feature], { feature, licence: 'none' }); },
    };
    const noLicence = await start();
    const noLicenceCallback = await fetch(`${baseUrl}/v1/identity/oidc/callback?code=a&state=b`, { redirect: 'manual' });
    gate = licensed;
    expect(noLicence.status).toBe(402);
    expect(((await noLicence.json()) as { error: { code: string } }).error.code).toBe('LICENCE_REQUIRED');
    expect(noLicenceCallback.status).toBe(402);

    // No plan gates single sign-on: an account whose row says free starts a sign-in like any other.
    await services.db.update(operators).set({ tier: 'free' }).where(eq(operators.id, operatorId));
    expect((await start()).status).toBe(302);
    await services.db.update(operators).set({ tier: 'enterprise' }).where(eq(operators.id, operatorId));

    await services.oidcIdpConfigRepo.update((await services.oidcIdpConfigRepo.findActiveByOperator(operatorId))!.id, { sso_login_enabled: false });
    const off = await start();
    expect(off.status).toBe(404);
    expect(((await off.json()) as { error: { code: string } }).error.code).toBe('NOT_FOUND');
  });
});
