import { Redis } from 'ioredis';
import postgres from 'postgres';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
// The kit is plain JavaScript with no declarations.
// @ts-expect-error TS7016
import * as conformanceKit from '../../../spec/conformance/src/index.mjs';
import { isDedicatedStackTestDatabase } from './test/dedicated-test-database.js';
import { createOwnDatabase, type OwnDatabase } from './test/own-database.js';
import { startEngine, type EngineHandle } from './test/engine-process.js';

/**
 * The engine's own HTTP surface against the conformance kit (`spec/conformance`): the built self-managed server is
 * booted the way the engine image boots it, and every suite that tests a server runs against it. A person's
 * approval is given with the install's command line (`stack-engine approvals approve`), as an install's owner does.
 *
 * The suites are the specifications' own tests (agent sign-in and key enrollment, fleet enrollment, the workload
 * exchange, the OAuth server profile, Passport verification, revocation and delegation). They are slow on purpose:
 * the server rate-limits enrollment, issue and verify, and the kit waits for each window.
 *
 * Needs `pnpm --filter @stack/api build`, a dedicated test database (DATABASE_URL, migrated) and Redis (REDIS_URL).
 * The install runs on a database of its own, made and dropped here: a booted install moves every operator of its
 * database to the contract plan.
 */

const databaseUrl = process.env['DATABASE_URL'];
const redisUrl = process.env['REDIS_URL'] ?? process.env['STACK_TEST_REDIS_URL'];
const enabled = isDedicatedStackTestDatabase(databaseUrl) && Boolean(redisUrl);

type Report = { suite: string; conforms: boolean; failed: number; warnings: number; passed: number; skipped: number };
type Kit = Record<string, (options: unknown) => Promise<Report>> & { formatReport: (report: Report) => string };

describe.runIf(enabled)('the engine against the conformance kit', { timeout: 900_000 }, () => {
  let engine: EngineHandle;
  let own: OwnDatabase;
  let kit: Kit;
  let headers: Record<string, string>;
  const approve = (id: string) => engine.approve(id);

  beforeAll(async () => {
    kit = conformanceKit as unknown as Kit;
    own = await createOwnDatabase(databaseUrl, 'identity');
    engine = await startEngine({ databaseUrl: own.url, redisUrl: redisUrl! });
    headers = { authorization: `Bearer ${engine.apiKey}` };
  }, 240_000);

  afterAll(async () => {
    await engine?.stop();
    await own?.drop();
  });

  const conforms = (report: Report, skipped = 0) => {
    expect(report.failed, kit.formatReport(report)).toBe(0);
    expect(report.warnings, kit.formatReport(report)).toBe(0);
    expect(report.skipped, kit.formatReport(report)).toBe(skipped);
    expect(report.passed).toBeGreaterThan(0);
  };

  it('enrolls agent keys: challenge, proof of possession, a person\'s approval, tickets, rotation and the published key set', async () => {
    conforms(await kit['runAgentEnrollmentSuite']!({ baseUrl: engine.baseUrl, headers, approve }));
  });

  it('verifies agent JWTs as the specification says, over HTTP, including a single use of every token', async () => {
    const { registerAgent, enrollAgent, enrollmentClient, presenterFromServer } = kit as unknown as {
      registerAgent: (client: unknown) => Promise<string>;
      enrollAgent: (client: unknown, agentId: string) => Promise<{ privateJwk: object }>;
      enrollmentClient: (options: unknown) => unknown;
      presenterFromServer: (options: unknown) => unknown;
    };
    const client = enrollmentClient({ baseUrl: engine.baseUrl, headers, approve });
    const agentId = await registerAgent(client);
    const enrolled = await enrollAgent(client, agentId);
    conforms(await kit['runAgentJwtVerifierSuite']!(presenterFromServer({ baseUrl: engine.baseUrl, agentId, privateJwk: enrolled.privateJwk })));
  });

  it('enrolls fleet workers through a provisioner agent', async () => {
    conforms(await kit['runFleetEnrollmentSuite']!({ baseUrl: engine.baseUrl, headers, approve }));
  });

  it('refuses workload exchanges that need no trust configuration, with the codes of the specification', async () => {
    conforms(await kit['runWorkloadExchangeSuite']!({ baseUrl: engine.baseUrl }));
  });

  it('serves the OAuth server profile', async () => {
    conforms(await kit['runOAuthSuite']!({ baseUrl: engine.baseUrl }));
  });

  describe('Passports', () => {
    let sql: ReturnType<typeof postgres>;
    let subscriber: Redis;
    beforeAll(() => {
      sql = postgres(own.url, { max: 2 });
      subscriber = new Redis(redisUrl!);
    });
    afterAll(async () => {
      await sql?.end({ timeout: 5 });
      subscriber?.disconnect();
    });

    it('verifies online, revokes, publishes on stack:revoked and narrows delegation', async () => {
      const me = await fetch(`${engine.baseUrl}/v1/operators/me`, { headers });
      const operatorId = ((await me.json()) as { id: string }).id;
      const suffix = Date.now().toString(36);
      const serviceId = `svc_conf_${suffix}`;
      const connectionId = `scon_conf_${suffix}`;
      await sql`INSERT INTO services(id, provider, name, description, oauth_auth_url, oauth_token_url, scopes_available)
        VALUES (${serviceId}, ${`conformance_${suffix}`}, 'Conformance', 'Conformance', 'https://conformance.example/oauth', 'https://conformance.example/token', '["read","write"]')`;
      await sql`INSERT INTO service_connections(id, operator_id, service_id, provider, scopes, credential_ref, credential_encrypted, allowed_hosts)
        VALUES (${connectionId}, ${operatorId}, ${serviceId}, ${`conformance_${suffix}`}, '["read","write"]', 'conformance', ${Buffer.from('{"access_token":"x"}').toString('base64')}, '["conformance.example"]')`;
      const revocations = {
        subscribe: async (onEvent: (event: unknown) => void) => {
          await subscriber.subscribe('stack:revoked');
          subscriber.on('message', (_channel, message) => {
            try {
              onEvent(JSON.parse(message));
            } catch {
              /* a message that is not JSON is not an event */
            }
          });
          return async () => {
            await subscriber.unsubscribe('stack:revoked');
          };
        },
      };
      const connection = {
        id: connectionId,
        scopes: ['read', 'write'],
        grantTo: async (agentId: string) => {
          await sql`INSERT INTO agent_service_grants(id, agent_id, service_connection_id, scopes)
            VALUES (${`asg_conf_${agentId.slice(-8)}`}, ${agentId}, ${connectionId}, '["read","write"]')`;
        },
      };
      conforms(await kit['runPassportOnlineSuite']!({ baseUrl: engine.baseUrl, headers, approve, revocations, connection }));
    });
  });
});
