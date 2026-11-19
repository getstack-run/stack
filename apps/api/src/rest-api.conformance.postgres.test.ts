import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bootBuiltEngine, type BuiltEngine } from './test/built-engine.js';
import { isDedicatedStackTestDatabase } from './test/dedicated-test-database.js';
import { createOwnDatabase, type OwnDatabase } from './test/own-database.js';
import { REPO_ROOT } from './test/route-scan.js';

/**
 * The `rest-api` suite of the conformance kit (spec/conformance), run against the BUILT self-managed engine, started the
 * way the engine image starts it, exactly as an outside party would point the kit at their own server: the envelope, the
 * reading of a request, the refusal of a credential, the governance step-up end to end (the person at the machine decides
 * the approval with the engine's own command), a 402 of an install without a licence, and the cost cap on a model call
 * on the customer's own key (which the engine ignores).
 *
 * Needs `pnpm --filter @stack/api build`, a dedicated test database (DATABASE_URL, migrated) and Redis (REDIS_URL).
 * The engine runs on a database of its own, made and dropped here: a booted install moves every operator of its
 * database to the contract plan.
 */

const databaseUrl = process.env['DATABASE_URL'];
const redisUrl = process.env['REDIS_URL'] ?? process.env['STACK_TEST_REDIS_URL'];
const enabled = isDedicatedStackTestDatabase(databaseUrl) && Boolean(redisUrl);

type Kit = { runRestApiSuite(options: Record<string, unknown>): Promise<{ results: Array<{ id: string; level: string; status: string; detail?: string }>; conforms: boolean }>; formatReport(report: unknown): string };

describe.runIf(enabled)('the built engine against the rest-api conformance suite', { timeout: 300_000 }, () => {
  let engine: BuiltEngine;
  let own: OwnDatabase;
  let kit: Kit;

  const call = async (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await fetch(`${engine.baseUrl}${path}`, {
      method,
      headers: { 'content-type': 'application/json', authorization: `Bearer ${engine.apiKey}`, ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    return { status: res.status, body: JSON.parse(text) as Record<string, any>, text };
  };

  beforeAll(async () => {
    kit = (await import(pathToFileURL(join(REPO_ROOT, 'spec', 'conformance', 'src', 'index.mjs')).href)) as Kit;
    own = await createOwnDatabase(databaseUrl, 'restapi');
    engine = await bootBuiltEngine(own.url, redisUrl!);
  }, 280_000);

  afterAll(async () => {
    await engine?.stop();
    await own?.drop();
  });

  it('conforms, with every check run but the refusals of a customer\'s controls (held to the same checks in refusals-wire.test.ts)', async () => {
    const report = await kit.runRestApiSuite({
      url: engine.baseUrl,
      apiKey: engine.apiKey,
      approve: (approvalId: string) => engine.approve(approvalId),
      probes: {
        // An install with no licence key turns an enterprise feature away with 402.
        payment: { method: 'POST', path: '/v1/team/members', body: { email: 'conformance@corp.example', name: 'C', role: 'admin' }, code: 'LICENCE_REQUIRED' },
        // A model gateway call on the customer's own key: the engine ignores the cap there and answers the call itself. The
        // call is the engine's own usage list, so no provider is ever reached.
        costCap: { mode: 'own_key_ignored', method: 'GET', path: '/v1/llm/usage' },
      },
      timeoutMs: 30_000,
    });
    expect(report.conforms, kit.formatReport(report)).toBe(true);
    expect(report.results.filter((r) => r.status === 'fail'), kit.formatReport(report)).toEqual([]);
    // M01 is skipped in this mode: a server that ignores the cap on the customer's own key does not read it.
    expect(report.results.filter((r) => r.status === 'skip').map((r) => r.id).sort()).toEqual(['C01', 'C02', 'M01']);
    expect(report.results.filter((r) => r.status === 'pass').length).toBe(24);
    // The suite registered test agents to ask for approvals of an unblock; it retires them when it ends (a deleted agent
    // stays in the list as revoked, and its name is free again).
    const agents = (await call('GET', '/v1/agents')).body as unknown as Array<{ name: string; status: string }>;
    const made = agents.filter((agent) => agent.name.startsWith('conformance-'));
    expect(made).toHaveLength(2);
    expect(made.filter((agent) => agent.status !== 'revoked').map((agent) => agent.name)).toEqual([]);
  });
});
