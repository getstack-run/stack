import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * What an account's agent can reach beyond its own account surfaces.
 *
 *   1. Drop-offs, skill invokes, agent-to-agent calls, intents and authority
 *      delegation stay open to it: none of those producers refuses an agent
 *      for having an account. They admit it like any agent, through the
 *      Mission admission check (beginAgentRuntime) and the approval gate.
 *   2. Granting it a customer's own connection keeps the one-time governance
 *      step-up: the grant route asks for approval on every widening grant
 *      (a first grant always widens), whoever the agent is.
 *   3. The broker to the customer's own systems is not limited by plan: no
 *      controls check on the proxy, credential or connection routes, and the
 *      connection count is unlimited on every plan.
 *
 * The deployment's own producers (skills, connect links) and the plan check are covered by its own tests.
 */

const ROUTES = dirname(fileURLToPath(import.meta.url));
const API_SRC = join(ROUTES, '..');
/** Where a producer is read: the engine's routes. */
const ROUTE_ROOTS = [ROUTES];

function files(path: string): string[] {
  const full = join(ROUTE_ROOTS.find((root) => existsSync(join(root, path))) ?? ROUTES, path);
  if (!statSync(full).isDirectory()) return [full];
  return readdirSync(full)
    .filter((entry) => entry.endsWith('.ts') && !entry.endsWith('.test.ts'))
    .map((entry) => join(full, entry));
}

const code = (file: string) =>
  readFileSync(file, 'utf8').split('\n').filter((line) => !/^\s*(\/\/|\*)/.test(line)).join('\n');

/** Anything that asks whether an agent has an account, or what its owner's plan or controls are. */
const ACCOUNT_REFUSAL = /findOpenAccountByAgent|findNotClosedByAgent|isAccountAgent|accountDetection|agentAccounts\b|controlsEnabled/;

describe('an account agent beyond its account', () => {
  it('reaches drop-offs, skills, A2A, intents and authority delegation like any agent', () => {
    const producers = [
      'dropoffs.ts',
      'a2a.ts',
      'intents.ts',
      'authority.ts',
      'authority-flows',
    ];
    const offenders = producers.flatMap(files)
      .filter((file) => ACCOUNT_REFUSAL.test(code(file)))
      .map((file) => relative(API_SRC, file));
    expect(offenders).toEqual([]);
    // The one admission check those producers share does not look at accounts either.
    expect(ACCOUNT_REFUSAL.test(code(join(API_SRC, 'lib', 'agent-runtime.ts')))).toBe(false);
  });

  it('a connection grant that widens an agent always asks a human first', () => {
    const source = readFileSync(join(ROUTES, 'services.ts'), 'utf8').replace(/\r\n/g, '\n');
    const start = source.indexOf("app.post('/v1/services/grant'");
    expect(start).toBeGreaterThan(-1);
    const block = source.slice(start, source.indexOf('\n  });', start));
    expect(block).toMatch(/const widensAuthority = await services\.serviceConnection\.grantAccessWidens\(/);
    expect(block).toMatch(/if \(widensAuthority\) \{\s*await enforceGovernanceStepUp\(services, request, \{\s*action: 'service_grant_expand'/);
    // Nothing about the agent's account, mode or plan decides whether to ask.
    expect(block).not.toMatch(/account|accountability|controls|tier/i);
  });

  it('the broker to own systems is not gated by plan', () => {
    const broker = ['proxy.ts', 'proxy-call', 'credentials.ts', 'services.ts'];
    const offenders = broker.flatMap(files)
      .filter((file) => /controlsEnabled|TierLimitExceededError|\.tier\s*[!=]==/.test(code(file)))
      .map((file) => relative(API_SRC, file));
    expect(offenders).toEqual([]);
  });
});
