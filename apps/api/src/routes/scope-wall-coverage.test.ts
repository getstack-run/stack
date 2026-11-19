import { describe, it, expect } from 'vitest';
import { engineRoutes } from '../test/route-scan.js';
import { defineScopeWallClassification } from './scope-wall-coverage.checks.js';
import { authoritySource } from './stage-flow/authority-source.js';
import { flowSource } from './stage-flow/flow-source.js';

/**
 * Complete mediation.
 *
 * The three gates that decide what a call may CARRY (closed-operation policy,
 * the data-flow rule, parameter constraints) ran on /v1/proxy and nowhere
 * else. The LLM gateway is the higher-volume door and checked only which
 * provider the passport could reach, so a scope that was closed for proxy
 * calls was open for LLM calls.
 *
 * Both routes now call `enforceScopeWall`. Two things can silently undo that,
 * and neither would fail an ordinary test:
 *
 *   1. Deleting the call from one route. The route keeps working. It just
 *      stops enforcing.
 *   2. Moving the call BELOW credential retrieval or the upstream forward.
 *      The gate still runs, but the credential has already been decrypted or
 *      the request has already left. A refusal after the fact is not a
 *      refusal.
 *
 * So the placement is pinned structurally, the same way the entity_observation
 * emission is.
 */

const read = (f: string) => engineRoutes.read(f);

/** Every route file that reaches an external service on a passport's behalf. */
const WALLED_ROUTES = ['proxy.ts', 'llm.ts'];

/** Every route that hands content from one agent to another: it carries provenance. */
const PROVENANCE_ROUTES = ['dropoffs.ts', 'a2a.ts'];

/** A walled route's source; the LLM gateway and proxy are composed from stage modules, read in execution order. */
const readWalled = (f: string) =>
  f === 'llm.ts' ? flowSource('llm') : f === 'proxy.ts' ? flowSource('proxy') : read(f);

describe('scope wall coverage', () => {
  for (const file of WALLED_ROUTES) {
    it(`${file} runs the wall`, () => {
      expect(
        readWalled(file).includes('enforceScopeWall('),
        `${file} reaches an external service on a passport's behalf but no longer runs the ` +
          'scope wall. Policy, data-flow and constraint enforcement are silently off for it.',
      ).toBe(true);
    });
  }

  it('llm.ts runs the wall before it retrieves a credential', () => {
    const src = flowSource('llm');
    const wall = src.indexOf('enforceScopeWall(');
    const credential = src.indexOf('retrieveCredentialByConnectionId(');
    expect(wall).toBeGreaterThan(-1);
    expect(credential).toBeGreaterThan(-1);
    expect(
      wall < credential,
      'the scope wall now runs AFTER credential retrieval - a refused call has already had its ' +
        'credential decrypted',
    ).toBe(true);
  });

  it('an image on the customer\'s own key runs the wall, then the prompt scan, before the key is read or anything is forwarded', () => {
    const src = read('llm.ts').replace(/\r\n/g, '\n');
    const handler = src.slice(src.indexOf('export function makeImageHandler('), src.indexOf('export async function anthropicImages('));
    const order = ['beginAgentRuntime(', 'enforceProviderScope(', 'scanInboundMessages(', 'decideModelCall(', 'redactUserPii(', 'retrieveProviderCredential(', 'forwardImageResponse('].map((call) => handler.indexOf(call));
    expect(order.every((at) => at > -1), 'makeImageHandler lost a gate').toBe(true);
    expect([...order].sort((a, b) => a - b), 'makeImageHandler runs its gates out of order').toEqual(order);
  });

  it('llm.ts runs the wall before it forwards anything upstream', () => {
    const src = flowSource('llm');
    const wall = src.indexOf('enforceScopeWall(');
    const forward = src.indexOf('services.llmGateway.forward');
    expect(forward).toBeGreaterThan(-1);
    expect(
      wall < forward,
      'the scope wall now runs AFTER the upstream forward - the request has already left',
    ).toBe(true);
  });

  it('proxy.ts runs the wall before it executes the request', () => {
    const src = flowSource('proxy');
    const wall = src.indexOf('enforceScopeWall(');
    const forward = src.indexOf('services.proxy.forward(');
    expect(wall).toBeGreaterThan(-1);
    expect(forward).toBeGreaterThan(-1);
    expect(wall < forward).toBe(true);
  });

  // Hand-offs used to be exempt ("drop-offs stay inside STACK"). That was the
  // hole: content read by one agent left through
  // another, and the second agent's record said it had read nothing. A hand-off
  // route is now classified as CARRYING PROVENANCE: the payload is matched
  // against the depositor's Mission before it is stored, and the collector's
  // Mission records the original sources before custody transfers. Behaviour is
  // proven in lib/provenance.test.ts; placement is pinned here.
  for (const file of PROVENANCE_ROUTES) {
    it(`${file} computes provenance before it deposits`, () => {
      const src = read(file);
      const provenance = src.indexOf('computeDepositProvenance(');
      const deposit = src.indexOf('services.dropoff.deposit(');
      expect(provenance, `${file} no longer records where a hand-off's content came from`).toBeGreaterThan(-1);
      expect(deposit).toBeGreaterThan(-1);
      expect(provenance < deposit, `${file} stores the hand-off before its provenance is known`).toBe(true);
      expect(src.replace(/\r\n/g, '\n')).toMatch(/services\.dropoff\.deposit\([\s\S]*?provenance as unknown as Record<string, unknown>,\s*\)/);
    });
  }

  it('dropoffs.ts records inherited provenance on the collector inside the collect transaction', () => {
    const src = read('dropoffs.ts');
    const region = src.slice(src.indexOf("'/v1/dropoffs/:id/collect',"));
    const collect = region.indexOf('services.dropoff.collectWithProvenance(');
    const record = region.indexOf('recordCollectedProvenance(');
    const audit = region.indexOf('services.audit.write(');
    expect(collect).toBeGreaterThan(-1);
    expect(record, "collection no longer passes the hand-off's sources to the collector").toBeGreaterThan(collect);
    expect(record < audit, 'provenance must be recorded before the custody transfer commits').toBe(true);
  });
});

defineScopeWallClassification(engineRoutes, {
  walled: WALLED_ROUTES,
  provenance: PROVENANCE_ROUTES,
  other: {
    'intents.ts': 'simulate and submit reason ABOUT a call; neither makes one',
  },
  exempt: {
    'proxy-operations.ts':
      'operation lookup reads prior state; Stripe reconciliation uses an immutable stored marker ' +
      'and cannot submit a new delegated action',
    'inbound.ts': 'inbound is a receiver; its one outbound hop is the forward_url guard',
    'inbound-webhooks.ts': 'configuration only, no upstream call on a passport',
    'intents.ts': 'simulate and submit reason ABOUT a call; neither makes one',
    'passports.ts': 'passport lifecycle; reaches no upstream',
    'scan.ts': 'scans content the caller supplies; reaches no upstream',
    'credentials.ts':
      'hands the raw credential to the caller instead of calling upstream itself, so there ' +
      'is no request for the wall to inspect. This was the one real second way out: an agent ' +
      'with credential_access other than proxy_only fetches the secret and calls the provider ' +
 'directly, outside every gate. It is shut by the default, not by this file - ' +
      'made proxy_only the base posture (migration 0033 + AgentService.register), so the ' +
      'route now refuses unless an operator deliberately chose `direct`.',
    'authority.ts':
      'native presentations are not general service calls: the authority binding pins the ' +
      'receiver, profile, agent key, domain action, exact request hash and disclosure policy ' +
      'before the protocol adapter can deliver anything',
  },
  // authority.ts declares the routes; its handlers live in authority-flows/.
  sourceOf: (file) => (file === 'authority.ts' ? authoritySource() : undefined),
});
