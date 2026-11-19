import { describe, expect, it, vi } from 'vitest';
import type { FastifyRequest } from 'fastify';
import type { ControlSocketRuntime } from '@stack/vault';
import { decideControl } from '../control-decision.js';
import { HostedDecider, NoneDecider } from './deciders.js';
import { ControlDecisionEngine } from './engine.js';
import type { Decider } from './types.js';

/**
 * What the decider adds to a checked action's path, measured over the real
 * `decideControl` and engine with the network, the database and the wallet
 * stubbed to answer at once. So the figure is STACK's own work per action:
 * reading the cached socket, the controls decision, building and hashing the
 * request, the decider, and handing the slim row off. The database-backed
 * figure with the real wallet meter is measured in the end-to-end suite.
 *
 * The bounds are deliberately generous (a shared CI machine is noisy); the
 * numbers are printed so a regression shows well before it breaks a bound.
 */

const ITERATIONS = 20_000;
const WARMUP = 2_000;

function socket(over: Partial<ControlSocketRuntime> = {}): ControlSocketRuntime {
  return { socketId: 'csk_1', modeSetting: 'auto', decisionUrl: null, decisionStatus: 'unverified', timeoutMs: 1500, onUnavailable: 'refuse', checkedTypes: null, ...over };
}

function services(mode: ControlSocketRuntime, controlsOn: boolean, remote?: Decider) {
  const engine = new ControlDecisionEngine({
    sockets: { runtime: async () => mode },
    repo: { insertDecision: async () => {} },
    controls: { controlsEnabled: async () => controlsOn },
    audit: { write: vi.fn(async () => 'aud') } as never,
    none: new NoneDecider(),
    hosted: new HostedDecider([]),
    remote: remote ?? new NoneDecider(),
    charge: async () => {},
    chargeDecision: async () => {},
  });
  return { controlDecisions: engine, accountSubscriptions: {} } as never;
}

const request = { id: 'req', operatorId: 'op_bench', headers: {} } as unknown as FastifyRequest;
const input = {
  action: 'email.send' as const, scope: 'account' as const, accountId: 'acct_1', agentId: 'agt_1',
  runtime: { passportJti: 'pas_1', missionId: 'ms_1' },
  target: { recipients: [{ address: 'someone@example.test', domain: 'example.test' }], recipient_count: 1 },
};

async function measure(run: () => Promise<void>): Promise<{ meanUs: number; p50Us: number; p99Us: number }> {
  for (let i = 0; i < WARMUP; i += 1) await run();
  const samples = new Float64Array(ITERATIONS);
  for (let i = 0; i < ITERATIONS; i += 1) {
    const start = performance.now();
    await run();
    samples[i] = (performance.now() - start) * 1000;
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const mean = sorted.reduce((sum, v) => sum + v, 0) / sorted.length;
  return { meanUs: mean, p50Us: sorted[Math.floor(sorted.length * 0.5)]!, p99Us: sorted[Math.floor(sorted.length * 0.99)]! };
}

describe('the decider adds little to an action', () => {
  it('NoneDecider (no controls): a cached read and nothing else', async () => {
    const s = services(socket({ modeSetting: 'none' }), false);
    const result = await measure(() => decideControl(s, request, input));
    console.info(`[latency] none decider      mean ${result.meanUs.toFixed(1)} us, p50 ${result.p50Us.toFixed(1)} us, p99 ${result.p99Us.toFixed(1)} us per action`);
    expect(result.meanUs).toBeLessThan(500);
    expect(result.p99Us).toBeLessThan(5_000);
  });

  it('automatic choice with controls off is as cheap', async () => {
    const s = services(socket(), false);
    const result = await measure(() => decideControl(s, request, input));
    console.info(`[latency] controls off      mean ${result.meanUs.toFixed(1)} us, p50 ${result.p50Us.toFixed(1)} us, p99 ${result.p99Us.toFixed(1)} us per action`);
    expect(result.meanUs).toBeLessThan(500);
    expect(result.p99Us).toBeLessThan(5_000);
  });

  it('HostedDecider (controls on): build and hash the request, decide, hand off the row', async () => {
    const s = services(socket(), true);
    const result = await measure(() => decideControl(s, request, input));
    console.info(`[latency] hosted decider    mean ${result.meanUs.toFixed(1)} us, p50 ${result.p50Us.toFixed(1)} us, p99 ${result.p99Us.toFixed(1)} us per action`);
    expect(result.meanUs).toBeLessThan(2_000);
    expect(result.p99Us).toBeLessThan(10_000);
  });
});
