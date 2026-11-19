import { describe, it, expect, vi } from 'vitest';
import { collectStrings, contentFingerprints, extractEntities, ServiceUnavailableError } from '@stack/shared';
import {
  computeDepositProvenance,
  llmResponseText,
  recordCollectedProvenance,
  recordInheritedResponse,
  recordLlmResponseProvenance,
} from './provenance.js';

const BANK = { accounts: [{ name: 'Operating', accountNumber: '123456789012', availableBalance: 48213.55 }] };
const bankRow = () => ({
  sourceService: 'mercury',
  entities: extractEntities(BANK, { financial: true }).map((e) => e.entity),
  fingerprints: contentFingerprints(collectStrings(BANK).join(' ')),
});

function services(rows: unknown[] | Error = [], controls = true, belongsToAccount = true) {
  const claims: Array<Record<string, any>> = [];
  const events: Array<Record<string, any>> = [];
  return {
    claims,
    events,
    services: {
      passportClaimsRepo: {
        findObservedContentForFlow: vi.fn(async () => {
          if (rows instanceof Error) throw rows;
          return rows;
        }),
      },
      claimRegistry: { registerClaim: vi.fn(async (c: Record<string, any>) => { claims.push(c); return { claimId: `pc_${claims.length}` }; }) },
      securityEvent: { record: vi.fn(async (e: Record<string, any>) => { events.push(e); }) },
      entitlements: { controlsEnabled: vi.fn(async () => controls) },
      accountDetection: {
        forAgent: vi.fn(async () => (belongsToAccount ? { mode: 'standard', skipL3: true, withhold: false } : null)),
      },
    } as never,
  };
}

const AUDIT = { summary: 'Operating holds $48,213.55 today. Reserve unchanged.' };

describe('hand-off provenance at the API boundary', () => {
  it('matches a deposit against the depositor MISSION and records the original source', async () => {
    const s = services([bankRow()]);
    const provenance = await computeDepositProvenance(s.services, {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'dropoff',
    });
    expect((s.services as any).passportClaimsRepo.findObservedContentForFlow).toHaveBeenCalledWith({
      operatorId: 'op_1', passportId: 'pas_cfo', missionId: 'ms_cfo',
    });
    expect(provenance.sources).toEqual(['mercury']);
  });

  it('refuses the deposit (503) and alarms without content when provenance cannot be established, controls on', async () => {
    const s = services(new Error('connection reset'));
    await expect(computeDepositProvenance(s.services, {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'a2a',
    })).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(s.events).toHaveLength(1);
    expect(s.events[0]!.severity).toBe('critical');
    expect(s.events[0]!.metadata).toEqual({ provenance_unavailable: true, stage: 'a2a_deposit', error: 'Error', failed: 'closed' });
    expect(JSON.stringify(s.events)).not.toContain('48');
  });

  it('writes the collector observations with the ORIGINAL source, never "stack:dropoff"', async () => {
    const depositor = services([bankRow()]);
    const provenance = await computeDepositProvenance(depositor.services, {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'dropoff',
    });
    const collector = services();
    const sources = await recordCollectedProvenance(collector.services, {
      operatorId: 'op_1', collectorAgentId: 'agt_slack', passportJti: 'pas_slack', missionId: 'ms_slack',
      dropoffId: 'dof_1', fromAgentId: 'agt_cfo', payload: AUDIT, provenance: JSON.parse(JSON.stringify(provenance)),
    });
    expect(sources).toEqual(['mercury']);
    expect(collector.claims).toHaveLength(1);
    const claim = collector.claims[0]!;
    expect(claim).toMatchObject({
      passportJti: 'pas_slack', claimType: 'entity_observation', sourceOperationId: 'dropoff:dof_1', sourceRole: 'provenance:mercury:0',
    });
    expect(claim.payload).toMatchObject({ source_service: 'mercury', mission_ref: 'ms_slack', agent_id: 'agt_slack' });
    expect(claim.payload.entity_types).toContain('money_amount');
  });

  it('an LLM response inherits the sources its prompt carried, with money recognised for a bank source', async () => {
    const s = services();
    await recordInheritedResponse(s.services, {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', sources: ['mercury'],
      text: 'Quarterly treasury summary for the leadership review: operating holds $48,213.55.', provider: 'openai',
    });
    expect(s.claims).toHaveLength(1);
    expect(s.claims[0]!.payload).toMatchObject({ source_service: 'mercury', mission_ref: 'ms_cfo', metadata: { source: 'llm_response' } });
    expect(s.claims[0]!.payload.entity_types).toContain('money_amount');
    expect(s.claims[0]!.payload.content_fingerprints.length).toBeGreaterThan(0);
  });

  it('records nothing for a response whose prompt carried nothing', async () => {
    const s = services();
    await recordInheritedResponse(s.services, {
      operatorId: 'op_1', agentId: 'a', passportJti: 'p', missionId: 'ms_1', sources: [], text: 'anything at all here', provider: 'openai',
    });
    expect(s.claims).toEqual([]);
  });

  it('reads the assistant text of both provider shapes', () => {
    expect(llmResponseText({ id: 'msg_1', content: [{ type: 'text', text: 'hello there' }] })).toBe('hello there');
    expect(llmResponseText({ id: 'cmpl', choices: [{ message: { role: 'assistant', content: 'hi' } }] })).toBe('hi');
  });
});

describe('LLM response provenance write fails closed for a model call, with controls on', () => {
  const input = {
    operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', sources: ['mercury'],
    text: 'Operating holds $48,213.55.', provider: 'openai',
  };
  const broken = () => {
    const s = services();
    (s.services as unknown as { claimRegistry: { registerClaim: unknown } }).claimRegistry.registerClaim = vi.fn(async () => { throw new Error('db down'); });
    return s;
  };

  it('withholds the response (503) and alarms when the record cannot be written, in standard mode', async () => {
    const s = broken();
    await expect(recordLlmResponseProvenance(s.services, { ...input, mode: 'standard', bytesAlreadySent: false }))
      .rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(s.events).toHaveLength(1);
    expect(s.events[0]!.metadata).toMatchObject({ provenance_unavailable: true, stage: 'llm_response', failed: 'closed' });
    expect(JSON.stringify(s.events)).not.toMatch(/48[,.]?213/);
  });

  it('can only alarm once a stream has already sent the bytes', async () => {
    const s = broken();
    await expect(recordLlmResponseProvenance(s.services, { ...input, mode: 'standard', bytesAlreadySent: true })).resolves.toBeUndefined();
    expect(s.events[0]!.metadata).toMatchObject({ failed: 'open' });
  });

  it('with controls off delivers the response and only warns', async () => {
    const s = services([], false);
    (s.services as unknown as { claimRegistry: { registerClaim: unknown } }).claimRegistry.registerClaim = vi.fn(async () => { throw new Error('db down'); });
    await expect(recordLlmResponseProvenance(s.services, { ...input, mode: 'standard', bytesAlreadySent: false })).resolves.toBeUndefined();
    expect(s.events).toHaveLength(1);
    expect(s.events[0]).toMatchObject({ severity: 'warning', skipAgentAutoBlock: true, metadata: { stage: 'llm_response', failed: 'open' } });
  });

  it('records normally and says nothing when the write succeeds', async () => {
    const s = services();
    await recordLlmResponseProvenance(s.services, { ...input, mode: 'standard', bytesAlreadySent: false });
    expect(s.claims).toHaveLength(1);
    expect(s.events).toEqual([]);
  });
});

describe('hand-offs with controls off never block the agent', () => {
  it('deposits with no sources recorded, and a warning, when provenance cannot be established', async () => {
    const s = services(new Error('connection reset'), false);
    const provenance = await computeDepositProvenance(s.services, {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'dropoff',
    });
    expect(provenance.sources).toEqual([]);
    expect(s.events).toHaveLength(1);
    expect(s.events[0]).toMatchObject({ severity: 'warning', skipAgentAutoBlock: true, metadata: { stage: 'dropoff_deposit' } });
  });

  it('collects and warns when the collector\'s record cannot be written; with controls on it rolls back', async () => {
    const depositor = services([bankRow()]);
    const provenance = await computeDepositProvenance(depositor.services, {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'dropoff',
    });
    const collect = (controls: boolean) => {
      const c = services([], controls);
      (c.services as unknown as { claimRegistry: { registerClaim: unknown } }).claimRegistry.registerClaim = vi.fn(async () => { throw new Error('db down'); });
      return {
        c,
        run: () => recordCollectedProvenance(c.services, {
          operatorId: 'op_1', collectorAgentId: 'agt_slack', passportJti: 'pas_slack', missionId: 'ms_slack',
          dropoffId: 'dof_1', fromAgentId: 'agt_cfo', payload: AUDIT, provenance: JSON.parse(JSON.stringify(provenance)),
        }),
      };
    };
    const off = collect(false);
    await expect(off.run()).resolves.toBeDefined();
    expect(off.c.events[0]).toMatchObject({ severity: 'warning', skipAgentAutoBlock: true });
    const on = collect(true);
    await expect(on.run()).rejects.toThrow('db down');
    expect(on.c.events[0]).toMatchObject({ severity: 'critical' });
  });

  it('an unreadable controls status counts as on', async () => {
    const s = services(new Error('connection reset'));
    (s.services as unknown as { entitlements: { controlsEnabled: unknown } }).entitlements.controlsEnabled = vi.fn(async () => { throw new Error('billing down'); });
    await expect(computeDepositProvenance(s.services, {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'a2a',
    })).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('an agent outside an account keeps its accountability mode, whatever the owner\'s controls say', () => {
  const brokenClaims = (s: ReturnType<typeof services>) => {
    (s.services as unknown as { claimRegistry: { registerClaim: unknown } }).claimRegistry.registerClaim = vi.fn(async () => { throw new Error('db down'); });
  };
  const deposit = (s: ReturnType<typeof services>, mode: 'enforced' | 'standard') => computeDepositProvenance(s.services, {
    operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'dropoff', mode,
  });
  const llmInput = {
    operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', sources: ['mercury'],
    text: 'Operating holds $48,213.55.', provider: 'openai', bytesAlreadySent: false,
  };

  it('refuses a deposit it cannot trace in enforced mode only, with controls on or off', async () => {
    for (const controls of [true, false]) {
      const enforced = services(new Error('connection reset'), controls, false);
      await expect(deposit(enforced, 'enforced')).rejects.toBeInstanceOf(ServiceUnavailableError);
      expect(enforced.events[0]).toMatchObject({ severity: 'critical', metadata: { failed: 'closed' } });
      expect(enforced.events[0]).not.toHaveProperty('skipAgentAutoBlock');

      const standard = services(new Error('connection reset'), controls, false);
      await expect(deposit(standard, 'standard')).resolves.toMatchObject({ sources: [] });
      // The alarm is still the critical one it always was, and may still block the agent.
      expect(standard.events[0]).toMatchObject({ severity: 'critical', metadata: { failed: 'open' } });
      expect(standard.events[0]).not.toHaveProperty('skipAgentAutoBlock');
    }
  });

  it('rolls a collection back in enforced mode only', async () => {
    const provenance = JSON.parse(JSON.stringify(await computeDepositProvenance(services([bankRow()]).services, {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'dropoff',
    })));
    const collect = (mode: 'enforced' | 'standard', controls: boolean) => {
      const c = services([], controls, false);
      brokenClaims(c);
      return {
        c,
        run: () => recordCollectedProvenance(c.services, {
          operatorId: 'op_1', collectorAgentId: 'agt_slack', passportJti: 'pas_slack', missionId: 'ms_slack',
          dropoffId: 'dof_1', fromAgentId: 'agt_cfo', payload: AUDIT, provenance, mode,
        }),
      };
    };
    for (const controls of [true, false]) {
      await expect(collect('enforced', controls).run()).rejects.toThrow('db down');
      const standard = collect('standard', controls);
      await expect(standard.run()).resolves.toBeDefined();
      expect(standard.c.events[0]).toMatchObject({ severity: 'critical' });
    }
  });

  it('withholds a model response it cannot trace in enforced mode only', async () => {
    for (const controls of [true, false]) {
      const enforced = services([], controls, false);
      brokenClaims(enforced);
      await expect(recordLlmResponseProvenance(enforced.services, { ...llmInput, mode: 'enforced' })).rejects.toBeInstanceOf(ServiceUnavailableError);
      const standard = services([], controls, false);
      brokenClaims(standard);
      await expect(recordLlmResponseProvenance(standard.services, { ...llmInput, mode: 'standard' })).resolves.toBeUndefined();
      expect(standard.events[0]).toMatchObject({ severity: 'critical', metadata: { failed: 'open' } });
    }
  });

  it('never reads the owner\'s controls for it, and an account\'s agent in the same mode still follows them', async () => {
    const outside = services(new Error('connection reset'), false, false);
    await expect(deposit(outside, 'standard')).resolves.toBeDefined();
    expect((outside.services as unknown as { entitlements: { controlsEnabled: ReturnType<typeof vi.fn> } }).entitlements.controlsEnabled)
      .not.toHaveBeenCalled();

    const account = services(new Error('connection reset'), false, true);
    await expect(deposit(account, 'enforced')).resolves.toMatchObject({ sources: [] });
    expect(account.events[0]).toMatchObject({ severity: 'warning', skipAgentAutoBlock: true });
  });
});

describe('the data trail follows the customer\'s per-kind choice, through one posture', () => {
  /** Controls are on; the customer chose to check only some kinds of action. */
  const withPosture = (checked: ReadonlySet<string | null>, rows: unknown[] | Error = new Error('connection reset')) => {
    const s = services(rows, true, true);
    const hostedApplies = vi.fn(async (_operatorId: string, action: string | null) => checked.has(action));
    (s.services as unknown as Record<string, unknown>)['controlPosture'] = { hostedApplies };
    return { ...s, hostedApplies };
  };
  const deposit = (s: ReturnType<typeof withPosture>) => computeDepositProvenance(s.services, {
    operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', payload: AUDIT, producer: 'dropoff',
  });

  it('a kind the customer checks refuses what it cannot trace, as with controls on', async () => {
    const s = withPosture(new Set(['dropoff.deposit']));
    await expect(deposit(s)).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(s.hostedApplies).toHaveBeenCalledWith('op_1', 'dropoff.deposit');
    expect(s.events[0]).toMatchObject({ severity: 'critical', metadata: { failed: 'closed' } });
  });

  it('a kind the customer did not choose is only warned about, and never blocks the agent', async () => {
    const s = withPosture(new Set(['model.call']));
    await expect(deposit(s)).resolves.toMatchObject({ sources: [] });
    expect(s.events[0]).toMatchObject({ severity: 'warning', skipAgentAutoBlock: true });
  });

  it('an unreadable posture counts as on', async () => {
    const s = withPosture(new Set(['dropoff.deposit']));
    (s.services as unknown as { controlPosture: { hostedApplies: unknown } }).controlPosture.hostedApplies = vi.fn(async () => { throw new Error('socket down'); });
    await expect(deposit(s)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('a model response is judged as a model call', async () => {
    const llm = (checked: string[]) => {
      const s = withPosture(new Set(checked));
      (s.services as unknown as { claimRegistry: { registerClaim: unknown } }).claimRegistry.registerClaim = vi.fn(async () => { throw new Error('db down'); });
      return s;
    };
    const input = {
      operatorId: 'op_1', agentId: 'agt_cfo', passportJti: 'pas_cfo', missionId: 'ms_cfo', sources: ['mercury'],
      text: 'Operating holds $48,213.55.', provider: 'openai', bytesAlreadySent: false, mode: 'standard' as const,
    };
    const checked = llm(['model.call']);
    await expect(recordLlmResponseProvenance(checked.services, input)).rejects.toBeInstanceOf(ServiceUnavailableError);
    const unchecked = llm(['proxy.call']);
    await expect(recordLlmResponseProvenance(unchecked.services, input)).resolves.toBeUndefined();
    expect(unchecked.events[0]).toMatchObject({ severity: 'warning', skipAgentAutoBlock: true });
  });
});
