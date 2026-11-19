import { describe, expect, it, vi } from 'vitest';
import { AccountabilityService } from './accountability-service.js';

const passport = {
  jti: 'pas_bridge',
  operator_id: 'op_bridge',
  agent_id: 'agt_bridge',
  intent_summary: 'Read calendar',
  intent_services: ['calendar'],
  intent_delegates: false,
  mission_ids: ['ms_bridge'],
  issued_at: new Date(),
  checked_out_at: null,
  estimated_duration_seconds: null,
};

const agent = { id: 'agt_bridge', accountability_mode: 'standard' };

// Declares calendar, uses email: the review engine raises undeclared_service.
const checkout = {
  services_used: ['email'],
  tool_calls: [{ service: 'email', method: 'send' }],
  actions_count: 1,
  summary: 'Sent email',
  delegated_to: [],
};

function makeHarness(opts: { registerClaim?: () => Promise<{ claimId: string }> } = {}) {
  const securityEventRepo = {
    findByPassport: vi.fn(async () => []),
    existsForPassport: vi.fn(async () => false),
    create: vi.fn(async (row: Record<string, unknown>) => row),
  };
  const registerClaim = vi.fn(
    async (_input: Record<string, unknown>) => (opts.registerClaim ? opts.registerClaim() : { claimId: 'clm_bridge' }),
  );
  const service = new AccountabilityService(
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    undefined,
    securityEventRepo as never,
  );
  service.setClaimRegistryService({ registerClaim } as never);
  return { service, securityEventRepo, registerClaim };
}

async function runReview(service: AccountabilityService) {
  return (service as unknown as {
    runReviewEngine(
      passportInput: typeof passport,
      agentInput: typeof agent,
      checkpoints: unknown[],
      checkoutInput: typeof checkout,
    ): Promise<{ flags: Array<{ type: string; severity: string }> }>;
  }).runReviewEngine(passport, agent, [], checkout);
}

describe('AccountabilityService review-flag bridge', () => {
  it('signs a detector_signal claim for each bridged flag and stores its id on the row', async () => {
    const { service, securityEventRepo, registerClaim } = makeHarness();
    const review = await runReview(service);

    const bridged = review.flags.filter((f) => f.severity !== 'info');
    expect(bridged.length).toBeGreaterThan(0);
    expect(registerClaim).toHaveBeenCalledTimes(bridged.length);
    const call = registerClaim.mock.calls[0]![0] as {
      operatorId: string;
      passportJti: string;
      claimType: string;
      payload: Record<string, unknown>;
    };
    expect(call.operatorId).toBe('op_bridge');
    expect(call.passportJti).toBe('pas_bridge');
    expect(call.claimType).toBe('detector_signal');
    expect(call.payload).toMatchObject({
      type: 'detector_signal',
      agent_id: 'agt_bridge',
      mission_ref: 'ms_bridge',
    });

    expect(securityEventRepo.create).toHaveBeenCalledTimes(bridged.length);
    const row = securityEventRepo.create.mock.calls[0]![0] as Record<string, unknown>;
    expect(row['claim_id']).toBe('clm_bridge');
    expect(row['mission_id']).toBe('ms_bridge');
    expect(row['detector_key']).toBeUndefined();
    expect(call.payload['detector_key']).toBe(row['signal_type']);
  });

  it('still records the row, with no claim id, when signing fails', async () => {
    const { service, securityEventRepo } = makeHarness({
      registerClaim: async () => {
        throw new Error('signing key unavailable');
      },
    });
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await runReview(service);
    errors.mockRestore();

    expect(securityEventRepo.create).toHaveBeenCalled();
    const row = securityEventRepo.create.mock.calls[0]![0] as Record<string, unknown>;
    expect(row['claim_id']).toBeNull();
  });
});
