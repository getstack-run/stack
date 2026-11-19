import { describe, expect, it, vi } from 'vitest';
import { trailEntityDigest } from '@stack/shared';
import { ProxyPostResponseService } from './proxy-post-response-service.js';

/**
 * Who counts as a new counterparty: the service the owner connected never does, a counterparty the agent dealt
 * with in any earlier Mission does not, and only what is left is flagged.
 */

interface Setup {
  candidates: string[];
  connectionHosts?: string[];
  missionHistory?: string[];
  agentHistory?: string[];
}

async function run(setup: Setup) {
  const record = vi.fn(async () => null);
  const agentRead = vi.fn(async () => setup.agentHistory ?? []);
  const service = new ProxyPostResponseService({
    proxyOperation: {
      claimPostResponseWork: async () => ({
        token: 'lease-token',
        operation: {
          id: 'pop_test',
          operator_id: 'op_test',
          agent_id: 'agt_test',
          passport_jti: 'pas_test',
          adapter_kind: 'generic',
          response_hash: 'a'.repeat(64),
          authority_use_id: null,
          post_response_attempts: 1,
          post_response_credential_at: null,
          post_response_audit_at: null,
          post_response_claims_at: null,
          post_response_security_at: null,
          post_response_analytics_at: null,
          post_response_authority_at: null,
          post_response_intent_claim_id: null,
          post_response_outcome_claim_id: null,
        },
        context: {
          version: 1,
          audit: { traceId: 't', spanId: 's', durationMs: 1, requestBytes: 1, responseBytes: 1, requestEntropy: 0, responseEntropy: 0 },
          action: {
            accountability: 'standard',
            service: 'custom_grocer',
            method: 'POST',
            originalUrl: 'https://api.grocer.example/v1/cart',
            originalBody: {},
            resolvedHost: 'api.grocer.example',
            startedAt: 1,
            recordedAt: 2,
            statusCode: 201,
            responseBodyHash: 'b'.repeat(64),
            parametersHash: 'c'.repeat(64),
            redactionsCount: 0,
            detectorFiresCount: 0,
            missionIds: ['ms_one'],
            missionRef: 'ms_one',
            approvedIntentClaimId: null,
            entityObservation: null,
            undeclaredCandidates: setup.candidates,
            ...(setup.connectionHosts ? { connectionHosts: setup.connectionHosts } : {}),
          },
        },
      }),
      markPostResponseStep: async (input: { step: string }) => ({ id: 'pop_test', [`post_response_${input.step}_at`]: new Date() }),
      releasePostResponseWork: async () => true,
    },
    redis: { sadd: async () => 1, expire: async () => 1 },
    audit: { write: async () => 'audit' },
    claimRegistry: { registerClaim: async () => ({ claimId: 'pc_x', envelopeCose: 'x', subject: 'x' }) },
    authority: { completeRuntimeAuthorityUseByHash: async () => {} },
    securityEvent: { record },
    passportClaimsRepo: {
      findObservedContentForFlow: async () => (setup.missionHistory ? [{ entities: setup.missionHistory }] : []),
      findObservedEntitiesForAgent: agentRead,
    },
    analytics: { fireOnce: async () => {}, capture: () => {} },
  } as never);
  await expect(service.processOne()).resolves.toMatchObject({ state: 'completed' });
  return { record, agentRead };
}

describe('undeclared counterparties', () => {
  it('never flags the host the owner connected, and does not read any history for it', async () => {
    const { record, agentRead } = await run({ candidates: ['api.grocer.example'], connectionHosts: ['api.grocer.example'] });
    expect(record).not.toHaveBeenCalled();
    expect(agentRead).not.toHaveBeenCalled();
  });

  it('knows a suffix host the connection declares, and its subdomains', async () => {
    const { record } = await run({ candidates: ['eu.api.grocer.example', 'grocer.example'], connectionHosts: ['.grocer.example'] });
    expect(record).not.toHaveBeenCalled();
  });

  it('flags a host that is not the connection\'s', async () => {
    const { record } = await run({ candidates: ['api.grocer.example', 'tracker.example'], connectionHosts: ['api.grocer.example'] });
    expect(record).toHaveBeenCalledTimes(1);
    expect(record).toHaveBeenCalledWith(expect.objectContaining({
      signalType: 'undeclared_target',
      metadata: expect.objectContaining({ undeclared_entities: ['tracker.example'] }),
    }));
  });

  it('flags a new counterparty when nothing is known about the connection or the agent', async () => {
    const { record } = await run({ candidates: ['someone@example.invalid'] });
    expect(record).toHaveBeenCalledTimes(1);
  });

  it('knows a counterparty the agent dealt with in an earlier Mission, as a digest or as text', async () => {
    const first = await run({ candidates: ['someone@example.invalid'], agentHistory: [trailEntityDigest('someone@example.invalid')] });
    expect(first.record).not.toHaveBeenCalled();
    const second = await run({ candidates: ['someone@example.invalid'], agentHistory: ['someone@example.invalid'] });
    expect(second.record).not.toHaveBeenCalled();
  });

  it('reads the agent history only for what the cheaper checks left', async () => {
    const { agentRead } = await run({ candidates: ['someone@example.invalid'], missionHistory: [trailEntityDigest('someone@example.invalid')] });
    expect(agentRead).not.toHaveBeenCalled();
  });

  it('flags only the counterparties the agent has not met, not the ones it has', async () => {
    const { record } = await run({
      candidates: ['met@example.invalid', 'new@example.invalid'],
      agentHistory: [trailEntityDigest('met@example.invalid')],
    });
    expect(record).toHaveBeenCalledWith(expect.objectContaining({
      metadata: expect.objectContaining({ undeclared_entities: ['new@example.invalid'] }),
    }));
  });

  it('a context stored before connection hosts were kept behaves as it did, flagging the host', async () => {
    const { record } = await run({ candidates: ['api.grocer.example'] });
    expect(record).toHaveBeenCalledTimes(1);
  });
});
