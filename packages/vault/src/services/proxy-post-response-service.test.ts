import { describe, expect, it, vi } from 'vitest';
import { trailEntityDigest } from '@stack/shared';
import { ProxyPostResponseService } from './proxy-post-response-service.js';

describe('ProxyPostResponseService', () => {
  it('checks prior entity history before recording the current observation', async () => {
    const knownEntities: string[] = [];
    const securityRecord = vi.fn(async () => null);
    const markPostResponseStep = vi.fn(async (input: { step: string }) => ({
      id: 'pop_test',
      [`post_response_${input.step}_at`]: new Date(),
    }));
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
            audit: {
              traceId: 'trace', spanId: 'span', durationMs: 1,
              requestBytes: 1, responseBytes: 1, requestEntropy: 0, responseEntropy: 0,
            },
            action: {
              accountability: 'standard',
              service: 'custom_test',
              method: 'POST',
              originalUrl: 'https://api.example.invalid/write',
              originalBody: { email: 'first@example.invalid' },
              resolvedHost: 'api.example.invalid',
              startedAt: 1,
              recordedAt: 2,
              statusCode: 201,
              responseBodyHash: 'b'.repeat(64),
              parametersHash: 'c'.repeat(64),
              redactionsCount: 0,
              detectorFiresCount: 0,
              missionIds: [],
              missionRef: null,
              approvedIntentClaimId: null,
              entityObservation: {
                type: 'entity_observation',
                entities: ['first@example.invalid'],
                entity_types: ['email'],
                agent_id: 'agt_test',
                source_service: 'custom_test',
                content_fingerprints: [],
                metadata: {},
                observed_at: 2,
              },
              undeclaredCandidates: ['first@example.invalid'],
            },
          },
        }),
        markPostResponseStep,
        releasePostResponseWork: async () => true,
      },
      redis: { sadd: async () => 1, expire: async () => 1 },
      audit: { write: async () => 'audit' },
      claimRegistry: {
        registerClaim: async (input: { claimType: string; payload: { entities?: string[] } }) => {
          if (input.claimType === 'entity_observation') {
            knownEntities.push(...(input.payload.entities ?? []));
          }
          return { claimId: `pc_${input.claimType}`, envelopeCose: 'test', subject: 'test' };
        },
      },
      authority: { completeRuntimeAuthorityUseByHash: async () => {} },
      securityEvent: { record: securityRecord },
      passportClaimsRepo: {
        findObservedEntitiesForAgent: async () => [],
        findObservedContentForFlow: async () => (
          knownEntities.length > 0 ? [{ entities: [...knownEntities] }] : []
        ),
      },
      analytics: { fireOnce: async () => {}, capture: () => {} },
    } as never);

    await expect(service.processOne()).resolves.toMatchObject({ state: 'completed' });
    expect(securityRecord).toHaveBeenCalledWith(expect.objectContaining({
      signalType: 'undeclared_target',
      metadata: expect.objectContaining({ undeclared_entities: ['first@example.invalid'] }),
    }));
    const securityIndex = markPostResponseStep.mock.calls.findIndex(([input]) => input.step === 'security');
    const claimsIndex = markPostResponseStep.mock.calls.findIndex(([input]) => input.step === 'claims');
    expect(securityIndex).toBeGreaterThanOrEqual(0);
    expect(securityIndex).toBeLessThan(claimsIndex);

    // a caller may answer its client at `onRecorded`. By then the
    // record must be durable (credential, audit, security, claims with the
    // entity_observation); only analytics and authority completion remain.
    markPostResponseStep.mockClear();
    knownEntities.length = 0;
    let stepsAtRecorded: string[] | null = null;
    let entitiesAtRecorded: string[] = [];
    await expect(service.processOne(undefined, {
      onRecorded: () => {
        stepsAtRecorded = markPostResponseStep.mock.calls.map(([input]) => input.step);
        entitiesAtRecorded = [...knownEntities];
      },
    })).resolves.toMatchObject({ state: 'completed' });
    expect(stepsAtRecorded).toEqual(['credential', 'audit', 'security', 'claims']);
    expect(entitiesAtRecorded).toEqual(['first@example.invalid']);
    expect(markPostResponseStep.mock.calls.map(([input]) => input.step)).toEqual(
      ['credential', 'audit', 'security', 'claims', 'analytics', 'authority'],
    );
  });

  it.each([
    ['a one-way digest', () => [trailEntityDigest('first@example.invalid')]],
    ['text recorded before digests', () => ['first@example.invalid']],
  ])('treats a counterparty already observed as %s as known', async (_form, history) => {
    const knownEntities: string[] = history();
    const securityRecord = vi.fn(async () => null);
    const markPostResponseStep = vi.fn(async (input: { step: string }) => ({
      id: 'pop_test',
      [`post_response_${input.step}_at`]: new Date(),
    }));
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
            audit: {
              traceId: 'trace', spanId: 'span', durationMs: 1,
              requestBytes: 1, responseBytes: 1, requestEntropy: 0, responseEntropy: 0,
            },
            action: {
              accountability: 'standard',
              service: 'custom_test',
              method: 'POST',
              originalUrl: 'https://api.example.invalid/write',
              originalBody: { email: 'first@example.invalid' },
              resolvedHost: 'api.example.invalid',
              startedAt: 1,
              recordedAt: 2,
              statusCode: 201,
              responseBodyHash: 'b'.repeat(64),
              parametersHash: 'c'.repeat(64),
              redactionsCount: 0,
              detectorFiresCount: 0,
              missionIds: [],
              missionRef: null,
              approvedIntentClaimId: null,
              entityObservation: {
                type: 'entity_observation',
                entities: ['first@example.invalid'],
                entity_types: ['email'],
                agent_id: 'agt_test',
                source_service: 'custom_test',
                content_fingerprints: [],
                metadata: {},
                observed_at: 2,
              },
              undeclaredCandidates: ['first@example.invalid'],
            },
          },
        }),
        markPostResponseStep,
        releasePostResponseWork: async () => true,
      },
      redis: { sadd: async () => 1, expire: async () => 1 },
      audit: { write: async () => 'audit' },
      claimRegistry: {
        registerClaim: async (input: { claimType: string; payload: { entities?: string[] } }) => {
          if (input.claimType === 'entity_observation') {
            knownEntities.push(...(input.payload.entities ?? []));
          }
          return { claimId: `pc_${input.claimType}`, envelopeCose: 'test', subject: 'test' };
        },
      },
      authority: { completeRuntimeAuthorityUseByHash: async () => {} },
      securityEvent: { record: securityRecord },
      passportClaimsRepo: {
        findObservedEntitiesForAgent: async () => [],
        findObservedContentForFlow: async () => (
          knownEntities.length > 0 ? [{ entities: [...knownEntities] }] : []
        ),
      },
      analytics: { fireOnce: async () => {}, capture: () => {} },
    } as never);

    await expect(service.processOne()).resolves.toMatchObject({ state: 'completed' });
    expect(securityRecord).not.toHaveBeenCalledWith(expect.objectContaining({ signalType: 'undeclared_target' }));
  });
});
