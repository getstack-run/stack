import { describe, expect, it, vi } from 'vitest';
import { ProxyPostResponseService } from './proxy-post-response-service.js';

// The signed intent_claim and intent_outcome a proxied call leaves
// record its URL without the query string and its path as the agent sent it
// (before credential interpolation), with secret-looking segments redacted.

const QUERY_SECRET = ['q', 'secret', 'value', '4471'].join('-');
const CREDENTIAL_IN_PATH = ['bot', '123456789', ':', 'AAHf9xQk2LmZ0pRt7VwYb3Nc8DsE1uGiJ'].join('');

describe('proxy post-response evidence', () => {
  it('signs no query string, no path secret and no interpolated credential', async () => {
    const payloads: unknown[] = [];
    const service = new ProxyPostResponseService({
      proxyOperation: {
        claimPostResponseWork: async () => ({
          token: 'lease-token',
          operation: {
            id: 'pop_test', operator_id: 'op_test', agent_id: 'agt_test', passport_jti: 'pas_test', adapter_kind: 'generic',
            response_hash: 'a'.repeat(64), authority_use_id: null, post_response_attempts: 1,
            post_response_credential_at: null, post_response_audit_at: null, post_response_claims_at: null,
            post_response_security_at: null, post_response_analytics_at: null, post_response_authority_at: null,
            post_response_intent_claim_id: null, post_response_outcome_claim_id: null,
          },
          context: {
            version: 1,
            audit: { traceId: 'trace', spanId: 'span', durationMs: 1, requestBytes: 1, responseBytes: 1, requestEntropy: 0, responseEntropy: 0 },
            action: {
              accountability: 'logged', service: 'telegram', method: 'POST',
              originalUrl: `https://api.telegram.org/{{bot_token}}/sendMessage?chat_id=${QUERY_SECRET}`,
              originalBody: null,
              resolvedHost: 'api.telegram.org',
              resolvedPath: `/${CREDENTIAL_IN_PATH}/sendMessage`,
              startedAt: 1, recordedAt: 2, statusCode: 200,
              responseBodyHash: 'b'.repeat(64), parametersHash: 'c'.repeat(64),
              redactionsCount: 0, detectorFiresCount: 0, missionIds: [], missionRef: null, approvedIntentClaimId: null,
              entityObservation: null, undeclaredCandidates: [],
            },
          },
        }),
        markPostResponseStep: vi.fn(async (input: { step: string }) => ({ id: 'pop_test', [`post_response_${input.step}_at`]: new Date() })),
        releasePostResponseWork: async () => true,
      },
      redis: { sadd: async () => 1, expire: async () => 1 },
      audit: { write: async () => 'audit' },
      claimRegistry: {
        registerClaim: async (input: { claimType: string; payload: unknown }) => {
          payloads.push(input.payload);
          return { claimId: `pc_${input.claimType}`, envelopeCose: 'test', subject: 'test' };
        },
      },
      authority: { completeRuntimeAuthorityUseByHash: async () => {} },
      securityEvent: { record: async () => null },
      passportClaimsRepo: { findObservedContentForFlow: async () => [] },
      analytics: { fireOnce: async () => {}, capture: () => {} },
    } as never);

    await expect(service.processOne()).resolves.toMatchObject({ state: 'completed' });
    expect(payloads.length).toBeGreaterThanOrEqual(2);
    const signed = JSON.stringify(payloads);
    expect(signed).not.toContain(QUERY_SECRET);
    expect(signed).not.toContain('AAHf9xQk2LmZ0pRt7VwYb3Nc8DsE1uGiJ');
    expect(payloads).toContainEqual(expect.objectContaining({
      type: 'intent_claim', action: 'POST https://api.telegram.org/%7B%7Bbot_token%7D%7D/sendMessage',
      parameters: expect.objectContaining({ url: 'https://api.telegram.org/%7B%7Bbot_token%7D%7D/sendMessage' }),
    }));
    expect(payloads).toContainEqual(expect.objectContaining({
      type: 'intent_outcome', actual_target: 'api.telegram.org', actual_method_path: 'POST /%7B%7Bbot_token%7D%7D/sendMessage',
    }));
  });
});
