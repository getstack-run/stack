import { describe, expect, it, vi } from 'vitest';
import { canonicalize, ForbiddenError, ServiceUnavailableError, sha256, StackError } from '@stack/shared';
import {
  completeRuntimeAuthorityUse,
  enforceRuntimeAuthority,
  markRuntimeAuthorityDispatched,
  runtimeAuthorityFailureResult,
  runtimeAuthorityRequestIdFromHeaders,
  runtimeAuthorityRequestHash,
  type RuntimeAuthorityEvaluator,
} from './runtime-authority.js';

function evaluator(
  evaluateRuntimeAuthority: RuntimeAuthorityEvaluator['evaluateRuntimeAuthority'],
) {
  return {
    evaluateRuntimeAuthority,
    markRuntimeAuthorityDispatched: vi.fn(async () => undefined),
    completeRuntimeAuthorityUse: vi.fn(async () => undefined),
  };
}

describe('runtime authority API boundary', () => {
  it('canonicalizes and prefixes the exact server request hash', () => {
    const receiverRequestId = 'rrq_00000000-0000-4000-8000-000000000001';
    expect(runtimeAuthorityRequestHash(receiverRequestId, { z: 1, nested: { b: 2, a: 3 } })).toBe(
      runtimeAuthorityRequestHash(receiverRequestId, { nested: { a: 3, b: 2 }, z: 1 }),
    );
    expect(runtimeAuthorityRequestHash(receiverRequestId, { body: { amount: 1 } })).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(runtimeAuthorityRequestHash(receiverRequestId, { body: { amount: 1 } })).not.toBe(
      runtimeAuthorityRequestHash(receiverRequestId, { body: { amount: 2 } }),
    );
    expect(runtimeAuthorityRequestHash(receiverRequestId, { personal_number: 'enumerable-value' })).not.toBe(
      runtimeAuthorityRequestHash('rrq_00000000-0000-4000-8000-000000000002', {
        personal_number: 'enumerable-value',
      }),
    );
  });

  it('accepts a caller-stable high-entropy authority request identifier', () => {
    expect(runtimeAuthorityRequestIdFromHeaders({
      'x-stack-authority-request-id': 'rrq_00000000-0000-4000-8000-000000000001',
    })).toBe('rrq_00000000-0000-4000-8000-000000000001');
    expect(runtimeAuthorityRequestIdFromHeaders({
      'x-stack-authority-request-id': 'A'.repeat(22),
    })).toBe('A'.repeat(22));
    expect(runtimeAuthorityRequestIdFromHeaders({})).toBeNull();
  });

  it.each([
    'predictable',
    'contains spaces but is long enough',
    ['rrq_00000000-0000-4000-8000-000000000001'],
  ])('rejects malformed authority request header values: %j', (value) => {
    expect(() => runtimeAuthorityRequestIdFromHeaders({
      'x-stack-authority-request-id': value,
    })).toThrow(StackError);
  });

  it('passes only server-derived boundary facts and the computed digest', async () => {
    const evaluateRuntimeAuthority = vi.fn(async () => ({ allowed: true, authorityUseId: 'ause_one' }));
    const normalizedRequest = {
      method: 'POST',
      url: { origin: 'https://example.test', pathname: '/submit', host: 'example.test' },
      body: { year: 2026 },
      query: {},
      headers: {},
    };

    await enforceRuntimeAuthority(evaluator(evaluateRuntimeAuthority), {
      operatorId: 'op_one',
      passportJti: 'pass_one',
      agentId: 'agt_one',
      authenticatedAgentId: 'agt_one',
      receiverRequestId: 'rrq_00000000-0000-4000-8000-000000000001',
      missionId: 'mis_one',
      boundary: {
        kind: 'proxy',
        serviceConnectionId: 'scon_one',
        provider: 'tax-service',
        method: 'POST',
      },
      normalizedRequest,
      verificationMode: 'proxy_mediated',
    });

    expect(evaluateRuntimeAuthority).toHaveBeenCalledWith({
      operatorId: 'op_one',
      passportJti: 'pass_one',
      agentId: 'agt_one',
      authenticatedAgentId: 'agt_one',
      receiverRequestId: 'rrq_00000000-0000-4000-8000-000000000001',
      missionId: 'mis_one',
      boundary: {
        kind: 'proxy',
        serviceConnectionId: 'scon_one',
        provider: 'tax-service',
        method: 'POST',
      },
      normalizedRequest,
      requestHash: runtimeAuthorityRequestHash(
        'rrq_00000000-0000-4000-8000-000000000001',
        normalizedRequest,
      ),
      verificationMode: 'proxy_mediated',
    });
  });

  it('passes no request digest when the caller omits the ID and preserves only vault-proven legacy behavior', async () => {
    const evaluateRuntimeAuthority = vi.fn(async () => ({ enforced: false as const }));
    const result = await enforceRuntimeAuthority(
      evaluator(evaluateRuntimeAuthority),
      {
        operatorId: 'op_one',
        passportJti: 'pass_legacy',
        agentId: 'agt_one',
        authenticatedAgentId: null,
        receiverRequestId: null,
        boundary: { kind: 'skill', skillId: 'sk_one' },
        normalizedRequest: { skill_id: 'sk_one', input: {} },
        verificationMode: 'proxy_mediated',
      },
    );
    expect(result).toEqual({ enforced: false });
    expect(evaluateRuntimeAuthority).toHaveBeenCalledWith(expect.objectContaining({
      receiverRequestId: null,
      requestHash: null,
    }));
  });

  it('derives the same digest for exact retries using the same stable request ID', async () => {
    const seenRequestHashes: Array<string | null | undefined> = [];
    const evaluateRuntimeAuthority: RuntimeAuthorityEvaluator['evaluateRuntimeAuthority'] = vi.fn(async (input) => {
      seenRequestHashes.push(input.requestHash);
      return { allowed: true, authorityUseId: 'ause_same' };
    });
    const shared = {
      operatorId: 'op_one', passportJti: 'pass_one', agentId: 'agt_one', authenticatedAgentId: 'agt_one',
      receiverRequestId: 'rrq_00000000-0000-4000-8000-000000000001',
      boundary: { kind: 'skill' as const, skillId: 'sk_one' },
      normalizedRequest: { skill_id: 'sk_one', input: { year: 2026 } },
      verificationMode: 'proxy_mediated' as const,
    };
    await enforceRuntimeAuthority(evaluator(evaluateRuntimeAuthority), shared);
    await enforceRuntimeAuthority(evaluator(evaluateRuntimeAuthority), shared);
    expect(seenRequestHashes).toHaveLength(2);
    expect(seenRequestHashes[0]).toBe(seenRequestHashes[1]);
  });

  it('fails closed when an authority-bearing Passport is not allowed', async () => {
    await expect(enforceRuntimeAuthority(
      evaluator(vi.fn(async () => ({ allowed: false, denialCode: 'APPROVAL_REQUIRED' }))),
      {
        operatorId: 'op_one',
        passportJti: 'pass_one',
        agentId: 'agt_one',
        authenticatedAgentId: null,
        receiverRequestId: 'rrq_00000000-0000-4000-8000-000000000001',
        boundary: { kind: 'a2a', receiverAgentId: 'agt_two' },
        normalizedRequest: { method: 'tasks/send' },
        verificationMode: 'proxy_mediated',
      },
    )).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('fails closed when an allowed authority decision has no durable use id', async () => {
    await expect(enforceRuntimeAuthority(
      evaluator(vi.fn(async () => ({ allowed: true }))),
      {
        operatorId: 'op_one',
        passportJti: 'pass_one',
        agentId: 'agt_one',
        authenticatedAgentId: null,
        receiverRequestId: 'rrq_00000000-0000-4000-8000-000000000001',
        boundary: { kind: 'skill', skillId: 'sk_one' },
        normalizedRequest: { skill_id: 'sk_one' },
        verificationMode: 'proxy_mediated',
      },
    )).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('marks and completes enforced uses while leaving legacy calls untouched', async () => {
    const enforcedEvaluator = evaluator(vi.fn());
    const enforced = { allowed: true, authorityUseId: 'ause_one' };
    expect(await markRuntimeAuthorityDispatched(enforcedEvaluator, 'op_one', enforced)).toBe(true);
    await completeRuntimeAuthorityUse(
      enforcedEvaluator,
      'op_one',
      enforced,
      'succeeded',
      { status: 200, body: { ok: true } },
      { intentClaimId: 'clm_intent', outcomeClaimId: 'clm_outcome' },
    );
    expect(enforcedEvaluator.markRuntimeAuthorityDispatched).toHaveBeenCalledWith('op_one', 'ause_one');
    expect(enforcedEvaluator.completeRuntimeAuthorityUse).toHaveBeenCalledWith({
      operatorId: 'op_one',
      useId: 'ause_one',
      outcome: 'succeeded',
      exactResult: { status: 200, body: { ok: true } },
      intentClaimId: 'clm_intent',
      outcomeClaimId: 'clm_outcome',
    });

    const legacyEvaluator = evaluator(vi.fn());
    const legacy = { enforced: false as const };
    expect(await markRuntimeAuthorityDispatched(legacyEvaluator, 'op_one', legacy)).toBe(false);
    await completeRuntimeAuthorityUse(legacyEvaluator, 'op_one', legacy, 'succeeded', { ok: true });
    expect(legacyEvaluator.markRuntimeAuthorityDispatched).not.toHaveBeenCalled();
    expect(legacyEvaluator.completeRuntimeAuthorityUse).not.toHaveBeenCalled();
  });

  it('passes only structural failure facts, never exception messages', () => {
    const failure = runtimeAuthorityFailureResult({
      code: 'UPSTREAM_FAILED',
      statusCode: 502,
      name: 'StackError',
      message: 'personal-number-should-never-be-hashed-as-evidence',
    });
    expect(failure).toEqual({
      outcome: 'failed',
      error_code: 'UPSTREAM_FAILED',
      status: 502,
    });
  });

  it('does not create a public raw hash oracle for a low-entropy result', async () => {
    const exactResult = { tax_status: 'accepted' };
    const evaluatorWithCommitment = evaluator(vi.fn());
    await completeRuntimeAuthorityUse(
      evaluatorWithCommitment,
      'op_one',
      { allowed: true, authorityUseId: 'ause_one' },
      'succeeded',
      exactResult,
    );
    expect(evaluatorWithCommitment.completeRuntimeAuthorityUse).toHaveBeenCalledWith({
      operatorId: 'op_one',
      useId: 'ause_one',
      outcome: 'succeeded',
      exactResult,
    });
    const rawDictionaryHash = `sha256:${sha256(canonicalize(exactResult))}`;
    const serializedCall = JSON.stringify(evaluatorWithCommitment.completeRuntimeAuthorityUse.mock.calls);
    expect(serializedCall).not.toContain(rawDictionaryHash);
    expect(serializedCall).not.toContain('resultHash');
  });

  it('propagates durable completion failures so a protected result cannot be returned', async () => {
    const durableFailure = new ServiceUnavailableError('authority evidence store unavailable');
    const failingEvaluator = evaluator(vi.fn());
    failingEvaluator.completeRuntimeAuthorityUse.mockRejectedValueOnce(durableFailure);
    await expect(completeRuntimeAuthorityUse(
      failingEvaluator,
      'op_one',
      { allowed: true, authorityUseId: 'ause_one' },
      'succeeded',
      { status: 200, body: { ok: true } },
    )).rejects.toBe(durableFailure);
  });
});
