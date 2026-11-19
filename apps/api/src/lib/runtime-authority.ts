import { canonicalize, ForbiddenError, ServiceUnavailableError, sha256, StackError } from '@stack/shared';

export const RUNTIME_AUTHORITY_REQUEST_ID_HEADER = 'x-stack-authority-request-id';

export type RuntimeAuthorityBoundary =
  | {
      kind: 'proxy';
      serviceConnectionId: string;
      provider: string;
      method: string;
    }
  | {
      kind: 'llm';
      serviceConnectionId: string;
      provider: string;
      operation: string;
    }
  | {
      kind: 'skill';
      skillId: string;
    }
  | {
      kind: 'a2a';
      receiverAgentId: string;
    }
  | {
      kind: 'dropoff';
      action: 'create' | 'deposit' | 'collect';
      participantAgentId: string;
    };

export interface RuntimeAuthorityInput {
  operatorId: string;
  passportJti: string;
  agentId: string;
  authenticatedAgentId: string | null;
  receiverRequestId?: string | null;
  missionId?: string;
  boundary: RuntimeAuthorityBoundary;
  normalizedRequest: unknown;
  requestHash?: `sha256:${string}` | null;
  verificationMode: 'native_receiver' | 'proxy_mediated';
}

export interface RuntimeAuthorityResult {
  allowed: boolean;
  authorityUseId?: string;
  executionState?: 'pending' | 'waiting_approval' | 'authorized' | 'denied' | 'dispatched' | 'succeeded' | 'failed';
  denialCode?: string;
}

export interface LegacyRuntimeAuthorityResult {
  /** The only legacy escape hatch: the persisted Passport has zero refs. */
  enforced: false;
}

export interface RuntimeAuthorityEvaluator {
  evaluateRuntimeAuthority(
    input: RuntimeAuthorityInput,
  ): Promise<RuntimeAuthorityResult | LegacyRuntimeAuthorityResult>;
  markRuntimeAuthorityDispatched(operatorId: string, useId: string): Promise<void>;
  completeRuntimeAuthorityUse(input: {
    operatorId: string;
    useId: string;
    outcome: 'succeeded' | 'failed';
    exactResult: unknown;
    intentClaimId?: string;
    outcomeClaimId?: string;
  }): Promise<void>;
}

export function runtimeAuthorityRequestHash(
  receiverRequestId: string,
  normalizedRequest: unknown,
): `sha256:${string}` {
  return `sha256:${sha256(canonicalize({
    receiver_request_id: receiverRequestId,
    normalized_request: normalizedRequest,
  }))}`;
}

export function isEnforcedRuntimeAuthority(
  result: RuntimeAuthorityResult | LegacyRuntimeAuthorityResult,
): result is RuntimeAuthorityResult & { authorityUseId: string } {
  return !('enforced' in result) && typeof result.authorityUseId === 'string';
}

/** Error evidence is deliberately structural: exception messages can contain credentials or PII. */
export function runtimeAuthorityFailureResult(error: unknown): Record<string, unknown> {
  if (!error || typeof error !== 'object') return { outcome: 'failed', error_code: 'INTERNAL_ERROR' };
  const candidate = error as { code?: unknown; statusCode?: unknown; status?: unknown };
  const errorCode = typeof candidate.code === 'string' ? candidate.code : 'INTERNAL_ERROR';
  const status = typeof candidate.statusCode === 'number'
    ? candidate.statusCode
    : typeof candidate.status === 'number'
      ? candidate.status
      : undefined;
  return {
    outcome: 'failed',
    error_code: errorCode,
    ...(status !== undefined ? { status } : {}),
  };
}

export async function markRuntimeAuthorityDispatched(
  evaluator: RuntimeAuthorityEvaluator,
  operatorId: string,
  result: RuntimeAuthorityResult | LegacyRuntimeAuthorityResult,
): Promise<boolean> {
  if (!isEnforcedRuntimeAuthority(result)) return false;
  await evaluator.markRuntimeAuthorityDispatched(operatorId, result.authorityUseId);
  return true;
}

export async function completeRuntimeAuthorityUse(
  evaluator: RuntimeAuthorityEvaluator,
  operatorId: string,
  result: RuntimeAuthorityResult | LegacyRuntimeAuthorityResult,
  outcome: 'succeeded' | 'failed',
  exactResult: unknown,
  claimRefs?: { intentClaimId?: string | null; outcomeClaimId?: string | null },
): Promise<void> {
  if (!isEnforcedRuntimeAuthority(result)) return;
  await evaluator.completeRuntimeAuthorityUse({
    operatorId,
    useId: result.authorityUseId,
    outcome,
    exactResult,
    ...(claimRefs?.intentClaimId ? { intentClaimId: claimRefs.intentClaimId } : {}),
    ...(claimRefs?.outcomeClaimId ? { outcomeClaimId: claimRefs.outcomeClaimId } : {}),
  });
}

/**
 * Extract the caller-stable transaction identifier used to resume an approval.
 * The shape provides at least 128 bits when generated randomly; the API cannot
 * measure randomness, so SDKs must generate rather than derive this value.
 */
export function runtimeAuthorityRequestIdFromHeaders(
  headers: Record<string, unknown>,
): string | null {
  const value = headers[RUNTIME_AUTHORITY_REQUEST_ID_HEADER];
  if (value === undefined) return null;
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{22,256}$/.test(value)) {
    throw new StackError(
      'X-STACK-Authority-Request-Id must be a high-entropy base64url identifier',
      'INVALID_REQUEST',
      400,
    );
  }
  return value;
}

/**
 * The API owns request normalization and hashing; the vault owns all authority
 * selection and policy. The null result is the sole legacy escape hatch and is
 * returned only when the persisted Passport has no authority references.
 */
export async function enforceRuntimeAuthority(
  evaluator: RuntimeAuthorityEvaluator,
  input: Omit<RuntimeAuthorityInput, 'requestHash'>,
): Promise<RuntimeAuthorityResult | LegacyRuntimeAuthorityResult> {
  const requestHash = input.receiverRequestId
    ? runtimeAuthorityRequestHash(input.receiverRequestId, input.normalizedRequest)
    : null;
  const result = await evaluator.evaluateRuntimeAuthority({
    ...input,
    requestHash,
  });
  if ('enforced' in result) return result;
  if (!result.allowed) {
    throw new ForbiddenError('Authority approval is required for this action');
  }
  if (!result.authorityUseId) {
    throw new ServiceUnavailableError('Authority use evidence is unavailable');
  }
  return result;
}
