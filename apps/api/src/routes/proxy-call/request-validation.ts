import { ProxyRequestInput, StackError } from '@stack/shared';
import { runtimeAuthorityRequestIdFromHeaders } from '../../lib/runtime-authority.js';
import type { ParsedProxyRequest, ProxyHttpRequest } from './types.js';

/**
 * Step 1: parse the body, require the receiver's operation handle on
 * non-GET requests.
 */
export function validateProxyRequest(request: ProxyHttpRequest): ParsedProxyRequest {
  // 1. Parse input
  const parsed = ProxyRequestInput.safeParse(request.body);
  if (!parsed.success) {
    throw new StackError(
      parsed.error.errors.map((e) => e.message).join(', '),
      'INVALID_REQUEST',
      400,
    );
  }
  const input = parsed.data;
  const isMutation = input.method !== 'GET';
  const operationKey = runtimeAuthorityRequestIdFromHeaders(request.headers);
  if (isMutation && !operationKey) {
    throw new StackError(
      'X-STACK-Authority-Request-Id is required for non-GET proxy requests',
      'INVALID_REQUEST',
      400,
    );
  }

  return { input, isMutation, operationKey };
}
