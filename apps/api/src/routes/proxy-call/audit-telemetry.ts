import { shannonEntropy } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';
import type {
  ParsedProxyRequest,
  ProxyHttpRequest,
  UpstreamResult,
  VerifiedProxyPassport,
} from './types.js';

/** 10. Track credential access for Signal 9. */
export async function recordCredentialAccess(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
): Promise<void> {
  const { input } = parsedRequest;
  const { jti } = verified;
  await services.redis.sadd(`cred_accessed:${jti}`, input.service);
  await services.redis.expire(`cred_accessed:${jti}`, 7200);
}

/**
 * 11. Audit log — also records body metrics for the
 * behavioral_genome producer. Bytes are UTF-8 byte
 * length of the serialized body; entropy is Shannon entropy in
 * bits per byte over the same bytes. Both null-safe for absent
 * bodies (e.g. GET requests, empty responses).
 */
export async function writeProxyAudit(
  services: Services,
  request: ProxyHttpRequest,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  result: UpstreamResult,
  start: number,
): Promise<void> {
  const { input } = parsedRequest;
  const { jti, agentId } = verified;
  const requestBodyStr =
    input.body == null
      ? ''
      : typeof input.body === 'string'
        ? input.body
        : JSON.stringify(input.body);
  const responseBodyStr =
    result.body == null
      ? ''
      : typeof result.body === 'string'
        ? result.body
        : JSON.stringify(result.body);

  await services.audit.write({
    ctx: auditCtx(request, { agent_id: agentId, passport_jti: jti }),
    layer: 'vault',
    action: 'credential.proxy',
    outcome: result.status >= 200 && result.status < 400 ? 'success' : 'failure',
    duration_ms: Date.now() - start,
    request_bytes: Buffer.byteLength(requestBodyStr, 'utf8'),
    response_bytes: Buffer.byteLength(responseBodyStr, 'utf8'),
    request_entropy: shannonEntropy(requestBodyStr),
    response_entropy: shannonEntropy(responseBodyStr),
  });
}
