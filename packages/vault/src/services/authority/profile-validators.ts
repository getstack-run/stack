/** Protocol keys and the receiver-profile validators of the built-in STACK protocols. */
import { ForbiddenError, canonicalize } from '@stack/shared';
import type { AuthorityReceiverRecord } from './records.js';
import { parseAuthorityApprovalPolicy } from './approval-policy.js';

export const STACK_DIRECT_POST_PROTOCOL_KEY = 'stack.direct_post.jwt';

export const STACK_DIRECT_POST_PROTOCOL_VERSION = '1';

export const STACK_DIRECT_POST_REQUEST_AUTH_METHOD = 'stack.http_request.jwt';

export const STACK_DIRECT_POST_DELIVERY_MODE = 'stack.direct_post.jwt';

export const STACK_PROXY_BRIDGE_PROTOCOL_KEY = 'stack.proxy_bridge';

export const STACK_PROXY_BRIDGE_PROTOCOL_VERSION = '1';

export function assertStackInternalProfile(
  config: Record<string, unknown>,
  receiver: AuthorityReceiverRecord,
): void {
  const protocol = config.protocol as Record<string, unknown> | undefined;
  if (
    canonicalize(Object.keys(config).sort()) !==
      canonicalize(
        [
          'approval_policy',
          'audience',
          'canonical_identifier',
          'live_status_required',
          'protocol',
          'receiver_id',
        ].sort(),
      ) ||
    protocol?.key !== 'stack.internal_runtime' ||
    protocol.version !== '1' ||
    config.receiver_id !== receiver.id ||
    config.canonical_identifier !== receiver.canonical_identifier ||
    config.live_status_required !== true
  )
    throw new ForbiddenError();
  parseAuthorityApprovalPolicy(config.approval_policy);
}

export function assertStackProxyBridgeProfile(
  config: Record<string, unknown>,
  receiver: AuthorityReceiverRecord,
): void {
  const protocol = config.protocol as Record<string, unknown> | undefined;
  const keys = Object.keys(config).sort();
  if (
    canonicalize(keys) !==
      canonicalize(
        [
          'approval_policy',
          'audience',
          'live_status_required',
          'protocol',
          'receiver_id',
          'service_connection_id',
        ].sort(),
      ) ||
    protocol?.key !== STACK_PROXY_BRIDGE_PROTOCOL_KEY ||
    protocol.version !== STACK_PROXY_BRIDGE_PROTOCOL_VERSION ||
    config.receiver_id !== receiver.id ||
    config.service_connection_id !== receiver.proxy_service_connection_id ||
    config.live_status_required !== true
  ) {
    throw new ForbiddenError('receiver profile is incompatible with stack.proxy_bridge/v1');
  }
  parseAuthorityApprovalPolicy(config.approval_policy);
}

export function assertStackDirectPostProfile(config: Record<string, unknown>): void {
  const protocol = config.protocol as Record<string, unknown>;
  const request = config.request_authentication as Record<string, unknown>;
  const delivery = config.delivery as Record<string, unknown>;
  const receipt = config.receipt as Record<string, unknown> | undefined;
  const requestAlgorithms = request?.allowed_algs;
  if (
    protocol?.key !== STACK_DIRECT_POST_PROTOCOL_KEY ||
    String(protocol?.version) !== STACK_DIRECT_POST_PROTOCOL_VERSION ||
    request?.method !== STACK_DIRECT_POST_REQUEST_AUTH_METHOD ||
    delivery?.mode !== STACK_DIRECT_POST_DELIVERY_MODE ||
    !Array.isArray(requestAlgorithms) ||
    requestAlgorithms.length === 0 ||
    requestAlgorithms.some((algorithm) => algorithm !== 'EdDSA' && algorithm !== 'ES256') ||
    canonicalize(delivery?.allowed_key_management_algs) !== canonicalize(['ECDH-ES+A256KW']) ||
    canonicalize(delivery?.allowed_content_encryption_algs) !== canonicalize(['A256GCM']) ||
    (receipt !== undefined &&
      (!Array.isArray(receipt.allowed_algs) ||
        receipt.allowed_algs.length === 0 ||
        receipt.allowed_algs.some((algorithm) => algorithm !== 'EdDSA' && algorithm !== 'ES256') ||
        !Array.isArray(receipt.signing_key_ids) ||
        receipt.signing_key_ids.length === 0))
  ) {
    throw new ForbiddenError('receiver profile is incompatible with stack.direct_post.jwt/v1');
  }
  parseAuthorityApprovalPolicy(config.approval_policy);
}
