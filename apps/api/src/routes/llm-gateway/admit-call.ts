// Stages 1 and 2: validate the body against the provider schema, verify the
// passport, resolve the connection the call will use and ask the runtime
// authority for a decision. Everything here throws on refusal; nothing is
// metered, admitted to a Mission or sent upstream yet.

import type { FastifyRequest } from 'fastify';
import { ConnectionSelector, ForbiddenError, NotFoundError, StackError } from '@stack/shared';
import { LLM_PROVIDERS } from '@stack/vault';
import { connectionEligibility, requireMissionRef } from '../../lib/agent-runtime.js';
import {
  enforceRuntimeAuthority,
  runtimeAuthorityRequestIdFromHeaders,
} from '../../lib/runtime-authority.js';
import { assertProviderGranted } from './scope-wall.js';
import type { Services } from '../../config/services.js';
import type { ModelAccess } from '../../lib/model-access-policy.js';
import type { LlmHandlerConfig } from './provider-configs.js';
import type { AdmittedCall } from './types.js';

/** What the provider call is, before the caller is known: the body it carries, its method, and where it goes. */
/** Which connection of the provider the call runs on, by name or id; needed only when the caller may use several. */
export const CONNECTION_HEADER = 'x-stack-connection';

export interface CallShape {
  body: Record<string, unknown>;
  method: string;
  upstream: URL;
  /**
   * Asked once the caller's key is known, before STACK's provider balance, the authority or anything else is touched:
   * a refusal here (an endpoint an account's agent does not reach on STACK's key) costs nothing.
   */
  allowOn?: (access: ModelAccess, who: { operatorId: string; agentId: string }) => Promise<void>;
}

export async function admitCall(
  services: Services,
  request: FastifyRequest,
  config: LlmHandlerConfig,
): Promise<AdmittedCall> {
  // 1. Parse + validate request body against provider schema.
  const parsed = config.schema.safeParse(request.body);
  if (!parsed.success) {
    throw new StackError(
      parsed.error.errors.map((e: { message: string }) => e.message).join(', '),
      'INVALID_REQUEST',
      400,
    );
  }
  return admitCaller(services, request, config, {
    body: parsed.data as Record<string, unknown>,
    method: 'POST',
    upstream: new URL(config.upstreamUrl ?? LLM_PROVIDERS[config.provider].url),
  });
}

/**
 * 2. The caller: passport mandatory, whose key the call runs on, and the runtime authority's decision for it. The
 * body has been read already (a provider's own schema, or the OpenRouter passthrough's raw request).
 */
export async function admitCaller(
  services: Services,
  request: FastifyRequest,
  config: LlmHandlerConfig,
  shape: CallShape,
): Promise<AdmittedCall> {
  const { body, method, upstream } = shape;
  const isStreaming = body.stream === true;

  // 2. Passport mandatory.
  const passportToken = request.headers['x-passport-token'] as string | undefined;
  if (!passportToken) {
    throw new ForbiddenError('X-Passport-Token header required for LLM requests');
  }
  const claims = await services.passport.verify(passportToken);
  const jti = claims.jti;
  const agentId = claims.stk.agent_id;
  const operatorId = claims.stk.operator_id;
  const mode = claims.stk.accountability as 'enforced' | 'logged' | 'standard' | undefined;
  const missionIds = claims.stk.mission_ids;
  // Required before the authority attribution below; beginAgentRuntime then
  // admits the call against this Mission.
  const missionRef = requireMissionRef(missionIds);
  const normalizedRequest = {
    method,
    url: {
      pathname: upstream.pathname,
      host: upstream.host.toLowerCase(),
      origin: upstream.origin,
    },
    body,
    query: {},
    headers: {},
    resource_type: 'llm_model',
    resource_ref: typeof body.model === 'string' ? body.model : upstream.pathname,
  };
  // Whose key this call runs on. An agent account's agent runs on STACK's
  // OpenRouter key and has no connection of its own for the provider; a
  // refusal here (account not open, models not ready) happens before anything
  // is metered. Every other agent resolves its operator's connection as before.
  const modelAccess = await services.modelAccessPolicy.resolve(operatorId, agentId, config.provider);
  if (modelAccess.kind === 'account' && claims.stk.fleet) {
    throw new ForbiddenError('A fleet passport cannot use the models of an agent account');
  }
  if (shape.allowOn) await shape.allowOn(modelAccess, { operatorId, agentId });
  // The one pick among the connections this caller may use, made here once: the authority below, Mission admission and
  // the credential read all use the connection it names, so the key sent is the connection that was authorized. A
  // refusal (ambiguous, or not the caller's) comes before anything is metered, decrypted or sent.
  //
  // A provider the Passport never granted is refused first, with its security event: the pick below would otherwise
  // answer that caller with the account's connection names.
  if (modelAccess.kind !== 'account' && !claims.stk.services.some((s) => s.service_name === config.provider)) {
    await assertProviderGranted(services, config.provider, { claims, jti, agentId, operatorId, mode, missionIds, modelAccess });
  }
  const connection = modelAccess.kind === 'account'
    ? undefined
    : await services.serviceConnection.resolveProxyConnection(
      operatorId,
      config.provider,
      connectionEligibility(request, config.provider, claims),
      readConnectionSelector(request),
    ).catch((err: unknown) => {
      if (err instanceof NotFoundError) {
        throw new ForbiddenError(
          `No ${config.provider} connection on this operator. Connect ${config.provider} at /services first.`,
        );
      }
      throw err;
    });
  // No customer connection exists for an agent account. The runtime authority boundary is bound to the account
  // instead, so no receiver bound to a real connection can match it: an authority-protected passport is refused, not
  // widened.
  const authorityConnectionId = modelAccess.kind === 'account'
    ? `stack_account_models:${modelAccess.accountId}`
    : connection!.connection_id;
  const authorityDecision = await enforceRuntimeAuthority(services.authority, {
    operatorId,
    passportJti: jti,
    agentId,
    authenticatedAgentId: request.agentId ?? null,
    receiverRequestId: runtimeAuthorityRequestIdFromHeaders(request.headers),
    missionId: missionRef,
    boundary: {
      kind: 'llm',
      serviceConnectionId: authorityConnectionId,
      provider: config.provider,
      operation: config.action,
    },
    normalizedRequest,
    verificationMode: 'proxy_mediated',
  });
  return {
    body,
    method,
    isStreaming,
    passportToken,
    claims,
    jti,
    agentId,
    operatorId,
    mode,
    missionIds,
    missionRef,
    upstream,
    normalizedRequest,
    connectionId: connection?.connection_id,
    authorityConnectionId,
    authorityDecision,
    modelAccess,
  };
}

function readConnectionSelector(request: FastifyRequest): string | undefined {
  const raw = request.headers[CONNECTION_HEADER];
  if (raw === undefined) return undefined;
  const parsed = ConnectionSelector.safeParse(Array.isArray(raw) ? raw.join(',') : raw);
  if (!parsed.success) throw new StackError('X-Stack-Connection must be a connection name or id', 'INVALID_REQUEST', 400);
  return parsed.data;
}
