// What of OpenRouter's API a caller may reach, and how the call is named in the audit record and the signed intent.
//
// The customer's own OpenRouter key passes every endpoint and every method: it is their account. STACK's key is one
// OpenRouter account shared by every agent account, so an account's agent reaches the endpoints that make something
// (inference), the public reads (discovery) and a video job it started, and nothing that is the OpenRouter ACCOUNT of
// the key's holder (`OPENROUTER_ENDPOINTS`, packages/shared/src/constants/openrouter-endpoints.ts).

import { NotFoundError, OpenRouterEndpointRefusedError } from '@stack/shared';
import type { ModelAccess } from '../../../lib/model-access-policy.js';
import type { Services } from '../../../config/services.js';
import type { OpenRouterCall } from './request.js';

/** The class of an endpoint in the table; a path the table does not list is `unlisted`. */
export type CallKind = 'inference' | 'discovery' | 'job' | 'account' | 'unlisted';

export function kindOf(call: OpenRouterCall): CallKind {
  return call.match?.endpoint.kind ?? 'unlisted';
}

/** `chat/completions`, `get.videos.id.content`: the endpoint as a label with no ids in it, so the audit record stays countable. */
function label(call: OpenRouterCall): string {
  const template = call.match?.endpoint.path;
  const segments = template
    ? template.replace(/^\/+/, '').split('/').map((segment) => (segment.startsWith('{') ? 'id' : segment))
    : ['unlisted'];
  const dotted = segments.join('.');
  return call.method === 'POST' && template ? dotted : `${call.method.toLowerCase()}.${dotted}`;
}

/** The audit action and the named intent of a call. */
export function labelsOf(call: OpenRouterCall): { action: string; namedIntent: string } {
  const name = label(call);
  return { action: `llm.openrouter.${name}`, namedIntent: `openrouter:llm:${name}` };
}

/** A read changes nothing and is never put to the customer's decider; every other call is. */
export function isRead(call: OpenRouterCall): boolean {
  return call.method === 'GET' || call.method === 'HEAD';
}

/**
 * Whether the call takes a hold on STACK's key: an inference call (a POST that makes something). Everything else an
 * account's agent may reach is free.
 */
export function holdsOnStackKey(call: OpenRouterCall): boolean {
  return kindOf(call) === 'inference';
}

/**
 * The refusal an account's agent gets for an endpoint it does not reach on STACK's key, or the missing job. Asked once
 * the caller's key is known, before anything is counted, held or sent.
 */
export function endpointGate(
  services: Pick<Services, 'modelAccessPolicy'>,
  call: OpenRouterCall,
): (access: ModelAccess, who: { operatorId: string; agentId: string }) => Promise<void> {
  return async (access, who) => {
    if (access.kind === 'customer') return;
    const kind = kindOf(call);
    const where = { method: call.method, path: call.path };
    if (kind === 'unlisted') {
      throw new OpenRouterEndpointRefusedError(
        `STACK's OpenRouter key passes the endpoints it knows (inference, the public lists and your own video jobs). ${call.method} ${call.path} is not one of them.`,
        { ...where, reason: 'not_listed' },
      );
    }
    if (kind === 'account') {
      throw new OpenRouterEndpointRefusedError(
        `${call.method} ${call.path} belongs to the OpenRouter account that holds STACK's key, which every agent account shares, so an account's agent cannot use it. Model calls, the public lists, images, audio, video and embeddings are open to it.`,
        { ...where, reason: 'account_endpoint' },
      );
    }
    if (kind === 'job') {
      const jobId = call.match?.params['jobId'] ?? '';
      // Not yours reads as not found: nothing says whose a job is.
      if (!(await services.modelAccessPolicy.ownsJob(who.operatorId, access.accountId, jobId))) {
        throw new NotFoundError('Video job', jobId);
      }
    }
  };
}
