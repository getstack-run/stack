// What a proxied call leaves on the data trail.
//
// An entity_observation records the entities a call READ (the answer's headers and body) and the ones it SENT (the
// request's own URL and body), as one-way digests. The undeclared-counterparty check needs both: a host, an address or
// an id the agent already dealt with is not new. The data-flow rule needs only the first, and only some of the second:
//
//   - what a service RETURNED is content read from it, and stays so;
//   - what the agent put in the request's own URL (host, path, query) is something the agent SENT, not something it
//     read. Counting it made `GET /v1/models` on one service refuse `GET /v1/models` on another: the second request's
//     own path matched the first call's recorded path.
//
// So the URL's entities stay in `entities` (the counterparty check reads them there) and the ones that are the request's
// own URL alone are listed again in `request_entities`, which the data-flow rule leaves out. An entity that the answer
// (or the request body) also carries is read content and is not listed: a path value the service echoed back is still
// read from it. Rows recorded before this field existed carry no `request_entities` and are read as they always were.

import {
  extractEntities,
  isFinancialProvider,
  trailEntity,
  type ExtractedEntity,
} from '@stack/shared';

/** An observation claim carries at most this many entities (the schema's cap). */
export const OBSERVATION_MAX_ENTITIES = 256;

/** Merge in order, first occurrence wins (by value, case-insensitively), capped at the claim's size. */
export function mergeProxyEntityCandidates<T extends { entity: string }>(
  responseEntities: readonly T[],
  outboundEntities: readonly T[],
): T[] {
  const seen = new Set<string>();
  const merged: T[] = [];
  for (const candidate of [...responseEntities, ...outboundEntities]) {
    const key = candidate.entity.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(candidate);
    if (merged.length === OBSERVATION_MAX_ENTITIES) break;
  }
  return merged;
}

export interface ProxyCallEntities {
  /** Everything the observation records, in order: what the answer carried, then the request's URL, then its body. */
  candidates: ExtractedEntity[];
  /** The digests, among those recorded, that are the request's own URL and nothing the call read. */
  requestEntities: string[];
  /** What the call sent (URL and body), as the undeclared-counterparty check judges it. */
  outbound: ExtractedEntity[];
}

export function proxyCallEntities(input: {
  service: string;
  method: string;
  resolvedUrl: string;
  requestBody: unknown;
  responseHeaders: unknown;
  /** The answer's body, parsed when it was JSON. */
  responseBody: unknown;
}): ProxyCallEntities {
  // Money amounts and account numbers are recorded only from a financial provider, and only as one-way digests.
  const financial = { financial: isFinancialProvider(input.service) };
  const read = extractEntities({
    method: input.method,
    response_headers: input.responseHeaders,
    response_body: input.responseBody,
  }, financial);
  const sentUrl = extractEntities({ url: input.resolvedUrl }, financial);
  const sentBody = extractEntities({ body: input.requestBody });

  const candidates = mergeProxyEntityCandidates(read, [...sentUrl, ...sentBody]);

  // Read content: the answer, and the request body (which is what the agent is about to pass on). Only what is the
  // URL's alone is the request's own.
  const readKeys = new Set([...read, ...sentBody].map((c) => c.entity.toLowerCase()));
  const recorded = new Set(candidates.map((c) => c.entity.toLowerCase()));
  const requestEntities = [...new Set(
    sentUrl
      .map((c) => c.entity.toLowerCase())
      .filter((key) => recorded.has(key) && !readKeys.has(key)),
  )].map((key) => trailEntity(key));

  const outbound = mergeProxyEntityCandidates(
    sentUrl.filter((c) => c.entity_type !== 'money_amount' && c.entity_type !== 'account_number'),
    sentBody,
  );
  return { candidates, requestEntities, outbound };
}
