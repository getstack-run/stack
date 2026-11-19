// Every endpoint OpenRouter's API has, as the model gateway sees it (https://openrouter.ai/docs/api-reference and its
// OpenAPI document). The route `/v1/llm/openrouter/*` passes any path and method to OpenRouter; this table is what the
// gateway knows about each one, and what an account's agent, which runs on STACK's own OpenRouter key, may reach:
//
//   inference  makes something and costs money: its worst case is held first and the call is charged at the cost OpenRouter reports.
//   discovery  public reads (the model list and the rest): nothing is held, nothing is charged.
//   job        a read of something the caller made earlier (a video job): allowed for the account that made it only.
//   account    the OpenRouter ACCOUNT of whoever holds the key: its keys, credits, workspaces, guardrails, files, batches,
//              presets, stored generations and so on. STACK's own key is one account shared by every agent account, so
//              none of these is offered on it. On the customer's OWN key every endpoint passes, this table or not.
//
// A path this table does not list is passed on the customer's own key and refused on STACK's, until it is added here
// (`OPENROUTER_ENDPOINTS`, with a test that holds the table to the shape of the document).

export type OpenRouterEndpointKind = 'inference' | 'discovery' | 'job' | 'account';

export interface OpenRouterEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** The path below `https://openrouter.ai/api/v1`, with `{name}` for one segment that varies. */
  path: string;
  kind: OpenRouterEndpointKind;
  /** OpenRouter has marked it deprecated; it still passes. */
  deprecated?: true;
}

export const OPENROUTER_ENDPOINTS: readonly OpenRouterEndpoint[] = [
  { method: 'GET', path: '/activity', kind: 'account' },
  { method: 'GET', path: '/analytics/meta', kind: 'account' },
  { method: 'POST', path: '/analytics/query', kind: 'account' },
  { method: 'POST', path: '/api/alpha/decisions', kind: 'inference' },
  { method: 'POST', path: '/audio/speech', kind: 'inference' },
  { method: 'POST', path: '/audio/transcriptions', kind: 'inference' },
  { method: 'POST', path: '/auth/keys', kind: 'account' },
  { method: 'POST', path: '/auth/keys/code', kind: 'account' },
  { method: 'GET', path: '/batches', kind: 'account' },
  { method: 'POST', path: '/batches', kind: 'account' },
  { method: 'DELETE', path: '/batches/{id}', kind: 'account' },
  { method: 'GET', path: '/batches/{id}', kind: 'account' },
  { method: 'GET', path: '/benchmarks', kind: 'discovery' },
  { method: 'GET', path: '/byok', kind: 'account' },
  { method: 'POST', path: '/byok', kind: 'account' },
  { method: 'DELETE', path: '/byok/{id}', kind: 'account' },
  { method: 'GET', path: '/byok/{id}', kind: 'account' },
  { method: 'PATCH', path: '/byok/{id}', kind: 'account' },
  { method: 'POST', path: '/chat/completions', kind: 'inference' },
  { method: 'GET', path: '/classifications/task', kind: 'discovery' },
  { method: 'POST', path: '/completions', kind: 'inference' },
  { method: 'GET', path: '/containers/{container_id}/files', kind: 'account' },
  { method: 'GET', path: '/containers/{container_id}/files/{file_id}', kind: 'account' },
  { method: 'GET', path: '/containers/{container_id}/files/{file_id}/content', kind: 'account' },
  { method: 'POST', path: '/containers/{container_id}/files/{file_id}/promote', kind: 'account' },
  { method: 'GET', path: '/credits', kind: 'account' },
  { method: 'POST', path: '/credits/coinbase', kind: 'account', deprecated: true },
  { method: 'POST', path: '/cursor', kind: 'inference' },
  { method: 'GET', path: '/datasets/app-rankings', kind: 'discovery' },
  { method: 'GET', path: '/datasets/rankings-daily', kind: 'discovery' },
  { method: 'GET', path: '/datasets/session-cost', kind: 'discovery' },
  { method: 'POST', path: '/embeddings', kind: 'inference' },
  { method: 'GET', path: '/embeddings/models', kind: 'discovery' },
  { method: 'POST', path: '/endpoints/{id}/capabilities/disable', kind: 'account' },
  { method: 'POST', path: '/endpoints/{id}/limits', kind: 'account' },
  { method: 'POST', path: '/endpoints/{id}/video-input', kind: 'account' },
  { method: 'POST', path: '/endpoints/{id}/visibility', kind: 'account' },
  { method: 'GET', path: '/endpoints/zdr', kind: 'discovery' },
  { method: 'GET', path: '/external-users', kind: 'account' },
  { method: 'POST', path: '/external-users', kind: 'account' },
  { method: 'DELETE', path: '/external-users/{user}', kind: 'account' },
  { method: 'GET', path: '/external-users/{user}', kind: 'account' },
  { method: 'PATCH', path: '/external-users/{user}', kind: 'account' },
  { method: 'GET', path: '/files', kind: 'account' },
  { method: 'POST', path: '/files', kind: 'account' },
  { method: 'DELETE', path: '/files/{file_id}', kind: 'account' },
  { method: 'GET', path: '/files/{file_id}', kind: 'account' },
  { method: 'GET', path: '/files/{file_id}/content', kind: 'account' },
  { method: 'GET', path: '/generation', kind: 'account' },
  { method: 'GET', path: '/generation/content', kind: 'account' },
  { method: 'POST', path: '/generation/feedback', kind: 'account' },
  { method: 'GET', path: '/guardrails', kind: 'account' },
  { method: 'POST', path: '/guardrails', kind: 'account' },
  { method: 'DELETE', path: '/guardrails/{id}', kind: 'account' },
  { method: 'GET', path: '/guardrails/{id}', kind: 'account' },
  { method: 'PATCH', path: '/guardrails/{id}', kind: 'account' },
  { method: 'GET', path: '/guardrails/{id}/assignments/keys', kind: 'account' },
  { method: 'POST', path: '/guardrails/{id}/assignments/keys', kind: 'account' },
  { method: 'POST', path: '/guardrails/{id}/assignments/keys/remove', kind: 'account' },
  { method: 'GET', path: '/guardrails/{id}/assignments/members', kind: 'account' },
  { method: 'POST', path: '/guardrails/{id}/assignments/members', kind: 'account' },
  { method: 'POST', path: '/guardrails/{id}/assignments/members/remove', kind: 'account' },
  { method: 'GET', path: '/guardrails/assignments/keys', kind: 'account' },
  { method: 'GET', path: '/guardrails/assignments/members', kind: 'account' },
  { method: 'POST', path: '/images', kind: 'inference' },
  { method: 'GET', path: '/images/models', kind: 'discovery' },
  { method: 'GET', path: '/images/models/{author}/{slug}/endpoints', kind: 'discovery' },
  { method: 'GET', path: '/key', kind: 'account' },
  { method: 'GET', path: '/keys', kind: 'account' },
  { method: 'POST', path: '/keys', kind: 'account' },
  { method: 'DELETE', path: '/keys/{hash}', kind: 'account' },
  { method: 'GET', path: '/keys/{hash}', kind: 'account' },
  { method: 'PATCH', path: '/keys/{hash}', kind: 'account' },
  { method: 'POST', path: '/messages', kind: 'inference' },
  { method: 'GET', path: '/model/{author}/{slug}', kind: 'discovery' },
  { method: 'GET', path: '/models', kind: 'discovery' },
  { method: 'GET', path: '/models/{author}/{slug}/endpoints', kind: 'discovery' },
  { method: 'GET', path: '/models/count', kind: 'discovery' },
  { method: 'GET', path: '/models/user', kind: 'account' },
  { method: 'GET', path: '/oauth/jwks', kind: 'account' },
  { method: 'POST', path: '/oauth/token', kind: 'account' },
  { method: 'GET', path: '/observability/destinations', kind: 'account' },
  { method: 'POST', path: '/observability/destinations', kind: 'account' },
  { method: 'DELETE', path: '/observability/destinations/{id}', kind: 'account' },
  { method: 'GET', path: '/observability/destinations/{id}', kind: 'account' },
  { method: 'PATCH', path: '/observability/destinations/{id}', kind: 'account' },
  { method: 'GET', path: '/organization/members', kind: 'account' },
  { method: 'GET', path: '/organization/settings', kind: 'account' },
  { method: 'PATCH', path: '/organization/settings', kind: 'account' },
  { method: 'GET', path: '/presets', kind: 'account' },
  { method: 'GET', path: '/presets/{slug}', kind: 'account' },
  { method: 'POST', path: '/presets/{slug}/chat/completions', kind: 'account' },
  { method: 'POST', path: '/presets/{slug}/messages', kind: 'account' },
  { method: 'POST', path: '/presets/{slug}/responses', kind: 'account' },
  { method: 'GET', path: '/presets/{slug}/versions', kind: 'account' },
  { method: 'GET', path: '/presets/{slug}/versions/{version}', kind: 'account' },
  { method: 'GET', path: '/private-endpoints', kind: 'account' },
  { method: 'POST', path: '/private-endpoints', kind: 'account' },
  { method: 'DELETE', path: '/private-endpoints/{id}', kind: 'account' },
  { method: 'GET', path: '/private-endpoints/{id}', kind: 'account' },
  { method: 'PATCH', path: '/private-endpoints/{id}', kind: 'account' },
  { method: 'POST', path: '/private-endpoints/{id}/activate', kind: 'account' },
  { method: 'POST', path: '/private-endpoints/{id}/disable', kind: 'account' },
  { method: 'POST', path: '/private-endpoints/{id}/enable', kind: 'account' },
  { method: 'PUT', path: '/private-endpoints/{id}/parameters', kind: 'account', deprecated: true },
  { method: 'PUT', path: '/private-endpoints/{id}/pricing', kind: 'account', deprecated: true },
  { method: 'POST', path: '/private-endpoints/{id}/validate', kind: 'account' },
  { method: 'GET', path: '/private-providers', kind: 'account' },
  { method: 'POST', path: '/private-providers', kind: 'account' },
  { method: 'DELETE', path: '/private-providers/{slug}', kind: 'account' },
  { method: 'GET', path: '/private-providers/{slug}', kind: 'account' },
  { method: 'PATCH', path: '/private-providers/{slug}', kind: 'account' },
  { method: 'GET', path: '/providers', kind: 'discovery' },
  { method: 'GET', path: '/providers/{slug}', kind: 'account' },
  { method: 'GET', path: '/providers/{slug}/members', kind: 'account' },
  { method: 'POST', path: '/provisioning/oauth/token', kind: 'account' },
  { method: 'POST', path: '/rerank', kind: 'inference' },
  { method: 'POST', path: '/responses', kind: 'inference' },
  { method: 'GET', path: '/scim/group-mappings', kind: 'account' },
  { method: 'POST', path: '/scim/group-mappings', kind: 'account' },
  { method: 'DELETE', path: '/scim/group-mappings/{id}', kind: 'account' },
  { method: 'GET', path: '/scim/group-mappings/{id}', kind: 'account' },
  { method: 'PATCH', path: '/scim/group-mappings/{id}', kind: 'account' },
  { method: 'GET', path: '/scim/groups', kind: 'account' },
  { method: 'POST', path: '/scim/sync-jobs', kind: 'account' },
  { method: 'GET', path: '/scim/sync-jobs/{id}', kind: 'account' },
  { method: 'POST', path: '/systemone', kind: 'inference' },
  { method: 'GET', path: '/tools', kind: 'discovery' },
  { method: 'GET', path: '/tools/{name}', kind: 'discovery' },
  { method: 'GET', path: '/vault/interns/{internId}/connections', kind: 'account' },
  { method: 'GET', path: '/vault/interns/{internId}/effective-secrets', kind: 'account' },
  { method: 'GET', path: '/vault/interns/{internId}/secrets', kind: 'account' },
  { method: 'DELETE', path: '/vault/interns/{internId}/secrets/{name}', kind: 'account' },
  { method: 'PUT', path: '/vault/interns/{internId}/secrets/{name}', kind: 'account' },
  { method: 'POST', path: '/vault/interns/{internId}/secrets/copy', kind: 'account' },
  { method: 'GET', path: '/vault/secrets', kind: 'account' },
  { method: 'DELETE', path: '/vault/secrets/{name}', kind: 'account' },
  { method: 'PUT', path: '/vault/secrets/{name}', kind: 'account' },
  { method: 'POST', path: '/videos', kind: 'inference' },
  { method: 'GET', path: '/videos/{jobId}', kind: 'job' },
  { method: 'GET', path: '/videos/{jobId}/content', kind: 'job' },
  { method: 'GET', path: '/videos/models', kind: 'discovery' },
  { method: 'GET', path: '/workspaces', kind: 'account' },
  { method: 'POST', path: '/workspaces', kind: 'account' },
  { method: 'DELETE', path: '/workspaces/{id}', kind: 'account' },
  { method: 'GET', path: '/workspaces/{id}', kind: 'account' },
  { method: 'PATCH', path: '/workspaces/{id}', kind: 'account' },
  { method: 'GET', path: '/workspaces/{id}/members', kind: 'account' },
  { method: 'POST', path: '/workspaces/{id}/members/add', kind: 'account' },
  { method: 'POST', path: '/workspaces/{id}/members/remove', kind: 'account' },
  { method: 'GET', path: '/workspaces/{workspace_ref}/budgets', kind: 'account' },
  { method: 'DELETE', path: '/workspaces/{workspace_ref}/budgets/{interval}', kind: 'account' },
  { method: 'GET', path: '/workspaces/{workspace_ref}/budgets/{interval}', kind: 'account' },
  { method: 'PUT', path: '/workspaces/{workspace_ref}/budgets/{interval}', kind: 'account' },
];

export interface OpenRouterEndpointMatch {
  endpoint: OpenRouterEndpoint;
  /** The values of the `{name}` segments, by name. */
  params: Record<string, string>;
}

/** One segment of a path below the API base: letters, digits and the few marks a model id or a job id carries. */
const SEGMENT = /^[A-Za-z0-9~@][A-Za-z0-9._~:@+=,-]{0,199}$/;

/**
 * Why a path below `https://openrouter.ai/api/v1` is not one the gateway sends, or null when it is. The host is fixed and
 * so is the base: no `..`, no empty segment, no percent-encoding (a model id never needs it), no backslash.
 */
export function openRouterPathProblem(path: string): string | null {
  if (path.length === 0 || path.length > 512) return 'The path must be 1 to 512 characters.';
  const segments = path.split('/');
  if (segments.length > 12) return 'The path has too many segments.';
  for (const segment of segments) {
    if (!SEGMENT.test(segment) || segment === '.' || segment === '..') {
      return 'The path has a segment OpenRouter does not use: only letters, digits and . _ ~ : @ + = , - are sent, and none may be empty.';
    }
  }
  return null;
}

function matchSegments(template: string[], actual: string[]): Record<string, string> | null {
  if (template.length !== actual.length) return null;
  const params: Record<string, string> = {};
  for (let index = 0; index < template.length; index += 1) {
    const want = template[index]!;
    const have = actual[index]!;
    if (want.startsWith('{') && want.endsWith('}')) params[want.slice(1, -1)] = have;
    else if (want !== have) return null;
  }
  return params;
}

/** How many segments of a template are fixed: `/videos/models` is more specific than `/videos/{jobId}`. */
function specificity(template: string[]): number {
  return template.filter((segment) => !segment.startsWith('{')).length;
}

/** The table's endpoint for a method and a path (no leading slash needed), the most specific match, or null. */
export function matchOpenRouterEndpoint(method: string, path: string): OpenRouterEndpointMatch | null {
  const actual = path.replace(/^\/+/, '').split('/');
  let best: (OpenRouterEndpointMatch & { score: number }) | null = null;
  for (const endpoint of OPENROUTER_ENDPOINTS) {
    if (endpoint.method !== method) continue;
    const template = endpoint.path.replace(/^\/+/, '').split('/');
    const params = matchSegments(template, actual);
    if (!params) continue;
    const score = specificity(template);
    if (!best || score > best.score) best = { endpoint, params, score };
  }
  return best ? { endpoint: best.endpoint, params: best.params } : null;
}
