/** Resolution of a normalized request to the action a pinned domain profile defines. */
import { ForbiddenError } from '@stack/shared';
import type { AuthorityBindingRecord, AuthorityRuntimeBoundary } from './records.js';
import type { AuthorityServiceDeps } from './contracts.js';
import type { AuthorityCore } from './core.js';
import { jsonSchemaMatches } from './domain-schema.js';

type DomainAction = Record<string, unknown>;

/** `resource_ref` and `resource_type` as the normalized request declares them. */
function declaredResource(normalizedRequest: unknown): {
  resourceRef: string | undefined;
  resourceType: string | undefined;
} {
  const request =
    normalizedRequest && typeof normalizedRequest === 'object' && !Array.isArray(normalizedRequest)
      ? (normalizedRequest as Record<string, unknown>)
      : {};
  return {
    resourceRef: request.resource_ref === undefined ? undefined : String(request.resource_ref),
    resourceType: request.resource_type === undefined ? undefined : String(request.resource_type),
  };
}

/** A domain action that lists resource types only admits requests of one of them. */
function assertResourceTypeAllowed(
  action: DomainAction,
  resourceType: string | undefined,
  message: string,
): void {
  const allowedResourceTypes = (action.resource_types as string[]) ?? [];
  if (
    allowedResourceTypes.length > 0 &&
    (!resourceType || !allowedResourceTypes.includes(resourceType))
  ) {
    throw new ForbiddenError(message);
  }
}

/**
 * The two resolvers below share the pinned-profile lookup, action matching and
 * resource-type check. They are deliberately not merged: the runtime resolver
 * also checks the boundary domain and refuses an action without a semantic URI,
 * and each reports its own refusal messages.
 */
export class DomainSemantics {
  private readonly deps: AuthorityServiceDeps;

  constructor(core: AuthorityCore) {
    this.deps = core.deps;
  }

  /** The active domain profile configuration the binding pinned at creation. */
  private async pinnedDomainConfig(
    binding: AuthorityBindingRecord,
  ): Promise<Record<string, unknown>> {
    if (!binding.domain_profile_version_id)
      throw new ForbiddenError('authority binding has no pinned domain profile');
    const row = await this.deps.repo.findProfileVersion(
      binding.operator_id,
      'domain',
      binding.domain_profile_version_id,
    );
    if (!row || row.status !== 'active')
      throw new ForbiddenError('pinned authority domain profile is unavailable');
    return row.config_json as Record<string, unknown>;
  }

  private matchingDomainActions(
    config: Record<string, unknown>,
    normalizedRequest: unknown,
  ): DomainAction[] {
    return ((config.actions as DomainAction[]) ?? []).filter((candidate) =>
      jsonSchemaMatches(candidate.normalized_request_schema, normalizedRequest),
    );
  }

  async resolveRuntimeSemantics(
    binding: AuthorityBindingRecord,
    boundary: AuthorityRuntimeBoundary,
    normalizedRequest: unknown,
  ): Promise<{ actionUri: string; resourceRef?: string }> {
    const config = await this.pinnedDomainConfig(binding);
    const boundaryDomain =
      boundary.kind === 'proxy' || boundary.kind === 'llm'
        ? boundary.provider
        : boundary.kind === 'skill'
          ? 'stack:skill'
          : boundary.kind === 'dropoff'
            ? 'stack:dropoff'
            : 'stack:agent';
    if (config.domain !== boundaryDomain)
      throw new ForbiddenError('runtime boundary does not match the pinned domain profile');
    const actions = this.matchingDomainActions(config, normalizedRequest);
    if (actions.length === 0)
      throw new ForbiddenError('normalized request matches no action in the pinned domain profile');
    if (actions.length > 1)
      throw new ForbiddenError('normalized request ambiguously matches multiple domain actions');
    const action = actions[0]!;
    const actionUri = String(action.action_uri ?? '');
    if (!actionUri) throw new ForbiddenError('pinned domain action has no semantic URI');
    const { resourceRef, resourceType } = declaredResource(normalizedRequest);
    assertResourceTypeAllowed(
      action,
      resourceType,
      'normalized request resource type is outside the pinned domain action',
    );
    return { actionUri, ...(resourceRef ? { resourceRef } : {}) };
  }

  async resolveNativeSemantics(
    binding: AuthorityBindingRecord,
    normalizedRequest: unknown,
  ): Promise<{ actionUri: string; resourceRef?: string }> {
    const config = await this.pinnedDomainConfig(binding);
    const actions = this.matchingDomainActions(config, normalizedRequest);
    if (actions.length !== 1)
      throw new ForbiddenError(
        actions.length === 0
          ? 'normalized native request matches no pinned domain action'
          : 'normalized native request ambiguously matches multiple domain actions',
      );
    const action = actions[0]!;
    const { resourceRef, resourceType } = declaredResource(normalizedRequest);
    assertResourceTypeAllowed(
      action,
      resourceType,
      'native request resource type is outside the pinned domain action',
    );
    return { actionUri: String(action.action_uri), ...(resourceRef ? { resourceRef } : {}) };
  }
}
