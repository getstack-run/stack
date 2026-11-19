import { decodeJwt } from 'jose';
import type { PassportIssueScope } from './types.js';

// This only prepares a request. The API verifies the signature and authority.
export function delegationScopesFromToken(token: string, providers?: string[]): PassportIssueScope[] {
  const claims = decodeJwt(token);
  const services = (claims['stk'] as { services?: unknown } | undefined)?.services;
  if (!Array.isArray(services)) throw new Error('Invalid input');
  const selected = providers ? services.filter(scope => providers.includes(scope.service_name)) : services;
  if (providers?.some(provider => !selected.some(scope => scope.service_name === provider))) throw new Error('Invalid input');
  return selected.map(scope => {
    if (typeof scope.connection_id !== 'string' || !Array.isArray(scope.scopes)) throw new Error('Invalid input');
    return { service_connection_id: scope.connection_id, scopes: scope.scopes,
      ...(scope.constraints ? { constraints: scope.constraints } : {}),
      ...(scope.allow_data_from ? { allow_data_from: scope.allow_data_from } : {}) };
  });
}
