import type { ServerResponse } from 'node:http';
import { MCP_DIRECTORY_OAUTH_SCOPES, MCP_OAUTH_SCOPES } from '../oauth-scopes.js';
import { DIRECTORY_PATH, MCP_PATH, PROTECTED_RESOURCE_PREFIX } from './config.js';
import type { EndpointConfig } from './types.js';

/**
 * The two MCP endpoints and the OAuth metadata URL each one names in its 401
 * challenge. /mcp serves every credential the API accepts except a token
 * granted for the directory resource; /directory serves only OAuth tokens
 * granted for its own exact resource.
 */
export function createEndpointTable(
  mcpResource: string,
  directoryResource: string,
): Record<string, EndpointConfig> {
  const protectedResourceMetadataUrl = `${new URL(mcpResource).origin}/.well-known/oauth-protected-resource`;
  // RFC 9728 §3.1: metadata for a resource with a path lives at the
  // well-known prefix followed by that path.
  const directoryMetadataUrl = `${new URL(directoryResource).origin}${PROTECTED_RESOURCE_PREFIX}${new URL(directoryResource).pathname}`;
  const endpoints: Record<string, EndpointConfig> = {
    [MCP_PATH]: {
      profile: 'standard',
      metadataUrl: protectedResourceMetadataUrl,
      scopes: MCP_OAUTH_SCOPES,
      // /mcp serves every credential the API accepts except a token granted
      // for the directory resource.
      acceptsResource: (resource) => resource !== directoryResource,
    },
    [DIRECTORY_PATH]: {
      profile: 'directory',
      metadataUrl: directoryMetadataUrl,
      scopes: MCP_DIRECTORY_OAUTH_SCOPES,
      // /directory serves only OAuth tokens granted for this exact resource.
      acceptsResource: (resource) => resource === directoryResource,
    },
  };
  return endpoints;
}

/**
 * RFC 9728 protected-resource metadata. Answers the root and `/mcp` documents
 * and the `/directory` document when OAuth is enabled; returns false for any
 * other path so the caller continues routing.
 */
export function handleProtectedResourceMetadata(
  url: URL,
  res: ServerResponse,
  settings: { oauthEnabled: boolean; apiUrl: string; mcpResource: string; directoryResource: string },
): boolean {
  const { oauthEnabled, apiUrl, mcpResource, directoryResource } = settings;
  if (
    (url.pathname === PROTECTED_RESOURCE_PREFIX
      || url.pathname === `${PROTECTED_RESOURCE_PREFIX}${MCP_PATH}`)
    && oauthEnabled
  ) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      resource: mcpResource,
      authorization_servers: [apiUrl],
      bearer_methods_supported: ['header'],
      scopes_supported: [...MCP_OAUTH_SCOPES],
    }));
    return true;
  }

  if (url.pathname === `${PROTECTED_RESOURCE_PREFIX}${DIRECTORY_PATH}` && oauthEnabled) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      resource: directoryResource,
      authorization_servers: [apiUrl],
      bearer_methods_supported: ['header'],
      scopes_supported: [...MCP_DIRECTORY_OAUTH_SCOPES],
    }));
    return true;
  }
  return false;
}
