import { env } from '../env.js';
import type { DeploymentCredentials } from '../../extension.js';

/**
 * What the environment says of the providers the engine itself uses, when the
 * system operator's vault holds none. A deployment that adds providers of its
 * own resolves those itself.
 */
export interface ProviderEnvFallbacks {
  openRouterKey?: string;
}

/**
 * Resolves the configuration of the providers the engine uses: the credential
 * vaulted on the system operator wins, the environment variable is the
 * fallback. A provider with neither resolves to an empty key and its service
 * stays off.
 */
export function resolveProviderConfigs(bootstrapped: DeploymentCredentials, fallbacks: ProviderEnvFallbacks = {}) {
  // Resend: vault first, env var fallback
  const resendKey = bootstrapped.resend?.apiKey ?? env.RESEND_API_KEY;

  // OpenRouter: vault first, env var fallback
  const openRouterKey = bootstrapped.openrouter?.apiKey ?? fallbacks.openRouterKey ?? '';

  return { resendKey, openRouterKey };
}

export type ProviderConfigs = ReturnType<typeof resolveProviderConfigs>;
