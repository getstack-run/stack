import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  OidcIdpConfigCreateInput,
  OidcIdpConfigUpdateInput,
  IdentityConfigExistsError,
  SSO_JWKS_CACHE_DEFAULT_SECONDS,
  assertPublicUrl,
  publicFetch,
  StackError,
  NotFoundError,
  ids,
  sha256,
} from '@stack/shared';
import type { Services } from '../../config/services.js';
import { auditCtx } from '../../middleware/audit.js';
import { enforceGovernanceStepUp } from '../../middleware/governance-stepup.js';

type OidcConfigRow = NonNullable<
  Awaited<ReturnType<Services['oidcIdpConfigRepo']['findById']>>
>;
type IdRequest = FastifyRequest<{ Params: { id: string } }>;

/** An OIDC config row without the secret and cache blobs. */
type PublicOidcConfig<T> = Omit<
  T,
  'client_secret_encrypted' | 'jwks_cached_jwks_json' | 'discovery_cached_json'
> & { jwks_cached: boolean };

interface OidcTestStep {
  step: string;
  ok: boolean;
  detail?: string;
}

/**
 * Fetch that refuses to follow redirects.
 *
 * An SSRF guard that validates a URL and then hands it to a redirect-
 * following fetch validates the wrong address: the attacker-controlled
 * host answers 302 and points us at 169.254.169.254, and assertPublicUrl
 * never sees that hop. Following redirects safely would mean re-guarding
 * every one; refusing them is simpler and costs nothing here, because
 * everything this is used for is a static document.
 */
async function fetchNoRedirect(url: string, timeoutMs = 5000): Promise<Response> {
  const res = await publicFetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: 'manual' });
  if (res.status >= 300 && res.status < 400) {
    throw new Error(
      `it redirected (HTTP ${res.status}); point this at the document itself, not a redirect`,
    );
  }
  return res;
}

/**
 * Single sign-on is part of the platform plan: no plan or tier gates it. On a
 * self-managed install the licence key decides (`sso`); the hosted gate always
 * says yes.
 */
export function assertSsoAvailable(services: Services): void {
  services.features.require('sso');
}

// ── OIDC IdP configuration (enterprise SSO) ──────────────────────
//
// Shape copied from the SPIFFE trust-domain CRUD (spiffe.ts): same auth
// posture, same 404-not-403 on a cross-operator id (a 403 would confirm
// the row exists and belongs to someone else).
//
// The client secret is write-only. It goes in KMS-wrapped under exactly
// {operator_id, provider:'oidc'} and comes back out of NO read path.
// contextsMatch compares key SETS by length first, so adding a third
// context key here would make every existing row undecryptable.
//
// Not exposed via the SDKs or as an MCP tool, deliberately: configuring
// who may log in is a governance action, and under no-self-authorization
// an agent context must never reach it. Whoever configures the provider
// decides who signs in as any member, the owner included, so every route
// is gated at the route by requireOperatorAdmin (owner or administrator
// member, agent contexts refused), reads too, and whatever loosens it is
// also a browser-only governance step-up here (`sso_config_change`): a new
// provider, a changed issuer, client, address, scope, claim mapping or
// role, turning sign-in on. Turning it off, renaming it, a cache time and
// deleting it only tighten, so they ask for no approval.

/** The settings that decide who the provider may sign in, so changing one is a loosening. */
const LOOSENING_FIELDS = [
  'issuer_uri',
  'client_id',
  'client_secret',
  'audience',
  'redirect_uri',
  'scopes',
  'claim_mapping_policy',
  'allowed_return_origins',
  'sso_slug',
  'default_member_role',
] as const;

/**
 * What the approval is bound to: the settings that loosen. The client secret is bound by its digest, never itself, so a
 * retry that stores a different secret than the request the approver was shown does not match the approval; the
 * digest is of a long random value the provider issued and only the approval's own hash is kept (the secret and the
 * digest are never stored or shown).
 */
function approvalPayload(input: Record<string, unknown>, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const payload: Record<string, unknown> = { ...extra };
  for (const field of LOOSENING_FIELDS) {
    if (input[field] === undefined) continue;
    payload[field] = field === 'client_secret' ? sha256(`oidc-client-secret\0${String(input[field])}`) : input[field];
  }
  return payload;
}

/**
 * The issuer's host name and nothing else, for the one line an approval is announced with (an email subject, a text):
 * what the caller typed after the host never reaches a person's phone in STACK's voice.
 */
function issuerHost(issuerUri: string): string {
  try {
    return new URL(issuerUri).hostname.slice(0, 80);
  } catch {
    return 'the address given';
  }
}

/** Strip the secret + heavy cache blobs from anything we hand back. */
function publicOidcConfig<T extends Record<string, unknown>>(row: T): PublicOidcConfig<T> {
  const {
    client_secret_encrypted: _secret,
    jwks_cached_jwks_json: jwks,
    discovery_cached_json: _disc,
    ...rest
  } = row;
  return { ...rest, jwks_cached: jwks ? true : false };
}

export async function getOidcConfig(
  request: FastifyRequest,
  services: Services,
): Promise<{ config: PublicOidcConfig<OidcConfigRow> | null }> {
  const row = await services.oidcIdpConfigRepo.findActiveByOperator(request.operatorId);
  return { config: row ? publicOidcConfig(row) : null };
}

export async function createOidcConfig(
  request: FastifyRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  const input = OidcIdpConfigCreateInput.parse(request.body);
  const start = Date.now();

  assertSsoAvailable(services);

  const existing = await services.oidcIdpConfigRepo.findActiveByOperator(request.operatorId);
  if (existing) {
    // One IdP per operator: oidc_idp_op_unique is on operator_id alone.
    // A friendly 409 beats an opaque constraint-violation 500.
    throw new IdentityConfigExistsError(
      'oidc',
      'This operator already has an OIDC IdP configured. Update it instead.',
      existing.id,
    );
  }

  await enforceGovernanceStepUp(services, request, {
    action: 'sso_config_change',
    resourceId: 'create',
    payload: approvalPayload(input, { active: input.active ?? true }),
    summary: `Set up ${issuerHost(input.issuer_uri)} as the identity provider of single sign-on. Anyone it signs in with an address of a member can then take that member's seat, the owner's included.`,
  });

  // .ciphertext is the stored form — the provider's decrypt() takes
  // exactly this string and re-derives the context from the envelope.
  const { ciphertext: client_secret_encrypted } = await services.kms.encrypt(
    input.client_secret,
    { operator_id: request.operatorId, provider: 'oidc' },
  );

  const row = await services.oidcIdpConfigRepo.create({
    id: ids.oidcIdpConfig(),
    operator_id: request.operatorId,
    display_name: input.display_name ?? null,
    issuer_uri: input.issuer_uri,
    client_id: input.client_id,
    client_secret_encrypted,
    audience: input.audience ?? null,
    redirect_uri: input.redirect_uri,
    scopes_json: input.scopes ?? ['openid', 'email', 'profile'],
    claim_mapping_policy_json: input.claim_mapping_policy ?? null,
    jwks_cache_ttl_seconds: input.jwks_cache_ttl_seconds ?? SSO_JWKS_CACHE_DEFAULT_SECONDS,
    allowed_return_origins: input.allowed_return_origins ?? null,
    sso_slug: input.sso_slug ?? null,
    // Never born enabled — configure, test, then enable.
    sso_login_enabled: false,
    default_member_role: input.default_member_role ?? 'standard',
    active: input.active ?? true,
  });

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'oidc.config.create',
    outcome: 'success',
    duration_ms: Date.now() - start,
    payload_hash: row.id,
  });

  return reply.code(201).send(publicOidcConfig(row));
}

export async function updateOidcConfig(
  request: IdRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  const input = OidcIdpConfigUpdateInput.parse(request.body);
  const start = Date.now();

  const row = await services.oidcIdpConfigRepo.findById(request.params.id);
  if (!row || row.operator_id !== request.operatorId) {
    throw new NotFoundError('OidcIdpConfig', request.params.id);
  }
  assertSsoAvailable(services);

  if (input.sso_login_enabled && !(input.sso_slug ?? row.sso_slug)) {
    throw new StackError(
      'SSO_SLUG_REQUIRED',
      'Set a login slug before enabling SSO login - /login/sso/<slug> is the entry point.',
      400,
    );
  }

  // Asked before anything is written, and only for what loosens: turning sign-in on or the provider back on counts
  // when it changes something, turning either off never does.
  const turnsSignInOn = input.sso_login_enabled === true && row.sso_login_enabled !== true;
  const turnsProviderOn = input.active === true && row.active !== true;
  const loosening = approvalPayload(input as Record<string, unknown>, {
    ...(turnsSignInOn ? { sso_login_enabled: true } : {}),
    ...(turnsProviderOn ? { active: true } : {}),
  });
  if (Object.keys(loosening).length > 0) {
    await enforceGovernanceStepUp(services, request, {
      action: 'sso_config_change',
      resourceId: request.params.id,
      payload: loosening,
      summary: `Change the identity provider of single sign-on (${Object.keys(loosening).join(', ').replaceAll('_', ' ')}). Anyone it signs in with an address of a member can take that member's seat, the owner's included.`,
    });
  }

  const updates: Record<string, unknown> = {};
  if (input.display_name !== undefined) updates['display_name'] = input.display_name;
  if (input.issuer_uri !== undefined) updates['issuer_uri'] = input.issuer_uri;
  if (input.client_id !== undefined) updates['client_id'] = input.client_id;
  if (input.audience !== undefined) updates['audience'] = input.audience;
  if (input.redirect_uri !== undefined) updates['redirect_uri'] = input.redirect_uri;
  if (input.scopes !== undefined) updates['scopes_json'] = input.scopes;
  if (input.claim_mapping_policy !== undefined) {
    updates['claim_mapping_policy_json'] = input.claim_mapping_policy;
  }
  if (input.jwks_cache_ttl_seconds !== undefined) {
    updates['jwks_cache_ttl_seconds'] = input.jwks_cache_ttl_seconds;
  }
  if (input.allowed_return_origins !== undefined) {
    updates['allowed_return_origins'] = input.allowed_return_origins;
  }
  if (input.sso_slug !== undefined) updates['sso_slug'] = input.sso_slug;
  if (input.default_member_role !== undefined) {
    updates['default_member_role'] = input.default_member_role;
  }
  if (input.active !== undefined) updates['active'] = input.active;
  if (input.client_secret !== undefined) {
    const rewrapped = await services.kms.encrypt(input.client_secret, {
      operator_id: request.operatorId,
      provider: 'oidc',
    });
    updates['client_secret_encrypted'] = rewrapped.ciphertext;
  }
  if (input.sso_login_enabled !== undefined) updates['sso_login_enabled'] = input.sso_login_enabled;
  updates['updated_at'] = new Date();

  const updated = await services.oidcIdpConfigRepo.update(request.params.id, updates as never);
  if (!updated) throw new NotFoundError('OidcIdpConfig', request.params.id);

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'oidc.config.update',
    outcome: 'success',
    duration_ms: Date.now() - start,
    payload_hash: request.params.id,
  });

  return reply.send(publicOidcConfig(updated));
}

// Test before enable. Reaches the IdP's discovery document and JWKS and
// unwraps the stored client secret — which catches the typos that
// actually happen: wrong issuer, unreachable host, a secret that was
// pasted with whitespace, a discovery doc missing endpoints.
//
// It is NOT a full sign-in: only a browser round-trip through the IdP
// proves the client_id and redirect_uri are registered correctly. The UI
// says so rather than implying a green tick means SSO definitely works.
export async function testOidcConfig(
  request: IdRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  const row = await services.oidcIdpConfigRepo.findById(request.params.id);
  if (!row || row.operator_id !== request.operatorId) {
    throw new NotFoundError('OidcIdpConfig', request.params.id);
  }

  const steps: OidcTestStep[] = [];
  type Discovery = {
    authorization_endpoint?: string;
    token_endpoint?: string;
    jwks_uri?: string;
  };
  let discovery: Discovery | null = null;

  try {
    // SSRF guard. issuer_uri is operator-supplied, and this route
    // fetches it server-side — without assertPublicUrl an operator
    // could point it at a private address and use the test button as
    // an internal port scanner. (This is the case url-guard IS for;
    // the open redirect in the callback is the case it is NOT.)
    const discoveryUrl = `${row.issuer_uri.replace(/\/$/, '')}/.well-known/openid-configuration`;
    await assertPublicUrl(discoveryUrl, { allowedProtocols: ['https:'] });
    // redirect: 'manual' closes the bypass. Guarding the URL and then
    // letting fetch follow a 302 checks the wrong address: a host that
    // passes the guard can redirect us to a private one, and the guard
    // never sees the hop. A discovery document is a static document —
    // an issuer that redirects for it is misconfigured, so refusing is
    // both safe and correct rather than merely cautious.
    const res = await fetchNoRedirect(discoveryUrl);
    if (!res.ok) throw new Error(`the issuer returned HTTP ${res.status}`);
    discovery = (await res.json()) as Discovery;
    const missing = (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const).filter(
      (k) => !discovery?.[k],
    );
    if (missing.length) throw new Error(`discovery document is missing ${missing.join(', ')}`);
    steps.push({ step: 'discovery', ok: true });
  } catch (err) {
    steps.push({ step: 'discovery', ok: false, detail: (err as Error).message });
  }

  if (discovery?.jwks_uri) {
    try {
      // Same guard: jwks_uri comes from the issuer's discovery
      // document, which is as caller-influenced as the issuer itself.
      await assertPublicUrl(discovery.jwks_uri, { allowedProtocols: ['https:'] });
      const res = await fetchNoRedirect(discovery.jwks_uri);
      if (!res.ok) throw new Error(`the JWKS endpoint returned HTTP ${res.status}`);
      const jwks = (await res.json()) as { keys?: unknown[] };
      if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) {
        throw new Error('the JWKS endpoint published no signing keys');
      }
      steps.push({ step: 'signing_keys', ok: true, detail: `${jwks.keys.length} key(s)` });
    } catch (err) {
      steps.push({ step: 'signing_keys', ok: false, detail: (err as Error).message });
    }
  }

  try {
    const secret = await services.kms.decrypt(row.client_secret_encrypted, {
      operator_id: request.operatorId,
      provider: 'oidc',
    });
    if (!secret) throw new Error('the stored client secret is empty');
    steps.push({ step: 'client_secret', ok: true });
  } catch {
    // Never echo the failure detail — it can carry key material or
    // context internals.
    steps.push({ step: 'client_secret', ok: false, detail: 'the stored secret could not be read' });
  }

  const ok = steps.every((s) => s.ok);
  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'oidc.config.test',
    outcome: ok ? 'success' : 'failure',
    payload_hash: row.id,
  });

  return reply.send({ ok, steps });
}

export async function deleteOidcConfig(
  request: IdRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  const start = Date.now();
  const row = await services.oidcIdpConfigRepo.findById(request.params.id);
  if (!row || row.operator_id !== request.operatorId) {
    throw new NotFoundError('OidcIdpConfig', request.params.id);
  }
  await services.oidcIdpConfigRepo.delete(request.params.id);

  await services.audit.write({
    ctx: auditCtx(request),
    layer: 'vault',
    action: 'oidc.config.delete',
    outcome: 'success',
    duration_ms: Date.now() - start,
    payload_hash: request.params.id,
  });

  return reply.code(204).send();
}
