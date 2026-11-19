import { z } from 'zod';
import { IdentityClaimInheritance, IdentityClaimTtl, SetServiceRequirementInput } from '@stack/shared';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const IDENTITY_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // Identity
  stack_get_identity_settings: hint.read('Get identity settings'),
  stack_list_identity_providers: hint.read('List identity providers'),
  stack_start_identity_verification: hint.write('Start identity verification', true),
  stack_get_identity_verification: hint.read('Get identity verification'),
  stack_list_identity_claims: hint.read('List identity claims'),
  stack_revoke_identity_claim: hint.destructive('Revoke identity claim'),
  stack_list_sso_domains: hint.read('List single sign-on domains'),
  stack_add_sso_domain: hint.write('Add single sign-on domain'),
  stack_verify_sso_domain: hint.write('Check single sign-on domain record', true),
  stack_remove_sso_domain: hint.destructive('Remove single sign-on domain'),
  stack_set_identity_settings: hint.destructive('Set identity settings'),
  stack_get_service_requirements: hint.read('Get service identity requirements'),
  stack_set_service_requirement: hint.destructive('Set service identity requirement'),
  stack_list_workload_identities: hint.read('List workload identity issuers'),
  stack_set_workload_identity: hint.destructive('Add or change workload identity issuer'),
  stack_remove_workload_identity: hint.destructive('Remove workload identity issuer'),
  stack_list_mcp_sessions: hint.read('List signed-in chat sessions'),
  stack_revoke_mcp_session: hint.destructive('Sign out chat session'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const IDENTITY_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  stack_start_identity_verification: 'Needs identity:write, withheld from directory tokens: it also covers identity-provider, SPIFFE and WIMSE trust configuration.',
  stack_get_identity_verification: 'Reads a verification session the directory profile cannot start. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_revoke_identity_claim: 'Needs identity:write, withheld from directory tokens: it also covers identity-provider, SPIFFE and WIMSE trust configuration.',
  stack_list_sso_domains: 'Reads the single sign-on setup of the account, which only an owner or admin may: withheld from directory tokens with the tools that change it.',
  stack_add_sso_domain: 'Needs identity:write, withheld from directory tokens: it changes which e-mail addresses the account\'s sign-in treats as verified.',
  stack_verify_sso_domain: 'Needs identity:write, withheld from directory tokens: it changes which e-mail addresses the account\'s sign-in treats as verified.',
  stack_remove_sso_domain: 'Needs identity:write, withheld from directory tokens: it changes which e-mail addresses the account\'s sign-in treats as verified.',
  stack_set_identity_settings: 'Needs account:write, withheld from directory tokens: it changes how long identity proof lasts and who inherits it, and the same scope signs chat sessions out.',
  stack_get_service_requirements: 'Owner administration of the account\'s identity requirements. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_set_service_requirement: 'Changes which identity proof an agent needs for a service. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_list_workload_identities: 'Lists the issuers that may obtain Passports for the account\'s agents. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_set_workload_identity: 'Needs identity:write, withheld from directory tokens: it decides which outside issuers may obtain Passports for the account\'s agents.',
  stack_remove_workload_identity: 'Needs identity:write, withheld from directory tokens: it also covers identity-provider, SPIFFE and WIMSE trust configuration.',
  stack_list_mcp_sessions: 'Lists the person\'s own signed-in chat clients. Kept out of the directory profile, whose reviewed tool set does not change.',
  stack_revoke_mcp_session: 'Needs account:write, withheld from directory tokens: the same scope changes the account\'s identity settings.',
};

/** Identity settings, providers, verification start and identity claims. */
export function registerIdentityTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;
  // ─── Identity Settings Tools ──────────────────────────────────────

  server.tool(
    'stack_get_identity_settings',
    "Get the operator's identity security settings: claim TTL, claim inheritance mode (auto vs opt-in), and auto-revoke on expiry.",
    {},
    async () => {
      const result = await api('GET', '/v1/operators/me/identity-settings');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_identity_providers',
    'List the identity-verification providers (humanity and identity checks) this deployment has registered, with their provider keys, supported claims and status. A self-managed install lists none until its operator registers one.',
    {},
    async () => {
      const result = await api('GET', '/v1/identity/providers');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_start_identity_verification',
    'Start identity verification with a configured provider. Returns the pending session reference and the URL or QR data the person needs to continue.',
    {
      provider_key: z.string().describe('Provider key returned by stack_list_identity_providers'),
      requested_claims: z
        .array(z.string())
        .min(1)
        .describe('Claims supported by that provider, such as verified_human or verified_identity'),
      return_url: z
        .string()
        .url()
        .optional()
        .describe('Optional URL to return to after the provider flow'),
    },
    async ({ provider_key, requested_claims, return_url }) => {
      const result = await api('POST', '/v1/identity/verify/initiate', {
        provider_key,
        requested_claims,
        ...(return_url ? { return_url } : {}),
      }) as Record<string, unknown>;
      const safeResult = {
        session_id: result['session_id'],
        session_ref: result['session_ref'],
        ...(typeof result['verification_url'] === 'string'
          ? { verification_url: result['verification_url'] }
          : {}),
        ...(typeof result['qr_code'] === 'string' ? { qr_code: result['qr_code'] } : {}),
        expires_at: result['expires_at'],
      };
      return toolJson(safeResult);
    },
  );

  server.tool(
    'stack_get_identity_verification',
    'Get one identity verification session started with stack_start_identity_verification: its status (pending while the person is at the provider; completed, failed or expired, which are final; a session nobody finished by expires_at is expired), the requested claims, and when it was created, expires and completed. No personal data is returned; the verified claims are read with stack_list_identity_claims.',
    {
      session_id: z.string().min(1).describe('The session_id returned by stack_start_identity_verification'),
    },
    async ({ session_id }) => {
      const result = await api('GET', `/v1/identity/verify/sessions/${encodeURIComponent(session_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_list_identity_claims',
    "List the account's verified identity claims (the L1 humanity and L2 identity claims agents can carry on Passports). Each claim carries an opaque claim_ref. Personal data stays encrypted at rest and is not returned.",
    {},
    async () => {
      const result = await api('GET', '/v1/identity/claims');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_revoke_identity_claim',
    'Revoke a verified identity claim by id. Only Passports that carry this claim are invalidated.',
    {
      claim_id: z.string().describe('The identity claim id to revoke'),
    },
    async ({ claim_id }) => {
      const result = await api('DELETE', `/v1/identity/claims/${encodeURIComponent(claim_id)}`);
      return toolJson(result);
    },
  );

  // ─── Single sign-on: verified e-mail domains ─────────────────────

  server.tool(
    'stack_list_sso_domains',
    "List the e-mail domains of the account's single sign-on, each with its state (pending, verified or lapsed), the DNS TXT record that proves it (record.name and record.value), when it was last checked and what the last lookup found (confirmed, missing or unavailable). Needs an owner or admin session.",
    {},
    async () => {
      const result = await api('GET', '/v1/identity/sso-domains');
      return toolJson(result);
    },
  );

  server.tool(
    'stack_add_sso_domain',
    `Claim an e-mail domain, such as corp.example.com, for the account's single sign-on. Some identity providers (Microsoft Entra ID among them) do not say that a person's address is verified; once the account has proved the domain, an address at exactly that domain counts as verified for a first sign-in when the provider's ID token has no email_verified claim at all. Returns the DNS TXT record to publish (record.name, record.value); nothing counts until stack_verify_sso_domain finds it. The exact domain only: a subdomain is a domain of its own. Needs an owner or admin session. A person approves it in a browser: the call fails first with approval_id and approval_url and the chat never approves it. Send the same domain with governance_approval_id once they have. A domain another account has verified is refused with a message that does not say who holds it.`,
    {
      domain: z.string().min(1).max(253).describe('The e-mail domain, such as corp.example.com: a name, with no address, port or path'),
      governance_approval_id: z
        .string()
        .optional()
        .describe('Approval id (gvr_*) from a GOVERNANCE_APPROVAL_REQUIRED response, once the person approved it in their browser'),
    },
    async ({ domain, governance_approval_id }) => {
      const headers = governance_approval_id ? { 'X-Governance-Approval': governance_approval_id } : undefined;
      const result = await api('POST', '/v1/identity/sso-domains', { domain }, headers);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_verify_sso_domain',
    "Look up the DNS TXT record of one claimed domain now. When the record is there the domain becomes verified; the answer says what the lookup found: confirmed, missing (the name server answered and the record is not there) or unavailable (no answer, which proves nothing either way). Asks the name server at most once in ten seconds for a domain, and keeps checking verified domains on its own: a domain whose record stays gone for seven days lapses and must be verified again.",
    {
      domain_id: z.string().min(1).max(128).describe('The id of the domain from stack_list_sso_domains'),
    },
    async ({ domain_id }) => {
      const result = await api('POST', `/v1/identity/sso-domains/${encodeURIComponent(domain_id)}/verify`, {});
      return toolJson(result);
    },
  );

  server.tool(
    'stack_remove_sso_domain',
    'Stop claiming an e-mail domain. It takes effect at once: the next sign-in no longer counts addresses at that domain as verified, and the domain is free for another account to verify. People already linked to their provider identity are not affected.',
    {
      domain_id: z.string().min(1).max(128).describe('The id of the domain from stack_list_sso_domains'),
    },
    async ({ domain_id }) => {
      const result = await api('DELETE', `/v1/identity/sso-domains/${encodeURIComponent(domain_id)}`);
      return toolJson(result);
    },
  );

  server.tool(
    'stack_set_identity_settings',
    `Change the account's identity settings: identity_claim_ttl (how long new identity proof lasts), identity_claim_inheritance (auto: agent Passports carry the account's identity proof; opt_in: only when asked) and identity_auto_revoke (whether Passports carrying expired proof are revoked). A field left out is unchanged. Owner or admin only. Returns the settings.`,
    {
      identity_claim_ttl: IdentityClaimTtl.optional().describe('How long new identity proof lasts: 30d, 90d, 180d or 1y'),
      identity_claim_inheritance: IdentityClaimInheritance.optional().describe('auto or opt_in'),
      identity_auto_revoke: z.boolean().optional().describe('Revoke Passports that carry expired proof'),
      governance_approval_id: z.string().optional().describe(
        'Deprecated and ignored: changing the identity settings no longer asks for an approval. Kept so existing callers keep working.',
      ),
    },
    async ({ governance_approval_id: _ignored, ...settings }) => toolJson(await api('PATCH', '/v1/operators/me/identity-settings', settings)),
  );

  server.tool(
    'stack_get_service_requirements',
    "Get the identity requirements the account sets for one service it is connected to: the claim an agent's Passport must carry (for example verified humanity), the minimum assurance and the accepted providers.",
    {
      service_id: z.string().min(1).max(200).describe('Catalog service id of a connected service'),
    },
    async ({ service_id }) => toolJson(await api('GET', `/v1/services/${encodeURIComponent(service_id)}/requirements`)),
  );

  server.tool(
    'stack_set_service_requirement',
    `Set or remove the identity requirement for one connected service. requirement replaces what is set now; requirement null removes it. An identity-layer requirement must set requires_pii true, and requires_pii true needs a lawful_basis. Owner or admin only, and only for a service the account has an active connection to. Returns the requirements now in force.`,
    {
      service_id: z.string().min(1).max(200).describe('Catalog service id of a connected service'),
      requirement: SetServiceRequirementInput.nullable().describe('The requirement, or null to remove it'),
      governance_approval_id: z.string().optional().describe(
        'Deprecated and ignored: changing a requirement no longer asks for an approval. Kept so existing callers keep working.',
      ),
    },
    async ({ service_id, requirement }) => toolJson(await api(
      'PUT',
      `/v1/services/${encodeURIComponent(service_id)}/requirements`,
      { requirement },
    )),
  );

  server.tool(
    'stack_list_workload_identities',
    'List the workload issuers the account trusts to obtain Passports for its agents: SPIFFE trust domains and WIMSE issuers, each with its id, issuer, keys URL, the agent each workload maps to and whether it is active.',
    {},
    async () => toolJson({
      spiffe: await api('GET', '/v1/identity/spiffe/trust-domains'),
      wimse: await api('GET', '/v1/identity/wimse/issuers'),
    }),
  );

  const workloadMapping = z.record(z.string(), z.object({ agent_id: z.string().regex(/^agt_[A-Za-z0-9_-]+$/) }));
  server.tool(
    'stack_set_workload_identity',
    "Add or change a workload issuer the account trusts. kind spiffe is a SPIFFE trust domain (trust_domain; mapping keys are spiffe:// ids under it); kind wimse is a WIMSE issuer (issuer_uri; mapping keys are workload URIs). jwks_uri is the issuer's https keys URL. mapping names the agent each workload acts as: whatever the issuer vouches for can obtain Passports for those agents. Without id it adds one; with id it changes only the fields given. Owner or admin only.",
    {
      kind: z.enum(['spiffe', 'wimse']).describe('spiffe or wimse'),
      id: z.string().min(1).max(200).optional().describe('Id of the issuer to change, from stack_list_workload_identities; omit to add'),
      trust_domain: z.string().min(1).max(253).optional().describe('spiffe: the trust domain, for example prod.example.com'),
      issuer_uri: z.string().url().optional().describe('wimse: the issuer, https'),
      jwks_uri: z.string().url().optional().describe("The issuer's https keys URL"),
      display_name: z.string().max(120).optional(),
      audience: z.string().max(512).nullable().optional(),
      mapping: workloadMapping.optional().describe('Workload id to { agent_id }'),
      active: z.boolean().optional().describe('false turns the issuer off without removing it'),
    },
    async ({ kind, id, trust_domain, issuer_uri, jwks_uri, display_name, audience, mapping, active }) => {
      const body: Record<string, unknown> = {
        ...(display_name !== undefined ? { display_name } : {}),
        ...(jwks_uri !== undefined ? { jwks_uri } : {}),
        ...(audience !== undefined ? { audience } : {}),
        ...(active !== undefined ? { active } : {}),
      };
      if (kind === 'spiffe') {
        if (trust_domain !== undefined) body['trust_domain'] = trust_domain;
        if (mapping !== undefined) body['spiffe_id_mapping_policy_json'] = mapping;
        return toolJson(id
          ? await api('PATCH', `/v1/identity/spiffe/trust-domains/${encodeURIComponent(id)}`, body)
          : await api('POST', '/v1/identity/spiffe/trust-domains', body));
      }
      if (issuer_uri !== undefined) body['issuer_uri'] = issuer_uri;
      if (mapping !== undefined) body['workload_id_mapping_policy_json'] = mapping;
      return toolJson(id
        ? await api('PATCH', `/v1/identity/wimse/issuers/${encodeURIComponent(id)}`, body)
        : await api('POST', '/v1/identity/wimse/issuers', body));
    },
  );

  server.tool(
    'stack_remove_workload_identity',
    'Remove a SPIFFE trust domain or a WIMSE issuer. It takes effect at once: its workloads can no longer obtain Passports. Owner or admin only.',
    {
      kind: z.enum(['spiffe', 'wimse']).describe('spiffe or wimse'),
      id: z.string().min(1).max(200).describe('Issuer id from stack_list_workload_identities'),
    },
    async ({ kind, id }) => {
      if (kind === 'spiffe') await api('DELETE', `/v1/identity/spiffe/trust-domains/${encodeURIComponent(id)}`);
      else await api('DELETE', `/v1/identity/wimse/issuers/${encodeURIComponent(id)}`);
      return toolJson({ removed: true, kind, id });
    },
  );

  server.tool(
    'stack_list_mcp_sessions',
    'List the signed-in chat sessions of this person, one for each chat client or connector that signed in: family_id, client and the created and last-used times. A team member sees their own sessions only.',
    {},
    async () => toolJson(await api('GET', '/v1/operators/me/mcp-sessions')),
  );

  server.tool(
    'stack_revoke_mcp_session',
    "Sign one chat session out (family_id from stack_list_mcp_sessions). The client's tokens stop working on its next call. Revoking the session this chat uses ends this chat's access.",
    {
      family_id: z.string().min(1).max(200).describe('Session family id'),
    },
    async ({ family_id }) => toolJson(await api('DELETE', `/v1/operators/me/mcp-sessions/${encodeURIComponent(family_id)}`)),
  );
}
