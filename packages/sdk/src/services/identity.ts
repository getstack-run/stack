import type { HttpClient } from '../client.js';
import type {
  IdentityProvider,
  IdentityClaim,
  IdentitySettings,
  UpdateIdentitySettingsInput,
  InitiateVerificationInput,
  VerificationResult,
  SetServiceRequirementInput,
  ServiceRequirement,
  ReplaceServiceRequirementResult,
  SsoDomain,
  SsoDomainCheck,
  IdentityVerificationSession,
} from '../types.js';

export class IdentityService {
  constructor(private client: HttpClient) {}

  async getSettings(): Promise<IdentitySettings> {
    return this.client.get<IdentitySettings>('/v1/operators/me/identity-settings');
  }

  /**
   * Change the identity settings, loosening or tightening, with no approval. `opts.governanceApprovalId` is accepted
   * for callers written before and has no effect.
   */
  async updateSettings(input: UpdateIdentitySettingsInput, opts?: { governanceApprovalId?: string }): Promise<IdentitySettings> {
    return this.client.patch<IdentitySettings>(
      '/v1/operators/me/identity-settings',
      input,
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }

  async listProviders(): Promise<IdentityProvider[]> {
    return this.client.get<IdentityProvider[]>('/v1/identity/providers');
  }

  async initiateVerification(input: InitiateVerificationInput): Promise<VerificationResult> {
    return this.client.post<VerificationResult>('/v1/identity/verify/initiate', input);
  }

  /**
   * One verification session by the `session_id` that `initiateVerification` returned. `status` is `pending` while the
   * person is at the provider, then `completed` or `failed`; a session nobody finished by `expires_at` is `expired`,
   * which is final. The verified claims are read with `listClaims`.
   */
  async getVerificationSession(sessionId: string): Promise<IdentityVerificationSession> {
    return this.client.get<IdentityVerificationSession>(`/v1/identity/verify/sessions/${encodeURIComponent(sessionId)}`);
  }

  async completeVerification(providerKey: string, sessionRef: string): Promise<unknown> {
    return this.client.post('/v1/identity/verify/complete', {
      provider_key: providerKey,
      session_ref: sessionRef,
    });
  }

  async grantDelegation(delegatedScopes: string[]): Promise<IdentityClaim> {
    return this.client.post<IdentityClaim>('/v1/identity/delegate', {
      delegated_scopes: delegatedScopes,
    });
  }

  async listClaims(): Promise<IdentityClaim[]> {
    return this.client.get<IdentityClaim[]>('/v1/identity/claims');
  }

  async revokeClaim(id: string): Promise<{ success: boolean }> {
    return this.client.delete<{ success: boolean }>(`/v1/identity/claims/${id}`);
  }

  // ── Single sign-on: verified e-mail domains ───────────────────────
  //
  // Some identity providers (Microsoft Entra ID among them) do not say that a person's address is verified. An
  // account proves it controls an e-mail domain with a DNS TXT record; once it has, an address at exactly that domain
  // counts as verified for a first sign-in when the provider's ID token has no `email_verified` claim at all. Owner or
  // admin only, on any plan; an agent is refused.

  /** The account's single sign-on domains, each with the record that proves it and where the proof stands. */
  async listSsoDomains(): Promise<SsoDomain[]> {
    return (await this.client.get<{ domains: SsoDomain[] }>('/v1/identity/sso-domains')).domains;
  }

  /**
   * Claim a domain such as `corp.example.com` and get the TXT record to publish (`record.name`, `record.value`).
   * Nothing counts until `verifySsoDomain` finds the record. Adding one needs a person in a signed-in browser: without a
   * dashboard session the call throws `GovernanceApprovalRequiredError` first, and once they approve it at its link,
   * send the same call again with its `governanceApprovalId`. A domain another account has verified is refused.
   */
  async addSsoDomain(domain: string, options?: { governanceApprovalId?: string }): Promise<SsoDomain> {
    return this.client.post<SsoDomain>(
      '/v1/identity/sso-domains',
      { domain },
      options?.governanceApprovalId ? { headers: { 'X-Governance-Approval': options.governanceApprovalId } } : undefined,
    );
  }

  /**
   * Look the record up now. The domain becomes verified when it is there. `check` says what the lookup found:
   * `confirmed`, `missing`, or `unavailable` (no answer, which proves nothing either way). A domain is looked up at most
   * once in ten seconds, and verified domains are checked again on their own.
   */
  async verifySsoDomain(id: string): Promise<SsoDomainCheck> {
    return this.client.post<SsoDomainCheck>(`/v1/identity/sso-domains/${encodeURIComponent(id)}/verify`, {});
  }

  /** Stop claiming a domain. The next sign-in no longer counts addresses at it as verified. */
  async removeSsoDomain(id: string): Promise<void> {
    await this.client.delete<void>(`/v1/identity/sso-domains/${encodeURIComponent(id)}`);
  }

  async getServiceRequirements(serviceId: string): Promise<ServiceRequirement[]> {
    return this.client.get<ServiceRequirement[]>(
      `/v1/services/${encodeURIComponent(serviceId)}/requirements`,
    );
  }

  // Shape mirrors the API's SetServiceRequirementInput
  // (@stack/shared identity schema). The caller must hold an active
  // connection to `serviceId`; requirements are scoped to your operator.
  async setServiceRequirement(
    serviceId: string,
    input: SetServiceRequirementInput,
  ): Promise<ServiceRequirement> {
    return this.client.post<ServiceRequirement>(
      `/v1/services/${encodeURIComponent(serviceId)}/requirements`,
      input,
    );
  }

  /**
   * Replace a service's requirement, or remove it with null, with no approval. `opts.governanceApprovalId` is accepted
   * for callers written before and has no effect.
   */
  async replaceServiceRequirement(
    serviceId: string,
    requirement: SetServiceRequirementInput | null,
    opts?: { governanceApprovalId?: string },
  ): Promise<ReplaceServiceRequirementResult> {
    return this.client.put<ReplaceServiceRequirementResult>(
      `/v1/services/${encodeURIComponent(serviceId)}/requirements`,
      { requirement },
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }

  /** Removes one requirement, with no approval (`opts.governanceApprovalId` has no effect). */
  async deleteServiceRequirement(serviceId: string, requirementId: string, opts?: { governanceApprovalId?: string }): Promise<void> {
    return this.client.delete<void>(
      `/v1/services/${encodeURIComponent(serviceId)}/requirements/${encodeURIComponent(requirementId)}`,
      opts?.governanceApprovalId ? { headers: { 'X-Governance-Approval': opts.governanceApprovalId } } : undefined,
    );
  }
}
