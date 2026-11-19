import type { HttpClient } from '../client.js';
import type { TeamMember, InviteMemberInput, UpdateMemberInput, ClearSsoBindingsInput, ClearSsoBindingsResult } from '../types.js';

export class TeamService {
  constructor(private client: HttpClient) {}

  async invite(input: InviteMemberInput): Promise<TeamMember> {
    return this.client.post<TeamMember>('/v1/team/members', input);
  }

  async list(): Promise<TeamMember[]> {
    return this.client.get<TeamMember[]>('/v1/team/members');
  }

  async update(id: string, input: UpdateMemberInput): Promise<TeamMember> {
    return this.client.patch<TeamMember>(`/v1/team/members/${id}`, input);
  }

  async revoke(id: string): Promise<{ success: boolean }> {
    return this.client.delete<{ success: boolean }>(`/v1/team/members/${id}`);
  }

  /**
   * Forget the single sign-on binding of one member (`{ member_id }`) or of every member bound to one issuer
   * (`{ issuer }`, the `iss` of the provider that was replaced), so the next verified sign-in with the provider in
   * use binds them again. A person bound to the old provider's subject is refused under the new one, so replacing
   * the provider locks out everyone who had signed in until this is called. Owner or admin only; an agent is
   * refused. It needs a person in a signed-in browser: without a dashboard session the call throws
   * `GovernanceApprovalRequiredError` first, and once they approve at its link, send the same call again with its
   * `governanceApprovalId`. The role, status and sessions of a member are untouched.
   */
  async clearSsoBindings(
    input: ClearSsoBindingsInput,
    options?: { governanceApprovalId?: string },
  ): Promise<ClearSsoBindingsResult> {
    return this.client.post<ClearSsoBindingsResult>(
      '/v1/team/sso-bindings/clear',
      input,
      options?.governanceApprovalId ? { headers: { 'X-Governance-Approval': options.governanceApprovalId } } : undefined,
    );
  }
}
