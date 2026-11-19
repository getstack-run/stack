import {
  ids,
  sha256,
  type InviteMemberInput,
  NotFoundError,
  ForbiddenError,
  ConflictError,
  teamMembers,
  oauthRefreshTokens,
  operators,
  acquireOAuthOperatorLock,
  acquireOAuthRefreshFamilyLocks,
  type Database,
  StackError,
  SsoLoginError,
  signinAllowed,
} from '@stack/shared';
import { eq, and, isNull, sql } from 'drizzle-orm';
import { MemberRepository, type DbTransaction } from '../repositories/member-repo.js';
import type { AuditService } from './audit-service.js';

/** A Postgres unique violation, whether the driver error is the thrown one or its cause. */
function isUniqueViolation(error: unknown): boolean {
  const code = (e: unknown) => (typeof e === 'object' && e !== null ? (e as { code?: unknown }).code : undefined);
  return code(error) === '23505' || code((error as { cause?: unknown } | null)?.cause) === '23505';
}

/** What vouched for an e-mail address the provider did not: a domain the account verified, or the issuer's own claim that the domain is verified. */
export type EmailVouchedBy = 'verified_domain' | 'issuer_domain_claim';

export interface MemberInviteAuditContext {
  trace_id: string;
  span_id: string;
  started_at_ms?: number;
}

export class MemberService {
  /**
   * Optional db handle for OAuth-token cascade-revocation on member.revoke.
   * Set after construction by the API bootstrap (see apps/api/src/config/
   * services.ts). When unset, member.revoke still revokes the API key
   * row but does NOT cascade to OAuth refresh tokens — that's only the
   * legacy unit-test path. Production always wires it in.
   */
  private db: Database | null = null;
  private audit: Pick<AuditService, 'write'> | null = null;

  // Every account may have any number of team members: there is no seat cap.
  constructor(private memberRepo: MemberRepository) {}

  setDb(db: Database): void {
    this.db = db;
  }

  setAuditService(audit: Pick<AuditService, 'write'>): void {
    this.audit = audit;
  }

  private async normalizeAllowedConnections(
    operatorId: string,
    allowedConnections: string[] | null | undefined,
    transaction?: DbTransaction,
  ): Promise<string[] | null | undefined> {
    if (allowedConnections === undefined || allowedConnections === null) {
      return allowedConnections;
    }
    const normalized = [...new Set(allowedConnections)];
    if (normalized.length === 0) return [];

    const activeIds = await this.memberRepo.findActiveConnectionIds(
      operatorId,
      normalized,
      transaction,
    );
    if (activeIds.length !== normalized.length) {
      // Uniform refusal: do not reveal whether an id exists on another
      // operator or names a revoked connection.
      throw new ForbiddenError('One or more allowed service connections are unavailable');
    }
    return normalized;
  }

  /** Active members on the account, excluding the owner. */
  async countActive(operatorId: string): Promise<number> {
    return this.memberRepo.countActiveByOperator(operatorId);
  }

  /** Invite a team member. Any number of members may be invited: no plan caps them. */
  async invite(operatorId: string, input: InviteMemberInput) {
    if (!this.db) throw new Error('member_invite_atomicity_not_configured');

    const email = input.email.trim().toLowerCase();
    // A staging deployment invites only the addresses on its allow-list: nothing is created and no invitation is sent,
    // with the answer an address that cannot be invited gets.
    if (!signinAllowed(email)) throw new ForbiddenError('This address cannot be invited to an account.');
    const rawToken = ids.inviteToken();
    const inviteTokenHash = sha256(rawToken);
    const inviteExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    return this.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, operatorId);
      const [operator] = await tx
        .select({ status: operators.status })
        .from(operators)
        .where(eq(operators.id, operatorId))
        .for('update');
      if (!operator || operator.status !== 'active') throw new ForbiddenError();

      const allowedConnections = await this.normalizeAllowedConnections(
        operatorId,
        input.allowed_connections,
        tx,
      );

      const [existing] = await tx
        .select()
        .from(teamMembers)
        .where(and(eq(teamMembers.operator_id, operatorId), eq(teamMembers.email, email)))
        .for('update');

      if (existing?.status === 'active') {
        throw new ConflictError(`Member with email ${email} already exists`);
      }

      if (existing) {
        const [member] = await tx
          .update(teamMembers)
          .set({
            name: input.name,
            role: input.role ?? 'standard',
            allowed_connections: allowedConnections ?? null,
            status: 'invited',
            invited_at: new Date(),
            joined_at: null,
            revoked_at: null,
            api_key_hash: null,
            key_prefix: null,
            invite_token_hash: inviteTokenHash,
            invite_expires_at: inviteExpiresAt,
            // An administrator who invites the person again vouches for them afresh: the provider
            // identity they sign in with next is linked, whatever the last one was.
            sso_issuer: null,
            sso_subject: null,
          })
          .where(eq(teamMembers.id, existing.id))
          .returning();
        return { member: member!, inviteToken: rawToken };
      }

      const member = await this.memberRepo.create(
        {
          id: ids.member(),
          operator_id: operatorId,
          email,
          name: input.name,
          role: input.role ?? 'standard',
          allowed_connections: allowedConnections ?? null,
          status: 'invited',
          invite_token_hash: inviteTokenHash,
          invite_expires_at: inviteExpiresAt,
        },
        tx,
      );

      return { member, inviteToken: rawToken };
    });
  }

  /**
   * Just-in-time provisioning for SSO login (spec/sso-login/SPEC.md, section 9).
   *
   * Deliberately NOT acceptInvite: SSO establishes identity through the
   * configured provider rather than an emailed invitation token. Both paths
   * create the same keyless member session once identity is established.
   *
   * The person is the provider's own name for them, the issuer and subject of
   * the ID token, not the e-mail claim: an address a user can change at the
   * provider, or one the provider never verified, must not be a way to sign in
   * as a colleague (the "nOAuth" pattern). So:
   *   - bound    → (account, issuer, subject) is a member: that member signs
   *                in, whatever the token now says its address is. A member
   *                removed from the account is refused.
   *   - unbound  → the address finds a member to LINK, and only when the
   *                address is vouched for: the provider says it is verified
   *                (`email_verified` is exactly true), or the caller found it
   *                vouched for in a way the account recognises (`vouchForEmail`:
   *                a domain the account verified, or the issuer's own claim that
   *                the domain is verified). A member already bound to another subject is
   *                refused, never re-bound; a member who was removed is
   *                refused; one who was invited and has not joined is adopted
   *                and activated; an active one is simply linked.
   *   - nobody   → a verified address creates a member, bound at once, when
   *                the account provisions; otherwise the person is refused.
   */
  async findOrProvisionForSso(input: {
    operatorId: string;
    email: string;
    /** The ID token's `email_verified` claim: only the boolean true counts. */
    emailVerified: boolean | undefined;
    /**
     * Another way the address can be vouched for, asked only when it is needed: after no member is linked to the
     * provider's identity and `emailVerified` is not true. The caller answers only for a token that has no
     * `email_verified` claim at all (spec/sso-login/SPEC.md section 9.5), with what vouches (a domain the account
     * verified, or the issuer's own claim that the domain is verified), or undefined. A person already linked never
     * asks it, so a sign-in that needs no lookup makes none.
     */
    vouchForEmail?: () => Promise<EmailVouchedBy | undefined>;
    /** The ID token's `iss` and `sub`: who the provider says the person is. */
    issuer: string;
    subject: string;
    name: string | null;
    defaultRole: string;
    /** False refuses to create a member (an existing one still signs in). Default true. */
    allowProvision?: boolean;
  }): Promise<{
    member: { id: string; email: string; role: string };
    provisioned: boolean;
    /** This sign-in made the link between the member and the provider's identity (a first sign-in, or provisioning). */
    linked: boolean;
    /** What vouched for the address when the provider did not: set only on a first sign-in or provisioning that needed it. */
    vouchedBy?: EmailVouchedBy;
  }> {
    const email = input.email.trim().toLowerCase();
    const { issuer, subject } = input;
    // A staging deployment signs in, links and provisions only the addresses on its allow-list. Anyone else gets the
    // answer of an organisation that has no account for them, before anything is read or written.
    if (!signinAllowed(email)) {
      throw new ForbiddenError('This organisation has no account for you. Ask an admin to invite you.');
    }
    if (!issuer || !subject) {
      throw new SsoLoginError('login_failed', 'The ID token carried no issuer or subject, so no account can be resolved.');
    }
    const refuseUnmatched = () =>
      new SsoLoginError(
        'login_failed',
        'This sign-in does not match the person it names. Ask an administrator of the organisation.',
      );
    const removed = () =>
      new ForbiddenError(
        'This account has been removed from the organisation. Ask an admin to re-invite you.',
      );

    const bound = await this.memberRepo.findBySsoSubject(input.operatorId, issuer, subject);
    if (bound) {
      if (bound.status === 'revoked') throw removed();
      if (bound.status !== 'active') await this.memberRepo.activateWithoutKey(bound.id);
      return {
        member: { id: bound.id, email: bound.email, role: bound.role },
        provisioned: false,
        linked: false,
      };
    }

    // From here the address is the only thing that finds a member, so the address must be vouched for: by the provider
    // (`email_verified` exactly true) or by a way the account recognises (a verified domain). Checked before anything
    // about the account is read, so an unverified address learns nothing about who is a member.
    const vouchedBy = input.emailVerified === true ? undefined : await input.vouchForEmail?.();
    if (input.emailVerified !== true && vouchedBy === undefined) {
      throw new SsoLoginError(
        'login_failed',
        'The identity provider did not confirm the e-mail address of this sign-in (email_verified is not true). If it never sends that claim, an administrator of the organisation can verify the e-mail domain for single sign-on.',
      );
    }

    const existing = await this.memberRepo.findByEmail(input.operatorId, email);
    if (existing) {
      if (existing.sso_subject !== null) throw refuseUnmatched();
      if (existing.status === 'revoked') throw removed();
      const linked = await this.memberRepo.linkSsoSubject(existing.id, issuer, subject);
      // A first sign-in that lost a race for this member, or found it removed in between.
      if (!linked) throw refuseUnmatched();
      return {
        member: { id: linked.id, email: linked.email, role: linked.role },
        provisioned: false,
        linked: true,
        ...(vouchedBy ? { vouchedBy } : {}),
      };
    }

    if (input.allowProvision === false) {
      throw new ForbiddenError(
        'This organisation has no account for you. Ask an admin to invite you.',
      );
    }
    let member;
    try {
      member = await this.memberRepo.create({
        id: ids.member(),
        operator_id: input.operatorId,
        email,
        name: input.name ?? email,
        role: input.defaultRole,
        allowed_connections: null,
        // Active immediately: the IdP already authenticated them. There is
        // no invite to accept and no key to hand over.
        status: 'active',
        joined_at: new Date(),
        sso_issuer: issuer,
        sso_subject: subject,
      });
    } catch (error) {
      // The same person signing in twice at once: the other sign-in made the member first.
      if (isUniqueViolation(error)) throw refuseUnmatched();
      throw error;
    }

    return { member: { id: member.id, email: member.email, role: member.role }, provisioned: true, linked: true, ...(vouchedBy ? { vouchedBy } : {}) };
  }

  /**
   * Forget the single sign-on binding of one member, or of every member bound to one issuer, so the next verified
   * sign-in with the provider now in use binds them again. A person bound to the old provider's subject is refused
   * under the new one (section 9 of spec/sso-login/SPEC.md), so replacing the provider locks out everyone who had
   * signed in until this runs. The role, status and sessions of a member are untouched, and a removed member stays
   * removed. Returns the members cleared (none when nobody had a binding). A member id of another account is
   * not found, as any other id of another account is.
   */
  async clearSsoBindings(operatorId: string, target: { memberId: string } | { issuer: string }) {
    if ('memberId' in target) {
      const member = await this.memberRepo.findByIdInAccount(operatorId, target.memberId);
      if (!member) throw new NotFoundError('Member', target.memberId);
    }
    return this.memberRepo.clearSsoBindings(operatorId, target);
  }

  async acceptInvite(rawToken: string, auditContext: MemberInviteAuditContext) {
    if (!this.db || !this.audit) {
      throw new Error('member_invite_atomicity_not_configured');
    }
    const db = this.db;
    const audit = this.audit;
    const invalidInvite = () =>
      new StackError('This invite is no longer valid.', 'INVALID_INVITE', 400);
    const tokenHash = sha256(rawToken);
    const discovered = await this.memberRepo.findByInviteTokenHash(tokenHash);
    if (!discovered) throw invalidInvite();

    return db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, discovered.operator_id);
      const [operator] = await tx
        .select({ id: operators.id, status: operators.status })
        .from(operators)
        .where(eq(operators.id, discovered.operator_id))
        .for('update');
      const member = await this.memberRepo.findByInviteTokenHash(tokenHash, tx);
      if (
        !operator ||
        operator.status !== 'active' ||
        !member ||
        member.operator_id !== discovered.operator_id ||
        member.status !== 'invited' ||
        !member.invite_expires_at ||
        member.invite_expires_at.getTime() <= Date.now() ||
        // An invitation made before a staging deployment limited sign-in opens nothing for an address it does not list.
        !signinAllowed(member.email)
      ) {
        throw invalidInvite();
      }

      const [activated] = await tx
        .update(teamMembers)
        .set({
          status: 'active',
          joined_at: new Date(),
          api_key_hash: null,
          key_prefix: null,
          invite_token_hash: null,
          invite_expires_at: null,
        })
        .where(
          and(
            eq(teamMembers.id, member.id),
            eq(teamMembers.status, 'invited'),
            eq(teamMembers.invite_token_hash, tokenHash),
            sql`${teamMembers.invite_expires_at} > clock_timestamp()`,
          ),
        )
        .returning();
      if (!activated) throw invalidInvite();

      await audit.write(
        {
          ctx: {
            trace_id: auditContext.trace_id,
            span_id: auditContext.span_id,
            operator_id: member.operator_id,
            agent_id: 'system',
            passport_jti: 'none',
          },
          layer: 'vault',
          action: 'member.accept',
          outcome: 'success',
          duration_ms:
            auditContext.started_at_ms === undefined
              ? undefined
              : Date.now() - auditContext.started_at_ms,
        },
        tx,
      );

      return { member: activated };
    });
  }

  async list(operatorId: string) {
    return this.memberRepo.findByOperator(operatorId);
  }

  async revoke(memberId: string, operatorId: string) {
    if (!this.db) {
      const member = await this.memberRepo.findById(memberId);
      if (!member) throw new NotFoundError('Member', memberId);
      if (member.operator_id !== operatorId) throw new ForbiddenError();
      return this.memberRepo.revoke(memberId);
    }

    return this.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, operatorId);
      const [member] = await tx
        .select({ operator_id: teamMembers.operator_id })
        .from(teamMembers)
        .where(eq(teamMembers.id, memberId))
        .for('update');
      if (!member) throw new NotFoundError('Member', memberId);
      if (member.operator_id !== operatorId) throw new ForbiddenError();
      const result = await this.memberRepo.revoke(memberId, tx);

      const families = await tx
        .selectDistinct({ token_family_id: oauthRefreshTokens.token_family_id })
        .from(oauthRefreshTokens)
        .where(eq(oauthRefreshTokens.member_id, memberId));
      await acquireOAuthRefreshFamilyLocks(
        tx,
        families.map((row) => row.token_family_id),
      );

      await tx
        .update(oauthRefreshTokens)
        .set({
          revoked_at: new Date(),
          revoked_reason: 'member_revoked',
          replacement_token_encrypted: null,
          replacement_retry_expires_at: null,
        })
        .where(
          and(eq(oauthRefreshTokens.member_id, memberId), isNull(oauthRefreshTokens.revoked_at)),
        );
      await tx
        .update(oauthRefreshTokens)
        .set({
          replacement_token_encrypted: null,
          replacement_retry_expires_at: null,
        })
        .where(eq(oauthRefreshTokens.member_id, memberId));
      return result;
    });
  }

  async updateAccess(
    memberId: string,
    operatorId: string,
    data: { role?: string; allowed_connections?: string[] | null },
  ) {
    const member = await this.memberRepo.findById(memberId);
    if (!member) throw new NotFoundError('Member', memberId);
    if (member.operator_id !== operatorId) throw new ForbiddenError();

    const allowedConnections = await this.normalizeAllowedConnections(
      operatorId,
      data.allowed_connections,
    );
    const updated = await this.memberRepo.updateAccess(memberId, {
      ...data,
      ...(data.allowed_connections !== undefined
        ? { allowed_connections: allowedConnections as string[] | null }
        : {}),
    });
    if (!updated) throw new NotFoundError('Member', memberId);
    return updated;
  }

  async findById(memberId: string) {
    return this.memberRepo.findById(memberId);
  }
}
