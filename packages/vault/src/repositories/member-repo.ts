import { eq, and, inArray, isNotNull, isNull, sql } from 'drizzle-orm';
import { type Database, serviceConnections, teamMembers } from '@stack/shared';

export type DbTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];

export class MemberRepository {
  constructor(private db: Database) {}

  async create(data: typeof teamMembers.$inferInsert, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor.insert(teamMembers).values(data).returning();
    return row!;
  }

  async findById(id: string, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .select()
      .from(teamMembers)
      .where(eq(teamMembers.id, id))
      .limit(1)
      .for('update');
    return row;
  }

  /** A member by id, only when it belongs to the account. */
  async findByIdInAccount(operatorId: string, id: string) {
    return this.db.query.teamMembers.findFirst({
      where: and(eq(teamMembers.operator_id, operatorId), eq(teamMembers.id, id)),
    });
  }

  async findByInviteTokenHash(hash: string, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .select()
      .from(teamMembers)
      .where(eq(teamMembers.invite_token_hash, hash))
      .limit(1)
      .for('update');
    return row;
  }

  /**
   * Whether each account has a member who was invited and has not joined (`invited`) or has joined (`active`), with no
   * address in the answer. An account with neither is absent from the map; a joined member wins over an invitation.
   */
  async inviteStatuses(operatorIds: string[]): Promise<Map<string, 'invited' | 'active'>> {
    const result = new Map<string, 'invited' | 'active'>();
    if (operatorIds.length === 0) return result;
    const rows = await this.db
      .select({ operator_id: teamMembers.operator_id, status: teamMembers.status })
      .from(teamMembers)
      .where(and(inArray(teamMembers.operator_id, operatorIds), inArray(teamMembers.status, ['invited', 'active'])));
    for (const row of rows) {
      if (row.status === 'active') result.set(row.operator_id, 'active');
      else if (!result.has(row.operator_id)) result.set(row.operator_id, 'invited');
    }
    return result;
  }

  /** The addresses of the people invited to an account and of those who joined it (not the removed), lower case. */
  async liveEmails(operatorId: string): Promise<string[]> {
    const rows = await this.db
      .select({ email: teamMembers.email })
      .from(teamMembers)
      .where(and(eq(teamMembers.operator_id, operatorId), inArray(teamMembers.status, ['invited', 'active'])));
    return rows.map((row) => row.email.trim().toLowerCase());
  }

  async findByOperator(operatorId: string) {
    return this.db.query.teamMembers.findMany({
      where: eq(teamMembers.operator_id, operatorId),
    });
  }

  /**
   * Activate a member without issuing an API key. SSO members authenticate
   * through their IdP, so `activate` (which stores a key hash) is the wrong
   * shape for them.
   */
  async activateWithoutKey(id: string) {
    const [row] = await this.db
      .update(teamMembers)
      .set({
        status: 'active',
        joined_at: new Date(),
        invite_token_hash: null,
        invite_expires_at: null,
        api_key_hash: null,
        key_prefix: null,
      })
      .where(eq(teamMembers.id, id))
      .returning();
    return row;
  }

  async findByEmail(operatorId: string, email: string) {
    return this.db.query.teamMembers.findFirst({
      where: and(eq(teamMembers.operator_id, operatorId), eq(teamMembers.email, email)),
    });
  }

  /** The member of an account that the identity provider's own name for a person (issuer and subject) is bound to. */
  async findBySsoSubject(operatorId: string, issuer: string, subject: string) {
    return this.db.query.teamMembers.findFirst({
      where: and(
        eq(teamMembers.operator_id, operatorId),
        eq(teamMembers.sso_issuer, issuer),
        eq(teamMembers.sso_subject, subject),
      ),
    });
  }

  /**
   * Bind an identity provider subject to a member that has none, in one conditional statement, so two first
   * sign-ins racing for one member cannot both win. A member who was invited and has not joined becomes active
   * in the same statement (the provider has authenticated them: no invitation to accept, no key to hand over).
   * Returns undefined when the member already has a binding, was removed, or is gone.
   */
  async linkSsoSubject(id: string, issuer: string, subject: string) {
    const [row] = await this.db
      .update(teamMembers)
      .set({
        sso_issuer: issuer,
        sso_subject: subject,
        status: 'active',
        joined_at: sql`COALESCE(${teamMembers.joined_at}, now())`,
        invite_token_hash: null,
        invite_expires_at: null,
        api_key_hash: null,
        key_prefix: null,
      })
      .where(
        and(
          eq(teamMembers.id, id),
          isNull(teamMembers.sso_subject),
          inArray(teamMembers.status, ['invited', 'active']),
        ),
      )
      .returning();
    return row;
  }

  /**
   * Forget the single sign-on binding of one member, or of every member bound to one issuer, within one account.
   * The rows are locked, read and cleared in one transaction, so a sign-in racing a clear either binds first (and is
   * then cleared) or finds no binding and binds afterwards. Returns who was cleared, with the issuer each was bound
   * to; a member with no binding is not in the list. Nothing else about a member changes.
   */
  async clearSsoBindings(operatorId: string, target: { memberId: string } | { issuer: string }) {
    return this.db.transaction(async (tx) => {
      const bound = await tx
        .select({ id: teamMembers.id, email: teamMembers.email, sso_issuer: teamMembers.sso_issuer })
        .from(teamMembers)
        .where(
          and(
            eq(teamMembers.operator_id, operatorId),
            isNotNull(teamMembers.sso_subject),
            'memberId' in target ? eq(teamMembers.id, target.memberId) : eq(teamMembers.sso_issuer, target.issuer),
          ),
        )
        .orderBy(teamMembers.email)
        .for('update');
      if (bound.length === 0) return [];
      await tx
        .update(teamMembers)
        .set({ sso_issuer: null, sso_subject: null })
        .where(and(eq(teamMembers.operator_id, operatorId), inArray(teamMembers.id, bound.map((member) => member.id))));
      return bound.map((member) => ({ id: member.id, email: member.email, sso_issuer: member.sso_issuer! }));
    });
  }

  async revoke(id: string, transaction?: DbTransaction) {
    const executor = transaction ?? this.db;
    const [row] = await executor
      .update(teamMembers)
      .set({
        status: 'revoked',
        revoked_at: new Date(),
        invite_token_hash: null,
        invite_expires_at: null,
        api_key_hash: null,
        key_prefix: null,
      })
      .where(eq(teamMembers.id, id))
      .returning();
    return row;
  }

  async updateAccess(
    id: string,
    data: { role?: string; allowed_connections?: string[] | null },
  ) {
    const [row] = await this.db
      .update(teamMembers)
      .set(data)
      .where(eq(teamMembers.id, id))
      .returning();
    return row;
  }

  async findActiveConnectionIds(
    operatorId: string,
    connectionIds: string[],
    transaction?: DbTransaction,
  ): Promise<string[]> {
    if (connectionIds.length === 0) return [];
    const executor = transaction ?? this.db;
    const rows = await executor
      .select({ id: serviceConnections.id })
      .from(serviceConnections)
      .where(
        and(
          eq(serviceConnections.operator_id, operatorId),
          eq(serviceConnections.status, 'active'),
          inArray(serviceConnections.id, connectionIds),
        ),
      );
    return rows.map((row) => row.id);
  }

  async countActiveByOperator(operatorId: string): Promise<number> {
    const rows = await this.db.query.teamMembers.findMany({
      where: and(
        eq(teamMembers.operator_id, operatorId),
        // Count invited + active (not revoked)
      ),
      columns: { id: true, status: true },
    });
    return rows.filter((r) => r.status !== 'revoked').length;
  }
}
