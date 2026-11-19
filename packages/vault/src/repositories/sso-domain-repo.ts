import { and, asc, count, eq, inArray, isNull, lt, or, sql } from 'drizzle-orm';
import { type Database, ssoVerifiedDomains } from '@stack/shared';

export type SsoDomainRow = typeof ssoVerifiedDomains.$inferSelect;

/**
 * sso_verified_domains: the e-mail domains an account has claimed for its single sign-on and the state of their DNS proof
 * (spec/sso-login/SPEC.md section 9.5). Every change of state is one conditional statement, so machines that run the same
 * upkeep never undo one another, and a domain verified for one account can be verified for no other (the partial unique
 * index `sso_domain_verified_unique`).
 */
export class SsoDomainRepository {
  constructor(private db: Database) {}

  async listByOperator(operatorId: string): Promise<SsoDomainRow[]> {
    return this.db
      .select()
      .from(ssoVerifiedDomains)
      .where(eq(ssoVerifiedDomains.operator_id, operatorId))
      .orderBy(asc(ssoVerifiedDomains.created_at), asc(ssoVerifiedDomains.id));
  }

  async findInAccount(operatorId: string, id: string): Promise<SsoDomainRow | undefined> {
    const [row] = await this.db
      .select()
      .from(ssoVerifiedDomains)
      .where(and(eq(ssoVerifiedDomains.operator_id, operatorId), eq(ssoVerifiedDomains.id, id)));
    return row;
  }

  async findByDomain(operatorId: string, domain: string): Promise<SsoDomainRow | undefined> {
    const [row] = await this.db
      .select()
      .from(ssoVerifiedDomains)
      .where(and(eq(ssoVerifiedDomains.operator_id, operatorId), eq(ssoVerifiedDomains.domain, domain)));
    return row;
  }

  async countByOperator(operatorId: string): Promise<number> {
    const [row] = await this.db
      .select({ n: count() })
      .from(ssoVerifiedDomains)
      .where(eq(ssoVerifiedDomains.operator_id, operatorId));
    return Number(row?.n ?? 0);
  }

  /** The row that holds a domain as VERIFIED, for whichever account. At most one exists. */
  async findVerifiedHolder(domain: string): Promise<SsoDomainRow | undefined> {
    const [row] = await this.db
      .select()
      .from(ssoVerifiedDomains)
      .where(and(eq(ssoVerifiedDomains.domain, domain), eq(ssoVerifiedDomains.status, 'verified')));
    return row;
  }

  async create(data: typeof ssoVerifiedDomains.$inferInsert): Promise<SsoDomainRow> {
    const [row] = await this.db.insert(ssoVerifiedDomains).values(data).returning();
    return row!;
  }

  async delete(operatorId: string, id: string): Promise<boolean> {
    const rows = await this.db
      .delete(ssoVerifiedDomains)
      .where(and(eq(ssoVerifiedDomains.operator_id, operatorId), eq(ssoVerifiedDomains.id, id)))
      .returning({ id: ssoVerifiedDomains.id });
    return rows.length > 0;
  }

  /**
   * The record was seen. A domain not yet verified becomes verified (this throws a unique violation when another account
   * holds it, which the caller turns into the neutral refusal), a verified one is confirmed again. Only the account's own
   * row, and only while it is not gone, so a check that raced a removal changes nothing.
   */
  async markConfirmed(id: string, now: Date): Promise<SsoDomainRow | undefined> {
    const [row] = await this.db
      .update(ssoVerifiedDomains)
      .set({
        status: 'verified',
        verified_at: sql`coalesce(${ssoVerifiedDomains.verified_at}, ${now.toISOString()}::timestamptz)`,
        last_checked_at: now,
        last_confirmed_at: now,
        last_check: 'confirmed',
        missing_since: null,
        updated_at: now,
      })
      .where(eq(ssoVerifiedDomains.id, id))
      .returning();
    return row;
  }

  /**
   * A lookup answered and the record is not there. A verified or lapsed domain keeps when it was first seen missing (the
   * lapse clock) and is left to lapse by `lapse`; a domain never verified only records the check.
   */
  async markMissing(id: string, now: Date): Promise<SsoDomainRow | undefined> {
    const [row] = await this.db
      .update(ssoVerifiedDomains)
      .set({
        last_checked_at: now,
        last_check: 'missing',
        missing_since: sql`case when ${ssoVerifiedDomains.status} = 'pending' then null else coalesce(${ssoVerifiedDomains.missing_since}, ${now.toISOString()}::timestamptz) end`,
        updated_at: now,
      })
      .where(eq(ssoVerifiedDomains.id, id))
      .returning();
    return row;
  }

  /** A lookup that gave no answer: nothing about the record is learned, so only the check is recorded. */
  async markUnavailable(id: string, now: Date): Promise<SsoDomainRow | undefined> {
    const [row] = await this.db
      .update(ssoVerifiedDomains)
      .set({ last_checked_at: now, last_check: 'unavailable', updated_at: now })
      .where(eq(ssoVerifiedDomains.id, id))
      .returning();
    return row;
  }

  /**
   * A verified domain whose record has been missing since `missingBefore` or earlier stops belonging to the account. One
   * conditional statement: a confirmation that landed in between (it clears `missing_since`) wins. Returns the row it
   * lapsed, or undefined.
   */
  async lapse(id: string, missingBefore: Date, now: Date): Promise<SsoDomainRow | undefined> {
    const [row] = await this.db
      .update(ssoVerifiedDomains)
      .set({ status: 'lapsed', verified_at: null, updated_at: now })
      .where(
        and(
          eq(ssoVerifiedDomains.id, id),
          eq(ssoVerifiedDomains.status, 'verified'),
          lt(ssoVerifiedDomains.missing_since, missingBefore),
        ),
      )
      .returning();
    return row;
  }

  /**
   * Take the verified domains not looked up since `checkedBefore`, at most `limit`, and mark them looked up now so that
   * the machines of one deployment do not each look the same ones up. One statement; a machine that dies after taking a
   * row leaves it for the next interval, which is shorter than the time a confirmation counts.
   */
  async claimDueForRecheck(checkedBefore: Date, now: Date, limit: number, onlyAccounts?: readonly string[]): Promise<SsoDomainRow[]> {
    const due = this.db
      .select({ id: ssoVerifiedDomains.id })
      .from(ssoVerifiedDomains)
      .where(
        and(
          eq(ssoVerifiedDomains.status, 'verified'),
          or(isNull(ssoVerifiedDomains.last_checked_at), lt(ssoVerifiedDomains.last_checked_at, checkedBefore)),
          ...(onlyAccounts ? [inArray(ssoVerifiedDomains.operator_id, [...onlyAccounts])] : []),
        ),
      )
      .orderBy(asc(ssoVerifiedDomains.last_checked_at))
      .limit(limit)
      .for('update', { skipLocked: true });
    return this.db
      .update(ssoVerifiedDomains)
      .set({ last_checked_at: now })
      .where(inArray(ssoVerifiedDomains.id, due))
      .returning();
  }

  /** Domains added and never verified, older than `createdBefore`, are dropped. Returns how many. */
  async deleteStalePending(createdBefore: Date, onlyAccounts?: readonly string[]): Promise<number> {
    const rows = await this.db
      .delete(ssoVerifiedDomains)
      .where(
        and(
          eq(ssoVerifiedDomains.status, 'pending'),
          lt(ssoVerifiedDomains.created_at, createdBefore),
          ...(onlyAccounts ? [inArray(ssoVerifiedDomains.operator_id, [...onlyAccounts])] : []),
        ),
      )
      .returning({ id: ssoVerifiedDomains.id });
    return rows.length;
  }
}
