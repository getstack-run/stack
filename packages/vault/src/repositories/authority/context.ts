import { sql } from 'drizzle-orm';
import { ConflictError, type Database } from '@stack/shared';
import type { AuthorityDbTransaction } from '../../services/authority/records.js';
import type { AuthorityRepositoryPort } from '../../services/authority/port.js';

/**
 * What every per-aggregate module of the authority repository shares: the
 * connection, the transaction the repository was created inside (if any), the
 * composed repository for cross-aggregate reads, and the two operations that
 * mint a transaction-scoped repository. A repository created inside a
 * transaction hands that same transaction to every aggregate.
 */
/** An internal receiver kind a deployment adds (a skill): whether this operator owns one of that kind, and it is active. */
export interface ReceiverDirectory {
  kind: string;
  isOwnedActive(operatorId: string, id: string): Promise<boolean>;
}

export interface AuthorityRepoContext {
  readonly db: Database;
  /** The internal receiver kinds a deployment adds to the engine's (an agent, a drop-off). */
  readonly receiverDirectories: readonly ReceiverDirectory[];
  readonly transaction: AuthorityDbTransaction | undefined;
  /** The composed repository: aggregates read each other through it. */
  readonly repo: AuthorityRepositoryPort;
  /** Runs the mutation on this repository's transaction, opening one when there is none. */
  atomic<T>(mutation: (repo: AuthorityRepositoryPort) => Promise<T>): Promise<T>;
  /** A repository bound to the given transaction. */
  forTransaction(transaction: AuthorityDbTransaction): AuthorityRepositoryPort;
}

/** Base class of the per-aggregate modules. */
export abstract class AuthorityAggregateRepository {
  constructor(protected readonly ctx: AuthorityRepoContext) {}

  protected get db(): Database {
    return this.ctx.db;
  }

  protected get transaction(): AuthorityDbTransaction | undefined {
    return this.ctx.transaction;
  }

  protected get repo(): AuthorityRepositoryPort {
    return this.ctx.repo;
  }

  protected atomic<T>(mutation: (repo: AuthorityRepositoryPort) => Promise<T>): Promise<T> {
    return this.ctx.atomic(mutation);
  }

  /**
   * Serialises disclosure, receipt finalisation, and destructive lifecycle work
   * for one tenant. The lock is transaction-scoped, so a failed operation can
   * never strand it. This deliberately favours a simple fail-closed ordering
   * over concurrent disclosure of one operator's authority graph.
   */
  protected async lockOperatorAuthorityGraph(operatorId: string): Promise<void> {
    if (!this.transaction) throw new ConflictError('authority graph lock requires an atomic transaction');
    await this.transaction.execute(sql`
      select pg_advisory_xact_lock(hashtextextended(${`stack-authority:${operatorId}`}, 0))
    `);
  }
}
