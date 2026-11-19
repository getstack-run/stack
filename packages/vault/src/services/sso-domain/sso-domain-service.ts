import { randomBytes } from 'node:crypto';
import {
  NotFoundError,
  SSO_DOMAINS_MAX_PER_ACCOUNT,
  SSO_DOMAIN_CHECK_COOLDOWN_SECONDS,
  SSO_DOMAIN_LAPSE_SECONDS,
  SSO_DOMAIN_PENDING_SECONDS,
  SSO_DOMAIN_RECHECK_SECONDS,
  SSO_DOMAIN_TOKEN_BYTES,
  SSO_DOMAIN_TRUST_SECONDS,
  SsoDomainError,
  ids,
  normalizeDomain,
  safeErrorSummary,
  sha256,
  ssoDomainRecordName,
  ssoDomainRecordValue,
  txtRecordsProve,
  type SsoDomainCheckResult,
  type SsoDomainView,
} from '@stack/shared';
import type { SsoDomainRepository, SsoDomainRow } from '../../repositories/sso-domain-repo.js';
import type { AuditService } from '../audit-service.js';
import { DnsNameAbsentError, type DnsTxtResolver } from './dns-txt.js';

/** A Postgres unique violation, whether the driver error is the thrown one or its cause. */
function isUniqueViolation(error: unknown): boolean {
  const code = (e: unknown) => (typeof e === 'object' && e !== null ? (e as { code?: unknown }).code : undefined);
  return code(error) === '23505' || code((error as { cause?: unknown } | null)?.cause) === '23505';
}

export interface SsoDomainServiceOptions {
  /** The current time; tests move it. */
  now?: () => Date;
}

/** The refusal for a domain this account cannot take, said the same whoever holds the name. */
const unavailable = () => new SsoDomainError('unavailable', 'This domain cannot be added to this account.');

/**
 * The verified e-mail domains of an account's single sign-on (spec/sso-login/SPEC.md section 9.5).
 *
 * An account claims a domain, STACK gives it a TXT record to publish, and a lookup that finds the record makes the
 * domain verified for that account, and for no other. An address at a verified domain then counts as verified for a first
 * sign-in or provisioning when the provider's ID token does not say.
 *
 * What a verified domain is worth is bounded in time and fails closed:
 *  - it counts only while the record was SEEN within `SSO_DOMAIN_TRUST_SECONDS`; past that, the sign-in looks the record up
 *    again and a lookup that fails, or finds the record gone, means the domain does not count;
 *  - the deployment looks every verified domain up again every `SSO_DOMAIN_RECHECK_SECONDS` (`recheckDue`), so a sign-in
 *    seldom has to;
 *  - a lookup that gives no answer says nothing about the record and never starts the lapse clock; a record seen gone
 *    for `SSO_DOMAIN_LAPSE_SECONDS` makes the domain lapse, which frees it for any account and needs verifying again.
 *
 * It is exact: `corp.example.com` is not `example.com`, and a verified parent domain is worth nothing to its children.
 */
export class SsoDomainService {
  private readonly now: () => Date;

  constructor(
    private repo: SsoDomainRepository,
    private dns: DnsTxtResolver,
    private audit: Pick<AuditService, 'write'> | null = null,
    options: SsoDomainServiceOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
  }

  /** The domain as the API shows it: the record to publish, and where the proof stands. */
  static view(row: SsoDomainRow): SsoDomainView {
    return {
      id: row.id,
      domain: row.domain,
      status: row.status as SsoDomainView['status'],
      record: { type: 'TXT', name: ssoDomainRecordName(row.domain), value: ssoDomainRecordValue(row.token) },
      verified_at: row.verified_at?.toISOString() ?? null,
      last_checked_at: row.last_checked_at?.toISOString() ?? null,
      last_check: (row.last_check as SsoDomainCheckResult | null) ?? null,
      missing_since: row.missing_since?.toISOString() ?? null,
      created_at: row.created_at.toISOString(),
    };
  }

  async list(operatorId: string): Promise<SsoDomainView[]> {
    return (await this.repo.listByOperator(operatorId)).map(SsoDomainService.view);
  }

  /**
   * Claim a domain for the account. Nothing is granted by this: the domain counts only once its record has been seen.
   * Adding one the account already has returns it unchanged. A name another account has VERIFIED is refused with the
   * neutral answer, the same as any other name this account cannot take, and so is one over the account's limit.
   */
  async add(operatorId: string, rawDomain: string): Promise<{ domain: SsoDomainView; created: boolean }> {
    const domain = normalizeDomain(rawDomain);
    if (!domain) {
      throw new SsoDomainError('invalid', 'Enter an e-mail domain such as corp.example.com: a name, with no address, port or path.');
    }
    const existing = await this.repo.findByDomain(operatorId, domain);
    if (existing) return { domain: SsoDomainService.view(existing), created: false };

    if ((await this.repo.countByOperator(operatorId)) >= SSO_DOMAINS_MAX_PER_ACCOUNT) {
      throw new SsoDomainError('limit_reached', `An account can hold ${SSO_DOMAINS_MAX_PER_ACCOUNT} domains. Remove one first.`);
    }
    const holder = await this.repo.findVerifiedHolder(domain);
    if (holder && holder.operator_id !== operatorId) throw unavailable();

    const now = this.now();
    try {
      const row = await this.repo.create({
        id: ids.ssoDomain(),
        operator_id: operatorId,
        domain,
        token: randomBytes(SSO_DOMAIN_TOKEN_BYTES).toString('base64url'),
        status: 'pending',
        created_at: now,
        updated_at: now,
      });
      return { domain: SsoDomainService.view(row), created: true };
    } catch (error) {
      // The same account adding the same name twice at once: the other call made it.
      if (isUniqueViolation(error)) {
        const row = await this.repo.findByDomain(operatorId, domain);
        if (row) return { domain: SsoDomainService.view(row), created: false };
      }
      throw error;
    }
  }

  /**
   * Look the record up now, for the account's own domain. Looking up more than once in `SSO_DOMAIN_CHECK_COOLDOWN_SECONDS`
   * answers with what the last lookup found and asks no name server. Verifying a domain another account verified in the
   * meantime is refused with the neutral answer.
   */
  async verify(operatorId: string, id: string): Promise<{ domain: SsoDomainView; check: SsoDomainCheckResult }> {
    const row = await this.repo.findInAccount(operatorId, id);
    if (!row) throw new NotFoundError('SsoDomain', id);
    const now = this.now();
    if (row.last_checked_at && now.getTime() - row.last_checked_at.getTime() < SSO_DOMAIN_CHECK_COOLDOWN_SECONDS * 1000 && row.last_check) {
      return { domain: SsoDomainService.view(row), check: row.last_check as SsoDomainCheckResult };
    }
    if (row.status !== 'verified') {
      const holder = await this.repo.findVerifiedHolder(row.domain);
      if (holder && holder.operator_id !== operatorId) throw unavailable();
    }
    const { row: updated, check } = await this.checkRow(row, { claimant: true });
    return { domain: SsoDomainService.view(updated), check };
  }

  async remove(operatorId: string, id: string): Promise<SsoDomainRow> {
    const row = await this.repo.findInAccount(operatorId, id);
    if (!row) throw new NotFoundError('SsoDomain', id);
    await this.repo.delete(operatorId, id);
    return row;
  }

  /**
   * Whether an address's domain counts as verified for this account's sign-in right now. True only for a domain the
   * account holds as verified whose record was seen within `SSO_DOMAIN_TRUST_SECONDS`, or that a lookup made now sees. A
   * stale confirmation, a record that is gone, a lookup that fails and anything unexpected are all false: a sign-in that
   * is refused is a sign-in the administrator can mend, one that is let in on a lapsed claim is not.
   */
  async isVerifiedFor(operatorId: string, domain: string): Promise<boolean> {
    try {
      const row = await this.repo.findByDomain(operatorId, domain);
      if (!row || row.status !== 'verified') return false;
      const now = this.now();
      if (row.last_confirmed_at && now.getTime() - row.last_confirmed_at.getTime() <= SSO_DOMAIN_TRUST_SECONDS * 1000) return true;
      // Stale: ask again, once in a while, rather than once per sign-in.
      if (row.last_checked_at && now.getTime() - row.last_checked_at.getTime() < SSO_DOMAIN_CHECK_COOLDOWN_SECONDS * 1000) return false;
      const { row: updated, check } = await this.checkRow(row, { claimant: false });
      return check === 'confirmed' && updated.status === 'verified';
    } catch (error) {
      console.error('[SSO_DOMAIN] sign-in check failed so domain not counted:', safeErrorSummary(error));
      return false;
    }
  }

  /**
   * The deployment's upkeep, one pass: look up again each verified domain not looked up for `SSO_DOMAIN_RECHECK_SECONDS`
   * (at most `limit`, taken so that two machines do not take the same one), and drop domains added and never verified for
   * `SSO_DOMAIN_PENDING_SECONDS`. A failure on one domain does not stop the others. `onlyAccounts` limits the pass to
   * those accounts' domains (a deployment passes none; a test that shares its database passes its own).
   */
  async recheckDue(limit = 50, onlyAccounts?: readonly string[]): Promise<{ checked: number; lapsed: number; dropped: number }> {
    const now = this.now();
    const claimed = await this.repo.claimDueForRecheck(
      new Date(now.getTime() - SSO_DOMAIN_RECHECK_SECONDS * 1000),
      now,
      limit,
      onlyAccounts,
    );
    let lapsed = 0;
    for (const row of claimed) {
      try {
        const { row: updated } = await this.checkRow(row, { claimant: false });
        if (updated.status === 'lapsed') lapsed += 1;
      } catch (error) {
        console.error('[SSO_DOMAIN] recheck failed', safeErrorSummary(error));
      }
    }
    const dropped = await this.repo.deleteStalePending(new Date(now.getTime() - SSO_DOMAIN_PENDING_SECONDS * 1000), onlyAccounts);
    return { checked: claimed.length, lapsed, dropped };
  }

  // ── the lookup and what it changes ──────────────────────────────────────────────────────────────────────────

  /** What one lookup found: the record, no such record, or no answer. Never throws. */
  private async lookup(row: SsoDomainRow): Promise<SsoDomainCheckResult> {
    try {
      const records = await this.dns.resolveTxt(ssoDomainRecordName(row.domain));
      return txtRecordsProve(records, row.token) ? 'confirmed' : 'missing';
    } catch (error) {
      return error instanceof DnsNameAbsentError ? 'missing' : 'unavailable';
    }
  }

  /**
   * Look a row's record up and write what was found. `claimant` is true when the account asked (it may make a domain
   * verified; a lookup for a stale sign-in or the upkeep only keeps one it already has).
   */
  private async checkRow(row: SsoDomainRow, options: { claimant: boolean }): Promise<{ row: SsoDomainRow; check: SsoDomainCheckResult }> {
    const check = await this.lookup(row);
    const now = this.now();

    if (check === 'confirmed') {
      if (row.status !== 'verified' && !options.claimant) return { row, check: 'unavailable' };
      try {
        const updated = await this.repo.markConfirmed(row.id, now);
        if (!updated) throw new NotFoundError('SsoDomain', row.id);
        return { row: updated, check };
      } catch (error) {
        // Another account verified the name first: the one answer, whoever it is.
        if (isUniqueViolation(error)) throw unavailable();
        throw error;
      }
    }

    if (check === 'missing') {
      const marked = (await this.repo.markMissing(row.id, now)) ?? row;
      if (marked.status === 'verified' && marked.missing_since) {
        const lapsed = await this.repo.lapse(row.id, new Date(now.getTime() - SSO_DOMAIN_LAPSE_SECONDS * 1000), now);
        if (lapsed) {
          await this.writeAudit(lapsed, 'sso.domain.lapse');
          return { row: lapsed, check };
        }
      }
      return { row: marked, check };
    }

    return { row: (await this.repo.markUnavailable(row.id, now)) ?? row, check };
  }

  private async writeAudit(row: SsoDomainRow, action: string): Promise<void> {
    if (!this.audit) return;
    try {
      await this.audit.write({
        ctx: { trace_id: `sso-domain-${row.id}`, span_id: row.id, operator_id: row.operator_id, agent_id: 'system', passport_jti: 'none' },
        layer: 'vault',
        action,
        outcome: 'success',
        payload_hash: sha256(row.domain),
      });
    } catch (error) {
      console.error('[SSO_DOMAIN] audit write failed', safeErrorSummary(error));
    }
  }
}
