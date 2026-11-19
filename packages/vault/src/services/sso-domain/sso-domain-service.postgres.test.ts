import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { eq, inArray } from 'drizzle-orm';
import {
  SSO_DOMAINS_MAX_PER_ACCOUNT,
  SSO_DOMAIN_CHECK_COOLDOWN_SECONDS,
  SSO_DOMAIN_LAPSE_SECONDS,
  SSO_DOMAIN_PENDING_SECONDS,
  SSO_DOMAIN_RECHECK_SECONDS,
  SSO_DOMAIN_TRUST_SECONDS,
  createDb,
  operators,
  ssoDomainRecordName,
  ssoDomainRecordValue,
  ssoVerifiedDomains,
} from '@stack/shared';
import { SsoDomainRepository } from '../../repositories/sso-domain-repo.js';
import { DnsNameAbsentError, type DnsTxtResolver } from './dns-txt.js';
import { SsoDomainService } from './sso-domain-service.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

type Answer = string[][] | 'absent' | 'error';

/** A DNS the test publishes into: names it has records for, names that do not exist and names whose server does not answer. */
class FakeDns implements DnsTxtResolver {
  readonly records = new Map<string, Answer>();
  lookups: string[] = [];
  publish(domain: string, token: string, extra: string[][] = []) {
    this.records.set(ssoDomainRecordName(domain), [...extra, [ssoDomainRecordValue(token)]]);
  }
  async resolveTxt(name: string): Promise<string[][]> {
    this.lookups.push(name);
    const answer = this.records.get(name) ?? 'absent';
    if (answer === 'absent') throw new DnsNameAbsentError(name);
    if (answer === 'error') throw new Error('SERVFAIL');
    return answer;
  }
}

const HOUR = 3600_000;
const SECOND = 1000;

describeWithDb('SsoDomainService', () => {
  const db = createDb(DATABASE_URL!);
  const suffix = Math.random().toString(36).slice(2, 10);
  const a = `op_ssod_a_${suffix}`;
  const b = `op_ssod_b_${suffix}`;
  const domainOf = (label: string) => `${label}-${suffix}.example.com`;

  let clock = new Date('2026-10-26T10:00:00Z');
  const dns = new FakeDns();
  const repo = new SsoDomainRepository(db);
  const audits: string[] = [];
  const service = new SsoDomainService(repo, dns, { write: async (input) => { audits.push(input.action); return {} as never; } }, { now: () => clock });
  const advance = (ms: number) => { clock = new Date(clock.getTime() + ms); };

  async function clean() {
    await db.delete(ssoVerifiedDomains).where(inArray(ssoVerifiedDomains.operator_id, [a, b])).catch(() => undefined);
    await db.delete(operators).where(inArray(operators.id, [a, b])).catch(() => undefined);
  }
  afterAll(clean);

  beforeEach(async () => {
    await clean();
    for (const id of [a, b]) await db.insert(operators).values({ id, email: `${id}@test.invalid`, api_key_hash: `hash_${id}` });
    dns.records.clear();
    dns.lookups = [];
    audits.length = 0;
    clock = new Date('2026-10-26T10:00:00Z');
  });

  /** Claim a domain for an account, publish its record and verify it. */
  async function verified(operatorId: string, domain: string) {
    const { domain: claim } = await service.add(operatorId, domain);
    dns.publish(domain, claim.record.value.slice('stack-sso-verification='.length));
    const result = await service.verify(operatorId, claim.id);
    expect(result.domain.status).toBe('verified');
    return claim.id;
  }

  describe('adding a domain', () => {
    it('stores the canonical name with the record to publish, and grants nothing yet', async () => {
      const { domain, created } = await service.add(a, `  ${domainOf('Corp').toUpperCase()}. `);
      expect(created).toBe(true);
      expect(domain.domain).toBe(domainOf('corp'));
      expect(domain.status).toBe('pending');
      expect(domain.record).toEqual({ type: 'TXT', name: `_stack-sso.${domainOf('corp')}`, value: expect.stringMatching(/^stack-sso-verification=[A-Za-z0-9_-]{32}$/) });
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);
    });

    it('returns the claim the account already has, with the same record', async () => {
      const first = await service.add(a, domainOf('corp'));
      const second = await service.add(a, domainOf('CORP'));
      expect(second.created).toBe(false);
      expect(second.domain).toEqual(first.domain);
    });

    it.each(['localhost', 'https://corp.example.com', 'corp.example.com/x', '10.1.2.3', 'a@corp.example.com', '*.example.com', ''])(
      'refuses %j as not a domain',
      async (name) => {
        await expect(service.add(a, name)).rejects.toMatchObject({ code: 'SSO_DOMAIN_INVALID', statusCode: 400 });
      },
    );

    it('refuses an account more than its limit', async () => {
      for (let i = 0; i < SSO_DOMAINS_MAX_PER_ACCOUNT; i++) await service.add(a, domainOf(`d${i}`));
      await expect(service.add(a, domainOf('one-too-many'))).rejects.toMatchObject({ code: 'SSO_DOMAIN_LIMIT_REACHED' });
    });

    it('refuses a domain another account has verified, with the answer it gives for any name it cannot take', async () => {
      await verified(a, domainOf('shared'));
      const refusal = await service.add(b, domainOf('shared')).catch((e) => e);
      expect(refusal).toMatchObject({ code: 'SSO_DOMAIN_UNAVAILABLE', statusCode: 409, message: 'This domain cannot be added to this account.' });
      expect(JSON.stringify(refusal)).not.toContain(a);
    });
  });

  describe('verifying a domain', () => {
    it('verifies it when the record is there, and counts it at sign-in', async () => {
      const id = await verified(a, domainOf('corp'));
      const [row] = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.id, id));
      expect(row).toMatchObject({ status: 'verified', last_check: 'confirmed', missing_since: null });
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(true);
    });

    it('does not verify when the record is not there, or says another token, or has the token with more around it', async () => {
      const { domain } = await service.add(a, domainOf('corp'));
      expect((await service.verify(a, domain.id)).check).toBe('missing');
      advance(SSO_DOMAIN_CHECK_COOLDOWN_SECONDS * SECOND + SECOND);
      dns.records.set(ssoDomainRecordName(domainOf('corp')), [[ssoDomainRecordValue('someone-elses-token')], ['v=spf1 -all']]);
      expect((await service.verify(a, domain.id)).check).toBe('missing');
      advance(SSO_DOMAIN_CHECK_COOLDOWN_SECONDS * SECOND + SECOND);
      dns.records.set(ssoDomainRecordName(domainOf('corp')), [[`${domain.record.value}x`], [`prefix ${domain.record.value}`]]);
      const result = await service.verify(a, domain.id);
      expect(result.check).toBe('missing');
      expect(result.domain.status).toBe('pending');
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);
    });

    it('reads a record the name server split into several strings as one', async () => {
      const { domain } = await service.add(a, domainOf('corp'));
      const [first, second] = [domain.record.value.slice(0, 10), domain.record.value.slice(10)];
      dns.records.set(ssoDomainRecordName(domainOf('corp')), [[first!, second!]]);
      expect((await service.verify(a, domain.id)).domain.status).toBe('verified');
    });

    it('fails closed on a lookup that gives no answer: it says so, verifies nothing and is not read as the record being gone', async () => {
      const { domain } = await service.add(a, domainOf('corp'));
      dns.records.set(ssoDomainRecordName(domainOf('corp')), 'error');
      const result = await service.verify(a, domain.id);
      expect(result.check).toBe('unavailable');
      expect(result.domain.status).toBe('pending');
      expect(result.domain.last_check).toBe('unavailable');
    });

    it('looks a name up at most once in the cooldown, answering with the last result', async () => {
      const { domain } = await service.add(a, domainOf('corp'));
      await service.verify(a, domain.id);
      dns.publish(domainOf('corp'), domain.record.value.slice('stack-sso-verification='.length));
      const again = await service.verify(a, domain.id);
      expect(again.check).toBe('missing');
      expect(dns.lookups).toHaveLength(1);
      advance(SSO_DOMAIN_CHECK_COOLDOWN_SECONDS * SECOND + SECOND);
      expect((await service.verify(a, domain.id)).check).toBe('confirmed');
    });

    it('does not find another account\'s domain or claim', async () => {
      const { domain } = await service.add(a, domainOf('corp'));
      await expect(service.verify(b, domain.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
      await expect(service.remove(b, domain.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
      expect(await service.list(b)).toEqual([]);
    });

    it('lets a second account claim a name the first has not proved, but only one can verify it', async () => {
      const first = await service.add(a, domainOf('contested'));
      const second = await service.add(b, domainOf('contested'));
      expect(second.created).toBe(true);
      // The name publishes both accounts' records (their own tokens are different).
      dns.records.set(ssoDomainRecordName(domainOf('contested')), [[first.domain.record.value], [second.domain.record.value]]);
      expect((await service.verify(a, first.domain.id)).domain.status).toBe('verified');
      await expect(service.verify(b, second.domain.id)).rejects.toMatchObject({ code: 'SSO_DOMAIN_UNAVAILABLE' });
      expect(await service.isVerifiedFor(b, domainOf('contested'))).toBe(false);
      expect(await service.isVerifiedFor(a, domainOf('contested'))).toBe(true);
    });

    it('settles two accounts verifying the same name at once on one of them', async () => {
      const first = await service.add(a, domainOf('race'));
      const second = await service.add(b, domainOf('race'));
      dns.records.set(ssoDomainRecordName(domainOf('race')), [[first.domain.record.value], [second.domain.record.value]]);
      const results = await Promise.allSettled([service.verify(a, first.domain.id), service.verify(b, second.domain.id)]);
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1);
      const held = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.domain, domainOf('race')));
      expect(held.filter((row) => row.status === 'verified')).toHaveLength(1);
    });
  });

  describe('what a verified domain is worth at sign-in', () => {
    it('counts the exact domain only: not its parent, not a subdomain, not another account', async () => {
      await verified(a, domainOf('corp'));
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(true);
      expect(await service.isVerifiedFor(a, `mail.${domainOf('corp')}`)).toBe(false);
      expect(await service.isVerifiedFor(a, 'example.com')).toBe(false);
      expect(await service.isVerifiedFor(b, domainOf('corp'))).toBe(false);
    });

    it('trusts a confirmation for the trust window without asking DNS, and asks again after it', async () => {
      await verified(a, domainOf('corp'));
      dns.lookups = [];
      advance((SSO_DOMAIN_TRUST_SECONDS - 60) * SECOND);
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(true);
      expect(dns.lookups).toHaveLength(0);

      advance(120 * SECOND);
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(true);
      expect(dns.lookups).toHaveLength(1);
    });

    it('stops counting a domain whose record is gone once the trust window has passed, and keeps it verified until it lapses', async () => {
      const id = await verified(a, domainOf('corp'));
      dns.records.delete(ssoDomainRecordName(domainOf('corp')));
      // Within the window the cached confirmation still counts: that is what the window is.
      advance((SSO_DOMAIN_TRUST_SECONDS - 60) * SECOND);
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(true);
      // Past it, the sign-in asks, finds nothing and refuses.
      advance(120 * SECOND);
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);
      const [row] = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.id, id));
      expect(row).toMatchObject({ status: 'verified', last_check: 'missing' });
      expect(row!.missing_since).not.toBeNull();
    });

    it('counts nothing once the window has passed and the lookup fails, and does not mistake the failure for the record being gone', async () => {
      const id = await verified(a, domainOf('corp'));
      dns.records.set(ssoDomainRecordName(domainOf('corp')), 'error');
      advance((SSO_DOMAIN_TRUST_SECONDS + 60) * SECOND);
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);
      const [row] = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.id, id));
      expect(row).toMatchObject({ status: 'verified', last_check: 'unavailable', missing_since: null });
    });

    it('counts it again as soon as the record is back', async () => {
      await verified(a, domainOf('corp'));
      const wanted = dns.records.get(ssoDomainRecordName(domainOf('corp')))!;
      dns.records.delete(ssoDomainRecordName(domainOf('corp')));
      advance((SSO_DOMAIN_TRUST_SECONDS + 60) * SECOND);
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);
      dns.records.set(ssoDomainRecordName(domainOf('corp')), wanted);
      advance((SSO_DOMAIN_CHECK_COOLDOWN_SECONDS + 1) * SECOND);
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(true);
      const [row] = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.domain, domainOf('corp')));
      expect(row!.missing_since).toBeNull();
    });

    it('does not count a removed domain', async () => {
      const id = await verified(a, domainOf('corp'));
      await service.remove(a, id);
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);
    });

    it('does not let a sign-in look a lookup up more than once in the cooldown', async () => {
      await verified(a, domainOf('corp'));
      dns.records.set(ssoDomainRecordName(domainOf('corp')), 'error');
      advance((SSO_DOMAIN_TRUST_SECONDS + 60) * SECOND);
      dns.lookups = [];
      for (let i = 0; i < 5; i++) expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);
      expect(dns.lookups).toHaveLength(1);
    });
  });

  describe('the upkeep', () => {
    it('looks verified domains up again after the recheck interval, and only those', async () => {
      await verified(a, domainOf('corp'));
      await service.add(a, domainOf('pending'));
      dns.lookups = [];
      expect(await service.recheckDue(50, [a, b])).toMatchObject({ checked: 0 });
      advance((SSO_DOMAIN_RECHECK_SECONDS + 1) * SECOND);
      expect(await service.recheckDue(50, [a, b])).toMatchObject({ checked: 1, lapsed: 0 });
      expect(dns.lookups).toEqual([ssoDomainRecordName(domainOf('corp'))]);
      // Taken once: a second machine's pass at the same moment finds nothing due.
      expect(await service.recheckDue(50, [a, b])).toMatchObject({ checked: 0 });
    });

    it('keeps a domain counting while the record keeps being seen, past the trust window of the first check', async () => {
      await verified(a, domainOf('corp'));
      for (let i = 0; i < 12; i++) {
        advance((SSO_DOMAIN_RECHECK_SECONDS + 1) * SECOND);
        await service.recheckDue(50, [a, b]);
      }
      dns.lookups = [];
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(true);
      expect(dns.lookups).toHaveLength(0);
    });

    it('lapses a domain whose record has been missing for the lapse time, frees it for another account and writes it down', async () => {
      const id = await verified(a, domainOf('corp'));
      dns.records.delete(ssoDomainRecordName(domainOf('corp')));
      const passes = Math.ceil((SSO_DOMAIN_LAPSE_SECONDS + 2 * SSO_DOMAIN_RECHECK_SECONDS) / SSO_DOMAIN_RECHECK_SECONDS);
      let lapsed = 0;
      for (let i = 0; i < passes && lapsed === 0; i++) {
        advance((SSO_DOMAIN_RECHECK_SECONDS + 1) * SECOND);
        lapsed += (await service.recheckDue(50, [a, b])).lapsed;
      }
      expect(lapsed).toBe(1);
      const [row] = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.id, id));
      expect(row).toMatchObject({ status: 'lapsed', verified_at: null });
      expect(audits).toContain('sso.domain.lapse');
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);

      // It is free now: another account can claim and verify it.
      const other = await service.add(b, domainOf('corp'));
      dns.publish(domainOf('corp'), other.domain.record.value.slice('stack-sso-verification='.length));
      expect((await service.verify(b, other.domain.id)).domain.status).toBe('verified');
      // And the first account must prove it again, which it cannot while the other holds it.
      dns.records.set(ssoDomainRecordName(domainOf('corp')), [[ssoDomainRecordValue('x')]]);
      advance((SSO_DOMAIN_CHECK_COOLDOWN_SECONDS + 1) * SECOND);
      await expect(service.verify(a, id)).rejects.toMatchObject({ code: 'SSO_DOMAIN_UNAVAILABLE' });
    });

    it('does not lapse a domain on lookups that failed, however long they fail', async () => {
      const id = await verified(a, domainOf('corp'));
      dns.records.set(ssoDomainRecordName(domainOf('corp')), 'error');
      for (let i = 0; i < 24 * 9; i++) {
        advance((SSO_DOMAIN_RECHECK_SECONDS + 1) * SECOND);
        await service.recheckDue(50, [a, b]);
      }
      const [row] = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.id, id));
      expect(row).toMatchObject({ status: 'verified', missing_since: null });
      // It does not count either: nothing has seen the record for longer than the window.
      expect(await service.isVerifiedFor(a, domainOf('corp'))).toBe(false);
    });

    it('does not lapse a domain whose record came back before the lapse time', async () => {
      const id = await verified(a, domainOf('corp'));
      const wanted = dns.records.get(ssoDomainRecordName(domainOf('corp')))!;
      dns.records.delete(ssoDomainRecordName(domainOf('corp')));
      advance((SSO_DOMAIN_RECHECK_SECONDS + 1) * SECOND);
      await service.recheckDue(50, [a, b]);
      let [row] = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.id, id));
      expect(row!.missing_since).not.toBeNull();
      dns.records.set(ssoDomainRecordName(domainOf('corp')), wanted);
      advance(12 * HOUR);
      await service.recheckDue(50, [a, b]);
      [row] = await db.select().from(ssoVerifiedDomains).where(eq(ssoVerifiedDomains.id, id));
      expect(row).toMatchObject({ status: 'verified', missing_since: null });
    });

    it('lets a lapsed domain be verified again by its account, with the same record', async () => {
      const id = await verified(a, domainOf('corp'));
      await db.update(ssoVerifiedDomains).set({ status: 'lapsed', verified_at: null }).where(eq(ssoVerifiedDomains.id, id));
      advance((SSO_DOMAIN_CHECK_COOLDOWN_SECONDS + 1) * SECOND);
      const result = await service.verify(a, id);
      expect(result.domain.status).toBe('verified');
    });

    it('drops a domain added and never verified after the pending time', async () => {
      await service.add(a, domainOf('never'));
      advance((SSO_DOMAIN_PENDING_SECONDS - 60) * SECOND);
      expect((await service.recheckDue(50, [a, b])).dropped).toBe(0);
      advance(120 * SECOND);
      expect((await service.recheckDue(50, [a, b])).dropped).toBe(1);
      expect(await service.list(a)).toEqual([]);
    });
  });
});
