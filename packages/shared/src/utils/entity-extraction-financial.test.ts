import { describe, it, expect } from 'vitest';
import { canonicalMoneyAmount, extractEntities } from './entity-extraction.js';
import { isFinancialProvider } from '../constants/financial-providers.js';

const money = (input: unknown) =>
  extractEntities(input, { financial: true }).filter((e) => e.entity_type === 'money_amount').map((e) => e.entity);
const accounts = (input: unknown) =>
  extractEntities(input, { financial: true }).filter((e) => e.entity_type === 'account_number').map((e) => e.entity);

describe('canonicalMoneyAmount', () => {
  it.each([
    ['$12,345.67', '12345.67'],
    ['12.345,67 EUR', '12345.67'],
    ['USD 12345.67', '12345.67'],
    ["CHF 1'234.50", '1234.50'],
    ['$20,000.00', '20000'],
    ['20000', '20000'],
    ['-12,345.6', '12345.60'],
    ['0012.50', '12.50'],
  ])('%s -> %s', (raw, canonical) => {
    expect(canonicalMoneyAmount(raw)).toBe(canonical);
  });

  it.each(['$9.99', '$100', '1.5', '12'])('ignores %s (fewer than four digits)', (raw) => {
    expect(canonicalMoneyAmount(raw)).toBeNull();
  });
});

describe('extractEntities({ financial: true })', () => {
  it('reads a balance sent as a JSON number and the same balance written in a sentence as one entity', () => {
    const fromBank = money({ account: { availableBalance: 12345.67, currentBalance: 20000 } });
    const inSlack = money({ channel: 'C123', text: 'Operating account: $12,345.67, reserve USD 20,000.' });
    expect(inSlack).toEqual(expect.arrayContaining(fromBank.slice(0, 1)));
    expect(new Set(inSlack).size).toBe(2);
    for (const value of fromBank) expect(inSlack).toContain(value);
  });

  it('reads an integer in minor units the way Stripe sends it', () => {
    const fromStripe = money({ amount: 1234567 });
    expect(fromStripe).toEqual(expect.arrayContaining(money('Charged $12,345.67 today')));
  });

  it('records a digest, never the figure', () => {
    const all = extractEntities({ balance: 12345.67, accountNumber: '123456789012' }, { financial: true });
    const text = JSON.stringify(all);
    expect(text).not.toContain('12345');
    expect(text).not.toContain('123456789012');
    expect(all.every((e) => e.entity_type !== 'money_amount' || /^money:[0-9a-f]{24}$/.test(e.entity))).toBe(true);
  });

  it('matches an account number and an IBAN however they are spaced', () => {
    expect(accounts({ accountNumber: '123456789012' })).toEqual(accounts('Wire to account 123456789012 please'));
    expect(accounts({ iban: 'SE4550000000058398257466' })).toEqual(accounts('IBAN SE45 5000 0000 0583 9825 7466'));
  });

  it('does not call a bare year, a short count or a version money', () => {
    expect(money('In 2026 we shipped 3 releases, v1.5 and 12 fixes')).toEqual([]);
  });

  it('is off by default, so ordinary producers and the undeclared-target detector are unchanged', () => {
    const plain = extractEntities({ balance: 12345.67, text: 'paid $12,345.67 to acct 123456789012' });
    expect(plain.some((e) => e.entity_type === 'money_amount' || e.entity_type === 'account_number')).toBe(false);
  });

  it('stays linear on adversarial digit runs', () => {
    const hostile = `$${'1,'.repeat(20_000)}1`;
    const started = performance.now();
    extractEntities({ text: hostile }, { financial: true });
    expect(performance.now() - started).toBeLessThan(2000);
  });
});

describe('isFinancialProvider', () => {
  it('tags the banks and payment providers, case-insensitively', () => {
    for (const provider of ['mercury', 'Stripe', 'plaid', 'brex', 'wise', 'quickbooks', 'xero']) {
      expect(isFinancialProvider(provider)).toBe(true);
    }
  });
  it('does not tag messaging or unknown providers', () => {
    for (const provider of ['slack', 'gmail', 'resend', 'custom_bank', '', undefined, null]) {
      expect(isFinancialProvider(provider)).toBe(false);
    }
  });
});
