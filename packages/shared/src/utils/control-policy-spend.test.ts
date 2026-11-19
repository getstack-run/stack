import { describe, expect, it } from 'vitest';
import { PolicyDefinition, type PolicyDefinitionInput } from '../schemas/control-policy.js';
import {
  categoryOf,
  chatApprovalLimits,
  classifyPolicyRevision,
  evaluatePolicy,
  matchingSpendRules,
  normalizePolicy,
  paymentFactsOf,
  scopedPeriodKey,
  spendPlanFor,
  type PolicyCall,
} from './control-policy.js';

type Sections = Omit<PolicyDefinitionInput, 'name'> & { name?: string };
const policy = (input: Sections = {}) => normalizePolicy({ name: 'p', ...input });
const PAYEE_A = `0x${'a'.repeat(40)}`;
const PAYEE_B = `0x${'b'.repeat(40)}`;
const card = (origin: string, cents: number | null): PolicyCall => ({
  action: 'card.checkout',
  target: { merchant_origin: origin, amount_minor: cents, currency: 'USD' },
  amountCents: cents,
});
const wallet = (payee: string | null, cents: number | null): PolicyCall => ({
  action: 'wallet.payment',
  target: payee === null ? {} : { payee },
  amountCents: cents,
});

describe('spend rules in the definition', () => {
  it('parse with defaults, and refuse a rule that sets no limit or names both a merchant and a payee', () => {
    const parsed = PolicyDefinition.parse({ name: 'x' });
    expect(parsed.spend.rules).toEqual([]);
    expect(parsed.spend.categories).toEqual([]);
    const bad = (rule: Record<string, unknown>) => PolicyDefinition.safeParse({ name: 'x', spend: { rules: [{ id: 'r', ...rule }] } }).success;
    expect(bad({ merchant: 'shop.example' })).toBe(false);
    expect(bad({ merchant: 'shop.example', payee: PAYEE_A, max_per_day_cents: 100 })).toBe(false);
    expect(bad({ merchant: 'shop.example', max_per_day_cents: 100 })).toBe(true);
    expect(bad({ category: 'Groceries', max_per_day_cents: 100 })).toBe(false);
    expect(bad({ category: 'groceries', max_per_payment_cents: 100 })).toBe(true);
  });

  it('refuses duplicate rule ids and two labels for one merchant', () => {
    const rules = [{ id: 'r', max_per_day_cents: 100 }, { id: 'r', max_per_day_cents: 200 }];
    expect(PolicyDefinition.safeParse({ name: 'x', spend: { rules } }).success).toBe(false);
    const categories = [{ merchant: 'shop.example', category: 'a' }, { merchant: 'shop.example', category: 'b' }];
    expect(PolicyDefinition.safeParse({ name: 'x', spend: { categories } }).success).toBe(false);
    expect(PolicyDefinition.safeParse({ name: 'x', spend: { categories: [{ category: 'a' }] } }).success).toBe(false);
  });
});

describe('what a payment is', () => {
  it('reads the merchant host from the card checkout and the payee from the wallet payment', () => {
    expect(paymentFactsOf('card.checkout', { merchant_origin: 'https://Shop.Example:8443' })).toEqual({ surface: 'card', merchant: 'shop.example', payee: null });
    expect(paymentFactsOf('card.checkout', { merchant_origin: 'not a url' })).toEqual({ surface: 'card', merchant: null, payee: null });
    expect(paymentFactsOf('wallet.payment', { payee: PAYEE_A.toUpperCase().replace('0X', '0x') })).toEqual({ surface: 'wallet', merchant: null, payee: PAYEE_A });
    expect(paymentFactsOf('wallet.payment', {})).toEqual({ surface: 'wallet', merchant: null, payee: null });
    expect(paymentFactsOf('email.send', {})).toBeNull();
  });

  it('takes the category from the customer labels, and none when the labels disagree or say nothing', () => {
    const p = policy({
      spend: { categories: [{ merchant: '*.cloud.example', category: 'software' }, { merchant: 'a.cloud.example', category: 'travel' }, { payee: PAYEE_A, category: 'tools' }] },
    });
    expect(categoryOf(p, { surface: 'card', merchant: 'b.cloud.example', payee: null })).toBe('software');
    expect(categoryOf(p, { surface: 'card', merchant: 'a.cloud.example', payee: null })).toBeNull();
    expect(categoryOf(p, { surface: 'card', merchant: 'other.example', payee: null })).toBeNull();
    expect(categoryOf(p, { surface: 'card', merchant: null, payee: null })).toBeNull();
    expect(categoryOf(p, { surface: 'wallet', merchant: null, payee: PAYEE_A })).toBe('tools');
  });
});

describe('which rules a payment falls under', () => {
  const p = policy({
    spend: {
      rules: [
        { id: 'shop', merchant: 'shop.example', max_per_day_cents: 5_000 },
        { id: 'any-sw', category: 'software', max_per_payment_cents: 2_000, max_per_month_cents: 20_000 },
        { id: 'payee-a', payee: PAYEE_A, max_per_payment_cents: 300 },
        { id: 'all', max_per_month_cents: 100_000 },
      ],
      categories: [{ merchant: 'saas.example', category: 'software' }, { merchant: 'shop.example', category: 'groceries' }],
    },
  });
  const ids = (facts: Parameters<typeof matchingSpendRules>[1]) => matchingSpendRules(p, facts).map((r) => r.id).sort();

  it('applies a rule when the merchant, payee or category is that one', () => {
    expect(ids({ surface: 'card', merchant: 'shop.example', payee: null })).toEqual(['all', 'shop']);
    expect(ids({ surface: 'card', merchant: 'saas.example', payee: null })).toEqual(['all', 'any-sw']);
    expect(ids({ surface: 'wallet', merchant: null, payee: PAYEE_A })).toEqual(['all', 'any-sw', 'payee-a']);
    expect(ids({ surface: 'wallet', merchant: null, payee: PAYEE_B })).toEqual(['all', 'any-sw']);
  });

  it('holds an unknown merchant or category to every rule it might match: the strictest applies', () => {
    // A merchant the customer never labelled: the category is unknown, so the software rule applies too.
    expect(ids({ surface: 'card', merchant: 'new.example', payee: null })).toEqual(['all', 'any-sw']);
    // A merchant that cannot be read: every card rule may match.
    expect(ids({ surface: 'card', merchant: null, payee: null })).toEqual(['all', 'any-sw', 'shop']);
    // A payee that cannot be read: every wallet rule may match.
    expect(ids({ surface: 'wallet', merchant: null, payee: null })).toEqual(['all', 'any-sw', 'payee-a']);
  });

  it('plans the tightest per-payment limit and one counter per window of each matching rule', () => {
    const plan = spendPlanFor(p, { surface: 'card', merchant: null, payee: null });
    expect(plan.perPayment).toEqual({ limit: 2_000, ruleId: 'any-sw' });
    expect(plan.counters.map((c) => `${c.ruleId}:${c.kind}:${c.limit}:${c.scope}`).sort()).toEqual([
      'all:month:100000:spend:all',
      'any-sw:month:20000:spend:any-sw',
      'shop:day:5000:spend:shop',
    ]);
  });
});

describe('the per-payment limit', () => {
  const p = policy({
    spend: {
      rules: [{ id: 'sw', category: 'software', max_per_payment_cents: 2_000 }, { id: 'w', payee: PAYEE_A, max_per_payment_cents: 500 }],
      categories: [{ merchant: 'saas.example', category: 'software' }],
    },
  });

  it('allows a payment within it and refuses one over it, naming the rule and never the merchant', () => {
    expect(evaluatePolicy(p, card('https://saas.example', 2_000)).verdict).toBe('allow');
    const over = evaluatePolicy(p, card('https://saas.example', 2_001));
    expect(over).toMatchObject({ verdict: 'deny', section: 'spend', rule: 'rules.sw.max_per_payment_cents', code: 'amount_over_limit', detail: { limit_cents: 2_000 } });
    expect(JSON.stringify(over)).not.toContain('saas.example');
  });

  it('holds an unknown merchant to the category limit', () => {
    expect(evaluatePolicy(p, card('https://stranger.example', 2_001))).toMatchObject({ verdict: 'deny', code: 'amount_over_limit' });
    expect(evaluatePolicy(p, card('https://stranger.example', 1_000)).verdict).toBe('allow');
  });

  it('refuses a limited payment whose amount cannot be read in USD', () => {
    expect(evaluatePolicy(p, card('https://saas.example', null))).toMatchObject({ verdict: 'deny', code: 'policy_unevaluable' });
    expect(evaluatePolicy(p, wallet(PAYEE_A, null))).toMatchObject({ verdict: 'deny', code: 'policy_unevaluable' });
  });

  it('applies to a wallet payee, and a payee nobody can read counts as the strictest', () => {
    expect(evaluatePolicy(p, wallet(PAYEE_A, 501))).toMatchObject({ verdict: 'deny', rule: 'rules.w.max_per_payment_cents' });
    expect(evaluatePolicy(p, wallet(PAYEE_B, 1_999)).verdict).toBe('allow');
    expect(evaluatePolicy(p, wallet(null, 501))).toMatchObject({ verdict: 'deny', rule: 'rules.w.max_per_payment_cents' });
  });

  it('leaves every other action alone', () => {
    expect(evaluatePolicy(p, { action: 'email.send', target: {}, amountCents: 10_000_000 }).verdict).toBe('allow');
  });
});

describe('revising spend rules: only a provable tightening applies at once', () => {
  const base = policy({
    spend: { rules: [{ id: 'shop', merchant: 'shop.example', max_per_day_cents: 5_000, max_per_payment_cents: 1_000 }] },
  });
  const revise = (sections: Sections) => classifyPolicyRevision(policy(sections), base);

  it('adding a rule or lowering a limit tightens', () => {
    expect(revise({ spend: { rules: [...base.spend.rules, { id: 'more', category: 'x', max_per_day_cents: 1 }] } })).toBe('tighten');
    expect(revise({ spend: { rules: [{ id: 'shop', merchant: 'shop.example', max_per_day_cents: 4_000, max_per_payment_cents: 1_000 }] } })).toBe('tighten');
    expect(revise({ spend: { rules: [{ id: 'shop', merchant: 'shop.example', max_per_day_cents: 5_000, max_per_payment_cents: 1_000, max_per_month_cents: 9_000 }] } })).toBe('tighten');
  });

  it('removing a rule, raising or dropping a limit, or narrowing its scope loosens', () => {
    expect(revise({})).toBe('loosen');
    expect(revise({ spend: { rules: [{ id: 'shop', merchant: 'shop.example', max_per_day_cents: 6_000, max_per_payment_cents: 1_000 }] } })).toBe('loosen');
    expect(revise({ spend: { rules: [{ id: 'shop', merchant: 'shop.example', max_per_payment_cents: 1_000 }] } })).toBe('loosen');
    expect(revise({ spend: { rules: [{ id: 'shop', merchant: 'a.shop.example', max_per_day_cents: 5_000, max_per_payment_cents: 1_000 }] } })).toBe('loosen');
  });

  it('a wider rule with limits no higher still tightens, and a new id does not hide a loosening', () => {
    expect(revise({ spend: { rules: [{ id: 'all', max_per_day_cents: 5_000, max_per_payment_cents: 1_000 }] } })).toBe('tighten');
    expect(revise({ spend: { rules: [{ id: 'renamed', merchant: 'shop.example', max_per_day_cents: 9_000, max_per_payment_cents: 1_000 }] } })).toBe('loosen');
  });

  it('with a category rule in force the labels are frozen: a new label could move a merchant out of it', () => {
    const labelled = policy({ spend: { rules: [{ id: 'sw', category: 'software', max_per_day_cents: 100 }], categories: [{ merchant: 'a.example', category: 'software' }] } });
    const relabelled = policy({ spend: { rules: [{ id: 'sw', category: 'software', max_per_day_cents: 100 }], categories: [{ merchant: 'a.example', category: 'software' }, { merchant: 'b.example', category: 'travel' }] } });
    expect(classifyPolicyRevision(relabelled, labelled)).toBe('loosen');
    // With no category rule in force the labels constrain nothing yet.
    const noRules = policy({});
    expect(classifyPolicyRevision(policy({ spend: { categories: [{ merchant: 'b.example', category: 'travel' }] } }), noRules)).toBe('tighten');
  });
});

describe('chat approval limits', () => {
  it('are off until both are set', () => {
    expect(chatApprovalLimits(policy())).toBeNull();
    expect(chatApprovalLimits(policy({ review: { chat: { max_per_payment_cents: 1_000 } } }))).toBeNull();
    expect(chatApprovalLimits(policy({ review: { chat: { max_per_day_cents: 5_000 } } }))).toBeNull();
    expect(chatApprovalLimits(policy({ review: { chat: { max_per_payment_cents: 1_000, max_per_day_cents: 5_000 } } }))).toEqual({ perPaymentCents: 1_000, perDayCents: 5_000 });
  });

  it('turning them on or raising them is a loosening; off or lower is a tightening', () => {
    const off = policy();
    const on = policy({ review: { chat: { max_per_payment_cents: 1_000, max_per_day_cents: 5_000 } } });
    expect(classifyPolicyRevision(on, off)).toBe('loosen');
    expect(classifyPolicyRevision(off, on)).toBe('tighten');
    expect(classifyPolicyRevision(policy({ review: { chat: { max_per_payment_cents: 1_001, max_per_day_cents: 5_000 } } }), on)).toBe('loosen');
    expect(classifyPolicyRevision(policy({ review: { chat: { max_per_payment_cents: 900, max_per_day_cents: 5_000 } } }), on)).toBe('tighten');
    // Half a setting is off, so it is no wider than off.
    expect(classifyPolicyRevision(policy({ review: { chat: { max_per_payment_cents: 5 } } }), off)).toBe('tighten');
  });
});

describe('counter keys', () => {
  it('put a scope after the window key, and none leaves it as it was', () => {
    expect(scopedPeriodKey('2026-10-21', undefined)).toBe('2026-10-21');
    expect(scopedPeriodKey('2026-10-21', 'spend:shop')).toBe('2026-10-21@spend:shop');
  });
});
