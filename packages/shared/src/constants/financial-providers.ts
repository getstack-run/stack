// Catalog providers whose responses carry money and bank identifiers.
//
// WHY THIS EXISTS. The data-flow rule matches content an agent read from one
// service against what it later sends to another. A bank balance such as
// `12345.67` is invisible to the generic entity catalogue (it is not an
// email, URL or id), and it rarely survives as an eight-word verbatim run
// once an agent writes it into a sentence, so a balance read from Mercury
// and posted to a Slack channel would slip through both tiers. Money amounts
// recognised as entities, but ONLY on content read from a provider listed
// here: recognising every four-digit number from every service would turn
// ordinary counts and ids into "money" and refuse ordinary work.
//
// WHY A CATALOG CATEGORY AND NOT A PER-CONNECTION FLAG. This is the least
// invasive correct tag: the category is a property of the provider (Mercury
// is a bank whoever connects it), it needs no migration, no operator action
// and no UI, and it cannot be switched off by a compromised operator key.
// A per-connection flag would add a new mutable security setting with its
// own authorization question. The cost is that a custom provider
// (`custom_*`) cannot opt in today.
//
// PROVENANCE. The list is the "Payments & Finance" section of the service
// catalog seed, plus `gusto` (payroll, which carries salaries and bank accounts).
// Keep it in step with that section when a provider is added there.

export const FINANCIAL_PROVIDERS: ReadonlySet<string> = new Set([
  'stripe',
  'plaid',
  'quickbooks',
  'xero',
  'paypal',
  'square',
  'brex',
  'mercury',
  'ramp',
  'wise',
  'coinbase',
  'gusto',
]);

/** True when content read from this provider may carry money amounts and account numbers. */
export function isFinancialProvider(provider: string | null | undefined): boolean {
  return typeof provider === 'string' && FINANCIAL_PROVIDERS.has(provider.toLowerCase());
}
