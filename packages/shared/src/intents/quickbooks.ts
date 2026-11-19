import { z } from 'zod';
import { defineIntent } from './types.js';

// Intuit QuickBooks Online API — https://developer.intuit.com/app/developer/qbo/docs/api/accounting.
// Base: quickbooks.api.intuit.com/v3/company/{realmId}/{resource}. Realm IDs
// are 15 to 20 digit identifiers that scope every call to a specific company
// file. Intents gate on method + realm + resource subpath.

const realmFmt = z
  .string()
  .min(8)
  .max(32)
  .regex(/^[0-9]+$/, 'realmId must be numeric');
const realmList = z.union([realmFmt, z.array(realmFmt).min(1)]);
type RealmList = z.infer<typeof realmList>;
const toList = (v: RealmList): string[] => (Array.isArray(v) ? v : [v]);

function realmPath(realm: RealmList, suffix: string) {
  const list = toList(realm);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches' as const,
    value: `^/v3/company/${alt}${suffix}$`,
  };
}

export const quickbooksIntents = [
  defineIntent({
    name: 'quickbooks.create_invoice',
    effect: 'write',
    description:
      'Create a new QuickBooks invoice for a specific company file. Binds POST /v3/company/{realmId}/invoice. Money-moving; scope realm and validate CustomerRef downstream.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/invoice'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.read_invoice',
    effect: 'read',
    description:
      'Read a QuickBooks invoice by ID. Binds GET /v3/company/{realmId}/invoice/{id}.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      realmPath(realm, '/invoice/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.send_invoice',
    effect: 'send',
    recipient_paths: ['query.sendTo'],
    description:
      'Email a QuickBooks invoice to its customer. Binds POST /v3/company/{realmId}/invoice/{id}/send.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/invoice/[^/]+/send'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.void_invoice',
    effect: 'write',
    description:
      'Void a QuickBooks invoice so it stops posting to the ledger. Binds POST /v3/company/{realmId}/invoice with operation=void in the query.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/invoice'),
      { path: 'query.operation', op: 'eq', value: 'void' },
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_customer',
    effect: 'write',
    description:
      'Create a QuickBooks customer. Binds POST /v3/company/{realmId}/customer.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/customer'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.read_customer',
    effect: 'read',
    description:
      'Read a QuickBooks customer by ID. Binds GET /v3/company/{realmId}/customer/{id}.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      realmPath(realm, '/customer/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_bill',
    effect: 'write',
    description:
      'Record a new supplier bill in QuickBooks. Binds POST /v3/company/{realmId}/bill. Money-moving once paid; keep realm tight.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/bill'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.pay_bill',
    effect: 'write',
    description:
      'Pay a previously recorded supplier bill. Binds POST /v3/company/{realmId}/billpayment. Money-moving, scope to a specific realm and amount allowlist.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/billpayment'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_expense',
    effect: 'write',
    description:
      'Record an expense (Purchase) in QuickBooks. Binds POST /v3/company/{realmId}/purchase.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/purchase'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_payment',
    effect: 'write',
    description:
      'Record a customer payment against invoices. Binds POST /v3/company/{realmId}/payment. Money-moving; pair with amount cap.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/payment'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_estimate',
    effect: 'write',
    description:
      'Create a QuickBooks estimate (quote). Binds POST /v3/company/{realmId}/estimate.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/estimate'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_credit_memo',
    effect: 'write',
    description:
      'Create a QuickBooks credit memo to offset a customer balance. Binds POST /v3/company/{realmId}/creditmemo.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/creditmemo'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_vendor',
    effect: 'write',
    description:
      'Create a QuickBooks vendor record. Binds POST /v3/company/{realmId}/vendor.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/vendor'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.read_accounts',
    effect: 'read',
    description:
      'Read the chart of accounts via query. Binds GET /v3/company/{realmId}/query.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      realmPath(realm, '/query'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_journal_entry',
    effect: 'write',
    description:
      'Post a journal entry to the ledger. Binds POST /v3/company/{realmId}/journalentry. Directly mutates books; restrict realm and reviewer workflow.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/journalentry'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.create_item',
    effect: 'write',
    description:
      'Create a product or service item in QuickBooks. Binds POST /v3/company/{realmId}/item.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      realmPath(realm, '/item'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.run_report',
    effect: 'read',
    description:
      'Run a QuickBooks report (ProfitAndLoss, BalanceSheet, etc.). Binds GET /v3/company/{realmId}/reports/{reportName}.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      realmPath(realm, '/reports/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'quickbooks.query',
    effect: 'read',
    description:
      'Execute a SQL-like query against the QuickBooks company file. Binds GET /v3/company/{realmId}/query.',
    params: z.object({ realm: realmList }),
    expand: ({ realm }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      realmPath(realm, '/query'),
    ],
  }),
];
