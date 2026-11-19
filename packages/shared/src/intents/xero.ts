import { z } from 'zod';
import { defineIntent } from './types.js';

// Xero Accounting API — https://developer.xero.com/documentation/api/accounting.
// Base: api.xero.com/api.xro/2.0/{resource}. Tenant is selected via the
// xero-tenant-id header on every request. Intents gate on method + path;
// tenant allowlist should be enforced as a raw header constraint alongside.

const tenantFmt = z
  .string()
  .min(8)
  .max(64)
  .regex(/^[0-9a-fA-F-]+$/, 'tenantId must be a UUID');
const tenantList = z.union([tenantFmt, z.array(tenantFmt).min(1)]);
type TenantList = z.infer<typeof tenantList>;
const toList = (v: TenantList): string[] => (Array.isArray(v) ? v : [v]);

function tenantHeader(tenant: TenantList) {
  const list = toList(tenant);
  return list.length === 1
    ? { path: 'headers.xero-tenant-id', op: 'eq' as const, value: list[0]! }
    : { path: 'headers.xero-tenant-id', op: 'in' as const, value: list };
}

export const xeroIntents = [
  defineIntent({
    name: 'xero.create_invoice',
    effect: 'write',
    description:
      'Create a sales invoice in a specific Xero tenant. Binds POST /api.xro/2.0/Invoices to the allowlisted xero-tenant-id header.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/Invoices' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.read_invoices',
    effect: 'read',
    description:
      'List or read invoices from a Xero tenant. Binds GET /api.xro/2.0/Invoices and /api.xro/2.0/Invoices/{id}.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api.xro/2.0/Invoices(/[^/]+)?$' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.update_invoice',
    effect: 'write',
    description:
      'Update a Xero invoice (including marking as voided via Status). Binds POST /api.xro/2.0/Invoices/{id}.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api.xro/2.0/Invoices/[^/]+$' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.email_invoice',
    effect: 'send',
    description:
      'Email a Xero invoice to its contact. Binds POST /api.xro/2.0/Invoices/{id}/Email.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/api.xro/2.0/Invoices/[^/]+/Email$' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.create_contact',
    effect: 'write',
    description:
      'Create a Xero contact (customer or supplier). Binds POST /api.xro/2.0/Contacts.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/Contacts' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.read_contacts',
    effect: 'read',
    description:
      'List or read Xero contacts. Binds GET /api.xro/2.0/Contacts and /api.xro/2.0/Contacts/{id}.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api.xro/2.0/Contacts(/[^/]+)?$' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.read_accounts',
    effect: 'read',
    description:
      'Read the Xero chart of accounts. Binds GET /api.xro/2.0/Accounts.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/Accounts' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.create_bank_transaction',
    effect: 'write',
    description:
      'Record a spend or receive transaction against a bank account. Binds POST /api.xro/2.0/BankTransactions. Money-moving to the books.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/BankTransactions' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.create_bank_transfer',
    effect: 'write',
    description:
      'Transfer funds between Xero bank accounts. Binds PUT /api.xro/2.0/BankTransfers. Money-moving, scope tenant tightly.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/BankTransfers' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.create_credit_note',
    effect: 'write',
    description:
      'Create a credit note to offset a customer or supplier balance. Binds POST /api.xro/2.0/CreditNotes.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/CreditNotes' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.create_payment',
    effect: 'write',
    description:
      'Apply a payment against an invoice or credit note. Binds PUT /api.xro/2.0/Payments. Money-moving; pair with amount cap.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/Payments' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.create_purchase_order',
    effect: 'write',
    description:
      'Create a purchase order in Xero. Binds POST /api.xro/2.0/PurchaseOrders.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/PurchaseOrders' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.create_quote',
    effect: 'write',
    description:
      'Create a Xero quote for a contact. Binds POST /api.xro/2.0/Quotes.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/Quotes' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.create_manual_journal',
    effect: 'write',
    description:
      'Post a manual journal to the Xero ledger. Binds PUT /api.xro/2.0/ManualJournals. Mutates books directly.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/ManualJournals' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.read_items',
    effect: 'read',
    description:
      'Read the Xero product/service item list. Binds GET /api.xro/2.0/Items.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/api.xro/2.0/Items' },
      tenantHeader(tenant),
    ],
  }),

  defineIntent({
    name: 'xero.run_report',
    effect: 'read',
    description:
      'Run a Xero report (ProfitAndLoss, BalanceSheet, TrialBalance, etc.). Binds GET /api.xro/2.0/Reports/{reportName}.',
    params: z.object({ tenant: tenantList }),
    expand: ({ tenant }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/api.xro/2.0/Reports/[^/]+$' },
      tenantHeader(tenant),
    ],
  }),
];
