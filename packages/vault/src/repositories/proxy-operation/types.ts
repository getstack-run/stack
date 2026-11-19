// Row, result and input types for the proxy operation ledger, plus its capacity limits.
// Re-exported from proxy-operation-repo.ts, which stays the import path for every other package.

import {
  type Database,
  proxyAccountingReceipts,
  proxyOperationReplacementAcknowledgements,
  proxyOperations,
} from '@stack/shared';

export type ProxyOperationTransaction = Parameters<Parameters<Database['transaction']>[0]>[0];
export type ProxyOperationRow = typeof proxyOperations.$inferSelect;
export type ProxyOperationInsert = typeof proxyOperations.$inferInsert;
export type ProxyPostResponseStep =
  | 'credential'
  | 'audit'
  | 'claims'
  | 'security'
  | 'analytics'
  | 'authority';
export type ProxyOperationReplacementAcknowledgement =
  typeof proxyOperationReplacementAcknowledgements.$inferSelect;

export const PROXY_NONTERMINAL_LIMIT = 1_000;
export const PROXY_REPLAY_CAPACITY_BYTES = 256 * 1024 * 1024;

export type DbHandle = Database | ProxyOperationTransaction;

export type InsertAdmittedResult =
  | { state: 'created' | 'existing'; operation: ProxyOperationRow }
  | { state: 'capacity_exceeded'; kind: 'nonterminal'; limit: number; used: number };

export type DispatchClaimResult =
  | { state: 'acquired'; operation: ProxyOperationRow; dispatchFence: number }
  | { state: 'replay' | 'busy' | 'outcome_unknown'; operation: ProxyOperationRow }
  | { state: 'capacity_exceeded'; kind: 'replay_bytes'; limit: number; used: number };

export type ProxyAccountingReceipt = typeof proxyAccountingReceipts.$inferSelect;
export interface ProxyAccountingProjection {
  operatorId: string;
  accountingPeriod: string;
  evaluatedUnits: number;
  overageUnits10000thCent: number;
  committedCents: number;
  updatedAt: Date;
}

export interface FencedDispatch {
  operatorId: string;
  operationId: string;
  dispatchOwnerHash: string;
  dispatchFence: number;
}
