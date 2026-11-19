import type { Database } from '@stack/shared';
import {
  EmailChangeService,
  GovernanceApprovalService,
  GovernanceApprovalRepository,
  type AuditService,
  type GovernanceActionPreviews,
  type NotificationService,
  type EmailSender,
} from '@stack/vault';
import { env } from '../env.js';
import type { RedisClient } from './infra.js';

export interface AccountSecurityServices {
  /** Transferring the address an account signs in with. */
  emailChange: EmailChangeService;
  /**
   * Operate-vs-govern step-up: pending/approve/consume for the four gated
   * governance actions. Decide is dashboard-session-only.
   */
  governanceApprovals: GovernanceApprovalService;
}

export function createAccountSecurityServices(deps: {
  db: Database;
  redis: RedisClient;
  audit: AuditService;
  notification: NotificationService;
  /** Account-security emails are not marketing and must send. */
  accountEmail: EmailSender | null;
  /** The governance actions the deployment adds to the engine's. */
  actions: GovernanceActionPreviews;
}): AccountSecurityServices {
  const { db, redis, audit, notification, accountEmail, actions } = deps;
  const emailChange = new EmailChangeService({
    db,
    email: accountEmail,
    rateLimitStore: redis,
    audit,
    dashboardUrl: env.DASHBOARD_URL,
  });
  // The notification push carries the dashboard approvals URL; it degrades
  // silently without channels.
  const governanceApprovals = new GovernanceApprovalService({
    repo: new GovernanceApprovalRepository(db),
    notification,
    dashboardUrl: env.DASHBOARD_URL,
    actions,
  });
  return { emailChange, governanceApprovals };
}
