import { reconnectMessage, safeErrorSummary } from '@stack/shared';
import type {
  AuditService,
  NotificationService,
  ReconnectRequiredHandler,
} from '@stack/vault';

/** Map audit actions to notification severity levels. */
export function getEventSeverity(action: string): 'info' | 'warning' | 'critical' {
  const CRITICAL = new Set([
    'passport.revoke_agent',
    'passport.revoke_all',
    'agent.delete',
    'operator.delete',
    'skill.suspend',
    'skill.reject',
  ]);
  const WARNING = new Set([
    'passport.revoke',
    'passport.revoke_session',
    'passport.review_decide',
    'agent.unblock',
    'service.disconnect',
    'service.revoke',
    'oauth_app.delete',
    'dropoff.expire',
    'member.revoke',
    'identity.claim.revoke',
  ]);
  if (CRITICAL.has(action)) return 'critical';
  if (WARNING.has(action)) return 'warning';
  return 'info';
}

/**
 * Audit → notification dispatch. Fire-and-forget: every successful audit event
 * triggers notification matching against the operator's configured channels.
 */
export function bridgeAuditToNotifications(
  audit: AuditService,
  notification: NotificationService,
): void {
  audit.onWrite((operatorId, action, _outcome, agentId) => {
    const severity = getEventSeverity(action);
    notification
      .publishEvent({
        operatorId,
        eventType: action,
        severity,
        payload: { agent_id: agentId || undefined },
      })
      .catch((err) => {
        console.error('[NOTIFICATION] Dispatch failed:', safeErrorSummary(err));
      });
  });
}

/** Tells the operator a stored credential needs to be reconnected. */
export function createReconnectNotifier(
  notification: NotificationService,
): ReconnectRequiredHandler {
  return async (event) => {
    await notification.publishEvent({
      operatorId: event.operatorId,
      eventType: 'security.credential_reconnect_required',
      severity: 'warning',
      payload: {
        event_id: event.eventId,
        connection_id: event.connectionId,
        provider: event.provider,
        message: reconnectMessage(event.reason),
        ...(event.reason ? { reason: event.reason } : {}),
        status: 'reconnect_required',
        action: 'reconnect',
        action_path: '/services',
        credential_version: event.credentialVersion,
      },
    });
  };
}
