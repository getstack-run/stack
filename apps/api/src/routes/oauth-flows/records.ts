import { createHash } from 'node:crypto';
import { generateId, safeErrorSummary } from '@stack/shared';
import type { Services } from '../../config/services.js';

// ─── Audit + security event helpers ──────────────────────────────────

export async function audit(services: Services, operatorId: string, action: string, payload: Record<string, unknown>) {
  try {
    await services.audit.write({
      ctx: {
        trace_id: generateId('trc', 16),
        span_id: generateId('spn', 16),
        operator_id: operatorId,
        agent_id: '-',
        passport_jti: '-',
      },
      layer: 'system',
      action,
      outcome: 'success',
      payload_hash: createHash('sha256').update(JSON.stringify(payload)).digest('hex'),
    });
  } catch (err) {
    // Audit must not block the OAuth response. Log + continue.
    console.error('[oauth] audit write failed', safeErrorSummary(err));
  }
}

export async function recordSecurityEvent(
  services: Services,
  operatorId: string,
  signalType: 'oauth_refresh_reuse' | 'oauth_invalid_pkce' | 'oauth_unknown_client' | 'oauth_redirect_uri_mismatch',
  severity: 'info' | 'warning' | 'critical',
  message: string,
  metadata: Record<string, unknown>,
) {
  try {
    await services.securityEvent.record({
      operatorId,
      agentId: 'oauth',
      signalType,
      severity,
      message,
      metadata,
    });
  } catch (err) {
    console.error('[oauth] security event record failed', safeErrorSummary(err));
  }
}
