// The control socket's configuration: who decides for a customer, the decision
// and events addresses, their signing secrets and which action kinds are
// checked. One socket per customer.
//
// Secrets: a signing secret is created here, shown to the customer once by the
// caller, and stored only KMS-encrypted under {operator_id, socket_id,
// purpose}. A rotation keeps the previous secret verifying for 24 hours, and
// STACK signs with both while it does.
//
// The hot path (every checked action) reads `runtime()` and, for a remote
// decider, `decisionSecrets()`. Both are cached in process and invalidated on
// every write here and, across machines, over one Redis channel; the cache
// also expires on its own, so a missed message heals within a minute.

import {
  CONTROL_ACTION_TYPES,
  CONTROL_DECISION_TIMEOUT_DEFAULT_MS,
  CONTROL_SECRET_ROTATION_GRACE_MS,
  generateWebhookSecret,
  type ControlActionType,
  type ControlOnUnavailable,
  type ControlDecider,
  type ControlModeSetting,
  type ControlSocketRow,
  type ControlSocketView,
} from '@stack/shared';
import type { KmsService } from '../../crypto/kms.js';
import type { ControlSocketRepository, OutboxCounts } from '../../repositories/control-socket-repo.js';

/** What the hot path needs to decide, with no secrets. */
export interface ControlSocketRuntime {
  socketId: string | null;
  modeSetting: ControlModeSetting;
  decisionUrl: string | null;
  decisionStatus: 'unverified' | 'enforcing' | 'paused';
  timeoutMs: number;
  /** What happens when the customer's own server does not answer in time. */
  onUnavailable: ControlOnUnavailable;
  /** Null checks every action kind. */
  checkedTypes: ReadonlySet<ControlActionType> | null;
}

export const CONTROL_SOCKET_CACHE_TTL_MS = 30_000;
/** A decision address is paused after this many answers in a row that failed their signature check. */
export const CONTROL_BAD_ANSWER_PAUSE = 50;

const NO_SOCKET: ControlSocketRuntime = {
  socketId: null,
  modeSetting: 'auto',
  decisionUrl: null,
  decisionStatus: 'unverified',
  timeoutMs: CONTROL_DECISION_TIMEOUT_DEFAULT_MS,
  onUnavailable: 'refuse',
  checkedTypes: null,
};

export type SecretPurpose = 'decision' | 'events';

export interface ControlSocketServiceDeps {
  repo: ControlSocketRepository;
  kms: Pick<KmsService, 'encrypt' | 'decrypt'>;
  /** Tell the other machines to drop their cached view of this customer's socket. */
  publishInvalidation?: (operatorId: string) => Promise<void>;
  now?: () => number;
}

function kmsContext(operatorId: string, socketId: string, purpose: SecretPurpose): Record<string, string> {
  return { operator_id: operatorId, socket_id: socketId, purpose: `control_socket_${purpose}` };
}

function knownTypes(types: readonly string[] | null): ReadonlySet<ControlActionType> | null {
  if (types === null) return null;
  const known = new Set<string>(CONTROL_ACTION_TYPES);
  return new Set(types.filter((t): t is ControlActionType => known.has(t)));
}

export class ControlSocketService {
  private readonly runtimeCache = new Map<string, { at: number; value: ControlSocketRuntime }>();
  private readonly secretCache = new Map<string, { at: number; value: string[] | null }>();
  private readonly invalidationListeners = new Set<(operatorId: string) => void>();
  private readonly now: () => number;

  constructor(private readonly deps: ControlSocketServiceDeps) {
    this.now = deps.now ?? Date.now;
  }

  /** For a component that caches something derived from a customer's socket (the audit outbox sink). */
  onInvalidate(listener: (operatorId: string) => void): void {
    this.invalidationListeners.add(listener);
  }

  /** Drop this machine's cached view of one customer's socket. */
  invalidateLocal(operatorId: string): void {
    this.runtimeCache.delete(operatorId);
    this.secretCache.delete(`${operatorId}:decision`);
    this.secretCache.delete(`${operatorId}:events`);
    for (const listener of this.invalidationListeners) listener(operatorId);
  }

  /** Drop every machine's cached view of one customer's socket (this one at once, the others over Redis). */
  async invalidate(operatorId: string): Promise<void> {
    this.invalidateLocal(operatorId);
    try {
      await this.deps.publishInvalidation?.(operatorId);
    } catch {
      // The other machines' caches expire on their own within CONTROL_SOCKET_CACHE_TTL_MS.
    }
  }

  // ─── reads ──────────────────────────────────────────────────────

  async runtime(operatorId: string): Promise<ControlSocketRuntime> {
    const hit = this.runtimeCache.get(operatorId);
    if (hit && this.now() - hit.at < CONTROL_SOCKET_CACHE_TTL_MS) return hit.value;
    const row = await this.deps.repo.get(operatorId);
    const value = row ? this.toRuntime(row) : NO_SOCKET;
    this.runtimeCache.set(operatorId, { at: this.now(), value });
    return value;
  }

  private toRuntime(row: ControlSocketRow): ControlSocketRuntime {
    return {
      socketId: row.socket_id,
      modeSetting: row.decision_mode as ControlModeSetting,
      decisionUrl: row.decision_url,
      decisionStatus: row.decision_status as ControlSocketRuntime['decisionStatus'],
      timeoutMs: row.decision_timeout_ms,
      onUnavailable: row.decision_on_unavailable === 'allow' ? 'allow' : 'refuse',
      checkedTypes: knownTypes(row.checked_types),
    };
  }

  /**
   * The signing secrets that are live for one address: the current one, and the
   * previous one for 24 hours after a rotation. Null when none is set. Never
   * logged, never returned by an API.
   */
  async secrets(operatorId: string, purpose: SecretPurpose): Promise<string[] | null> {
    const key = `${operatorId}:${purpose}`;
    const hit = this.secretCache.get(key);
    if (hit && this.now() - hit.at < CONTROL_SOCKET_CACHE_TTL_MS) return hit.value;
    const row = await this.deps.repo.get(operatorId);
    const value = row ? await this.decryptLive(row, purpose) : null;
    this.secretCache.set(key, { at: this.now(), value });
    return value;
  }

  private async decryptLive(row: ControlSocketRow, purpose: SecretPurpose): Promise<string[] | null> {
    const current = purpose === 'decision' ? row.decision_secret_encrypted : row.events_secret_encrypted;
    if (!current) return null;
    const previous = purpose === 'decision' ? row.decision_secret_previous_encrypted : row.events_secret_previous_encrypted;
    const rotatedAt = purpose === 'decision' ? row.decision_secret_rotated_at : row.events_secret_rotated_at;
    const context = kmsContext(row.operator_id, row.socket_id, purpose);
    const live = [await this.deps.kms.decrypt(current, context)];
    if (previous && rotatedAt && this.now() - rotatedAt.getTime() < CONTROL_SECRET_ROTATION_GRACE_MS) {
      live.push(await this.deps.kms.decrypt(previous, context));
    }
    return live;
  }

  /** The customer's row as the API shows it. `controlsEnabled` is read by the caller from the one controls decision. */
  async view(operatorId: string, controlsEnabled: boolean): Promise<ControlSocketView> {
    const row = await this.deps.repo.get(operatorId);
    const counts: OutboxCounts = row ? await this.deps.repo.outboxCounts(operatorId) : { pending: 0, dead: 0 };
    const modeSetting = (row?.decision_mode ?? 'auto') as ControlModeSetting;
    const checked = knownTypes(row?.checked_types ?? null);
    return {
      socket_id: row?.socket_id ?? null,
      mode_setting: modeSetting,
      effective_mode: effectiveDecider(modeSetting, controlsEnabled),
      controls_enabled: controlsEnabled,
      decision: {
        url: row?.decision_url ?? null,
        pending_url: row?.decision_candidate_url ?? null,
        status: (row?.decision_status ?? 'unverified') as 'unverified' | 'enforcing' | 'paused',
        verified_at: row?.decision_verified_at?.toISOString() ?? null,
        secret_set: Boolean(row?.decision_secret_encrypted),
        secret_rotated_at: row?.decision_secret_rotated_at?.toISOString() ?? null,
        timeout_ms: row?.decision_timeout_ms ?? CONTROL_DECISION_TIMEOUT_DEFAULT_MS,
        on_unavailable: row?.decision_on_unavailable === 'allow' ? 'allow' : 'refuse',
      },
      events: {
        url: row?.events_url ?? null,
        pending_url: null,
        status: (row?.events_status ?? 'off') as 'off' | 'unverified' | 'active' | 'failing',
        verified_at: row?.events_verified_at?.toISOString() ?? null,
        secret_set: Boolean(row?.events_secret_encrypted),
        secret_rotated_at: row?.events_secret_rotated_at?.toISOString() ?? null,
        last_acknowledged_seq: row?.events_acked_seq ?? 0,
        pending_events: counts.pending,
        dead_events: counts.dead,
        last_error: row?.events_last_error ?? null,
      },
      checked_types: [...(checked ?? CONTROL_ACTION_TYPES)],
      checks_all_types: checked === null,
    };
  }

  // ─── the decision address ───────────────────────────────────────

  /**
   * Store a decision address. The first call creates the signing secret and
   * returns it, once. While the socket is enforcing, the new address waits as
   * a candidate and the current one keeps deciding until the candidate is
   * verified, so changing an address never leaves the customer without one.
   */
  async setDecisionAddress(
    operatorId: string,
    input: { url: string; timeoutMs?: number },
  ): Promise<{ secret: string | null }> {
    const row = await this.deps.repo.getOrCreate(operatorId);
    let secret: string | null = null;
    let encrypted = row.decision_secret_encrypted;
    if (!encrypted) {
      secret = generateWebhookSecret();
      encrypted = (await this.deps.kms.encrypt(secret, kmsContext(operatorId, row.socket_id, 'decision'))).ciphertext;
    }
    const timeoutMs = input.timeoutMs ?? row.decision_timeout_ms;
    if (row.decision_mode === 'remote') {
      await this.deps.repo.update(operatorId, {
        decision_candidate_url: input.url,
        decision_candidate_timeout_ms: timeoutMs,
        decision_secret_encrypted: encrypted,
      });
    } else {
      await this.deps.repo.update(operatorId, {
        decision_url: input.url,
        decision_candidate_url: null,
        decision_candidate_timeout_ms: null,
        decision_timeout_ms: timeoutMs,
        decision_secret_encrypted: encrypted,
        decision_status: 'unverified',
        decision_verified_at: null,
      });
    }
    await this.invalidate(operatorId);
    return { secret };
  }

  /** The address a verify call should challenge: the candidate if there is one, else the stored address. */
  async addressToVerify(operatorId: string): Promise<{ url: string; timeoutMs: number } | null> {
    const row = await this.deps.repo.get(operatorId);
    if (!row) return null;
    if (row.decision_candidate_url) {
      return { url: row.decision_candidate_url, timeoutMs: row.decision_candidate_timeout_ms ?? row.decision_timeout_ms };
    }
    return row.decision_url ? { url: row.decision_url, timeoutMs: row.decision_timeout_ms } : null;
  }

  /** The address passed its setup check: make it the one that decides. */
  async activateDecision(operatorId: string): Promise<void> {
    const row = await this.deps.repo.get(operatorId);
    if (!row) throw new Error('No control socket to activate');
    await this.deps.repo.update(operatorId, {
      decision_url: row.decision_candidate_url ?? row.decision_url,
      decision_timeout_ms: row.decision_candidate_timeout_ms ?? row.decision_timeout_ms,
      decision_candidate_url: null,
      decision_candidate_timeout_ms: null,
      decision_mode: 'remote',
      decision_status: 'enforcing',
      decision_verified_at: new Date(this.now()),
      decision_bad_answers: 0,
    });
    await this.invalidate(operatorId);
  }

  /** Remove the decision address and its secret. The customer falls back to the automatic choice. */
  async clearDecision(operatorId: string): Promise<void> {
    const row = await this.deps.repo.get(operatorId);
    if (!row) return;
    await this.deps.repo.update(operatorId, {
      decision_mode: row.decision_mode === 'remote' ? 'auto' : row.decision_mode,
      decision_url: null,
      decision_candidate_url: null,
      decision_candidate_timeout_ms: null,
      decision_secret_encrypted: null,
      decision_secret_previous_encrypted: null,
      decision_secret_rotated_at: null,
      decision_status: 'unverified',
      decision_verified_at: null,
      decision_bad_answers: 0,
    });
    await this.invalidate(operatorId);
  }

  /** Switch to STACK's hosted checks or to none. Leaving a remote socket leaves its address unverified. */
  async setMode(operatorId: string, mode: 'none' | 'hosted'): Promise<void> {
    const row = await this.deps.repo.getOrCreate(operatorId);
    await this.deps.repo.update(operatorId, {
      decision_mode: mode,
      ...(row.decision_mode === 'remote' ? { decision_status: 'unverified' as const, decision_verified_at: null } : {}),
    });
    await this.invalidate(operatorId);
  }

  /** What happens when the customer's own server does not answer in time. The caller has done the step-up for `allow`. */
  async setOnUnavailable(operatorId: string, value: ControlOnUnavailable): Promise<void> {
    await this.deps.repo.getOrCreate(operatorId);
    await this.deps.repo.update(operatorId, { decision_on_unavailable: value });
    await this.invalidate(operatorId);
  }

  /** `null` checks every kind. */
  async setCheckedTypes(operatorId: string, types: readonly ControlActionType[] | null): Promise<void> {
    await this.deps.repo.getOrCreate(operatorId);
    await this.deps.repo.update(operatorId, { checked_types: types === null ? null : [...new Set(types)] });
    await this.invalidate(operatorId);
  }

  /** One answer in a row, good or bad. At 50 bad ones the address pauses (and refuses) until verified again. */
  async noteAnswer(operatorId: string, good: boolean): Promise<void> {
    const count = await this.deps.repo.countBadAnswer(operatorId, good);
    if (!good && count >= CONTROL_BAD_ANSWER_PAUSE) {
      await this.deps.repo.update(operatorId, { decision_status: 'paused' });
      await this.invalidate(operatorId);
    }
  }

  // ─── the events address ─────────────────────────────────────────

  async setEventsAddress(operatorId: string, url: string): Promise<{ secret: string | null }> {
    const row = await this.deps.repo.getOrCreate(operatorId);
    let secret: string | null = null;
    let encrypted = row.events_secret_encrypted;
    if (!encrypted) {
      secret = generateWebhookSecret();
      encrypted = (await this.deps.kms.encrypt(secret, kmsContext(operatorId, row.socket_id, 'events'))).ciphertext;
    }
    await this.deps.repo.update(operatorId, {
      events_url: url,
      events_secret_encrypted: encrypted,
      events_status: 'unverified',
      events_verified_at: null,
      events_attempts: 0,
      events_client_errors: 0,
      events_first_failure_at: null,
      events_next_attempt_at: null,
      events_last_error: null,
    });
    await this.invalidate(operatorId);
    return { secret };
  }

  /**
   * The events address passed its setup check: delivery starts. What a paused
   * address skipped is announced to the receiver by one gap marker.
   */
  async activateEvents(operatorId: string): Promise<void> {
    await this.deps.repo.activateEvents(operatorId, {
      events_status: 'active',
      events_verified_at: new Date(this.now()),
      events_attempts: 0,
      events_client_errors: 0,
      events_first_failure_at: null,
      events_next_attempt_at: null,
      events_last_error: null,
    });
    await this.invalidate(operatorId);
  }

  async clearEvents(operatorId: string): Promise<void> {
    const row = await this.deps.repo.get(operatorId);
    if (!row) return;
    await this.deps.repo.update(operatorId, {
      events_url: null,
      events_secret_encrypted: null,
      events_secret_previous_encrypted: null,
      events_secret_rotated_at: null,
      events_status: 'off',
      events_verified_at: null,
      events_acked_seq: row.events_last_seq,
      events_attempts: 0,
      events_client_errors: 0,
      events_first_failure_at: null,
      events_next_attempt_at: null,
      events_last_error: null,
    });
    // Nothing is left to deliver to an address that is gone.
    await this.deps.repo.clearOutbox(operatorId);
    await this.invalidate(operatorId);
  }

  // ─── rotation ───────────────────────────────────────────────────

  /** A fresh secret, shown once. The previous one keeps verifying for 24 hours. */
  async rotateSecret(operatorId: string, purpose: SecretPurpose): Promise<{ secret: string; previousValidUntil: Date }> {
    const row = await this.deps.repo.get(operatorId);
    const current = row && (purpose === 'decision' ? row.decision_secret_encrypted : row.events_secret_encrypted);
    if (!row || !current) throw new Error('No signing secret to rotate');
    const secret = generateWebhookSecret();
    const ciphertext = (await this.deps.kms.encrypt(secret, kmsContext(operatorId, row.socket_id, purpose))).ciphertext;
    const rotatedAt = new Date(this.now());
    await this.deps.repo.update(
      operatorId,
      purpose === 'decision'
        ? { decision_secret_previous_encrypted: current, decision_secret_encrypted: ciphertext, decision_secret_rotated_at: rotatedAt }
        : { events_secret_previous_encrypted: current, events_secret_encrypted: ciphertext, events_secret_rotated_at: rotatedAt },
    );
    await this.invalidate(operatorId);
    return { secret, previousValidUntil: new Date(rotatedAt.getTime() + CONTROL_SECRET_ROTATION_GRACE_MS) };
  }
}

/**
 * Who decides, from what the customer chose and whether their hosted controls
 * are on. A remote socket that is paused still answers as `remote` (and
 * refuses): a configured broken socket never falls back to no controls.
 */
export function effectiveDecider(modeSetting: ControlModeSetting, controlsEnabled: boolean): ControlDecider {
  if (modeSetting === 'remote') return 'remote';
  if (modeSetting === 'none') return 'none';
  return controlsEnabled ? 'hosted' : 'none';
}
