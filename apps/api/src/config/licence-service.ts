import { readFileSync } from 'node:fs';
import {
  LICENCE_FEATURES,
  LICENCE_FEATURE_LABELS,
  LicenceRequiredError,
  licenceGrants,
  verifyLicence,
  type LicenceFeature,
  type LicenceState,
} from '@stack/shared';

/**
 * Which enterprise features this deployment has.
 *
 * STACK's hosted deployment gates them by plan, in the places that always did,
 * so its gate says yes to everything and changes nothing. A self-managed
 * install has no plans: its licence key decides. With no key, or an expired
 * one, the install keeps running with every enterprise feature off.
 */
export interface FeatureGate {
  /** Is the feature on right now? */
  has(feature: LicenceFeature): boolean;
  /** Throws `LicenceRequiredError` (402) when the feature is off. */
  require(feature: LicenceFeature): void;
  /** What an operator can read about the licence: never the key itself. */
  snapshot(): LicenceSnapshot;
  /** Check the key again every day; returns the function that stops it. */
  startDailyCheck(): () => void;
}

export interface LicenceSnapshot {
  mode: 'hosted' | 'self_managed';
  licence: LicenceState['status'];
  /** Why a key was refused, when it was. */
  reason?: string;
  customer?: string;
  issued_at?: string;
  expires_at?: string;
  features: LicenceFeature[];
  /** When the key was last read. */
  checked_at?: string;
}

/** The gate of STACK's hosted deployment: its plans decide, so this never refuses. */
export const hostedFeatureGate: FeatureGate = {
  has: () => true,
  require: () => {},
  snapshot: () => ({ mode: 'hosted', licence: 'valid', features: [...LICENCE_FEATURES] }),
  startDailyCheck: () => () => {},
};

export interface LicenceServiceOptions {
  /** Reads the key text now (the environment, or a file re-read so a renewed key is picked up). */
  readKey: () => string | undefined;
  trustedKeys?: Readonly<Record<string, string>>;
  now?: () => Date;
  log?: Pick<Console, 'log' | 'warn'>;
}

const DAY_MS = 24 * 60 * 60 * 1000;

export class LicenceService implements FeatureGate {
  private state: LicenceState = { status: 'none' };
  private checkedAt: Date | undefined;
  private lastLogged: string | undefined;
  private readonly now: () => Date;
  private readonly log: Pick<Console, 'log' | 'warn'>;

  constructor(private readonly options: LicenceServiceOptions) {
    this.now = options.now ?? (() => new Date());
    this.log = options.log ?? console;
  }

  /**
   * Read the key and check it. A key that cannot be read (a file that is
   * gone) is treated as no key: the install stays up with enterprise off,
   * and says so, rather than failing a boot or a day's check.
   */
  check(): LicenceState {
    let text: string | undefined;
    try {
      text = this.options.readKey();
    } catch {
      text = undefined;
      this.log.warn('[licence] The licence key could not be read; enterprise features are off.');
    }
    this.state = verifyLicence(text, {
      now: this.now(),
      ...(this.options.trustedKeys ? { trustedKeys: this.options.trustedKeys } : {}),
    });
    this.checkedAt = this.now();
    this.report();
    return this.state;
  }

  /** Check again every day, so a renewed key file is picked up and an expiry is announced. */
  startDailyCheck(): () => void {
    const timer = setInterval(() => this.check(), DAY_MS);
    timer.unref();
    return () => clearInterval(timer);
  }

  has(feature: LicenceFeature): boolean {
    // Expiry is read against the clock now, not the clock at the last check, so
    // a key stops granting on its expiry date even if the daily check is hours away.
    return licenceGrants(this.state, feature, this.now());
  }

  require(feature: LicenceFeature): void {
    if (this.has(feature)) return;
    const licence = this.state.status === 'valid' ? 'expired' : this.state.status;
    throw new LicenceRequiredError(LICENCE_FEATURE_LABELS[feature], { feature, licence });
  }

  snapshot(): LicenceSnapshot {
    const now = this.now();
    const base: LicenceSnapshot = {
      mode: 'self_managed',
      licence: this.state.status,
      features: LICENCE_FEATURES.filter((f) => licenceGrants(this.state, f, now)),
      ...(this.checkedAt ? { checked_at: this.checkedAt.toISOString() } : {}),
    };
    if (this.state.status === 'invalid') return { ...base, reason: this.state.reason };
    if (this.state.status === 'valid' || this.state.status === 'expired') {
      // A valid state whose date has since passed reads as expired.
      const expired = Date.parse(this.state.claims.expires_at) <= now.getTime();
      return {
        ...base,
        licence: expired ? 'expired' : this.state.status,
        customer: this.state.claims.customer,
        issued_at: this.state.claims.issued_at,
        expires_at: this.state.claims.expires_at,
      };
    }
    return base;
  }

  /** One line per change of state, so a log shows when a licence lapsed and not every day that it still has. */
  private report(): void {
    const s = this.snapshot();
    const line =
      s.licence === 'valid'
        ? `[licence] Licence for ${s.customer} is valid until ${s.expires_at}; features: ${s.features.join(', ') || 'none'}.`
        : s.licence === 'expired'
          ? `[licence] Licence for ${s.customer} expired ${s.expires_at}; enterprise features are off.`
          : s.licence === 'invalid'
            ? `[licence] The licence key was refused (${s.reason}); enterprise features are off.`
            : '[licence] No licence key; enterprise features are off.';
    if (line === this.lastLogged) return;
    this.lastLogged = line;
    if (s.licence === 'valid' || s.licence === 'none') this.log.log(line);
    else this.log.warn(line);
  }
}

/**
 * The licence key from the environment: `STACK_LICENCE_KEY`, or the file
 * `STACK_LICENCE_KEY_FILE` names (re-read on every check). Setting both is
 * refused: which one wins should not depend on read order.
 */
export function licenceKeyReaderFromEnv(
  env: Record<string, string | undefined>,
): () => string | undefined {
  const inline = env['STACK_LICENCE_KEY']?.trim();
  const file = env['STACK_LICENCE_KEY_FILE']?.trim();
  if (inline && file) {
    throw new Error('[BOOT] Set the licence key as STACK_LICENCE_KEY or STACK_LICENCE_KEY_FILE, not both');
  }
  if (file) return () => readFileSync(file, 'utf8');
  return () => inline;
}

/** A Fastify `onRequest` hook that refuses every request to its routes while the feature is off. */
export function requireFeatureHook(gate: FeatureGate, feature: LicenceFeature): () => Promise<void> {
  return async () => {
    gate.require(feature);
  };
}

/**
 * The gate for this process. It follows what the process runs, never what its environment says it is: the hosted
 * gate (it never refuses) belongs only to a process that has a hosted extension, whose plans decide; the engine alone
 * (no extension) always reads its licence key, whatever STACK_DEPLOYMENT holds, so a missing or wrong variable can
 * never switch the enterprise features on.
 */
export function createFeatureGate(
  hostedExtension: boolean,
  env: Record<string, string | undefined> = process.env,
): FeatureGate {
  if (hostedExtension) return hostedFeatureGate;
  const service = new LicenceService({ readKey: licenceKeyReaderFromEnv(env) });
  service.check();
  return service;
}
