import { probeObjectStore, type ArchiveStoreProbeResult } from '@stack/vault';
import type { Services } from './services.js';

/** How often each API machine asks the audit object store whether it is usable. */
export const ARCHIVE_STORE_PROBE_INTERVAL_MS = 10 * 60_000;

/**
 * HeadBucket on the audit object store, once at boot and every ten minutes.
 * The API reads the store for audit exports, evidence packs and account
 * erasure, so an unusable bucket (a wrong name, credentials that may not use
 * it) fails those calls with 503; this makes that visible to platform staff in
 * the admin health view before a customer's export finds it. `probeObjectStore`
 * never throws and records only a fixed reason, never the provider's text.
 */
export function startArchiveStoreProbe(
  services: Pick<Services, 'auditObjectStore' | 'redis'>,
  /** Told each verdict, for the deployment's record of it. Must not throw. */
  onResult?: (result: ArchiveStoreProbeResult) => void,
): () => void {
  const probe = () =>
    void probeObjectStore({ store: services.auditObjectStore, redis: services.redis, site: 'api' }).then((result) => {
      try {
        onResult?.(result);
      } catch {
        // A record of the verdict never changes the verdict.
      }
    });
  probe();
  const timer = setInterval(probe, ARCHIVE_STORE_PROBE_INTERVAL_MS);
  timer.unref();
  return () => clearInterval(timer);
}
