const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const STACK_CI_DATABASE = /^\/stack_ci(?:_[a-zA-Z0-9_-]+)?$/;
// The throwaway container on 55433 hosts one database per parallel run: `stack`, or
// `stack_` and 1 to 32 lowercase letters, digits or underscores.
const STACK_THROWAWAY_DATABASE = /^\/stack(?:_[a-z0-9_]{1,32})?$/;

/** Refuse destructive or stateful Vault test fixtures outside reviewed local databases. */
export function isDedicatedVaultTestDatabase(
  databaseUrl: string | undefined,
): databaseUrl is string {
  if (!databaseUrl) return false;

  let parsed: URL;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    return false;
  }

  if (!['postgres:', 'postgresql:'].includes(parsed.protocol)) return false;
  if (!LOOPBACK_HOSTS.has(parsed.hostname)) return false;
  // postgres.js forwards query parameters as startup options, including a
  // database override. Dedicated fixtures reject every startup override.
  if (parsed.search || parsed.hash) return false;

  return (
    (parsed.port === '5433' && STACK_CI_DATABASE.test(parsed.pathname)) ||
    (parsed.port === '5497' && parsed.pathname === '/stack_security_resume') ||
    (parsed.port === '55433' && STACK_THROWAWAY_DATABASE.test(parsed.pathname))
  );
}

/**
 * The database a Vault fixture may write to: the dedicated one above, or a
 * throwaway loopback database named explicitly in STACK_TEST_DATABASE_URL. The
 * explicit form never accepts the development ports 5432 and 5433, so a
 * developer's own database cannot be selected by a stray variable.
 */
export function resolveVaultFixtureDatabaseUrl(env: Record<string, string | undefined> = process.env): string | undefined {
  if (isDedicatedVaultTestDatabase(env['DATABASE_URL'])) return env['DATABASE_URL'];
  const explicit = env['STACK_TEST_DATABASE_URL'];
  if (!explicit) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(explicit);
  } catch {
    return undefined;
  }
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol)) return undefined;
  if (!LOOPBACK_HOSTS.has(parsed.hostname) || parsed.search || parsed.hash) return undefined;
  if (!parsed.port || parsed.port === '5432' || parsed.port === '5433') return undefined;
  return explicit;
}
