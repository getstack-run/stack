const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const STACK_CI_DATABASE = /^\/stack_ci(?:_[a-zA-Z0-9_-]+)?$/;
// The throwaway container on 55433 hosts one database per parallel run: `stack`, or
// `stack_` and 1 to 32 lowercase letters, digits or underscores.
const STACK_THROWAWAY_DATABASE = /^\/stack(?:_[a-z0-9_]{1,32})?$/;

/** Refuse destructive or stateful test fixtures outside the reviewed local databases. */
export function isDedicatedStackTestDatabase(
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
  // postgres.js forwards query parameters as startup options. A URL such as
  // stack_ci?database=stack would otherwise pass this guard and connect to the
  // application database.
  if (parsed.search || parsed.hash) return false;

  return (
    (parsed.port === '5433' && STACK_CI_DATABASE.test(parsed.pathname)) ||
    (parsed.port === '5497' && parsed.pathname === '/stack_security_resume') ||
    (parsed.port === '55433' && STACK_THROWAWAY_DATABASE.test(parsed.pathname))
  );
}
