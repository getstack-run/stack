/**
 * Whether this deployment is a staging copy, and who may get into it.
 *
 * A staging deployment (`STACK_STAGING=true`) runs STACK's own code with test
 * accounts only. It must never let a stranger in, never mail one, and never be
 * indexed: sign-in and account creation are limited to the exact addresses in
 * `STAGING_SIGNIN_ALLOWLIST`, every API and MCP answer is marked noindex, and
 * outbound email to any other address is skipped.
 *
 * Fail closed: a value of `STACK_STAGING` other than `true` or `false`, or a
 * staging deployment with no address on its allow-list (or a malformed one),
 * refuses to boot. Unset, the deployment is not staging and nothing here
 * changes what it does.
 *
 * Read lazily from the process environment like `deployment()`: the API, the
 * worker and the MCP server all read the same variables.
 */

type Env = Record<string, string | undefined>;

export interface StagingConfig {
  /** `STACK_STAGING=true`. */
  enabled: boolean;
  /** The lower-cased addresses that may sign in; empty when not staging. */
  signinAllowlist: ReadonlySet<string>;
}

/** The value of `X-Robots-Tag` on every API and MCP answer of a staging deployment. */
export const STAGING_ROBOTS_TAG = 'noindex, nofollow';

/** What a skipped email returns in place of a provider message id. */
export const STAGING_SKIPPED_EMAIL_ID = 'staging-skipped';

/** One plain, lower-cased address: no wildcard, no name, no list. */
const ADDRESS = /^[a-z0-9._%+'-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;

export function readStaging(env: Env = process.env): StagingConfig {
  const raw = env['STACK_STAGING']?.trim() ?? '';
  if (raw !== '' && raw !== 'true' && raw !== 'false') {
    throw new Error('[BOOT] STACK_STAGING must be "true" or "false"');
  }
  if (raw !== 'true') return { enabled: false, signinAllowlist: new Set() };

  const entries = (env['STAGING_SIGNIN_ALLOWLIST'] ?? '')
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry !== '');
  if (entries.length === 0) {
    throw new Error('[BOOT] STAGING_SIGNIN_ALLOWLIST must name at least one address when STACK_STAGING=true');
  }
  // An entry that is not one plain address would match nobody or, worse, read as a pattern: refused, never skipped.
  if (entries.some((entry) => !ADDRESS.test(entry))) {
    throw new Error('[BOOT] STAGING_SIGNIN_ALLOWLIST must be comma-separated email addresses');
  }
  return { enabled: true, signinAllowlist: new Set(entries) };
}

let cached: { key: string; config: StagingConfig } | undefined;

/** The staging configuration of this process, parsed again only when one of its variables changes. */
export function staging(): StagingConfig {
  const key = `${process.env['STACK_STAGING'] ?? ''}\u0000${process.env['STAGING_SIGNIN_ALLOWLIST'] ?? ''}`;
  if (cached?.key !== key) cached = { key, config: readStaging(process.env) };
  return cached.config;
}

/** The bare address of `Name <address>` or of an address, lower-cased. */
function bareAddress(value: string): string {
  const angled = /<([^<>]+)>\s*$/.exec(value);
  return (angled ? angled[1]! : value).trim().toLowerCase();
}

/**
 * Whether this address may sign in, be given an account or a membership, or be
 * sent a sign-in link. Always true outside staging; on staging, only an exact
 * (case-insensitive) member of the allow-list.
 */
export function signinAllowed(email: string | null | undefined, config: StagingConfig = staging()): boolean {
  if (!config.enabled) return true;
  if (typeof email !== 'string') return false;
  return config.signinAllowlist.has(bareAddress(email));
}

/**
 * Whether STACK may email this recipient. Outside staging, always; on staging,
 * only an address on the allow-list, so a test deployment never mails a
 * stranger whatever path the mail took.
 */
export function stagingRecipientAllowed(to: string, config: StagingConfig = staging()): boolean {
  return signinAllowed(to, config);
}
