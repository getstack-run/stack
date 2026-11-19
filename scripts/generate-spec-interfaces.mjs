// The generated parts of the specifications of two interfaces an outsider builds against or checks: the
// security-monitoring export (spec/siem-export) and single sign-on (spec/sso-login). scripts/generate-spec.mjs calls
// these three functions; the schemas come from the Zod definitions in packages/shared/src/schemas (siem-export.ts,
// identity.ts) and every table of constants from the constants the code runs on (packages/shared/src/constants).

export const INTERFACE_SPECS = [
  { dir: 'siem-export', id: 'siem-export', title: 'STACK Security Monitoring Export' },
  { dir: 'sso-login', id: 'sso-login', title: 'STACK Single Sign-on Profile' },
];

const SCHEMAS = {
  'siem-export': ['SiemRecord', 'SiemSecurityFields', 'SiemAuditFields'],
  'sso-login': ['OidcIdpConfigCreateInput', 'OidcIdpConfigUpdateInput', 'SsoDomainAddInput'],
};

/** Emit every schema of the specifications through the caller's `emitSchema(ctx, spec, name, zodSchema)`. */
export function interfaceSchemas(ctx, emitSchema) {
  for (const [spec, names] of Object.entries(SCHEMAS)) {
    for (const name of names) emitSchema(ctx, spec, name, ctx.shared[name]);
  }
}

const table = (header, rows) => [
  `| ${header.join(' | ')} |`,
  `|${header.map(() => '---').join('|')}|`,
  ...rows.map((row) => `| ${row.join(' | ')} |`),
].join('\n');

function seconds(n) {
  if (n % 86400 === 0) return `${n} s (${n / 86400} d)`;
  if (n % 3600 === 0) return `${n} s (${n / 3600} h)`;
  if (n % 60 === 0) return `${n} s (${n / 60} min)`;
  return `${n} s`;
}

/** The generated blocks of the two SPEC.md files, by name. */
export function interfaceBlocks(ctx) {
  const s = ctx.shared;
  const result = {};

  const pri = (severity) => s.SIEM_SYSLOG_FACILITY * 8 + s.SIEM_SYSLOG_SEVERITY[severity];
  result['siem-constants'] = table(['Constant', 'Value'], [
    ['Streams', s.SIEM_STREAMS.map((name) => `\`${name}\``).join(', ')],
    ['Severities', s.SIEM_SEVERITIES.map((name) => `\`${name}\``).join(', ')],
    ['Syslog facility', `${s.SIEM_SYSLOG_FACILITY} (security and authorization messages)`],
    ['Syslog severity of `critical`, `warning`, `info`', `${s.SIEM_SYSLOG_SEVERITY.critical}, ${s.SIEM_SYSLOG_SEVERITY.warning}, ${s.SIEM_SYSLOG_SEVERITY.info}`],
    ['PRI of `critical`, `warning`, `info`', `${pri('critical')}, ${pri('warning')}, ${pri('info')}`],
    ['Structured data identifier (SD-ID)', `\`${s.SIEM_SYSLOG_SD_ID}\``],
    ['APP-NAME', `\`${s.SIEM_SYSLOG_APP_NAME}\``],
    ['HOSTNAME', `\`${s.SIEM_SYSLOG_HOSTNAME}\``],
    ['Longest syslog message', `${s.SIEM_SYSLOG_MAX_BYTES} bytes`],
    ['Content type of a batch to an HTTPS collector', `\`${s.SIEM_HTTP_CONTENT_TYPE}\``],
    ['Records in a batch, at most', String(s.SIEM_BATCH_SIZE)],
    ['A record is left alone until it is', seconds(s.SIEM_SETTLE_SECONDS) + ' old'],
    ['How often the exporter looks for new records', seconds(s.SIEM_PASS_INTERVAL_SECONDS)],
    ['Time allowed for one connection or request', seconds(s.SIEM_SINK_TIMEOUT_SECONDS)],
    ['A machine holds a stream for at most', seconds(s.SIEM_LOCK_SECONDS)],
    ['Default syslog port over UDP and TCP, over TLS', `${s.SIEM_DEFAULT_SYSLOG_PORT}, ${s.SIEM_DEFAULT_SYSLOG_TLS_PORT}`],
  ]);

  result['sso-constants'] = table(['Constant', 'Value'], [
    ['State cookie name', `\`${s.SSO_STATE_COOKIE}\``],
    ['State cookie lifetime and sign-in attempt lifetime', seconds(s.SSO_STATE_TTL_SECONDS)],
    ['An authorization code is kept for', seconds(s.SSO_CODE_TTL_SECONDS)],
    ['Handoff reference lifetime (single use)', seconds(s.SSO_HANDOFF_TTL_SECONDS)],
    ['Clock tolerance on `exp` and `nbf`', seconds(s.SSO_ID_TOKEN_CLOCK_TOLERANCE_SECONDS)],
    ['Longest time for one request to the identity provider', seconds(s.SSO_FETCH_TIMEOUT_SECONDS)],
    ['Discovery document is kept for', seconds(s.SSO_DISCOVERY_TTL_SECONDS)],
    ['Key set cache lifetime, default and range', `${seconds(s.SSO_JWKS_CACHE_DEFAULT_SECONDS)}, ${s.SSO_JWKS_CACHE_MIN_SECONDS} to ${s.SSO_JWKS_CACHE_MAX_SECONDS} s`],
    ['Forced refetch of the key set for an unknown `kid`, at most once per', seconds(s.SSO_JWKS_REFETCH_COOLDOWN_SECONDS)],
    ['PKCE method', '`S256`'],
    ['Authorization request and sign-in path', `\`${s.SSO_START_PATH}\``],
    ['Callback path', `\`${s.SSO_CALLBACK_PATH}\``],
    ['Dashboard path the browser is sent to with the handoff reference', `\`${s.SSO_HANDOFF_REDIRECT_PATH}\``],
    ['DNS name of a domain\'s proof record',`\`${s.SSO_DOMAIN_RECORD_LABEL}.{domain}\``],
    ['Text a proof record starts with, then the token', `\`${s.SSO_DOMAIN_RECORD_PREFIX}\``],
    ['A successful check of a record counts at sign-in for', seconds(s.SSO_DOMAIN_TRUST_SECONDS)],
    ['A verified domain\'s record is looked up again every',seconds(s.SSO_DOMAIN_RECHECK_SECONDS)],
    ['A record seen missing for this long lapses the domain', seconds(s.SSO_DOMAIN_LAPSE_SECONDS)],
    ['A domain added and never verified is kept for', seconds(s.SSO_DOMAIN_PENDING_SECONDS)],
    ['A domain is looked up on request at most once in', seconds(s.SSO_DOMAIN_CHECK_COOLDOWN_SECONDS)],
    ['Longest time for one DNS lookup', seconds(s.SSO_DOMAIN_LOOKUP_TIMEOUT_SECONDS)],
    ['Most domains one account may hold', String(s.SSO_DOMAINS_MAX_PER_ACCOUNT)],
  ]);

  result['sso-errors'] = table(
    ['Code', 'HTTP status', 'Reason in the engine'],
    Object.entries(s.SSO_LOGIN_REASONS).map(([reason, [code, status]]) => [`\`${code}\``, String(status), `\`${reason}\``]),
  );

  return result;
}

/** What the hand-written text of the two specifications must cover, as a list of what is missing (the caller adds it to its own). */
export function interfaceCoverage(ctx, prose) {
  const missing = [];
  const sso = prose('spec/sso-login/SPEC.md');
  for (const [code] of Object.values(ctx.shared.SSO_LOGIN_REASONS)) {
    if (!sso.includes(`| \`${code}\` |`)) missing.push(`spec/sso-login/SPEC.md has no row for the sign-in error ${code}`);
  }
  const siem = prose('spec/siem-export/SPEC.md');
  for (const stream of ctx.shared.SIEM_STREAMS) {
    if (!siem.includes(`| \`${stream}\` |`)) missing.push(`spec/siem-export/SPEC.md has no row for the stream ${stream}`);
  }
  return missing;
}
