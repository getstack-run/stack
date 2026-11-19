// The generated parts of the identity specifications: agent runtime sign-in (spec/agent-auth), per-agent
// keys (spec/agent-keys), workload identity exchange (spec/workload-identity) and the OAuth server profile
// (spec/oauth-profile). scripts/generate-spec.mjs calls these three functions; the schemas come from the Zod
// definitions in packages/shared/src/schemas (agent-auth.ts, workload-wire.ts, oauth-wire.ts, fleet.ts) and
// every table of constants from the constants the code runs on.

export const IDENTITY_SPECS = [
  { dir: 'agent-auth', id: 'agent-auth', title: 'STACK Agent Runtime Sign-in' },
  { dir: 'agent-keys', id: 'agent-keys', title: 'STACK Agent Keys' },
  { dir: 'workload-identity', id: 'workload-identity', title: 'STACK Workload Identity Exchange' },
  { dir: 'oauth-profile', id: 'oauth-profile', title: 'STACK OAuth Server Profile' },
];

const SCHEMAS = {
  'agent-auth': [
    'AgentEnrollmentChallengeResult', 'AgentEnrollInput', 'AgentEnrollResult', 'AgentEnrollmentTicketInput',
    'AgentEnrollmentTicketResult', 'AgentJwtClaims', 'FleetEnrollmentInput', 'FleetEnrollmentChallengeResult',
    'FleetEnrollmentResult',
  ],
  'agent-keys': ['AgentJwk', 'AgentJwks'],
  'workload-identity': ['WorkloadPassportInput', 'WorkloadSvidPassportResult', 'WorkloadWitPassportResult'],
  'oauth-profile': [
    'OAuthError', 'OAuthServerMetadata', 'OAuthTokenResponse', 'OAuthTokenExchangeResponse',
    'OAuthClientRegistrationRequest', 'OAuthClientRegistrationResponse', 'OAuthDeviceAuthorizationResponse',
    'OAuthClientMetadataDocument',
  ],
};

/** Emit every schema of the four specifications through the caller's `emitSchema(ctx, spec, name, zodSchema)`. */
export function identitySchemas(ctx, emitSchema) {
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

const codes = (values) => values.map((value) => `\`${value}\``).join(', ');

/** The generated blocks of the four SPEC.md files, by name. */
export function identityBlocks(ctx) {
  const s = ctx.shared;
  const result = {};

  result['agent-auth-constants'] = table(['Constant', 'Value'], [
    ['Agent JWT issuer (`iss`)', `\`${s.AGENT_JWT_ISSUER}\``],
    ['Agent JWT audience (`aud`)', `\`${s.AGENT_JWT_AUDIENCE}\``],
    ['Signature algorithm', '`EdDSA` (Ed25519)'],
    ['Lifetime the SDKs mint', seconds(s.AGENT_JWT_TTL_SECONDS)],
    ['Longest lifetime a verifier accepts', seconds(s.AGENT_JWT_MAX_TTL_SECONDS)],
    ['Clock tolerance', seconds(s.AGENT_JWT_CLOCK_TOLERANCE_SECONDS)],
    ['Enrollment challenge lifetime', seconds(s.AGENT_ENROLLMENT_CHALLENGE_TTL_SECONDS)],
    ['Enrollment ticket audience', `\`${s.ENROLLMENT_TICKET_AUDIENCE}\``],
    ['Enrollment ticket lifetime', seconds(s.ENROLLMENT_TICKET_TTL_SECONDS)],
    ['Fleet enrollment challenge lifetime', seconds(s.FLEET_ENROLLMENT_CHALLENGE_TTL_SECONDS)],
  ]);

  const errors = [
    new s.InvalidApiKeyError(),
    new s.AgentJwtReplayedError(),
    new s.ForbiddenError(),
    new s.ConflictError('Conflict'),
    new s.ServiceUnavailableError('Enrollment temporarily unavailable, please retry'),
  ];
  result['agent-auth-errors'] = table(
    ['Code', 'HTTP status', 'Message'],
    errors.map((e) => [`\`${e.code}\``, String(e.statusCode), e.message]),
  );

  result['workload-reasons'] = table(
    ['Reason', 'Code', 'HTTP status'],
    Object.entries(s.WORKLOAD_ATTESTATION_REASONS).map(([reason, [code, status]]) => [`\`${reason}\``, `\`${code}\``, String(status)]),
  );

  result['oauth-constants'] = table(['Constant', 'Value'], [
    ['Access token lifetime, API resource', seconds(s.OAUTH_ACCESS_TOKEN_TTL_SECONDS_API)],
    ['Access token lifetime, MCP resources', seconds(s.OAUTH_ACCESS_TOKEN_TTL_SECONDS_MCP)],
    ['Refresh token lifetime', seconds(s.OAUTH_REFRESH_TOKEN_TTL_SECONDS)],
    ['Refresh rotation grace (a retry of the same request returns the same successor)', seconds(s.OAUTH_REFRESH_ROTATION_GRACE_SECONDS)],
    ['Authorization code lifetime (single use)', seconds(s.OAUTH_AUTHORIZATION_CODE_TTL_SECONDS)],
    ['Device code lifetime', seconds(s.OAUTH_DEVICE_CODE_TTL_SECONDS)],
    ['Device code polling interval, first and longest after `slow_down`', `${s.OAUTH_DEVICE_CODE_INTERVAL_SECONDS} s and ${s.OAUTH_DEVICE_CODE_MAX_INTERVAL_SECONDS} s`],
    ['Access token audience, API resource', `\`${s.OAUTH_ACCESS_TOKEN_AUDIENCE_API}\``],
    ['Access token audience, MCP resources', `\`${s.OAUTH_ACCESS_TOKEN_AUDIENCE_MCP}\``],
    ['Token exchange grant type', `\`${s.GRANT_TYPE_TOKEN_EXCHANGE}\``],
    ['Token type of a Passport in a token exchange', `\`${s.TOKEN_TYPE_STACK_PASSPORT}\``],
    ['Token type of a JWT in a token exchange', `\`${s.TOKEN_TYPE_JWT}\``],
    ['Scope granted when a request names none (API resource)', codes(s.OAUTH_DEFAULT_SCOPE.split(' '))],
  ]);

  const directory = new Set(s.OAUTH_DIRECTORY_SCOPES);
  const mcpDefault = new Set(s.OAUTH_MCP_DEFAULT_SCOPES);
  result['oauth-scopes'] = table(
    ['Scope', 'Granted for the directory resource', 'In the default MCP request'],
    s.OAUTH_SCOPES.map((scope) => [`\`${scope}\``, directory.has(scope) ? 'yes' : '-', mcpDefault.has(scope) ? 'yes' : '-']),
  );

  return result;
}
