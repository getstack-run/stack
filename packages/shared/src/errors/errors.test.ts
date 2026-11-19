import { describe, expect, it } from 'vitest';
import {
  IdentityConfigExistsError,
  InvalidJsonError,
  PassportInvalidError,
  InvalidRequestError,
  InvalidWebhookSignatureError,
  ServiceUnavailableError,
  isRedisUnavailableError,
  MissionRequiredError,
  NotConfiguredError,
  RateLimitedError,
  SigningKeyUnavailableError,
  SsoLoginError,
  StackError,
  TierLimitExceededError,
  UnboundedSendRuleError,
  WebhookHandlerFailedError,
  WorkloadAttestationError,
  type SsoLoginReason,
  type WorkloadAttestationReason,
} from './index.js';

describe('plan allowance error', () => {
  it('is the engines own: a refused agent, member or connection is 403 TIER_LIMIT_EXCEEDED', () => {
    const error = new TierLimitExceededError('agents', 3);
    expect(error).toBeInstanceOf(StackError);
    expect(error.code).toBe('TIER_LIMIT_EXCEEDED');
    expect(error.statusCode).toBe(403);
    expect(error.message).toContain('agents limit reached (3)');
  });
});

describe('request and webhook errors', () => {
  it.each([
    [new InvalidRequestError(), 'INVALID_REQUEST', 400],
    [new InvalidJsonError(), 'INVALID_JSON', 400],
    [new PassportInvalidError(), 'PASSPORT_INVALID', 401],
    [new InvalidWebhookSignatureError(), 'INVALID_WEBHOOK_SIGNATURE', 400],
    [new NotConfiguredError('Billing'), 'NOT_CONFIGURED', 501],
    [new WebhookHandlerFailedError('invoice.paid'), 'WEBHOOK_HANDLER_FAILED', 500],
    [new RateLimitedError(), 'RATE_LIMITED', 429],
    [new MissionRequiredError(), 'MISSION_REQUIRED', 400],
    [new SigningKeyUnavailableError('agent', 'agt_1'), 'SIGNING_KEY_UNAVAILABLE', 404],
    [new UnboundedSendRuleError('no recipients', { rules: [] }), 'UNBOUNDED_SEND_RULE', 400],
  ])('%s carries its stable code and status', (error, code, status) => {
    expect(error).toBeInstanceOf(StackError);
    expect(error.code).toBe(code);
    expect(error.statusCode).toBe(status);
  });

  it('keeps the details a caller needs', () => {
    expect(new WebhookHandlerFailedError('invoice.paid').details).toEqual({ event_type: 'invoice.paid' });
    expect(new RateLimitedError('slow down', { scope: 'ip' }).details).toEqual({ scope: 'ip' });
    expect(new SigningKeyUnavailableError('operator', 'op_1').details).toEqual({ operator_id: 'op_1' });
    expect(new NotConfiguredError('Billing').message).toBe('Billing is not configured');
  });
});

describe('IdentityConfigExistsError', () => {
  it.each([
    ['oidc', 'OIDC_CONFIG_EXISTS'],
    ['spiffe', 'TRUST_DOMAIN_EXISTS'],
    ['wimse', 'WIMSE_ISSUER_EXISTS'],
  ] as const)('answers a duplicate %s configuration with 409 %s and the id of the existing one', (kind, code) => {
    const error = new IdentityConfigExistsError(kind, 'already configured', 'cfg_1');
    expect(error.code).toBe(code);
    expect(error.statusCode).toBe(409);
    expect(error.details).toEqual({ existing_id: 'cfg_1' });
  });
});

describe('WorkloadAttestationError', () => {
  const expected: Record<WorkloadAttestationReason, [string, number]> = {
    malformed_jwt: ['WORKLOAD_TOKEN_MALFORMED', 400],
    missing_sub: ['WORKLOAD_SUBJECT_MISSING', 400],
    missing_iss: ['WORKLOAD_ISSUER_MISSING', 400],
    invalid_spiffe_id: ['WORKLOAD_SPIFFE_ID_INVALID', 400],
    trust_domain_mismatch: ['WORKLOAD_TRUST_DOMAIN_MISMATCH', 400],
    issuer_mismatch: ['WORKLOAD_ISSUER_MISMATCH', 400],
    missing_kid: ['WORKLOAD_KEY_ID_MISSING', 400],
    unknown_kid: ['WORKLOAD_KEY_ID_UNKNOWN', 400],
    verify_failed: ['WORKLOAD_VERIFY_FAILED', 400],
    too_close_to_expiry: ['WORKLOAD_TOKEN_TOO_CLOSE_TO_EXPIRY', 400],
    expired: ['WORKLOAD_TOKEN_EXPIRED', 401],
    audience_mismatch: ['WORKLOAD_AUDIENCE_MISMATCH', 401],
    signature_invalid: ['WORKLOAD_SIGNATURE_INVALID', 401],
    not_configured: ['WORKLOAD_ISSUER_NOT_CONFIGURED', 401],
    not_mapped: ['WORKLOAD_IDENTITY_NOT_MAPPED', 403],
    jwks_unavailable: ['WORKLOAD_JWKS_UNAVAILABLE', 503],
    provider_unavailable: ['WORKLOAD_PROVIDER_UNAVAILABLE', 500],
  };

  it.each(Object.entries(expected) as Array<[WorkloadAttestationReason, [string, number]]>)(
    'maps %s to its code and status',
    (reason, [code, status]) => {
      const error = new WorkloadAttestationError(reason, 'message');
      expect(error.code).toBe(code);
      expect(error.statusCode).toBe(status);
      expect(error.reason).toBe(reason);
    },
  );

  it('gives every reason a distinct code', () => {
    const codes = Object.values(expected).map(([code]) => code);
    expect(new Set(codes).size).toBe(codes.length);
  });
});

describe('SsoLoginError', () => {
  const expected: Record<SsoLoginReason, [string, number]> = {
    browser_binding_required: ['BROWSER_BINDING_REQUIRED', 400],
    invalid_callback: ['SSO_CALLBACK_INVALID', 400],
    upstream_error: ['SSO_UPSTREAM_ERROR', 400],
    state_invalid: ['SSO_STATE_INVALID', 400],
    state_not_bound: ['SSO_STATE_NOT_BOUND', 400],
    login_failed: ['SSO_LOGIN_FAILED', 400],
    handoff_invalid: ['SSO_HANDOFF_INVALID', 401],
    provider_unavailable: ['SSO_PROVIDER_UNAVAILABLE', 503],
  };

  it.each(Object.entries(expected) as Array<[SsoLoginReason, [string, number]]>)(
    'maps %s to its code and status',
    (reason, [code, status]) => {
      const error = new SsoLoginError(reason, 'message');
      expect(error.code).toBe(code);
      expect(error.statusCode).toBe(status);
    },
  );
});

describe('service unavailable', () => {
  it('is a retriable 503 that names how long to wait', () => {
    const error = new ServiceUnavailableError();
    expect(error.statusCode).toBe(503);
    expect(error.code).toBe('SERVICE_UNAVAILABLE');
    expect(error.details).toEqual({ retry_after_seconds: 5 });
    expect(new ServiceUnavailableError('later', 12).details).toEqual({ retry_after_seconds: 12 });
  });

  it('recognises the ioredis outage errors and nothing else', () => {
    const maxRetries = new Error('Reached the max retries per request limit (which is 2).');
    maxRetries.name = 'MaxRetriesPerRequestError';
    expect(isRedisUnavailableError(maxRetries)).toBe(true);
    expect(isRedisUnavailableError(new Error('Connection is closed.'))).toBe(true);
    expect(isRedisUnavailableError(new Error("Stream isn't writeable and enableOfflineQueue options is false"))).toBe(true);
    expect(isRedisUnavailableError(new Error('Command timed out'))).toBe(true);
    expect(isRedisUnavailableError(new Error('WRONGTYPE Operation against a key holding the wrong kind of value'))).toBe(false);
    expect(isRedisUnavailableError(new Error('connect ECONNREFUSED 127.0.0.1:5432'))).toBe(false);
    expect(isRedisUnavailableError('Connection is closed.')).toBe(false);
    expect(isRedisUnavailableError(undefined)).toBe(false);
  });
});
