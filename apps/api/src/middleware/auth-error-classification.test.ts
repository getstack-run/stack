import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  InvalidApiKeyError,
  NotFoundError,
  PassportExpiredError,
  PassportRevokedError,
  ServiceUnavailableError,
  StackError,
} from '@stack/shared';
import { errors as joseErrors } from 'jose';
import { isAuthDomainError } from './auth.js';

/**
 * The classification that decides whether an auth-path lookup
 * failure is the CALLER's fault (bad credential → uniform 401) or OURS
 * (infrastructure → 503). A swallowed lookup error (`.catch(() => null)` on the
 * agent lookup) would turn a dying DB pool on one machine into intermittent
 * 401 INVALID_API_KEY on a healthy connection. These tests are the spec for
 * the boundary.
 */
describe('isAuthDomainError', () => {
  describe('domain errors → 401 bucket', () => {
    it('classifies typed StackErrors as domain', () => {
      expect(isAuthDomainError(new NotFoundError('Agent', 'agt_x'))).toBe(true);
      expect(isAuthDomainError(new InvalidApiKeyError())).toBe(true);
      expect(isAuthDomainError(new PassportExpiredError())).toBe(true);
      expect(isAuthDomainError(new PassportRevokedError())).toBe(true);
      expect(isAuthDomainError(new StackError('custom', 'CUSTOM', 400))).toBe(true);
    });

    it('classifies jose token errors (JW* names) as domain', () => {
      // mirror jose's error shape without importing internals: jose
      // error classes all carry names starting with "JW"
      const sigFail = new Error('signature verification failed');
      sigFail.name = 'JWSSignatureVerificationFailed';
      const expired = new Error('"exp" claim timestamp check failed');
      expired.name = 'JWTExpired';
      const claim = new Error('unexpected "aud" claim value');
      claim.name = 'JWTClaimValidationFailed';
      expect(isAuthDomainError(sigFail)).toBe(true);
      expect(isAuthDomainError(expired)).toBe(true);
      expect(isAuthDomainError(claim)).toBe(true);
    });

    it('classifies a refused algorithm (an unsigned token) as domain: its jose class is not named JW*', () => {
      expect(isAuthDomainError(new joseErrors.JOSEAlgNotAllowed('"alg" not allowed'))).toBe(true);
      expect(isAuthDomainError(new joseErrors.JOSENotSupported('unsupported'))).toBe(true);
    });
  });

  describe('infrastructure errors → 503, never INVALID_API_KEY', () => {
    it('classifies DB driver errors as infrastructure', () => {
      // postgres-js / node-postgres reject with plain Errors
      expect(isAuthDomainError(new Error('connect ECONNREFUSED 127.0.0.1:5432'))).toBe(false);
      expect(isAuthDomainError(new Error('timeout exceeded when trying to connect'))).toBe(false);
      expect(isAuthDomainError(new Error('Connection terminated unexpectedly'))).toBe(false);
    });

    it('classifies Redis errors as infrastructure', () => {
      const maxRetries = new Error('Reached the max retries per request limit');
      maxRetries.name = 'MaxRetriesPerRequestError'; // ioredis
      expect(isAuthDomainError(maxRetries)).toBe(false);
      expect(isAuthDomainError(new Error('Connection is closed.'))).toBe(false);
    });

    it('classifies a typed dependency outage as infrastructure, not a refused credential', () => {
      expect(isAuthDomainError(new ServiceUnavailableError())).toBe(false);
    });

    it('classifies non-Error throws as infrastructure', () => {
      expect(isAuthDomainError('string throw')).toBe(false);
      expect(isAuthDomainError(undefined)).toBe(false);
      expect(isAuthDomainError(null)).toBe(false);
    });
  });
});

it('never passes a raw authentication error to the logger', () => {
  const source = readFileSync(new URL('./auth.ts', import.meta.url), 'utf8');
  expect(source).not.toMatch(/log\.(?:error|warn|info)\(\s*\{\s*err\s*\}/);
  expect(source).toMatch(/err:\s*safeErrorSummary\(err\)/);
});
