// verifyPassportHeader.
//
// Partner-side helper for the X-Stack-Passport convention. Pulls the
// passport token from request headers, resolves STACK's deployment JWKS,
// and verifies offline. No network after the first cached JWKS fetch.
//
// Usage:
//
//   import { verifyPassportHeader } from '@getstackrun/sdk';
//
//   // In Express / Fastify middleware:
//   const claims = await verifyPassportHeader(req.headers['x-stack-passport'], {
//     baseUrl: 'https://api.getstack.run',
//   });
//   // claims.stk.operator_id is the tenant; claims.stk.agent_id is the agent.

import { verifyPassportOffline, type VerifiedPassportClaims } from '../verify-offline.js';

const DEFAULT_BASE_URL = 'https://api.getstack.run';

export interface VerifyPassportHeaderOptions {
  /**
   * STACK API base URL. The deployment JWKS is fetched from
   * `{baseUrl}/v1/.well-known/jwks.json`.
   */
  baseUrl?: string;
  /**
   * Override the issuer check. Defaults to STACK's canonical issuer
   * (`getstack.run`).
   */
  issuer?: string;
  /** Override the audience check. Defaults to `stack:passport`. */
  audience?: string;
}

/**
 * Verify an X-Stack-Passport header value.
 *
 * The header value is a STACK passport JWT signed by STACK's deployment
 * signing key. `sub` identifies the agent and `stk.operator_id` identifies
 * the tenant. This function resolves the deployment JWKS URL and verifies
 * the token offline; the verifier caches the JWKS resolver per deployment.
 *
 * Throws on any failure: missing header, malformed JWT, missing claims,
 * signature failure, wrong issuer/audience, expired. The caller should
 * treat any throw as a 401 reject.
 *
 * Does NOT check revocation. For revocation-aware verification on
 * high-sensitivity actions, layer a short-window cache on
 * `POST /v1/passports/verify`.
 */
export async function verifyPassportHeader(
  headerValue: string | string[] | undefined,
  options: VerifyPassportHeaderOptions = {},
): Promise<VerifiedPassportClaims> {
  if (!headerValue) {
    throw new Error('verifyPassportHeader: missing header value');
  }
  const token = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (!token || typeof token !== 'string') {
    throw new Error('verifyPassportHeader: header value is empty');
  }

  const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
  const jwksUrl = `${baseUrl}/v1/.well-known/jwks.json`;

  return verifyPassportOffline(token, {
    jwksUrl,
    ...(options.issuer ? { issuer: options.issuer } : {}),
    ...(options.audience ? { audience: options.audience } : {}),
  });
}

/**
 * Express middleware factory.
 *
 *   import express from 'express';
 *   import { stackPassportMiddleware } from '@getstackrun/sdk';
 *
 *   const app = express();
 *   app.use(stackPassportMiddleware());
 *
 *   app.post('/send', (req, res) => {
 *     if (!req.stackPassport) return res.status(401).send('passport required');
 *     // ... use req.stackPassport.stk.services for scope check
 *   });
 *
 * Behaviour:
 *   - X-Stack-Passport absent → next() with `req.stackPassport = undefined`.
 *     (Caller decides whether passport is required.)
 *   - X-Stack-Passport present + valid → next() with `req.stackPassport`.
 *   - X-Stack-Passport present + invalid → 401 with `{error, detail}`.
 */
export function stackPassportMiddleware(options: VerifyPassportHeaderOptions = {}) {
  return async function middleware(
    req: { headers: Record<string, string | string[] | undefined>; stackPassport?: VerifiedPassportClaims | undefined },
    res: { status(code: number): { json(body: unknown): void } },
    next: () => void,
  ): Promise<void> {
    const header = req.headers['x-stack-passport'];
    if (!header) {
      req.stackPassport = undefined;
      return next();
    }
    try {
      req.stackPassport = await verifyPassportHeader(header, options);
      return next();
    } catch (err) {
      res.status(401).json({
        error: 'invalid_stack_passport',
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  };
}
