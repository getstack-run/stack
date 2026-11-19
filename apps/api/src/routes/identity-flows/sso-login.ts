import type { FastifyReply, FastifyRequest } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import {
  NotFoundError,
  SSO_HANDOFF_REDIRECT_PATH,
  SSO_HANDOFF_TTL_SECONDS,
  SSO_STATE_COOKIE,
  SSO_STATE_TTL_SECONDS,
  SsoLoginError,
  ids,
  acquireOAuthOperatorLock,
  canonicalize,
  emailDomainOf,
  operators,
  sha256,
} from '@stack/shared';
import type { OidcIdpProvider } from '@stack/vault';
import type { Services } from '../../config/services.js';
import { env } from '../../config/env.js';

/** What the identity provider appends to the callback URL. */
const OidcCallbackQuery = z.object({
  code: z.string().optional(),
  state: z.string().optional(),
  error: z.string().optional(),
  error_description: z.string().optional(),
});

function clearedSsoStateCookie(): string {
  return `${SSO_STATE_COOKIE}=; HttpOnly; Path=/v1/identity; Max-Age=0; SameSite=Lax`;
}

/** Read one cookie out of a raw Cookie header. */
function readCookie(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

function escapeHtml(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

// ── SSO login: handoff redemption ────────────────────────────────
//
// Server-to-server only in practice: the dashboard's route handler
// calls this, then mints the session itself. Public because the caller
// has no STACK credential yet; the 60-second single-use ref IS the auth,
// the same posture as the emailed magic-link token.
export async function redeemSsoHandoff(
  _request: FastifyRequest,
  _reply: FastifyReply,
): Promise<FastifyReply> {
  // Legacy redemption is deliberately inert. Final handoff redemption now
  // requires the dashboard proxy credential plus the originating browser's
  // HttpOnly binder at /internal/dashboard-auth/sso/verify. Do not consume
  // the ref here: a public caller must neither burn it nor receive identity.
  throw new NotFoundError('Endpoint', 'POST /v1/identity/sso/handoff');
}

// ── SSO login: entry ─────────────────────────────────────────────
//
// Public and unauthenticated by necessity: the caller is a browser
// belonging to someone who is not signed in. That is the whole feature.
//
// The SLUG names the operator, and it does so BEFORE any token is
// exchanged. The alternative — mapping the asserted email domain to an
// account — would let anyone who configures an IdP asserting acme.com
// walk into Acme's account, unless we first proved domain ownership by
// DNS. The slug sidesteps that entirely.
export async function startSsoLogin(
  request: FastifyRequest<{ Params: { slug: string }; Querystring: { browser_binding?: string } }>,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  const browserBindingHash = request.query.browser_binding;
  if (!browserBindingHash || !/^[a-f0-9]{64}$/.test(browserBindingHash)) {
    throw new SsoLoginError('browser_binding_required', 'Start sign-in from the STACK dashboard.');
  }
  const config = await services.oidcIdpConfigRepo.findBySsoSlug(request.params.slug);
  // 404 on unknown, disabled, or inactive alike — the response must not
  // tell a prober which organisations exist or which have SSO switched on.
  if (!config) throw new NotFoundError('SsoConnection', request.params.slug);

  const operator = await services.operator.getById(config.operator_id).catch(() => null);
  if (!operator || operator.status !== 'active') {
    throw new NotFoundError('SsoConnection', request.params.slug);
  }
  services.features.require('sso');

  const provider = services.identity.getProvider('oidc') as OidcIdpProvider | undefined;
  if (!provider) {
    throw new SsoLoginError('provider_unavailable', 'OIDC provider is not registered on this STACK instance');
  }

  const init = await provider.initiate(config.operator_id, {
    requested_claims: ['verified_human'],
  } as never);

  // Mark this state as a LOGIN so the shared callback knows which mode
  // it is in. Kept server-side rather than in the query string: a mode
  // an attacker can flip by editing a URL is not a mode.
  await services.redis.set(`oidc:login:${init.session_ref}`, JSON.stringify({
    config_id: config.id,
    browser_binding_hash: browserBindingHash,
  }), 'EX', SSO_STATE_TTL_SECONDS);

  // Bind the state to THIS browser (login CSRF / session fixation).
  // Without it, an attacker can run this flow against the customer's
  // IdP as themselves, stop at the callback, and hand that callback URL
  // to a colleague. The colleague's browser completes it and they are
  // silently signed in as the ATTACKER — their subsequent work, and its
  // audit trail, lands under the attacker's identity.
  //
  // SameSite=Lax is deliberate, not lax: the callback arrives as a
  // top-level GET navigation from the IdP, which Lax permits, while
  // still withholding the cookie from cross-site subrequests.
  reply.header(
    'set-cookie',
    [
      `${SSO_STATE_COOKIE}=${encodeURIComponent(init.session_ref!)}`,
      'HttpOnly',
      'Path=/v1/identity',
      `Max-Age=${SSO_STATE_TTL_SECONDS}`,
      'SameSite=Lax',
      ...(env.NODE_ENV === 'production' ? ['Secure'] : []),
    ].join('; '),
  );

  return reply.redirect(init.verification_url!, 302);
}

// ── OIDC IdP callback ────────────────────────────────────────────
//
// The IdP redirects the browser here after the user authenticates
// upstream. We pull code+state from the query, hand off to the provider's
// acceptCallback which stores the code keyed by state in Redis, then 302
// to the operator's original return_url (or a default success page).
//
// Unauthenticated by design — the IdP is the caller, the state
// parameter is the cryptographic gate that ties this callback to an
// active initiate() session. State validation happens inside
// OidcIdpProvider.acceptCallback.
export async function handleOidcCallback(
  request: FastifyRequest,
  reply: FastifyReply,
  services: Services,
): Promise<FastifyReply> {
  const q = OidcCallbackQuery.parse(request.query);
  services.features.require('sso');
  const code = q.code;
  const state = q.state;
  const errorParam = q.error;

  if (errorParam) {
    // Upstream returned an error. Surface the error_description if
    // present and don't try to redirect to a return_url that may not
    // exist. Operator-facing UX is intentionally minimal in v1.
    throw new SsoLoginError('upstream_error', q.error_description ?? errorParam);
  }

  if (!code || !state) {
    throw new SsoLoginError('invalid_callback', 'OIDC callback missing required code or state parameter');
  }

  const provider = services.identity.getProvider('oidc') as OidcIdpProvider | undefined;
  if (!provider) {
    throw new SsoLoginError('provider_unavailable', 'OIDC provider is not registered on this STACK instance');
  }

  let handoff;
  try {
    handoff = await provider.acceptCallback(state, code);
  } catch (err) {
    throw new SsoLoginError('state_invalid', (err as Error).message);
  }

  // ── login mode ────────────────────────────────────────────────
  //
  // The verification flow parks the code for an AUTHENTICATED
  // /verify/complete to redeem. Login cannot wait for that: you are not
  // signed in yet. So redemption happens inline, here, and what leaves
  // this route is a single-use handoff ref — never a session token in a
  // URL, which would put a 24-hour credential in browser history,
  // referer headers and server logs.
  const loginStateRaw = await services.redis.get(`oidc:login:${state}`);
  if (loginStateRaw) {
    let loginState: { config_id?: unknown; browser_binding_hash?: unknown };
    try {
      loginState = JSON.parse(loginStateRaw) as typeof loginState;
    } catch {
      throw new SsoLoginError('state_invalid', 'SSO login state is invalid.');
    }
    if (typeof loginState.config_id !== 'string'
      || typeof loginState.browser_binding_hash !== 'string'
      || !/^[a-f0-9]{64}$/.test(loginState.browser_binding_hash)) {
      throw new SsoLoginError('state_invalid', 'SSO login state is invalid.');
    }
    // The state must belong to the browser that started this login.
    // Checked BEFORE the code is redeemed, so a forwarded callback URL
    // never reaches the token exchange at all.
    const bound = readCookie(request.headers.cookie, SSO_STATE_COOKIE);
    const boundBuf = Buffer.from(bound ?? '');
    const stateBuf = Buffer.from(state);
    const matches =
      bound !== null &&
      boundBuf.length === stateBuf.length &&
      timingSafeEqual(boundBuf, stateBuf);

    if (!matches) {
      request.log.warn(
        { has_cookie: bound !== null },
        'sso: callback state not bound to this browser - refusing (login CSRF)',
      );
      reply.header('set-cookie', clearedSsoStateCookie());
      throw new SsoLoginError(
        'state_not_bound',
        'This sign-in link did not start in this browser. Start again from your organisation sign-in page.',
      );
    }

    await services.redis.del(`oidc:login:${state}`);
    // Single-use: burn the binding now so the same callback cannot be
    // replayed even from the browser that legitimately started it.
    reply.header('set-cookie', clearedSsoStateCookie());
    const start = Date.now();
    let identity;
    try {
      identity = await provider.completeForLogin(state);
    } catch (err) {
      throw new SsoLoginError('login_failed', (err as Error).message);
    }

    // An address the provider did not call verified may still be vouched for, but only when the token has no
    // `email_verified` claim at all (a provider that says false has said something): by the issuer's own claim that the
    // domain is verified (Microsoft Entra's `xms_edov`), or by a domain this account proved with a DNS record. Asked
    // by the member lookup only when it is needed, so a person already linked costs no lookup.
    const emailDomain = emailDomainOf(identity.email);
    const vouchForEmail = async () => {
      if (identity.email_verified || !identity.email_verified_absent) return undefined;
      if (identity.issuer_vouches_email_domain) return 'issuer_domain_claim' as const;
      if (emailDomain && (await services.ssoDomains.isVerifiedFor(identity.operator_id, emailDomain))) {
        return 'verified_domain' as const;
      }
      return undefined;
    };

    const member = await services.member.findOrProvisionForSso({
      operatorId: identity.operator_id,
      email: identity.email,
      emailVerified: identity.email_verified,
      vouchForEmail,
      issuer: identity.iss,
      subject: identity.sub,
      name: identity.name,
      defaultRole: identity.default_member_role,
      // Creating a member from a sign-in is the provisioning feature; an
      // existing member can always sign in.
      allowProvision: services.features.has('provisioning'),
    });

    await services.audit.write({
      ctx: {
        trace_id: request.id,
        span_id: identity.config_id,
        operator_id: identity.operator_id,
        agent_id: 'system',
        passport_jti: 'none',
      },
      layer: 'vault',
      action: member.provisioned ? 'sso.login.provision' : 'sso.login',
      outcome: 'success',
      duration_ms: Date.now() - start,
      payload_hash: member.member.id,
    });
    // The first sign-in of a person the provider did not vouch for: say on what it was linked, so a later reader of the
    // record can tell a link made on a verified domain from one made on the provider's word.
    if (member.linked && member.vouchedBy) {
      await services.audit.write({
        ctx: {
          trace_id: request.id,
          span_id: identity.config_id,
          operator_id: identity.operator_id,
          agent_id: 'system',
          passport_jti: 'none',
        },
        layer: 'vault',
        action: member.vouchedBy === 'verified_domain' ? 'sso.login.link.verified_domain' : 'sso.login.link.issuer_domain_claim',
        outcome: 'success',
        payload_hash: sha256(canonicalize({ member_id: member.member.id, domain: emailDomain })),
      });
    }

    // 60 seconds, single use. Long enough for one redirect, short
    // enough that a ref leaking via referer is already dead.
    const ref = ids.ssoHandoff();
    const issued = await services.db.transaction(async (tx) => {
      await acquireOAuthOperatorLock(tx, identity.operator_id);
      const [operator] = await tx
        .select({ status: operators.status })
        .from(operators)
        .where(eq(operators.id, identity.operator_id))
        .for('update');
      if (!operator || operator.status !== 'active') return false;
      await services.redis.set(
        `sso:handoff:${ref}`,
        JSON.stringify({
          operator_id: identity.operator_id,
          member_id: member.member.id,
          email: member.member.email,
          role: member.member.role,
          browser_binding_hash: loginState.browser_binding_hash,
        }),
        'EX',
        SSO_HANDOFF_TTL_SECONDS,
      );
      return true;
    });
    if (!issued) {
      throw new SsoLoginError('handoff_invalid', 'This sign-in link has already been used or has expired.');
    }

    const target = new URL(SSO_HANDOFF_REDIRECT_PATH, env.DASHBOARD_URL);
    target.searchParams.set('ref', ref);
    return reply.redirect(target.toString(), 302);
  }

  if (handoff.return_url) {
    // Append the session_ref (= state) so the operator's UI can call
    // /v1/identity/verify/complete with it.
    const target = new URL(handoff.return_url);
    target.searchParams.set('session_ref', state);
    return reply.redirect(target.toString(), 302);
  }

  // No return_url configured at initiate time — render a minimal
  // success page with the session_ref so the operator can invoke
  // complete() manually.
  return reply
    .header('content-type', 'text/html')
    .status(200)
    .send(
      `<!doctype html><html><body><h1>Authenticated</h1>` +
      `<p>Return this session_ref to your STACK client:</p>` +
      `<pre>${escapeHtml(state)}</pre></body></html>`,
    );
}
