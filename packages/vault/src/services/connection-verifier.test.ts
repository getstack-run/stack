import { describe, expect, it, vi } from 'vitest';
import { ConnectionVerifierService } from './connection-verifier.js';
import { OAuthLifecycleError, oauthClientIdDigest } from './oauth-token-lifecycle.js';

const CONNECTION = {
  id: 'scon_agentmail',
  operator_id: 'op_owner',
  provider: 'agentmail',
  status: 'active',
  credential_encrypted: 'kms-envelope',
};

function makeVerifier(status: number, providerBody = '') {
  const updateConnectionVerification = vi.fn(async () => undefined);
  const request = vi.fn(async () => new Response(providerBody, { status }));
  const verifier = new ConnectionVerifierService(
    {
      findConnectionById: vi.fn(async () => CONNECTION),
      updateConnectionVerification,
    } as never,
    { current: vi.fn(async () => JSON.stringify({ api_key: 'am_secret_value' })) } as never,
    {
      request: request as typeof fetch,
      assertPublicUrl: vi.fn(async (url: string) => new URL(url)),
      timeoutMs: 20,
    },
  );
  return { verifier, request, updateConnectionVerification };
}

describe('ConnectionVerifierService AgentMail verification', () => {
  it('uses the scope-safe Who Am I endpoint and marks a 200 healthy', async () => {
    const { verifier, request, updateConnectionVerification } = makeVerifier(200);

    const result = await verifier.verify(CONNECTION.id, CONNECTION.operator_id);

    expect(result.status).toBe('healthy');
    expect(request).toHaveBeenCalledWith(
      'https://api.agentmail.to/v0/auth/me',
      expect.objectContaining({
        method: 'GET',
        headers: { Authorization: 'Bearer am_secret_value' },
        redirect: 'manual',
      }),
    );
    expect(updateConnectionVerification).toHaveBeenCalledWith(CONNECTION.id, 'healthy');
  });

  it('reports 401 as failed authentication without exposing provider content', async () => {
    const { verifier } = makeVerifier(401, '{"code":"unknown_api_key","secret":"am_leak"}');

    const result = await verifier.verify(CONNECTION.id, CONNECTION.operator_id);

    expect(result).toMatchObject({
      status: 'unhealthy',
      message: 'Authentication failed (401)',
    });
    expect(JSON.stringify(result)).not.toContain('am_secret_value');
    expect(JSON.stringify(result)).not.toContain('am_leak');
    expect(JSON.stringify(result)).not.toContain('unknown_api_key');
  });

  it('reports 403 as denied access instead of failed authentication', async () => {
    const { verifier } = makeVerifier(403, '{"code":"missing_permission","fix":"private"}');

    const result = await verifier.verify(CONNECTION.id, CONNECTION.operator_id);

    expect(result).toMatchObject({
      status: 'unhealthy',
      message: 'Access denied or insufficient permission (403)',
    });
    expect(JSON.stringify(result)).not.toContain('missing_permission');
    expect(JSON.stringify(result)).not.toContain('private');
  });

  it('times out without returning the credential', async () => {
    const request = vi.fn((_url: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      }));
    const verifier = new ConnectionVerifierService(
      {
        findConnectionById: vi.fn(async () => CONNECTION),
        updateConnectionVerification: vi.fn(async () => undefined),
      } as never,
      { current: vi.fn(async () => JSON.stringify({ api_key: 'am_secret_value' })) } as never,
      {
        request: request as typeof fetch,
        assertPublicUrl: vi.fn(async (url: string) => new URL(url)),
        timeoutMs: 5,
      },
    );

    const result = await verifier.verify(CONNECTION.id, CONNECTION.operator_id);

    expect(result).toMatchObject({ status: 'unhealthy', message: 'Request timed out (5ms)' });
    expect(JSON.stringify(result)).not.toContain('am_secret_value');
  });

  it('does not expose credential-bearing transport errors', async () => {
    const { verifier, request } = makeVerifier(200);
    request.mockRejectedValueOnce(new TypeError('Invalid header: Bearer am_secret_value'));
    const result = await verifier.verify(CONNECTION.id, CONNECTION.operator_id);
    expect(result.status).toBe('unhealthy');
    expect(JSON.stringify(result)).not.toContain('am_secret_value');
  });
});

describe('ConnectionVerifierService OAuth verification', () => {
  function oauthVerifier(stored: string) {
    const request = vi.fn(async () => new Response('{}', { status: 200 }));
    const verifier = new ConnectionVerifierService(
      {
        findConnectionById: vi.fn(async () => ({ ...CONNECTION, id: 'scon_github', provider: 'github' })),
        updateConnectionVerification: vi.fn(async () => undefined),
      } as never,
      { current: vi.fn(async () => stored) } as never,
      { request: request as typeof fetch, assertPublicUrl: vi.fn(async (url: string) => new URL(url)), timeoutMs: 20 },
    );
    return { verifier, request };
  }
  const authHeader = (request: ReturnType<typeof vi.fn>) =>
    (request.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;

  it('sends only the access token from a hosted-OAuth JSON credential', async () => {
    const { verifier, request } = oauthVerifier(JSON.stringify({
      access_token: 'gho_synthetic', token_type: 'bearer', token_auth_method: 'client_secret_basic',
    }));
    await expect(verifier.verify('scon_github', 'op_owner')).resolves.toMatchObject({ status: 'healthy' });
    expect(authHeader(request).Authorization).toBe('Bearer gho_synthetic');
  });

  it('still sends a bare token string as stored', async () => {
    const { verifier, request } = oauthVerifier('gho_bare');
    await verifier.verify('scon_github', 'op_owner');
    expect(authHeader(request).Authorization).toBe('Bearer gho_bare');
  });

  it('reports a JSON credential without an access token instead of sending it', async () => {
    const { verifier, request } = oauthVerifier(JSON.stringify({ refresh_token: 'r' }));
    await expect(verifier.verify('scon_github', 'op_owner'))
      .resolves.toMatchObject({ status: 'unhealthy', message: 'Stored credential has no access token' });
    expect(request).not.toHaveBeenCalled();
  });
});

describe('ConnectionVerifierService Gmail verification', () => {
  const NARROW = 'https://scopes.example/narrow';
  const READ = 'https://www.googleapis.com/auth/gmail.readonly';
  const APP = {
    id: 'oa_google', owner_id: 'op_app_owner', provider: 'google', client_id_hash: oauthClientIdDigest('google-client-id'),
    service_id: 'svc_gmail', connection_provider: 'gmail', token_url: 'https://oauth2.googleapis.com/token',
  };
  /** The token check's answer is Google's: the app the token was issued to and the scopes it carries. */
  function gmailVerifier(credential: object, status = 200, recorded: string[] = [NARROW], tokenInfo: object = { aud: 'google-client-id', scope: NARROW }) {
    const request = vi.fn(async () => new Response(JSON.stringify(tokenInfo), { status }));
    const verifier = new ConnectionVerifierService(
      {
        findConnectionById: vi.fn(async () => ({ ...CONNECTION, id: 'scon_gmail', provider: 'gmail', scopes: recorded })),
        updateConnectionVerification: vi.fn(async () => undefined),
      } as never,
      { current: vi.fn(async () => JSON.stringify(credential)) } as never,
      { request: request as typeof fetch, assertPublicUrl: vi.fn(async (url: string) => new URL(url)), timeoutMs: 20 },
    );
    return { verifier, request };
  }

  it('reads the mailbox profile when the token holds a read scope', async () => {
    const { verifier, request } = gmailVerifier({ access_token: 'synthetic-read-token', scope: `${NARROW} ${READ}` });
    await expect(verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({ status: 'healthy' });
    expect(request).toHaveBeenCalledWith(
      'https://gmail.googleapis.com/gmail/v1/users/me/profile',
      expect.objectContaining({ method: 'GET', headers: { Authorization: 'Bearer synthetic-read-token' } }),
    );
  });

  it('asks Google about a token with no read scope, which the profile call refuses, with the token in the body', async () => {
    const { verifier, request } = gmailVerifier({ access_token: 'synthetic-narrow-token', scope: NARROW, oauth_app_binding: APP });
    await expect(verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({ status: 'healthy' });
    const [url, init] = request.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://oauth2.googleapis.com/tokeninfo');
    expect(init.method).toBe('POST');
    expect(init.body).toBe('access_token=synthetic-narrow-token');
    expect(init.headers).toEqual({ 'Content-Type': 'application/x-www-form-urlencoded' });
  });

  it('reports a token with no read scope Google rejects as unhealthy', async () => {
    const { verifier } = gmailVerifier({ access_token: 'synthetic-narrow-token', scope: NARROW, oauth_app_binding: APP }, 400);
    await expect(verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({ status: 'unhealthy' });
  });

  it('does not vouch for a token with no read scope when the connection records no app, or records no access', async () => {
    const noApp = gmailVerifier({ access_token: 'synthetic-narrow-token', scope: NARROW });
    await expect(noApp.verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({
      status: 'unhealthy', message: expect.stringContaining('records no app'),
    });
    const noAccess = gmailVerifier({ access_token: 'synthetic-narrow-token', scope: NARROW, oauth_app_binding: APP }, 200, []);
    await expect(noAccess.verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({
      status: 'unhealthy', message: expect.stringContaining('records no access'),
    });
  });

  it('does not vouch for a token issued to another app, or one carrying other scopes than the connection records', async () => {
    const otherApp = gmailVerifier({ access_token: 't', scope: NARROW, oauth_app_binding: APP }, 200, [NARROW], { aud: 'another-client', scope: NARROW });
    await expect(otherApp.verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({ status: 'unhealthy' });
    const otherScope = gmailVerifier({ access_token: 't', scope: NARROW, oauth_app_binding: APP }, 200, [NARROW], { aud: 'google-client-id', scope: `${NARROW} ${READ}` });
    await expect(otherScope.verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({ status: 'unhealthy' });
  });

  it('still reads the profile when the credential records no scope', async () => {
    const { verifier, request } = gmailVerifier({ access_token: 'synthetic-unscoped-token' });
    await verifier.verify('scon_gmail', 'op_owner');
    expect((request.mock.calls[0] as unknown as [string])[0]).toBe('https://gmail.googleapis.com/gmail/v1/users/me/profile');
  });
});

describe('ConnectionVerifierService renewal', () => {
  function renewing(error: unknown) {
    const request = vi.fn(async () => new Response('{}', { status: 200 }));
    const updateConnectionVerification = vi.fn(async () => undefined);
    const verifier = new ConnectionVerifierService(
      {
        findConnectionById: vi.fn(async () => ({ ...CONNECTION, id: 'scon_gmail', provider: 'gmail' })),
        updateConnectionVerification,
      } as never,
      { current: vi.fn(async () => { throw error; }) } as never,
      { request: request as typeof fetch, assertPublicUrl: vi.fn(async (url: string) => new URL(url)), timeoutMs: 20 },
    );
    return { verifier, request, updateConnectionVerification };
  }

  it('reports a connection the provider revoked as unhealthy and says to reconnect, without calling it', async () => {
    const { verifier, request, updateConnectionVerification } = renewing(new OAuthLifecycleError(true));
    await expect(verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({
      status: 'unhealthy',
      message: 'The provider no longer honours this connection; reconnect it',
    });
    expect(updateConnectionVerification).toHaveBeenCalledWith('scon_gmail', 'unhealthy');
    expect(request).not.toHaveBeenCalled();
  });

  it('reports an outage during renewal as unhealthy without asking for a reconnect', async () => {
    const { verifier } = renewing(new OAuthLifecycleError(false));
    await expect(verifier.verify('scon_gmail', 'op_owner')).resolves.toMatchObject({
      status: 'unhealthy',
      message: 'The provider could not renew this connection just now; try again shortly',
    });
  });

  it('lets any other failure through instead of calling it unhealthy', async () => {
    const { verifier } = renewing(new Error('kms unavailable'));
    await expect(verifier.verify('scon_gmail', 'op_owner')).rejects.toThrow('kms unavailable');
  });
});
