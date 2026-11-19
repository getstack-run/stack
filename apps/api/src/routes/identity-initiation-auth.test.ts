import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('identity verification initiation authorization', () => {
  it('denies agent-bearing authentication before provider initiation', () => {
    // The route declaration (and its preHandler) lives in identity.ts; the
    // handler body, which calls the provider, lives in identity-flows/.
    const source = readFileSync(new URL('./identity.ts', import.meta.url), 'utf8');
    const start = source.indexOf("app.post('/v1/identity/verify/initiate'");
    const end = source.indexOf("app.get('/v1/identity/verify/sessions'", start);
    expect(start).toBeGreaterThan(-1);
    const route = source.slice(start, end);
    expect(route).toContain('preHandler: [auth, denyAgentContexts]');
    expect(route).toContain('initiateVerification(request, reply, services)');

    const handlerSource = readFileSync(
      new URL('./identity-flows/verification.ts', import.meta.url),
      'utf8',
    );
    const handlerStart = handlerSource.indexOf('export async function initiateVerification(');
    const handlerEnd = handlerSource.indexOf('export async function listPendingSessions(', handlerStart);
    expect(handlerStart).toBeGreaterThan(-1);
    expect(handlerSource.slice(handlerStart, handlerEnd)).toContain('services.identity.initiate(');
  });
});
