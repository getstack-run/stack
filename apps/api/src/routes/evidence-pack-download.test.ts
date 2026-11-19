import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NotFoundError } from '@stack/shared';
import { errorHandler } from '../middleware/error-handler.js';

vi.mock('../middleware/auth.js', () => ({
  createAuthMiddleware: () => async (request: Record<string, unknown>) => {
    const token = String((request['headers'] as { authorization?: string }).authorization ?? '');
    request['operatorId'] = token.includes('foreign') ? 'op_foreign' : 'op_owner';
    request['operatorTier'] = 'enterprise';
  },
}));

vi.mock('../middleware/meter.js', () => ({ meterAction: vi.fn(async () => {}) }));

import { registerEvidencePacksRoutes } from './evidence-packs.js';

const apps: ReturnType<typeof Fastify>[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp() {
  const bytes = Buffer.from('{"pack_version":1,"claim":"exact"}', 'utf8');
  const getStoredManifest = vi.fn(async (operatorId: string, packId: string) => {
    if (operatorId !== 'op_owner') throw new NotFoundError('evidence-pack artifact', packId);
    return {
      pack_id: packId,
      claim_id: 'pc_pack',
      manifest_sha256: 'a'.repeat(64),
      byte_size: bytes.length,
      body: bytes,
    };
  });
  const app = Fastify();
  apps.push(app);
  app.setErrorHandler(errorHandler);
  registerEvidencePacksRoutes(app, {
    evidencePack: { getStoredManifest },
    entitlements: { controlsEnabled: async () => true },
  } as never);
  await app.ready();
  return { app, bytes, getStoredManifest };
}

describe('GET /v1/evidence-packs/:pack_id/download', () => {
  it('streams the exact stored bytes with artifact headers', async () => {
    const { app, bytes } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/evidence-packs/pck_one/download',
      headers: { authorization: 'Bearer owner' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.rawPayload).toEqual(bytes);
    expect(response.headers['content-disposition']).toBe('attachment; filename="pck_one.json"');
    expect(response.headers['digest']).toMatch(/^sha-256=/);
  });

  it('does not return a foreign operator artifact', async () => {
    const { app } = await makeApp();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/evidence-packs/pck_one/download',
      headers: { authorization: 'Bearer foreign' },
    });
    expect(response.statusCode).toBe(404);
  });
});

describe('GET /v1/evidence-packs artifact state', () => {
  it.each([
    { stored: false, expected: 'receipt_only' },
    { stored: true, expected: 'stored_manifest' },
  ])('reports $expected for a pack row', async ({ stored, expected }) => {
    const row = {
      claim_id: 'pc_pack',
      issued_at_ms: 1_766_000_000_000,
      body_json: {
        type: 'evidence_pack',
        pack_id: 'pck_one',
        content_hash: `sha256:${'a'.repeat(64)}`,
        scope: { kind: 'mission', ref: 'ms_one' },
        time_bounds: { t0_ms: 1, t1_ms: 2 },
        claim_count: 3,
        supersedes: null,
      },
    };
    const getArtifactStates = vi.fn(async () => (
      stored ? new Map([['pck_one', 'stored_manifest' as const]]) : new Map()
    ));
    const db = {
      select: vi.fn(() => ({
        from: vi.fn(() => ({
          where: vi.fn(() => ({
            orderBy: vi.fn(async () => [row]),
          })),
        })),
      })),
    };
    const app = Fastify();
    apps.push(app);
    app.setErrorHandler(errorHandler);
    registerEvidencePacksRoutes(app, {
      db,
      evidencePack: { getArtifactStates },
      entitlements: { controlsEnabled: async () => true },
    } as never);
    await app.ready();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/evidence-packs',
      headers: { authorization: 'Bearer owner' },
    });

    expect(response.statusCode).toBe(200);
    expect(getArtifactStates).toHaveBeenCalledWith('op_owner', ['pck_one']);
    expect(response.json().items[0].artifact_state).toBe(expected);
  });
});
