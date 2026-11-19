import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import type { Services } from '../config/services.js';
import { A2A_CARD_DESCRIPTION, registerA2aAgentCardRoute } from './a2a.js';

/**
 * The platform's A2A card says what the endpoint does and nothing about a business: a self-managed install has no
 * customer accounts. A deployment may put one line of its own in front, through the extension.
 */

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function card(options?: { tagline?: string }): Promise<{ description: string }> {
  const app = Fastify();
  apps.push(app);
  registerA2aAgentCardRoute(app, {} as unknown as Services, options);
  await app.ready();
  const response = await app.inject({ method: 'GET', url: '/.well-known/agent.json' });
  expect(response.statusCode).toBe(200);
  return response.json();
}

describe('the platform A2A card description', () => {
  it('is only the technical sentence in the engine', async () => {
    const body = await card();
    expect(body.description).toBe(A2A_CARD_DESCRIPTION);
    expect(body.description).not.toMatch(/control plane/i);
  });

  it('puts a deployment\'s own line in front of the technical sentence', async () => {
    const body = await card({ tagline: 'A line of the deployment.' });
    expect(body.description).toBe(`A line of the deployment. ${A2A_CARD_DESCRIPTION}`);
  });

  it('reads an absent or empty line as none', async () => {
    expect((await card({})).description).toBe(A2A_CARD_DESCRIPTION);
    expect((await card({ tagline: '' })).description).toBe(A2A_CARD_DESCRIPTION);
  });
});
