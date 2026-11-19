import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Monid API — https://monid.ai/docs/api/overview. Base: api.monid.ai/v1/….
// Auth via Authorization Bearer header (a `monid_live_` key bound to one
// workspace); the proxy injects it server-side so the agent never holds it.
//
// Monid is a paid data-endpoint marketplace: `run` spends from the Monid
// wallet, so the run intents pin which provider and endpoint may be called.
// `discover` and `inspect` are free reads. Endpoint shapes from Monid's API
// reference as of 2026-10-19. Run ids are opaque ULIDs.

const slug = z.string().min(1).max(128);
const slugList = z.union([slug, z.array(slug).min(1)]);
type SlugList = z.infer<typeof slugList>;
const toList = (v: SlugList): string[] => (Array.isArray(v) ? v : [v]);

function bodyIn(path: string, values: SlugList): Constraint {
  const list = toList(values);
  return list.length === 1
    ? { path, op: 'eq', value: list[0]! }
    : { path, op: 'in', value: list };
}

export const monidIntents = [
  // ─── Account ──────────────────────────────────────────────────────
  defineIntent({
    name: 'monid.whoami',
    effect: 'read',
    description: 'Identify the Monid key and its workspace. Binds GET /v1/auth/whoami.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/auth/whoami' },
    ],
  }),

  // ─── Catalog (free) ───────────────────────────────────────────────
  defineIntent({
    name: 'monid.discover',
    effect: 'read',
    description: 'Search Monid for data endpoints. Binds POST /v1/discover. Free; spends nothing.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/discover' },
    ],
  }),

  defineIntent({
    name: 'monid.inspect',
    effect: 'read',
    description: 'Read one endpoint\'s input schema and price. Binds POST /v1/inspect. Free; spends nothing.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/inspect' },
    ],
  }),

  // ─── Runs (paid) ──────────────────────────────────────────────────
  defineIntent({
    name: 'monid.run',
    effect: 'write',
    description:
      'Run a paid Monid endpoint from a provider allowlist. Binds POST /v1/run with body.provider pinned.',
    params: z.object({ provider: slugList }),
    expand: ({ provider }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/run' },
      bodyIn('body.provider', provider),
    ],
  }),

  defineIntent({
    name: 'monid.run_endpoint',
    effect: 'write',
    description:
      'Run one exact paid Monid endpoint. Binds POST /v1/run with body.provider and body.endpoint pinned.',
    params: z.object({ provider: slug, endpoint: z.string().min(1).max(256) }),
    expand: ({ provider, endpoint }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v1/run' },
      { path: 'body.provider', op: 'eq', value: provider },
      { path: 'body.endpoint', op: 'eq', value: endpoint },
    ],
  }),

  defineIntent({
    name: 'monid.list_runs',
    effect: 'read',
    description: 'List past runs. Binds GET /v1/runs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/runs' },
    ],
  }),

  defineIntent({
    name: 'monid.get_run',
    effect: 'read',
    description: 'Read one run\'s status and output. Binds GET /v1/runs/{runId}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/runs/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'monid.stop_run',
    effect: 'write',
    description: 'Stop a running run. Binds POST /v1/runs/{runId}/stop.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/runs/[^/]+/stop$' },
    ],
  }),

  // ─── Wallet (read) ────────────────────────────────────────────────
  defineIntent({
    name: 'monid.wallet_balance',
    effect: 'read',
    description: 'Read the Monid wallet balance. Binds GET /v1/wallet/balance.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/wallet/balance' },
    ],
  }),

  defineIntent({
    name: 'monid.wallet_activities',
    effect: 'read',
    description: 'List Monid wallet activity. Binds GET /v1/wallet/activities.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v1/wallet/activities' },
    ],
  }),
];
