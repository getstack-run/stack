// The table of routes the API registers, read from a real Fastify app that runs the same `registerEngineRoutes` the
// server runs, against services that answer nothing. It is what the OpenAPI document (`spec/rest-api/openapi.json`)
// is generated from, and what the check that every route has an entry compares against.
//
// Nothing here starts a server, opens a connection or reads a credential: a route is listed when it is registered,
// and its handler never runs.

import Fastify, { type FastifyInstance } from 'fastify';
import { registerEngineRoutes } from './start.js';
import type { ApiExtension } from './extension.js';

/** One route as the server registers it. */
export interface RouteRecord {
  /** The HTTP method in capitals (`HEAD` routes Fastify adds beside a `GET` are not listed). */
  readonly method: string;
  /** The full path template, `:name` for a path parameter. */
  readonly url: string;
  /** The source file that registered it, from the repository root (`apps/api/src/routes/dropoffs.ts`), or null. */
  readonly file: string | null;
  /** The route runs the API's authentication before its handler. */
  readonly authenticated: boolean;
  /** The names of the other functions that run before its handler (`denyAgentContexts`, `requireOperatorAdmin`). */
  readonly gates: readonly string[];
}

type HookFn = { name: string };
type Hooks = Array<{ event: string; fn: HookFn }>;

const HOOK_EVENTS = new Set(['onRequest', 'preParsing', 'preValidation', 'preHandler']);

/** A stand-in that answers every property read with itself and every call with itself: services that are not there. */
function nothing(): unknown {
  const target = function () {};
  const proxy: unknown = new Proxy(target, {
    get: (_t, property) => {
      if (property === 'then') return undefined;
      if (typeof property === 'symbol') return property === Symbol.toPrimitive ? () => '' : undefined;
      return nothing();
    },
    apply: () => nothing(),
    construct: () => nothing() as object,
  });
  return proxy;
}

/** The repository-relative source path of the first frame outside this file that is under `apps/api`. */
function registrarFile(stack: string | undefined): string | null {
  for (const line of (stack ?? '').split('\n').slice(1)) {
    const match = /[\\/](apps[\\/]api)[\\/](?:dist|src)[\\/]([^:)]+?)\.(?:js|ts)(?::\d+:\d+)?\)?$/.exec(line.trim());
    if (!match) continue;
    const rel = match[2]!.replaceAll('\\', '/');
    if (rel === 'route-table') continue;
    return `apps/api/src/${rel}.ts`;
  }
  return null;
}

/**
 * Every route a deployment registers: the engine's with `null`, STACK's own with its extension.
 * Routes come back sorted by path and method.
 */
export async function collectRouteTable<H extends object = object>(extension: ApiExtension<H> | null): Promise<RouteRecord[]> {
  const app: FastifyInstance = Fastify({ logger: false });
  const hooksOf = new WeakMap<object, Hooks>();

  // Remember which functions each encapsulated scope runs before its routes: a scope adds the
  // authentication or a gate with `addHook`, and the route itself never names it.
  // Fastify's own `addHook`, taken before any scope is wrapped. A child scope inherits its parent's wrapper, so
  // wrapping the inherited one would record the child's hook in the parent too (and register it on the parent),
  // making every later route of the parent look gated by a sibling scope's hooks.
  const fastifyAddHook = app.addHook as unknown as (this: FastifyInstance, ...args: unknown[]) => unknown;
  const track = (instance: FastifyInstance, inherited: Hooks): void => {
    const mine: Hooks = [...inherited];
    hooksOf.set(instance, mine);
    (instance as unknown as { addHook: (...args: unknown[]) => unknown }).addHook = (event: unknown, fn: unknown, ...rest: unknown[]) => {
      if (typeof event === 'string' && HOOK_EVENTS.has(event) && typeof fn === 'function') mine.push({ event, fn: fn as HookFn });
      return fastifyAddHook.call(instance, event, fn, ...rest);
    };
  };
  track(app, []);
  app.addHook('onRegister', (instance) => track(instance, hooksOf.get(Object.getPrototypeOf(instance) as object) ?? []));

  const records = new Map<string, RouteRecord>();
  app.addHook('onRoute', function (this: FastifyInstance, route) {
    const methods = (Array.isArray(route.method) ? route.method : [route.method]).filter((method) => method !== 'HEAD');
    const own: HookFn[] = [];
    for (const key of ['onRequest', 'preParsing', 'preValidation', 'preHandler'] as const) {
      const value = route[key];
      if (Array.isArray(value)) own.push(...(value as HookFn[]));
      else if (typeof value === 'function') own.push(value as HookFn);
    }
    // A function the stand-in services made has no name of its own: it is not one of the API's gates.
    const names = [...(hooksOf.get(this) ?? []).map((hook) => hook.fn), ...own].map((fn) => (typeof fn.name === 'string' ? fn.name : ''));
    const file = registrarFile(new Error().stack);
    for (const method of methods) {
      records.set(`${method} ${route.url}`, {
        method,
        url: route.url,
        file,
        authenticated: names.includes('authenticate'),
        gates: [...new Set(names.filter((name) => name !== 'authenticate' && name !== ''))],
      });
    }
  });

  await registerEngineRoutes(app, nothing() as never, extension);
  await app.ready();
  await app.close();
  return [...records.values()].sort((a, b) => (a.url === b.url ? a.method.localeCompare(b.method) : a.url.localeCompare(b.url)));
}
