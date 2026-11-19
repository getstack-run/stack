import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { vi, type Mock } from 'vitest';
import { API_SRC, type RouteScanner } from '../test/route-scan.js';

export function readScopeLiteral(relativePath: string, exportName: string): string[] {
  const source = readFileSync(join(API_SRC, 'middleware', relativePath), 'utf8');
  const declaration = new RegExp(
    `export const ${exportName} = \\[([\\s\\S]*?)\\] as const`,
  ).exec(source)?.[1];
  if (!declaration) throw new Error(`Missing ${exportName} in ${relativePath}`);
  return [...declaration.matchAll(/['"]([^'"]+)['"]/g)].map((match) => match[1]!);
}

function routeKey(filename: string, method: string, path: string): string {
  if (filename === 'admin-monitoring.ts') {
    return `${method} /v1/admin/monitoring${path}`;
  }
  if (filename === 'admin-challenge.ts') {
    return `${method} /v1/admin/challenge${path}`;
  }
  if (filename.startsWith('admin-')) {
    return `${method} /v1/admin${path}`;
  }
  return `${method} ${path}`;
}

/** The `METHOD /path` of every route the scanner's route files declare, as the scope ceiling keys them. */
export function declaredRouteKeys(scanner: RouteScanner): Set<string> {
  const keys = new Set<string>();
  // Route modules register on `app` (or the encapsulated `instance`). Do not
  // treat repository/Redis `.get()` and `.delete()` calls as Fastify routes.
  const declaration = /\b(?:app|instance)\.(get|post|put|patch|delete)(?:<[\s\S]*?>)?\s*\(\s*["'`]([^"'`]+)["'`]/g;
  // The engine entry's own health check is not a route a bearer reaches.
  for (const filename of scanner.files().filter((name) => !name.startsWith('..'))) {
    const source = scanner.read(filename);
    for (const match of source.matchAll(declaration)) {
      const method = match[1]!.toUpperCase();
      const path = match[2]!;
      if (path.includes('${action}')) {
        for (const action of ['suspend', 'unsuspend']) {
          keys.add(routeKey(filename, method, path.replace('${action}', action)));
        }
      } else {
        keys.add(routeKey(filename, method, path));
      }
    }
  }
  return keys;
}

/** A reply whose header, status and send calls are recorded; each returns the reply, as Fastify's do. */
export interface FakeReply {
  header: Mock;
  status: Mock;
  send: Mock;
}

export function fakeReply(): FakeReply {
  const reply = {
    header: vi.fn(),
    status: vi.fn(),
    send: vi.fn(),
  };
  reply.header.mockReturnValue(reply);
  reply.status.mockReturnValue(reply);
  reply.send.mockReturnValue(reply);
  return reply;
}
