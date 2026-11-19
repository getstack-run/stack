import { existsSync } from 'node:fs';
import { defineConfig } from 'drizzle-kit';

// The engine's Drizzle configuration: the engine schema alone, and the engine's migration chain.
//
// The chain is a folder of hand-written SQL, `drizzle-engine` or `drizzle`, so `out` names whichever folder the
// tree has.
export default defineConfig({
  schema: './src/db/schema/index.ts',
  out: existsSync('./drizzle-engine') ? './drizzle-engine' : './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    // Needed by `migrate` and `push`; `generate` reads no database.
    url: process.env['DATABASE_URL'] ?? '',
  },
});
