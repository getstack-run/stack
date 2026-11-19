/**
 * Seed script — populates the service catalog.
 * Run: npx tsx src/db/seed.ts
 */
import { createDb } from './connection.js';
import { services } from './schema/index.js';
import { isNull } from 'drizzle-orm';

async function seed() {
  const DATABASE_URL = process.env['DATABASE_URL'];
  if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
  const db = createDb(DATABASE_URL);

  console.log('Seeding service catalog...');

  await db
    .insert(services)
    .values([
      {
        id: 'svc_slack',
        provider: 'slack',
        name: 'Slack',
        description: 'Team messaging and collaboration platform',
        oauth_auth_url: 'https://slack.com/oauth/v2/authorize',
        oauth_token_url: 'https://slack.com/api/oauth.v2.access',
        scopes_available: [
          'channels:read',
          'channels:write',
          'chat:write',
          'chat:read',
          'users:read',
          'files:read',
          'files:write',
        ],
        available: true,
      },
      {
        id: 'svc_github',
        provider: 'github',
        name: 'GitHub',
        description: 'Code hosting and collaboration platform',
        oauth_auth_url: 'https://github.com/login/oauth/authorize',
        oauth_token_url: 'https://github.com/login/oauth/access_token',
        scopes_available: ['repo', 'repo:read', 'repo:write', 'user:read', 'org:read', 'issues:read', 'issues:write'],
        available: true,
      },
      {
        id: 'svc_notion',
        provider: 'notion',
        name: 'Notion',
        description: 'Workspace for docs, wikis, and project management',
        oauth_auth_url: 'https://api.notion.com/v1/oauth/authorize',
        oauth_token_url: 'https://api.notion.com/v1/oauth/token',
        scopes_available: ['read_content', 'update_content', 'insert_content', 'read_users'],
        available: true,
      },
    ])
    .onConflictDoNothing({
      target: services.provider,
      where: isNull(services.operator_id),
    });

  console.log('Seed complete.');
  process.exit(0);
}

seed().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
