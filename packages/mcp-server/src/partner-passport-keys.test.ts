import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createStackMcpServer } from './index.js';

// Which key set verifies a partner tenant's passport. A passport is signed with the deployment's key whoever it is
// issued for (`stk.operator_id` names the tenant); a tenant's own per-operator keys sign claim envelopes only. The
// tool's text is what a partner's engineer reads to decide where to fetch keys, so it must say the deployment's and
// must not send them to the tenant's JWKS, where a passport's signature can never verify. The behaviour itself is
// pinned by M10 in packages/vault/src/services/passport-service.mission-required.test.ts.

async function description(name: string): Promise<string> {
  const server = createStackMcpServer('http://api.test', 'oauth_access_token', { profile: 'standard' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'partner-keys-test', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const tool = (await client.listTools()).tools.find((t) => t.name === name);
  expect(tool, name).toBeDefined();
  return tool!.description ?? '';
}

describe('the partner tenant passport tool', () => {
  it("tells the reader to verify against the deployment's JWKS, not the tenant's", async () => {
    const text = await description('stack_partner_issue_account_passport');
    expect(text).toMatch(/deployment's signing key/);
    expect(text).toContain('/v1/.well-known/jwks.json');
    expect(text).not.toMatch(/signed with the tenant's/i);
    expect(text).not.toMatch(/verifies offline against the tenant's JWKS/i);
  });
});
