import { afterEach, describe, expect, it, vi } from 'vitest';
import { cmdAgentIdentity } from './agent-identity.js';

afterEach(() => vi.restoreAllMocks());

describe('agent-identity from the CLI', () => {
  it('prints where an agent\'s lookup and machine files are, with no sign-in', async () => {
    const out = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    await cmdAgentIdentity(['urls', 'agt_Q2x5b3Vkc0FyZUp1c3RlA']);
    const printed = JSON.parse(String(out.mock.calls[0]?.[0])) as Record<string, string>;
    expect(printed['lookup']).toMatch(/\/v1\/agent-identity\?agent_id=agt_Q2x5b3Vkc0FyZUp1c3RlA$/);
    expect(printed['agentCard']).toMatch(/\/v1\/agent-identity\/agents\/agt_Q2x5b3Vkc0FyZUp1c3RlA\/agent-card\.json$/);
    expect(printed['keyDirectory']).toMatch(/http-message-signatures-directory$/);
  });

  it('asks about exactly one thing, and knows no other verb', async () => {
    await expect(cmdAgentIdentity(['lookup'])).rejects.toThrow(/exactly one of --key-id/);
    await expect(cmdAgentIdentity(['lookup', '--key-id', 'a', '--site', 'b.example'])).rejects.toThrow(/exactly one of --key-id/);
    await expect(cmdAgentIdentity(['urls'])).rejects.toThrow(/agent id/);
    await expect(cmdAgentIdentity(['whois'])).rejects.toThrow(/lookup or urls/);
  });
});
