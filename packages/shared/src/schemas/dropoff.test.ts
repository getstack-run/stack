import { describe, expect, it } from 'vitest';
import { CreateDropoffInput, namedDropoffRecipients } from './dropoff.js';

const schema = { type: 'object' };

function parse(input: Record<string, unknown>) {
  return CreateDropoffInput.parse({ from_agent: 'agt_a', schema, ...input });
}

describe('the agents a drop-off names', () => {
  it('reads one agent from to_agent, as before', () => {
    expect(namedDropoffRecipients(parse({ to_agent: 'agt_b' }))).toEqual(['agt_b']);
  });

  it('reads a group from to_agents, in the order named', () => {
    expect(namedDropoffRecipients(parse({ to_agents: ['agt_c', 'agt_b', 'agt_d'] }))).toEqual(['agt_c', 'agt_b', 'agt_d']);
  });

  it('wants exactly one of to_agent and to_agents', () => {
    expect(() => namedDropoffRecipients(parse({}))).toThrow(/not both/);
    expect(() => namedDropoffRecipients(parse({ to_agent: 'agt_b', to_agents: ['agt_c'] }))).toThrow(/not both/);
  });

  it('refuses an agent named twice and a group that names its own sender', () => {
    expect(() => namedDropoffRecipients(parse({ to_agents: ['agt_b', 'agt_b'] }))).toThrow(/more than once/);
    expect(() => namedDropoffRecipients(parse({ to_agents: ['agt_b', 'agt_a'] }))).toThrow(/own sender/);
  });

  it('takes a group of any size and refuses an empty one before any service sees it', () => {
    const many = Array.from({ length: 25 }, (_, index) => `agt_${index}`);
    expect(namedDropoffRecipients(parse({ to_agents: many }))).toHaveLength(25);
    expect(() => parse({ to_agents: [] })).toThrow();
  });

  it('takes any time to live from a minute, with no longest', () => {
    for (const ttl of [60, 1800, 86_400, 7 * 86_400]) expect(() => parse({ to_agent: 'agt_b', ttl_seconds: ttl })).not.toThrow();
    expect(() => parse({ to_agent: 'agt_b', ttl_seconds: 59 })).toThrow();
  });
});
