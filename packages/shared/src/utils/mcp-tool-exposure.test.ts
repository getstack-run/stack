import { describe, expect, it } from 'vitest';
import { CATALOGUE_TOOL_AUDIENCES } from '../constants/catalogue.js';
import { isToolListed, MCP_AUDIENCES, type McpToolListing, type McpToolSession } from './mcp-tool-exposure.js';

const agent = (...pieces: string[]): McpToolSession => ({ audience: 'agent', pieces: new Set(pieces) });
const owner = (...pieces: string[]): McpToolSession => ({ audience: 'owner', pieces: new Set(pieces) });
const tool = (audience: McpToolListing['audience'], ...pieces: string[]): McpToolListing => ({ audience, pieces });

describe('which tools a session lists', () => {
  it('lists the core to the audience it is for', () => {
    expect(isToolListed(tool('both'), agent())).toBe(true);
    expect(isToolListed(tool('both'), owner())).toBe(true);
    expect(isToolListed(tool('agent'), agent())).toBe(true);
    expect(isToolListed(tool('agent'), owner())).toBe(false);
  });

  it('never lists an owner\'s tool to an agent, and lists it to an owner whether or not its piece is on', () => {
    expect(isToolListed(tool('owner', 'post'), agent('post'))).toBe(false);
    expect(isToolListed(tool('owner'), agent())).toBe(false);
    expect(isToolListed(tool('owner', 'post'), owner())).toBe(true);
    expect(isToolListed(tool('owner'), owner())).toBe(true);
  });

  it('lists a tool of a piece only while a piece it names is on', () => {
    expect(isToolListed(tool('both', 'inbox'), agent())).toBe(false);
    expect(isToolListed(tool('both', 'inbox'), agent('inbox'))).toBe(true);
    expect(isToolListed(tool('both', 'inbox'), agent('post'))).toBe(false);
    expect(isToolListed(tool('both', 'inbox', 'phone'), agent('phone'))).toBe(true);
    expect(isToolListed(tool('both', 'inbox'), owner())).toBe(false);
    expect(isToolListed(tool('both', 'inbox'), owner('inbox'))).toBe(true);
    // An agent-only tool of a piece is never an owner's, whatever is on.
    expect(isToolListed(tool('agent', 'wallet'), owner('wallet'))).toBe(false);
    expect(isToolListed(tool('agent', 'wallet'), agent('wallet'))).toBe(true);
  });

  it('is the same three audiences the catalogue names', () => {
    expect([...MCP_AUDIENCES]).toEqual([...CATALOGUE_TOOL_AUDIENCES]);
  });
});
