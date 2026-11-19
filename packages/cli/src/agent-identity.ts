import { Stack, verifyAgentIdentity } from '@getstackrun/sdk';
import { API_URL } from './api.js';
import { printJson } from './format.js';
import { flag, noExtra } from './control-socket.js';

// Who an agent is, answered on request by STACK: public, so no sign-in is needed and none is sent.
// The lookup is by the key id of a request the agent signed, the host name of its site, or its id.
// The statement STACK signs is checked against STACK's published keys before anything is printed,
// and the facts printed are the signed ones; --no-verify prints the answer unchecked.

function publicStack(): Stack {
  return new Stack({ baseUrl: API_URL });
}

export async function cmdAgentIdentity(args: string[]): Promise<void> {
  const verb = args.shift();

  if (verb === 'lookup') {
    const keyId = flag(args, '--key-id');
    const site = flag(args, '--site');
    const agentId = flag(args, '--agent-id');
    const unchecked = args.includes('--no-verify');
    if (unchecked) args.splice(args.indexOf('--no-verify'), 1);
    noExtra(args);
    const given = [keyId, site, agentId].filter((value) => value !== undefined);
    if (given.length !== 1) throw new Error('Invalid input: give exactly one of --key-id <id>, --site <host> or --agent-id <id>');
    const by = keyId !== undefined ? { keyId } : site !== undefined ? { site } : { agentId: agentId as string };
    const expect = keyId !== undefined ? { key_id: keyId } : site !== undefined ? { site: site.toLowerCase() } : { agent_id: agentId as string };
    const stack = publicStack();
    if (unchecked) return printJson(await stack.agentIdentity.lookup(by));
    const answer = await stack.agentIdentity.lookup(by);
    const keys = { jwksUrl: `${API_URL.replace(/\/$/, '')}/v1/.well-known/jwks.json` };
    const claims = await verifyAgentIdentity(answer.statement, { ...keys, expect });
    return printJson({
      agent: claims.identity.agent,
      owner: claims.identity.owner,
      lookup: claims.identity.lookup,
      valid_until: new Date(claims.exp * 1000).toISOString(),
      statement: answer.statement,
    });
  }

  if (verb === 'urls') {
    const agentId = args.shift();
    if (!agentId || agentId.startsWith('--')) throw new Error('Invalid input: give the agent id');
    noExtra(args);
    return printJson(publicStack().agentIdentity.urls(agentId));
  }

  throw new Error('Invalid input: agent-identity takes lookup or urls');
}
