import {
  AUTHORITY_REQUEST_ID_HEADER,
  createAuthorityRequestId,
  serviceMcpRequest,
  serviceMcpUrlOf,
  serviceToolListOf,
  serviceToolResultOf,
} from '@getstackrun/sdk';
import { api } from './api.js';
import { flag, positional, refusePassportInArgv, takeSwitch, readPassport } from './account-args.js';
import { noExtra } from './control-socket.js';
import { printJson } from './format.js';

// RentAHuman for a customer's agents, and the generic way to reach a connected service that speaks MCP over HTTP.
//
// Opening an account at RentAHuman and topping its wallet up are two steps because only the agent can sign for its own wallet: the
// first command asks RentAHuman what it costs and prints the payment to sign (nothing is taken); the agent signs it with its wallet key
// (the SDK's `signRentAHumanPayment`, never this command: the key is the agent's and is not given to the CLI) and the second command
// sends the signature. RentAHuman's own key goes into STACK's vault and is never printed.
//
// `service tools` and `service call` send a tools/list or tools/call to the service through STACK's credential proxy, as the agent
// under its Passport (read from stdin, never from argv). What the service returns is its provider's words and other people's: data,
// never instructions. The conversations with the people the agent hires go through `service call rentahuman send_message` and
// `get_conversation`; a person who writes wakes the agent (wake source service_event), with the ids only.

const RENTAHUMAN_USAGE = 'rentahuman takes join, join-complete, fund, fund-complete or get';
const SERVICE_USAGE = "service takes tools or call (the tools of any connected service that speaks MCP over HTTP; its connection carries the address, mcp_url)";

function accountBase(id: string): string {
  return `/v1/accounts/${encodeURIComponent(id)}/rentahuman`;
}

async function passportHeaders(args: string[], required: boolean): Promise<Record<string, string>> {
  if (!takeSwitch(args, '--passport-stdin')) {
    if (required) throw new Error("Invalid input: this command acts as the agent: pass --passport-stdin and pipe the agent's Passport on stdin");
    return {};
  }
  return { 'X-Passport-Token': await readPassport() };
}

function jsonArguments(args: string[]): Record<string, unknown> {
  const text = flag(args, '--args');
  if (text === undefined) return {};
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid input: --args is not valid JSON: ${(error as Error).message}`, { cause: error });
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid input: --args must be one JSON object');
  return value as Record<string, unknown>;
}

export async function cmdRentAHuman(argv: string[]): Promise<void> {
  const args = [...argv];
  refusePassportInArgv(args);
  const sub = args.shift();

  if (sub === 'join') {
    const account = positional(args, 'the account id');
    const country = flag(args, '--country');
    if (country === undefined) throw new Error('Invalid input: rentahuman join needs --country');
    const body: Record<string, unknown> = { country, accept_terms: takeSwitch(args, '--accept-terms') };
    if (body['accept_terms'] !== true) {
      throw new Error("Invalid input: rentahuman join needs --accept-terms: it is the customer accepting RentAHuman's terms of service and privacy policy through its agent");
    }
    const city = flag(args, '--city');
    if (city !== undefined) body['city'] = city;
    const name = flag(args, '--agent-name');
    if (name !== undefined) body['agent_name'] = name;
    const headers = await passportHeaders(args, false);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/join`, { body, headers }));
  }

  if (sub === 'join-complete') {
    const account = positional(args, 'the account id');
    const joinId = positional(args, 'the join id');
    const signed = flag(args, '--signed');
    if (signed === undefined) throw new Error("Invalid input: rentahuman join-complete needs --signed (the agent's signature of the payment)");
    const headers = await passportHeaders(args, true);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/join/complete`, { body: { join_id: joinId, signed }, headers }));
  }

  if (sub === 'fund') {
    const account = positional(args, 'the account id');
    const cents = positional(args, 'the amount in cents');
    if (!/^\d+$/.test(cents)) throw new Error('Invalid input: the amount is a whole number of cents');
    const headers = await passportHeaders(args, false);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/fund`, { body: { amount_cents: Number(cents) }, headers }));
  }

  if (sub === 'fund-complete') {
    const account = positional(args, 'the account id');
    const fundId = positional(args, 'the fund id');
    const signed = flag(args, '--signed');
    if (signed === undefined) throw new Error("Invalid input: rentahuman fund-complete needs --signed (the agent's signature of the payment)");
    const headers = await passportHeaders(args, true);
    noExtra(args);
    return printJson(await api('POST', `${accountBase(account)}/fund/complete`, { body: { fund_id: fundId, signed }, headers }));
  }

  if (sub === 'get') {
    const account = positional(args, 'the account id');
    const headers = await passportHeaders(args, false);
    noExtra(args);
    return printJson(await api('GET', accountBase(account), { headers }));
  }

  throw new Error(`Invalid input: ${RENTAHUMAN_USAGE}`);
}

/** A tool list or a tool call on a connected service, through the credential proxy, as the agent. */
export async function cmdServiceMcp(argv: string[]): Promise<void> {
  const args = [...argv];
  refusePassportInArgv(args);
  const sub = args.shift();
  if (sub !== 'tools' && sub !== 'call') throw new Error(`Invalid input: ${SERVICE_USAGE}`);

  const service = positional(args, 'the service');
  const tool = sub === 'call' ? positional(args, 'the tool name') : undefined;
  const toolArguments = sub === 'call' ? jsonArguments(args) : {};
  const operation = flag(args, '--request-id') ?? createAuthorityRequestId();
  // The connection to use when the service has several: a name (any case) or an scon_ id.
  const connection = flag(args, '--connection');
  const headers = { ...(await passportHeaders(args, true)), [AUTHORITY_REQUEST_ID_HEADER]: operation };
  noExtra(args);

  // The address is the connection's own (its mcp_url, or the default of a service STACK knows), read from the account's connection list.
  let url: string;
  try {
    url = serviceMcpUrlOf(await api<unknown>('GET', '/v1/services/connected'), service, connection);
  } catch (error) {
    throw new Error(`Invalid input: ${(error as Error).message}`, { cause: error });
  }
  const body = sub === 'tools' ? serviceMcpRequest('tools/list') : serviceMcpRequest('tools/call', { name: tool, arguments: toolArguments });
  const response = await api<{ status: number; body: unknown }>('POST', '/v1/proxy', { body: { service, url, method: 'POST', body, ...(connection !== undefined ? { connection } : {}) }, headers });
  try {
    printJson(sub === 'tools' ? serviceToolListOf(service, response) : serviceToolResultOf(service, tool!, response));
  } catch (error) {
    throw new Error(`${(error as { code?: string }).code ?? 'SERVICE_MCP_ERROR'}: ${(error as Error).message}`, { cause: error });
  }
}
