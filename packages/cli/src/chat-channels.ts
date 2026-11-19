import { api, takeFlag } from './api.js';
import { printJson } from './format.js';

// Chat channels: the Telegram, text and Slack identities an owner approves a
// small held payment from (only within the per-payment and per-day limits set
// in the policy's `review.chat`; there is no default, so it is off until set).
//
// Binding is the owner's own act in the console, signed in in their own browser.
// This command starts one and prints what to carry into the chat; typing a text's
// code, confirming an identity the chat proved and installing STACK's Slack app
// are done in the console (the CLI's sign-in is not a dashboard session, so the
// API refuses them here). Ending an identity only narrows who can approve, so
// `remove` works from here.

const USAGE = 'chat takes list, link, remove, slack-install-url or slack-remove';

function flag(args: string[], name: string): string | undefined {
  const value = takeFlag(args, name);
  if (value === true) throw new Error(`${name} needs a value`);
  return typeof value === 'string' ? value : undefined;
}

function required(args: string[], name: string): string {
  const value = flag(args, name);
  if (value === undefined) throw new Error(`${name} is required`);
  return value;
}

function positional(args: string[], what: string): string {
  const value = args[0] && !args[0].startsWith('--') ? args.shift() : undefined;
  if (!value) throw new Error(`Invalid input: ${what} is required`);
  return value;
}

function noExtra(args: string[]): void {
  if (args.length > 0) throw new Error(`Unexpected arguments: ${args.join(' ')}`);
}

export async function cmdChat(args: string[]): Promise<void> {
  const sub = args.shift();

  if (sub === 'list') {
    noExtra(args);
    return printJson(await api('GET', '/v1/chat-channels'));
  }

  if (sub === 'link') {
    const channel = positional(args, 'the channel (telegram, sms or slack)');
    if (channel !== 'telegram' && channel !== 'sms' && channel !== 'slack') {
      throw new Error('Invalid input: the channel is telegram, sms or slack');
    }
    const phone = flag(args, '--phone');
    noExtra(args);
    if ((channel === 'sms') !== (phone !== undefined)) throw new Error('A phone number (--phone) goes with sms, and only sms');
    return printJson(await api('POST', '/v1/chat-channels/identities', { body: { channel, ...(phone !== undefined ? { phone } : {}) } }));
  }

  if (sub === 'remove') {
    const id = positional(args, 'identity id');
    noExtra(args);
    await api('DELETE', `/v1/chat-channels/identities/${encodeURIComponent(id)}`, { expectEmpty: true });
    return printJson({ removed: true, id });
  }

  if (sub === 'slack-install-url') {
    const redirectUri = required(args, '--redirect-uri');
    const state = required(args, '--state');
    noExtra(args);
    return printJson(await api('GET', '/v1/chat-channels/slack/install-url', { query: { redirect_uri: redirectUri, state } }));
  }

  if (sub === 'slack-remove') {
    noExtra(args);
    await api('DELETE', '/v1/chat-channels/slack', { expectEmpty: true });
    return printJson({ removed: true });
  }

  throw new Error(USAGE);
}
