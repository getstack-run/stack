// `stack quickstart` / `stack init` — the guided zero-to-first-governed-
// LLM-call flow.
//
// Every primitive to make a governed LLM call already exists; nothing
// sequences them, and the register-agent defaults are the opposite of what
// a "just let it run" bot wants. This command sequences the paved road and
// ends in proof — an audit row from a real call:
//
//   1. confirm the operator is signed in (no account creation here — that
//      is dashboard-only, magic-link)
//   2. confirm the LLM provider is connected (can't connect from the CLI —
//      the vault credential is added via the dashboard); guide there if not
//   3. register an agent with profile: 'proxied-llm-bot' (proxy_only +
//      logged + stack_managed) so the first call just works
//   4. open a Mission + its passport (POST /v1/missions/start), make ONE
//      real LLM call through the STACK gateway, then complete the Mission
//   5. print the audit row that call produced — "it worked, here's proof"
//
// No footgun decisions: the only inputs are the provider and an agent name,
// both with sane defaults.

import { env, stdout, stderr } from 'node:process';
import { createInterface } from 'node:readline/promises';
import { Stack, type LlmProvider } from '@getstackrun/sdk';
import { findAgentByName } from './agent-lookup.js';
import { api, takeFlag } from './api.js';
import { getAccessToken, invokeHint } from './auth.js';
import { governedApi } from './governance.js';

const DASHBOARD_URL = 'https://getstack.run';

const PROVIDER_CALLS: Record<
  LlmProvider,
  (stack: Stack, session: unknown) => Promise<unknown>
> = {
  anthropic: (stack, session) =>
    stack.llm.anthropic.messages.create(
      {
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 32,
        messages: [{ role: 'user', content: 'Reply with the single word: works' }],
      },
      { passport: session as never },
    ),
  openai: (stack, session) =>
    stack.llm.openai.chat.completions.create(
      {
        model: 'gpt-4o-mini',
        max_tokens: 32,
        messages: [{ role: 'user', content: 'Reply with the single word: works' }],
      },
      { passport: session as never },
    ),
  openrouter: (stack, session) =>
    stack.llm.openrouter.chat.completions.create(
      {
        model: 'openai/gpt-4o-mini',
        max_tokens: 32,
        messages: [{ role: 'user', content: 'Reply with the single word: works' }],
      },
      { passport: session as never },
    ),
};

interface QuickstartConnection {
  id: string;
  scopes?: string[];
}

interface QuickstartPermission {
  service_connection_id: string;
}

interface QuickstartAgent {
  id: string;
  name: string;
  status?: string;
  credential_access?: string;
  accountability_mode?: string;
  key_mode?: string;
}

export function quickstartAgentProfileProblem(agent: QuickstartAgent): string | undefined {
  const expected = {
    credential_access: 'proxy_only',
    accountability_mode: 'logged',
    key_mode: 'stack_managed',
  } as const;
  const mismatches = Object.entries(expected)
    .filter(([field, value]) => agent[field as keyof typeof expected] !== value)
    .map(
      ([field, value]) =>
        `${field}=${String(agent[field as keyof typeof expected] ?? 'unknown')} (expected ${value})`,
    );
  return mismatches.length > 0 ? mismatches.join(', ') : undefined;
}

export function quickstartGrantBody(
  connection: QuickstartConnection,
  permissions: QuickstartPermission[],
  agentId: string,
): Record<string, unknown> | undefined {
  if (permissions.some((grant) => grant.service_connection_id === connection.id)) return undefined;
  const scopes = connection.scopes ?? [];
  if (scopes.length === 0) throw new Error('the selected provider connection has no grantable scopes.');
  return {
    agent_id: agentId,
    service_connection_id: connection.id,
    scopes,
  };
}

interface QuickstartMissionStart {
  mission_id: string;
  expires_at: string;
  passport: { token: string; jti: string; expires_at: string };
}

/** Operator-form body for POST /v1/missions/start: one short Mission, one passport. */
export function quickstartMissionStartBody(agentId: string, provider: LlmProvider): Record<string, unknown> {
  return {
    agent_id: agentId,
    mission: {
      intent_summary: `quickstart: one governed ${provider} call`,
      intent_services: [provider],
      expires_in_seconds: 900,
    },
  };
}

async function completeMission(missionId: string): Promise<void> {
  try {
    await api('POST', `/v1/missions/${encodeURIComponent(missionId)}/complete`, { body: {} });
  } catch (err) {
    stderr.write(
      `  note: could not complete Mission ${missionId} (${(err as Error).message}); it expires on its own.\n`,
    );
  }
}

async function prompt(question: string, fallback: string): Promise<string> {
  // Non-interactive (piped / CI): take the fallback silently.
  if (!process.stdin.isTTY) return fallback;
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = (await rl.question(`${question} [${fallback}]: `)).trim();
    return answer || fallback;
  } finally {
    rl.close();
  }
}

export async function cmdQuickstart(args: string[]): Promise<void> {
  const baseUrl = env['STACK_API_URL'] ?? 'https://api.getstack.run';
  // Flags let a non-interactive caller skip the prompts entirely.
  const providerFlag = takeFlag(args, '--provider');
  const agentFlag = takeFlag(args, '--agent');

  // 1. Signed in?
  const token = await getAccessToken();
  if (!token) {
    stderr.write(
      `\n  You're not signed in. Two one-time steps in the dashboard first:\n\n` +
        `    1. Create your account (magic link):  ${DASHBOARD_URL}\n` +
        `    2. Connect an LLM provider (Anthropic/OpenAI):  ${DASHBOARD_URL}/services\n\n` +
        `  Then sign this CLI in and re-run:\n` +
        `    ${invokeHint('auth login')}\n` +
        `    ${invokeHint(`quickstart --provider ${typeof providerFlag === 'string' ? providerFlag : 'anthropic'}`)}\n\n`,
    );
    process.exit(1);
  }

  const opStack = new Stack({ baseUrl });

  // 2. Which provider — and is it connected?
  const providerInput = (
    typeof providerFlag === 'string' && providerFlag
      ? providerFlag
      : await prompt('  LLM provider (anthropic/openai/openrouter)', 'anthropic')
  ).trim() as LlmProvider;
  if (!(['anthropic', 'openai', 'openrouter'] as string[]).includes(providerInput)) {
    stderr.write(`error: provider must be anthropic, openai, or openrouter (got "${providerInput}").\n`);
    process.exit(2);
  }

  let connected: Array<{ id: string; provider: string; status: string; scopes?: string[] }>;
  try {
    connected = (await opStack.services.listConnected()) as Array<{
      id: string;
      provider: string;
      status: string;
      scopes?: string[];
    }>;
  } catch (err) {
    stderr.write(`error: could not list connected services (${(err as Error).message}).\n`);
    process.exit(1);
  }
  const providerConnection = connected.find((c) => c.provider === providerInput && c.status === 'active');
  if (!providerConnection) {
    stderr.write(
      `\n  ${providerInput} is not connected on this operator yet.\n` +
        `  Connect it in the dashboard (the API key goes in the vault, not on this box):\n\n` +
        `    ${DASHBOARD_URL}/services\n\n` +
        `  Then re-run:  ${invokeHint(`quickstart --provider ${providerInput}`)}\n\n`,
    );
    process.exit(1);
  }

  // 3. Register the agent with the safe preset. Reuse a same-named agent
  //    only when its security posture is exactly the one this flow promises.
  const agentName = (
    typeof agentFlag === 'string' && agentFlag ? agentFlag : await prompt('  Agent name', 'quickstart-bot')
  ).trim();

  let agentId: string;
  const existing = findAgentByName((await opStack.agents.list()) as QuickstartAgent[], agentName);
  if (existing) {
    const profileProblem = quickstartAgentProfileProblem(existing);
    if (profileProblem) {
      stderr.write(
        `error: an agent named "${agentName}" already exists with a different security posture:\n` +
          `  ${profileProblem}\n` +
          `Choose another name, for example:\n` +
          `  ${invokeHint(`quickstart --provider ${providerInput} --agent ${agentName}-stack`)}\n`,
      );
      process.exit(1);
    }
    agentId = existing.id;
    stdout.write(
      `  ✓ using existing ${agentName} (${agentId}) — proxy_only + logged + stack_managed\n`,
    );
  } else {
    const agent = await governedApi<QuickstartAgent>('POST', '/v1/agents/register', {
      body: { name: agentName, profile: 'proxied-llm-bot' },
    });
    agentId = agent.id;
    stdout.write(
      `  ✓ registered ${agentName} (${agentId}) — proxy_only + logged + stack_managed\n`,
    );
  }

  // The intent can only narrow an existing service grant. It cannot create
  // one. Keep an existing grant unchanged. Create the missing grant from the
  // connection's own scope ceiling before passport issuance.
  const permissions = await api<Array<{ service_connection_id: string }>>(
    'GET',
    `/v1/agents/${encodeURIComponent(agentId)}/permissions`,
  );
  let grantBody: Record<string, unknown> | undefined;
  try {
    grantBody = quickstartGrantBody(providerConnection, permissions, agentId);
  } catch {
    stderr.write(
      `error: the ${providerInput} connection has no grantable scopes. Verify the connection in the Console.\n`,
    );
    process.exit(1);
  }
  if (grantBody) {
    await governedApi('POST', '/v1/services/grant', { body: grantBody });
    stdout.write(`  ✓ granted ${providerInput} to ${agentName}\n`);
  }

  // 4. Open a Mission + issue its passport in one call, then make one real
  //    governed LLM call. The preset creates a stack_managed agent (no
  //    on-box keypair — STACK signs server-side), so we authenticate as
  //    the operator and use the operator form of POST /v1/missions/start.
  //    The passport's intent defaults to the Mission's summary + services,
  //    which logged-mode agents need at issue time.
  stdout.write(`  … opening a Mission and making one governed ${providerInput} call\n`);

  let started: QuickstartMissionStart;
  try {
    started = await api<QuickstartMissionStart>('POST', '/v1/missions/start', {
      body: quickstartMissionStartBody(agentId, providerInput),
    });
  } catch (err) {
    stderr.write(`error: could not open a Mission and issue its passport (${(err as Error).message}).\n`);
    process.exit(1);
  }

  try {
    await PROVIDER_CALLS[providerInput](opStack, started.passport.token);
  } catch (err) {
    stderr.write(
      `error: the governed ${providerInput} call failed (${(err as Error).message}).\n` +
        `If this is a scope error, ensure the agent is granted ${providerInput}.\n`,
    );
    await completeMission(started.mission_id);
    process.exit(1);
  }

  stdout.write(`  ✓ call succeeded\n`);
  // The one call is the whole job: close the Mission so its passport
  // stops working now instead of at expiry.
  await completeMission(started.mission_id);

  // 5. Proof — the audit row that call produced.
  try {
    const { entries } = await opStack.audit.list({ agentId, limit: 1 });
    const row = entries[0];
    if (row) {
      const ts = new Date(row.timestamp).toISOString();
      stdout.write(
        `\n  Here's your proof — the call landed in the tamper-evident audit chain:\n\n` +
          `    ${ts}  ${row.action}  →  ${row.outcome}  (agent ${agentId})\n` +
          `    entry_hash ${row.entry_hash.slice(0, 16)}…\n\n` +
          `  What just happened: a real ${providerInput} call went through STACK. The provider\n` +
          `  key never touched this box — it stayed in the vault and was injected at the gateway.\n\n` +
          `  Keep going:\n` +
          `    • Drop-in for any existing tool:   ${invokeHint(`proxy serve --agent ${agentName}`)}\n` +
          `    • Watch calls live:                ${invokeHint('monitor --follow')}\n` +
          `    • See spend:                       ${invokeHint('llm usage summary')}\n\n`,
      );
    } else {
      stdout.write(`\n  Call succeeded. (Audit row not yet visible — it lands within a moment.)\n\n`);
    }
  } catch {
    stdout.write(`\n  Call succeeded. (Could not read the audit tail just now.)\n\n`);
  }
}
