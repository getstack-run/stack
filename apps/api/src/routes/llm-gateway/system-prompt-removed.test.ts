// STACK adds nothing to a call on the customer's own Anthropic or OpenAI key:
// no system prompt and no extra message. The body that leaves the gateway is the
// body the agent sent, less what redaction removed.

import { readdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { LlmGatewayService } from '@stack/vault';
import type { Services } from '../../config/services.js';
import { authorizeBillingHold } from './billing-hold.js';
import { ANTHROPIC_CONFIG, OPENAI_CONFIG } from './provider-configs.js';
import type { AdmittedCall } from './types.js';

function services(): Services {
  return {
    llmUsage: {
      authorizeGateway: vi.fn(async () => ({ bounded: true, denyReason: null, heldCents: 1, pricing: null })),
      releaseGatewayAuthorization: vi.fn(async () => undefined),
    },
    fleetAdmission: { reserve: vi.fn(async () => undefined) },
  } as unknown as Services;
}

function admitted(body: Record<string, unknown>): AdmittedCall {
  return { body, isStreaming: false, operatorId: 'op_1' } as unknown as AdmittedCall;
}

describe('STACK adds no system prompt to a call on the customer own key', () => {
  it('sends an Anthropic body with no system field when the agent sent none', async () => {
    const body = { model: 'claude', max_tokens: 50, messages: [{ role: 'user', content: 'hi' }] };
    const hold = await authorizeBillingHold(services(), ANTHROPIC_CONFIG, admitted(body), null, body);
    expect(hold.providerBody).not.toHaveProperty('system');
    expect((hold.providerBody as { messages: unknown[] }).messages).toEqual(body.messages);
  });

  it('keeps the system prompt the agent sent, untouched, on Anthropic', async () => {
    const body = { model: 'claude', max_tokens: 50, system: 'You are terse.', messages: [{ role: 'user', content: 'hi' }] };
    const hold = await authorizeBillingHold(services(), ANTHROPIC_CONFIG, admitted(body), null, body);
    expect((hold.providerBody as { system: string }).system).toBe('You are terse.');
  });

  it('sends exactly the agent messages on OpenAI, with no system message added', async () => {
    const body = { model: 'gpt-4o', max_tokens: 50, messages: [{ role: 'user', content: 'hi' }] };
    const hold = await authorizeBillingHold(services(), OPENAI_CONFIG, admitted(body), null, body);
    expect((hold.providerBody as { messages: unknown[] }).messages).toEqual([{ role: 'user', content: 'hi' }]);
  });

  it('has no system-prompt stage in the gateway and no injection on the gateway service', () => {
    const stages = readdirSync(dirname(fileURLToPath(import.meta.url)));
    expect(stages).not.toContain('system-prompt.ts');
    expect('injectSystemPrompt' in new LlmGatewayService()).toBe(false);
  });
});
