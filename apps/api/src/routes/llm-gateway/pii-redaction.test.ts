// Redaction is a controls feature: without the owner's controls no model call is redacted (whatever the agent's flag says,
// recorded as skipped with -1 hits); with them it runs unless the agent's flag or the account's switch is off.

import { describe, expect, it, vi } from 'vitest';
import { LlmGatewayService, PiiRedactor } from '@stack/vault';
import type { Services } from '../../config/services.js';
import { redactUserPii, type RedactedCall } from './pii-redaction.js';
import type { GatewayAgent } from './types.js';

const BODY = { model: 'm', messages: [{ role: 'user', content: 'write to ada@example.com' }, { role: 'assistant', content: 'ada@example.com' }] };
const call: RedactedCall = { body: BODY, jti: 'pas_1', agentId: 'agt_1', operatorId: 'op_1' };

function services(controls: boolean, scan: object | null = {}) {
  return {
    entitlements: { controlsEnabled: vi.fn(async () => controls) },
    operatorPiiConfig: { resolveScanOptions: vi.fn(async () => scan) },
    llmGateway: new LlmGatewayService(),
    piiRedactor: new PiiRedactor(),
    securityEvent: { record: vi.fn(async () => undefined) },
  } as unknown as Services;
}
const agent = (flag: boolean) => ({ id: 'agt_1', llm_redact_pii: flag }) as unknown as GatewayAgent;
const request = { log: { warn: vi.fn() } } as never;

describe('redactUserPii', () => {
  for (const provider of ['anthropic', 'openai', 'openrouter'] as const) {
    it(`${provider}: with controls on and the flag on, the user message is redacted and the assistant's is not`, async () => {
      const { redactedBody, piiHits } = await redactUserPii(services(true), request, { provider }, call, agent(true));
      const messages = (redactedBody as typeof BODY).messages;
      expect(messages[0]!.content).not.toContain('ada@example.com');
      expect(messages[1]!.content).toBe('ada@example.com');
      expect(piiHits).toBeGreaterThan(0);
    });

    it(`${provider}: without controls nothing is redacted, whatever the agent's flag, and it is recorded as skipped`, async () => {
      for (const flag of [true, false]) {
        const { redactedBody, piiHits } = await redactUserPii(services(false), request, { provider }, call, agent(flag));
        expect(redactedBody).toBe(BODY);
        expect(piiHits).toBe(-1);
      }
    });
  }

  it('with controls on, an agent whose flag is off is not redacted', async () => {
    const { redactedBody, piiHits } = await redactUserPii(services(true), request, { provider: 'openai' }, call, agent(false));
    expect(redactedBody).toBe(BODY);
    expect(piiHits).toBe(-1);
  });

  it('with controls on, an account that switched redaction off is not redacted', async () => {
    const { redactedBody, piiHits } = await redactUserPii(services(true, null), request, { provider: 'openai' }, call, agent(true));
    expect(redactedBody).toBe(BODY);
    expect(piiHits).toBe(-1);
  });

  it("does not read the account's redaction settings without controls, and fails closed when controls cannot be read", async () => {
    const off = services(false);
    await redactUserPii(off, request, { provider: 'openai' }, call, agent(true));
    expect(off.operatorPiiConfig.resolveScanOptions).not.toHaveBeenCalled();
    const broken = services(true);
    (broken.entitlements.controlsEnabled as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('unreadable'));
    await expect(redactUserPii(broken, request, { provider: 'openai' }, call, agent(true))).rejects.toThrow('unreadable');
  });
});
