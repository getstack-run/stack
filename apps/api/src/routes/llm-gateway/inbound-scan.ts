// Stage 6: load the calling agent and scan the untrusted text of the request
// (user and tool messages) for prompt injection. Denies on an enforced-mode
// critical verdict; in other modes the events fire and the request continues.

import type { FastifyRequest } from 'fastify';
import { ForbiddenError, NotFoundError } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { agentDetectorMode } from '../../lib/agent-detector-mode.js';
import type { LlmHandlerConfig } from './provider-configs.js';
import type { AdmittedCall, GatewayAgent } from './types.js';

export async function scanInboundMessages(
  services: Services,
  request: FastifyRequest,
  config: LlmHandlerConfig,
  call: AdmittedCall,
): Promise<GatewayAgent> {
  const { body, jti, agentId, operatorId, mode } = call;
  // 6. Inbound prompt-injection scan. DetectorService.scanInput runs
  //    the L1+L2+L3 chain on user-supplied messages. Contract:
  //    deny-or-allow (denyReason: string | null), NOT redact-and-
  //    forward. On enforced + critical verdicts, 403. On logged or
  //    standard, events fire but the request continues.
  //
  //    PII redaction is a separate concern that runs at step 8 below
  //    (mutate-then-forward via PiiRedactor). The detector scan here
  //    catches prompt-injection attempts; the redactor scrubs
  //    incidental PII before forward.
  // scan ONLY untrusted-role text (user + tool), not the
  // whole transcript. The old code JSON.stringify'd body.messages
  // wholesale, so an agent-runtime's own system prompt + tool schemas
  // were classified as injection (FamilyBot: 5x critical@92 on normal
  // traffic). The trust boundary matches the PII redactor's. When
  // there's no untrusted content at all (e.g. a pure system+assistant
  // continuation), there's nothing external to scan.
  const untrusted = services.llmGateway.extractUntrustedText({
    provider: config.provider,
    body,
  });
  // Agent row hoisted above the scan: eval_traffic gates the
  // L3 spend here, and the mutation flags reuse it below.
  const agent = await services.agent.getById(agentId, operatorId);
  if (!agent) {
    throw new NotFoundError('agent', agentId);
  }
  if (untrusted.untrustedCount > 0) {
    // An account's agent scans as its owner's controls say: off, the local
    // patterns only and nothing refused; on, enforced with the classifier.
    const detection = await agentDetectorMode(services, operatorId, agentId, mode, 'model.call');
    const inScanResult = await services.detector.scanInput({
      ctx: { operatorId, agentId, passportJti: jti, tier: request.operatorTier, ...detection, ...(agent.eval_traffic ? { evalTraffic: true } : {}) },
      body: untrusted.text,
      fieldPath: 'messages',
      metadata: {
        request_service: config.provider,
        request_method: 'POST',
        model: body.model,
        scanned_roles: 'user,tool',
      },
      // outside enforced mode the L3 verdict is recorded but cannot
      // block, so the request does not wait for it. Enforced still waits.
      deferL3: true,
    });
    if (inScanResult.denyReason) {
      throw new ForbiddenError(`LLM request blocked by detector: ${inScanResult.denyReason}`);
    }
  }
  return agent;
}
