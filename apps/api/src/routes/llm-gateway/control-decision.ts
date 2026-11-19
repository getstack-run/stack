import type { FastifyRequest } from 'fastify';
import type { Services } from '../../config/services.js';
import { decideControl } from '../../lib/control-decision.js';
import { controlTargets } from '../../lib/control-socket/targets.js';
import type { LlmHandlerConfig } from './provider-configs.js';
import { maxOutputTokens } from './request-shaping.js';
import type { AdmittedCall } from './types.js';

/**
 * The customer's decider, asked once per model call (a stream included: one
 * round trip before the first token, nothing per chunk). Runs after Mission
 * admission and the inbound scan, before the billing hold and before the
 * provider credential is retrieved, so a refusal costs nothing and reaches no
 * provider. Asked only for an agent account's agent; any other agent keeps
 * today's controls.
 */
export async function decideModelCall(
  services: Pick<Services, 'controlDecisions' | 'accountDirectory'>,
  request: FastifyRequest,
  config: LlmHandlerConfig,
  call: AdmittedCall,
  runtime: { passportJti: string; missionId: string },
): Promise<void> {
  await decideControl(services, request, {
    action: 'model.call',
    scope: 'agent',
    agentId: call.agentId,
    runtime,
    target: controlTargets.modelCall({
      provider: config.provider,
      model: call.body['model'],
      stream: call.isStreaming,
      maxOutputTokens: maxOutputTokens(call.body),
    }),
  });
}
