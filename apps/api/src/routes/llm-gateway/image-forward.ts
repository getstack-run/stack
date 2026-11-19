// The forward stage of an image call on the customer's own key. Forwards the
// call, saves the pictures to the agent's drive (private to the agent), marks
// what comes back untrusted, scans the words the provider adds, records the
// call, and replies with files rather than bytes.
//
// The provider bills the customer, so there is nothing to hold or settle here:
// STACK counted one action and charges nothing else. A provider's refusal comes
// back with its status and body, as a chat call's does.

import { guardedDownload, presentGeneratedFile } from '@stack/vault';
import { ServiceUnavailableError, type GeneratedFile, type LlmImageProvider, type LlmImageResult } from '@stack/shared';
import {
  completeRuntimeAuthorityUse,
  markRuntimeAuthorityDispatched,
  runtimeAuthorityFailureResult,
} from '../../lib/runtime-authority.js';
import { recordLlmResponseProvenance } from '../../lib/provenance.js';
import { writePostCallTelemetry } from './post-call-telemetry.js';
import { imagesIn } from './image-request.js';
import type { ForwardContext } from './types.js';

export interface ImageForwardContext extends Omit<ForwardContext, 'hold'> {
  /** The body that leaves for the provider, built from the accepted fields with the redacted prompt. */
  providerBody: Record<string, unknown>;
  /** How many pictures the call asked for. */
  asked: number;
}

export async function forwardImageResponse(ctx: ImageForwardContext): Promise<void> {
  const { services, request, reply, config, start, call, gate, approvalIdHeader, apiKey, carriedSources, piiHits, providerBody, asked } = ctx;
  const { body, claims, jti, agentId, operatorId, mode, missionIds, missionRef, authorityDecision } = call;
  const provider = config.provider as LlmImageProvider;
  const requestBodyStr = JSON.stringify(providerBody);
  await markRuntimeAuthorityDispatched(services.authority, operatorId, authorityDecision);
  try {
    let answer;
    try {
      answer = await services.llmGateway.forwardImages({ provider, apiKey, body: providerBody });
    } catch {
      // Nothing the provider said, and nothing of the key, in the answer.
      throw new ServiceUnavailableError(`${provider} could not be reached for this image. Nothing was made or charged by STACK.`);
    }
    const success = answer.status >= 200 && answer.status < 300;

    let result: LlmImageResult | null = null;
    let replyBody: unknown = answer.body;
    if (success) {
      const images = imagesIn(answer.body, asked);
      // The words the provider adds are scanned like any model output; the pictures are bytes and are not text.
      let revised = images.map((image) => image.revisedPrompt).filter((text): text is string => text !== null);
      if (revised.length > 0) {
        const scanned = await services.detector.scanOutput({
          ctx: { operatorId, agentId, passportJti: jti, mode, tier: request.operatorTier },
          body: revised.join('\n'),
          headers: {},
          metadata: { response_status: answer.status, request_service: provider, request_method: 'POST', model: body['model'] },
        });
        if (scanned.redactedBody !== null) revised = [];
      }
      const owner = { operatorId, agentId, missionId: missionRef };
      const origin = { tool: `model:${provider}/${String(body['model'])}`, toolRunId: `img_${jti.slice(-12)}_${start.toString(36)}` };
      const files: GeneratedFile[] = [];
      for (const [index, image] of images.entries()) {
        let bytes: Buffer | null = image.base64 ? Buffer.from(image.base64, 'base64') : null;
        let mediaType = image.mediaType;
        if (!bytes && image.url) {
          try {
            const downloaded = await guardedDownload(image.url);
            bytes = downloaded.bytes;
            if (downloaded.contentType) mediaType = downloaded.contentType.split(';')[0]!.trim() || mediaType;
          } catch {
            bytes = null;
          }
        }
        const extension = mediaType.split('/')[1] ?? 'png';
        files.push(await presentGeneratedFile(
          services.generatedFiles,
          owner,
          origin,
          { name: `image-${origin.toolRunId}-${index + 1}.${extension}`.slice(0, 120), contentType: mediaType, bytes, sourceUrl: image.url },
        ));
      }
      result = { provider, model: String(body['model']), untrusted: true, key: 'own', files, revised_prompts: revised };
      replyBody = result;
      // The picture inherits the sources its prompt carried; recorded before the agent receives it.
      await recordLlmResponseProvenance(services, {
        operatorId, agentId, passportJti: jti, missionId: missionRef,
        sources: carriedSources, text: [String(providerBody['prompt']), ...revised].join('\n'), provider,
        mode, bytesAlreadySent: false,
      });
    }

    const responseStr = JSON.stringify(result ?? answer.body);
    const authorityClaimRefs = await writePostCallTelemetry({
      services, request, config, start, success, body, responseStr, responseStatus: answer.status, usage: null,
      claims, jti, agentId, operatorId, mode, missionIds, missionRef, gate, approvalIdHeader, requestBodyStr, piiHits,
      recordedCost: null, stackKey: false,
    });
    await completeRuntimeAuthorityUse(
      services.authority, operatorId, authorityDecision, success ? 'succeeded' : 'failed',
      { status: answer.status, body: result ? { files: result.files.length } : answer.body }, authorityClaimRefs,
    );
    reply.status(answer.status).send(replyBody);
  } catch (err) {
    try {
      await completeRuntimeAuthorityUse(services.authority, operatorId, authorityDecision, 'failed', runtimeAuthorityFailureResult(err));
    } catch (finalizationError) {
      request.log.error(
        { code: (finalizationError as { code?: unknown })?.code ?? 'AUTHORITY_FINALIZATION_FAILED' },
        '[authority] failed to finalize image failure',
      );
    }
    throw err;
  }
}
