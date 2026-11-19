// How much a call on STACK's OpenRouter key holds on the wallet before it is sent: the most the call can cost, from the model's
// listed prices and the request itself, or an estimate built from those prices and named assumptions where the most cannot be
// worked out (`openRouterWorstCase`, packages/shared/src/constants/openrouter-worst-case.ts). No call is refused for want of a
// price: a cost above the hold is taken from the wallet once the call is charged. The caller's `X-Max-Cost-Cents` lowers the
// hold to it when it is below; the customer's decider is shown the hold.

import { openRouterWorstCase } from '@stack/shared';
import type { Services } from '../../../config/services.js';
import type { OpenRouterCall } from './request.js';

/** The most of a form read for its `model` field: the fields come before the file in every client STACK knows of. */
const FORM_HEAD_BYTES = 64 * 1024;

/** A multipart form's `model` field and the size of the file in it (a transcription sent as a form), or undefined. */
export function formOf(call: Pick<OpenRouterCall, 'contentType' | 'rawBody'>): { model: string | null; fileBytes: number } | undefined {
  if (!call.rawBody || !call.contentType || !/^multipart\/form-data/i.test(call.contentType.trim())) return undefined;
  const head = call.rawBody.subarray(0, FORM_HEAD_BYTES).toString('latin1');
  const model = /content-disposition:[^\r\n]*\bname="model"[^\r\n]*\r\n(?:[^\r\n]+\r\n)*\r\n([^\r\n]{1,200})\r\n/i.exec(head);
  return { model: model ? model[1]!.trim() : null, fileBytes: call.rawBody.length };
}

export interface HoldSize {
  /** What is held, and what the customer's decider is shown: the worst case or the estimate, lowered to the caller's cap when that is below. */
  heldCents: number;
  /** What the figure rests on where it is an estimate. */
  assumptions: string[];
}

export async function holdSizeFor(
  services: Pick<Services, 'modelAccessPolicy'>,
  call: OpenRouterCall,
  cap: number | null,
): Promise<HoldSize> {
  const listings = await services.modelAccessPolicy.listings();
  const worst = openRouterWorstCase({ body: call.body, bodyBytes: call.rawBody?.length ?? 0, listings, form: formOf(call) });
  return {
    heldCents: cap !== null ? Math.min(worst.cents, cap) : worst.cents,
    assumptions: worst.assumptions,
  };
}
