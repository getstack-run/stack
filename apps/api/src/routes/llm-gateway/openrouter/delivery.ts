// How OpenRouter's answer reaches the caller. `streamDelivery` is the passthrough proper: the status, the filtered
// headers and the bytes as they come, never held back unless a gate needs the answer first (the runtime authority's
// record, the data trail of a call that carried another service's content), and then only up to a bound.
//
// Whatever the delivery, the call is not over when the last byte is read: `finalize` runs then (billing, the records,
// the authority's record) and, for a stream, before the answer ends, so a settlement that fails can say so on the stream.

import type { FastifyReply, FastifyRequest } from 'fastify';
import { once } from 'node:events';
import { StackError } from '@stack/shared';
import type { Services } from '../../../config/services.js';
import { holdRequestEnd } from '../../../middleware/request-end.js';
import type { OpenRouterCall } from './request.js';
import type { UpstreamAnswer } from './upstream.js';

/** The most of an answer that is held back until the gates have run; a larger one is streamed from that point on. */
export const HELD_ANSWER_MAX_BYTES = 16 * 1024 * 1024;

/**
 * The most of all answers one machine holds back for the data trail at once. An answer that would take the machine past it
 * streams from that point on instead of waiting, as one past its own bound does: the data trail is recorded either way. An
 * answer the runtime authority needs whole is not counted here; it is held to its own bound.
 */
export const HELD_ANSWERS_TOTAL_MAX_BYTES = 64 * 1024 * 1024;

/** What a delivery that writes somewhere of the caller's own checks before anything is held or sent. */
export interface DeliveryAdmission {
  services: Services;
  request: FastifyRequest;
  operatorId: string;
  agentId: string;
}

export interface FinalizeInput {
  /** Whether bytes of the answer had already reached the caller when the answer was read to its end. */
  bytesAlreadySent: boolean;
  /** The whole answer, when it was held back (up to `HELD_ANSWER_MAX_BYTES`); null when it streamed. */
  held: Buffer | null;
  /** The reading of the answer broke off (a clock ran out, a held answer was too large): what it was, or null. */
  broken: unknown;
  /** The caller hung up and the call to OpenRouter was stopped (only a streamed call is: `abortOnHangup`). */
  callerLeft?: boolean;
}

export interface FinalizeResult {
  /** Said on a stream when the call's billing could not be settled: the answer is out, the charge is saved for retry. */
  billingNote?: string;
}

/**
 * Whether the answer waits for the gates that follow it. `no`: it streams. `if_small`: it waits up to the bound and
 * streams past it (the data trail of a call that carried another service's content). `whole`: it must be held whole
 * for the authority's record, and one past the bound is refused.
 */
export type HoldMode = 'no' | 'if_small' | 'whole';

/** Whose call it is, for a delivery that writes to somewhere that belongs to the caller (the agent's drive). */
export interface DeliveryCaller {
  operatorId: string;
  agentId: string;
  missionId: string;
  passportJti: string;
  /** The accountability mode of the Passport, which the data trail reads. */
  accountability?: 'enforced' | 'logged' | 'standard';
}

export interface DeliveryInput {
  request: FastifyRequest;
  reply: FastifyReply;
  /** The call that was made: its method and path, for naming what is saved. */
  call: OpenRouterCall;
  caller: DeliveryCaller;
  answer: UpstreamAnswer;
  hold: HoldMode;
  /**
   * What a caller that hangs up does to the call to OpenRouter: a streamed call is stopped at once (true), any other call is
   * read to its end, nothing sent to the caller who is gone (false).
   */
  abortOnHangup: boolean;
  /** Called with each chunk as it is read, before it is written. */
  onChunk: (chunk: Uint8Array) => void;
  finalize: (input: FinalizeInput) => Promise<FinalizeResult>;
  /**
   * A delivery that takes the reply over (`reply.hijack()`) holds the end of the request (`holdRequestEnd`) and sets
   * `hijacked`, whatever happens after: the handler releases the end of the request when it is done.
   */
  state: { hijacked: boolean };
}

/**
 * The pluggable end of the passthrough: a delivery writes the caller's answer and calls `finalize` once. One that writes to a
 * place with gates of its own (the agent's drive) runs them in `admit`, before anything is held, counted on a wallet or sent.
 */
export type OutputDelivery = ((input: DeliveryInput) => Promise<void>) & {
  admit?: (input: DeliveryAdmission) => Promise<void>;
};

/** Headers every answer carries: not cacheable by anyone else, and never read as a page. */
export const ANSWER_HEADERS: Record<string, string> = {
  'cache-control': 'private, no-store',
  'x-content-type-options': 'nosniff',
};

/** The passthrough, with the machine's bound on held answers shared by every call it delivers. */
export function createStreamDelivery(options: { heldTotalMaxBytes?: number } = {}): OutputDelivery {
  const heldTotalMaxBytes = options.heldTotalMaxBytes ?? HELD_ANSWERS_TOTAL_MAX_BYTES;
  let heldAnswersBytes = 0;
  return async (input) => {
    const { request, reply, answer } = input;
    const raw = reply.raw;
    const held: Buffer[] = [];
    let heldBytes = 0;
    /** What this answer counts against the machine's bound on held answers, given back when it streams or ends. */
    let counted = 0;
    const uncount = () => {
      heldAnswersBytes -= counted;
      counted = 0;
    };
    let sentAny = false;
    let callerLeft = false;
    const onClose = () => {
      if (raw.writableEnded) return;
      // The caller hung up: a streamed call to OpenRouter is stopped, and what it billed for the generation settles the charge.
      callerLeft = true;
      if (input.abortOnHangup) answer.cancel();
    };
    raw.on('close', onClose);
    // A close that happened before this listener was attached is never heard: a socket already destroyed is a caller gone.
    if (raw.destroyed) onClose();
    const gone = (): boolean => {
      if (!callerLeft && raw.destroyed && !raw.writableEnded) onClose();
      return callerLeft;
    };

    const sse = /^text\/event-stream/i.test(answer.contentType);
    const startAnswer = () => {
      // A hijacked reply is not Fastify's to end: the settlement and the records go on after the last byte, so the end of
      // the request is held until the handler is done with it (`releaseRequestEnd`).
      holdRequestEnd(request);
      input.state.hijacked = true;
      reply.hijack();
      // What Fastify's own hooks set on the reply (the security headers) is copied over: a hijacked reply never sends it.
      for (const [name, value] of Object.entries(reply.getHeaders())) {
        if (value !== undefined) raw.setHeader(name, value as string);
      }
      for (const [name, value] of Object.entries({ ...answer.headers, ...ANSWER_HEADERS })) raw.setHeader(name, value);
      raw.statusCode = answer.status;
      raw.flushHeaders();
    };
    const write = async (bytes: Uint8Array) => {
      if (gone()) return;
      if (!raw.write(bytes)) {
        await Promise.race([once(raw, 'drain'), once(raw, 'close')]).catch(() => undefined);
      }
      sentAny = true;
    };

    let broken: unknown = null;
    try {
      // An event stream's headers go out at once: its first event can be a long way off, and the caller should know it is in.
      if (sse && input.hold === 'no') startAnswer();
      if (answer.body) {
        try {
          for await (const chunk of answer.body) {
            input.onChunk(chunk);
            if (gone() && input.abortOnHangup) {
              answer.cancel();
              break;
            }
            if (input.hold !== 'no' && !input.state.hijacked) {
              held.push(Buffer.from(chunk));
              heldBytes += chunk.byteLength;
              const machineFull = input.hold === 'if_small' && heldAnswersBytes + chunk.byteLength > heldTotalMaxBytes;
              if (heldBytes <= HELD_ANSWER_MAX_BYTES && !machineFull) {
                if (input.hold === 'if_small') {
                  heldAnswersBytes += chunk.byteLength;
                  counted += chunk.byteLength;
                }
                continue;
              }
              if (input.hold === 'whole') {
                answer.cancel();
                throw authorityStreamTooLarge();
              }
              // Past the bound (its own, or the machine's) the answer streams from here on, what was held first.
              startAnswer();
              for (const piece of held.splice(0)) await write(piece);
              uncount();
              continue;
            }
            if (!input.state.hijacked) startAnswer();
            await write(chunk);
          }
        } catch (error) {
          // What broke the reading (a clock, a held answer past its bound) is settled like any other cut-off call. A reading
          // stopped because the caller left is not a break: nobody is waiting for the answer.
          broken = callerLeft && input.abortOnHangup ? null : error;
        }
      }

      const wholeAnswer = !input.state.hijacked && input.hold !== 'no' ? Buffer.concat(held) : null;
      const outcome = await input.finalize({ bytesAlreadySent: sentAny, held: wholeAnswer, broken, callerLeft: callerLeft && input.abortOnHangup });

      if (!input.state.hijacked && broken) {
        // Held, and cut off before its end: nothing was sent, and a half answer is not passed on as a whole one.
        throw broken instanceof StackError
          ? broken
          : new StackError('The answer from OpenRouter broke off.', 'UPSTREAM_ANSWER_BROKE_OFF', 502);
      }
      if (!input.state.hijacked) {
        // The answer was held (or had no body): it goes out now, as an ordinary reply.
        for (const [name, value] of Object.entries({ ...answer.headers, ...ANSWER_HEADERS })) reply.header(name, value);
        await reply.status(answer.status).send(wholeAnswer ?? Buffer.alloc(0));
      } else {
        if (outcome.billingNote && sse && !callerLeft) {
          await write(Buffer.from(`event: stack_billing_error\ndata: ${JSON.stringify({ type: 'billing_error', note: outcome.billingNote })}\n\n`));
        }
        // An answer cut off in the middle is not ended cleanly: the caller must see it was cut.
        if (broken) raw.destroy();
        else if (!raw.writableEnded) raw.end();
      }
    } finally {
      uncount();
      raw.off('close', onClose);
      if (input.state.hijacked && !raw.writableEnded && !raw.destroyed) raw.end();
    }
  };
}

export const streamDelivery: OutputDelivery = createStreamDelivery();

/** A held answer that grew past the bound while the runtime authority required it whole: refused, nothing is sent. */
function authorityStreamTooLarge(): StackError {
  return new StackError(
    'Authority-protected response exceeds the safe evidence buffer limit',
    'AUTHORITY_STREAM_RESPONSE_TOO_LARGE',
    502,
  );
}
