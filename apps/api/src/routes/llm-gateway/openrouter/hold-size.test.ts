// A transcription sent as a multipart form is held from its model field and the size of its file, and the caller's cap only
// lowers what is held.
import { describe, expect, it } from 'vitest';
import { AUDIO_SECONDS_PER_MB, type WorstCaseListing } from '@stack/shared';
import { formOf, holdSizeFor } from './hold-size.js';
import type { OpenRouterCall } from './request.js';

const boundary = '----stack';
const form = (model: string, file: Buffer) => Buffer.concat([
  Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="model"\r\n\r\n${model}\r\n--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.mp3"\r\nContent-Type: audio/mpeg\r\n\r\n`),
  file,
  Buffer.from(`\r\n--${boundary}--\r\n`),
]);

const STT: WorstCaseListing = {
  id: 'acme/stt', modalities: { input: ['audio'], output: ['transcription'] },
  price: { unit: 'lines', provider_cost: { lines: [{ item: 'prompt', per: 'audio_unit', per_count: 1, cost_usd_micros: 100 }] } },
};
const services = { modelAccessPolicy: { listings: async () => ({ find: (id: string) => (id === STT.id ? STT : null), all: () => [STT] }) } };

function call(raw: Buffer): OpenRouterCall {
  return { method: 'POST', path: '/audio/transcriptions', search: '', match: null, contentType: `multipart/form-data; boundary=${boundary}`, rawBody: raw, body: {}, upstream: new URL('https://openrouter.ai/api/v1/audio/transcriptions') };
}

describe('the hold of a form', () => {
  it('reads the model field and the size of the body', () => {
    const raw = form('acme/stt', Buffer.alloc(1000, 1));
    expect(formOf(call(raw))).toEqual({ model: 'acme/stt', fileBytes: raw.length });
    expect(formOf({ contentType: 'application/json', rawBody: Buffer.from('{}') })).toBeUndefined();
  });

  it('holds the audio at its size, and lowers the hold to the cap', async () => {
    const raw = form('acme/stt', Buffer.alloc(1024 * 1024, 1));
    const seconds = Math.ceil((raw.length / (1024 * 1024)) * AUDIO_SECONDS_PER_MB);
    const size = await holdSizeFor(services as never, call(raw), null);
    expect(size).toMatchObject({ heldCents: Math.ceil((seconds * 100) / 10_000), assumptions: ['audio_estimated'] });
    const capped = await holdSizeFor(services as never, call(raw), 1);
    expect(capped).toMatchObject({ heldCents: 1 });
    expect(Object.keys(capped).sort()).toEqual(['assumptions', 'heldCents']);
  });
});
