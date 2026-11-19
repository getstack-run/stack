// Images on the customer's own provider key, through the gateway: what leaves for the provider, what comes
// back, and the order of the gates. The stages are the chat call's own, so the handler test names them in the
// order they run and fakes each; the forward stage and the request shaping run for real.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { LlmImageRequest, LlmImageResult, type GeneratedFile } from '@stack/shared';
import type { Services } from '../config/services.js';

const calls = vi.hoisted(() => [] as string[]);

vi.mock('./llm-gateway/admit-call.js', () => ({ admitCall: vi.fn() }));
vi.mock('./llm-gateway/meter.js', () => ({ meterLlmCall: vi.fn(async () => { calls.push('meter'); }) }));
vi.mock('../lib/agent-runtime.js', () => ({ beginAgentRuntime: vi.fn(async () => { calls.push('mission'); return { passportJti: 'pas_1', missionId: 'msn_1', fleet: null }; }) }));
vi.mock('./llm-gateway/approval-gate.js', () => ({ enforceApprovalGate: vi.fn(async () => { calls.push('approval'); return { gate: { skipped: true }, approvalIdHeader: undefined }; }) }));
vi.mock('./llm-gateway/scope-wall.js', () => ({ enforceProviderScope: vi.fn(async () => { calls.push('wall'); return { intentServices: [], carriedSources: ['gmail'] }; }) }));
vi.mock('./llm-gateway/inbound-scan.js', () => ({ scanInboundMessages: vi.fn(async () => { calls.push('scan'); return { llm_redact_pii: true }; }) }));
vi.mock('./llm-gateway/control-decision.js', () => ({ decideModelCall: vi.fn(async () => { calls.push('decider'); }) }));
vi.mock('./llm-gateway/pii-redaction.js', () => ({
  redactUserPii: vi.fn(async (_s: unknown, _r: unknown, _c: unknown, call: { body: { messages: Array<{ content: string }> } }) => {
    calls.push('redact');
    return { redactedBody: { ...call.body, messages: [{ role: 'user', content: call.body.messages[0]!.content.replace('jane@example.com', '[REDACTED:email]') }] }, piiHits: 1 };
  }),
}));
vi.mock('./llm-gateway/credential-retrieval.js', () => ({ retrieveProviderCredential: vi.fn(async () => { calls.push('credential'); return 'sk-own'; }) }));
vi.mock('./llm-gateway/image-forward.js', () => ({ forwardImageResponse: vi.fn(async () => { calls.push('forward'); }) }));

const { admitCall } = await import('./llm-gateway/admit-call.js');
const { forwardImageResponse } = await import('./llm-gateway/image-forward.js');
const { retrieveProviderCredential } = await import('./llm-gateway/credential-retrieval.js');
const { makeImageHandler, anthropicImages } = await import('./llm.js');
const { OPENAI_IMAGES_CONFIG } = await import('./llm-gateway/provider-configs.js');

function admitted(body: Record<string, unknown>, over: Record<string, unknown> = {}) {
  return {
    body, isStreaming: false, passportToken: 'p.jwt', claims: { stk: {} }, jti: 'pas_1', agentId: 'agt_1', operatorId: 'op_1',
    mode: 'standard', missionIds: ['msn_1'], missionRef: 'msn_1', upstream: new URL('https://api.openai.com/v1/images/generations'),
    normalizedRequest: {}, fleetConnection: undefined, authorityConnectionId: 'conn_1', authorityDecision: { enforced: false },
    modelAccess: { kind: 'customer' }, ...over,
  };
}

const request = (headers: Record<string, string> = {}) => ({ id: 'r1', body: {}, headers, operatorId: 'op_1', log: { error: vi.fn(), info: vi.fn() } }) as unknown as FastifyRequest;
const reply = () => ({ status: vi.fn().mockReturnThis(), send: vi.fn().mockReturnThis() }) as unknown as FastifyReply;
const services = {} as Services;

beforeEach(() => {
  calls.length = 0;
  vi.mocked(admitCall).mockReset();
  vi.mocked(forwardImageResponse).mockClear();
  vi.mocked(retrieveProviderCredential).mockClear();
});

describe('the image request', () => {
  it('names only what the provider may be sent, and nothing else', () => {
    expect(LlmImageRequest.safeParse({ model: 'gpt-image-1', prompt: 'a cat', size: '1024x1024', quality: 'high', n: 2 }).success).toBe(true);
    expect(LlmImageRequest.safeParse({ model: 'gpt-image-1', prompt: 'a cat', user: 'someone', response_format: 'url' }).success).toBe(false);
    expect(LlmImageRequest.safeParse({ model: 'm', prompt: 'p', n: 5 }).success).toBe(false);
    expect(LlmImageRequest.safeParse({ model: 'm', prompt: 'p', size: '10x10;drop' }).success).toBe(false);
    expect(LlmImageRequest.safeParse({ model: 'm', prompt: '' }).success).toBe(false);
  });

  it('is built field by field from what the route accepted', async () => {
    const { imageProviderBody } = await import('./llm-gateway/image-request.js');
    const base = { model: 'gpt-image-1', prompt: 'a cat' };
    expect(imageProviderBody({ ...base, size: '1024x1024', quality: 'low' }, 'a cat')).toEqual({ model: 'gpt-image-1', prompt: 'a cat', n: 1, size: '1024x1024', quality: 'low' });
    // DALL-E sends a link unless it is asked for the bytes; the GPT image models refuse the field.
    expect(imageProviderBody({ ...base, model: 'dall-e-3' }, 'a cat')).toMatchObject({ response_format: 'b64_json' });
    expect(imageProviderBody(base, 'a cat')).not.toHaveProperty('response_format');
    expect(imageProviderBody({ model: 'gpt-image-1', prompt: 'p', n: 3 }, 'redacted')).toEqual({ model: 'gpt-image-1', prompt: 'redacted', n: 3 });
  });

  it('reads the pictures of an answer, bytes or https links, and no more than were asked for', async () => {
    const { imagesIn } = await import('./llm-gateway/image-request.js');
    const answer = { data: [
      { b64_json: 'QUJD', revised_prompt: 'a tabby cat' },
      { url: 'https://cdn.example.test/a.png' },
      { url: 'http://insecure.example.test/b.png' },
      { b64_json: '' },
      { b64_json: 'REVG', media_type: 'image/webp' },
    ] };
    expect(imagesIn(answer, 4)).toEqual([
      { base64: 'QUJD', url: null, mediaType: 'image/png', revisedPrompt: 'a tabby cat' },
      { base64: null, url: 'https://cdn.example.test/a.png', mediaType: 'image/png', revisedPrompt: null },
      { base64: 'REVG', url: null, mediaType: 'image/webp', revisedPrompt: null },
    ]);
    expect(imagesIn(answer, 1)).toHaveLength(1);
    expect(imagesIn({ nothing: true }, 4)).toEqual([]);
    expect(imagesIn({ data: [{ b64_json: 'QUJD', media_type: 'text/html' }] }, 1)[0]!.mediaType).toBe('image/png');
  });
});

describe('POST /v1/llm/<provider>/images', () => {
  const body = { model: 'gpt-image-1', prompt: 'a cat for jane@example.com', size: '1024x1024' };

  it('runs the chat call\'s gates in order, sends the redacted prompt and the customer\'s key, and meters once', async () => {
    vi.mocked(admitCall).mockResolvedValue(admitted(body) as never);
    await makeImageHandler(services, OPENAI_IMAGES_CONFIG)(request(), reply());
    expect(calls).toEqual(['meter', 'mission', 'approval', 'wall', 'scan', 'decider', 'redact', 'credential', 'forward']);
    const sent = vi.mocked(forwardImageResponse).mock.calls[0]![0];
    expect(sent.providerBody).toEqual({ model: 'gpt-image-1', prompt: 'a cat for [REDACTED:email]', n: 1, size: '1024x1024' });
    expect(sent.apiKey).toBe('sk-own');
    expect(sent.carriedSources).toEqual(['gmail']);
    expect(sent.asked).toBe(1);
    // No hold was taken, so none is given back if the key cannot be read.
    expect(vi.mocked(retrieveProviderCredential).mock.calls[0]![4]).toBeNull();
  });

  it('refuses a fleet passport before anything is counted', async () => {
    vi.mocked(admitCall).mockResolvedValue(admitted(body, { claims: { stk: { fleet: { mission_id: 'msn_1' } } } }) as never);
    await expect(makeImageHandler(services, OPENAI_IMAGES_CONFIG)(request(), reply())).rejects.toMatchObject({ statusCode: 403 });
    expect(calls).toEqual([]);
    expect(vi.mocked(forwardImageResponse)).not.toHaveBeenCalled();
  });

  it('ignores a cost cap, which has no hold to size on the customer\'s own key', async () => {
    vi.mocked(admitCall).mockResolvedValue(admitted(body) as never);
    await makeImageHandler(services, OPENAI_IMAGES_CONFIG)(request({ 'x-max-cost-cents': '5' }), reply());
    await makeImageHandler(services, OPENAI_IMAGES_CONFIG)(request({ 'x-max-cost-cents': 'abc' }), reply());
    expect(calls.filter((call) => call === 'forward')).toHaveLength(2);
    expect(vi.mocked(forwardImageResponse)).toHaveBeenCalledTimes(2);
  });

  it('answers Anthropic with a clear refusal that says where an image can be made', async () => {
    await expect(anthropicImages()).rejects.toMatchObject({
      code: 'IMAGE_NOT_SUPPORTED', statusCode: 422, details: { provider: 'anthropic' },
      message: expect.stringMatching(/no image generation endpoint.*\/v1\/llm\/openai\/images.*\/v1\/llm\/openrouter\/images/s),
    });
  });
});

describe('the image result', () => {
  it('is untrusted, on the customer\'s key, and carries files, not bytes', () => {
    const file: GeneratedFile = { name: 'image-1.png', content_type: 'image/png', size_bytes: 3, drive_file_id: 'dfile_1', source_url: null, data_base64: null };
    expect(LlmImageResult.parse({ provider: 'openai', model: 'gpt-image-1', untrusted: true, key: 'own', files: [file], revised_prompts: [] }).untrusted).toBe(true);
    expect(LlmImageResult.safeParse({ provider: 'openai', model: 'm', untrusted: false, key: 'own', files: [], revised_prompts: [] }).success).toBe(false);
  });
});
