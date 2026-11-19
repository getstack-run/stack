import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import { ControlsRequiredError } from '../errors.js';

// Reading the record and changing the detector settings are controls features: without controls the API answers
// 402 CONTROLS_REQUIRED, and every SDK call for them throws the same typed error with the API's message and feature.

const MESSAGE = 'Reading the record needs controls.';

function refuse(feature: 'record' | 'detector_settings'): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      new Response(JSON.stringify({ error: { code: 'CONTROLS_REQUIRED', message: MESSAGE, details: { feature } } }), {
        status: 402,
        headers: { 'content-type': 'application/json' },
      }),
    ),
  );
}

const stack = () => new Stack({ apiKey: 'sk_live_controls_test', baseUrl: 'http://api.fixture' });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('CONTROLS_REQUIRED', () => {
  it.each([
    ['audit.list', () => stack().audit.list()],
    ['audit.chainHead', () => stack().audit.chainHead()],
    ['audit.verifyChain', () => stack().audit.verifyChain()],
    ['evidencePacks.list', () => stack().evidencePacks.list({ scope: 'mission:ms_1' })],
    ['evidencePacks.get', () => stack().evidencePacks.get('pk_1')],
    ['evidencePacks.download', () => stack().evidencePacks.download('pk_1')],
    ['missions.replay', () => stack().missions.replay('ms_1')],
    ['missions.downloadOperatorReview', () => stack().missions.downloadOperatorReview('ms_1', 'clm_1')],
    ['passports.getReport', () => stack().passports.getReport('jti_1')],
  ])('%s throws ControlsRequiredError for the record', async (_name, call) => {
    refuse('record');
    const error = await call().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlsRequiredError);
    expect(error).toMatchObject({ code: 'CONTROLS_REQUIRED', status: 402, feature: 'record', message: MESSAGE });
  });

  it('a detector settings change throws ControlsRequiredError for detector_settings', async () => {
    refuse('detector_settings');
    const error = await stack().detectorConfig.upsert('prompt_injection', { enabled: false }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlsRequiredError);
    expect((error as ControlsRequiredError).feature).toBe('detector_settings');
  });
});
