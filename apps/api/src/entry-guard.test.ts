import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * The engine's entry point runs a self-managed install. A hosted machine that
 * still starts it (a stale image or start command), and any process that forgot
 * STACK_DEPLOYMENT (unset reads as hosted), must stop at boot, in every
 * environment, rather than serve customers with no plan, no meter and no bill,
 * or without the licence check.
 */
describe('the engine entry guard', { timeout: 60_000 }, () => {
  let exit: ReturnType<typeof vi.spyOn>;
  let error: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.resetModules();
    exit = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`exit ${code}`);
    }) as never);
    error = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it.each(['production', 'staging', 'development', 'test'])(
    'refuses to start in %s unless the deployment is self-managed (variable unset or hosted)',
    async (nodeEnv) => {
      for (const deployment of ['', 'hosted']) {
        vi.resetModules();
        exit.mockClear();
        error.mockClear();
        vi.stubEnv('NODE_ENV', nodeEnv);
        vi.stubEnv('STACK_DEPLOYMENT', deployment);
        await expect(import('./entry-guard.js')).rejects.toThrow('exit 1');
        expect(exit).toHaveBeenCalledWith(1);
        expect(String(error.mock.calls[0]?.[0])).toMatch(/self-managed install/);
      }
    },
  );

  it('says what is wrong when the deployment setting is unreadable, not that the entry point is refused', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('STACK_DEPLOYMENT', 'other');
    await expect(import('./entry-guard.js')).rejects.toThrow('exit 1');
    expect(String(error.mock.calls[0]?.[0])).toBe('[BOOT] STACK_DEPLOYMENT must be "hosted" or "self_managed"');
  });

  it('says so when a self-managed install has no API address', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('STACK_DEPLOYMENT', 'self_managed');
    vi.stubEnv('STACK_API_BASE_URL', '');
    await expect(import('./entry-guard.js')).rejects.toThrow('exit 1');
    expect(String(error.mock.calls[0]?.[0])).toBe('[BOOT] STACK_API_BASE_URL is required when STACK_DEPLOYMENT=self_managed');
  });

  it('starts in production when the deployment is self-managed', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('STACK_DEPLOYMENT', 'self_managed');
    vi.stubEnv('STACK_API_BASE_URL', 'https://stack.example.test');
    await import('./entry-guard.js');
    expect(exit).not.toHaveBeenCalled();
  });

  it.each(['staging', 'development', 'test'])('starts in %s when the deployment is self-managed', async (nodeEnv) => {
    vi.stubEnv('NODE_ENV', nodeEnv);
    vi.stubEnv('STACK_DEPLOYMENT', 'self_managed');
    vi.stubEnv('STACK_API_BASE_URL', 'https://stack.example.test');
    await import('./entry-guard.js');
    expect(exit).not.toHaveBeenCalled();
  });
});
