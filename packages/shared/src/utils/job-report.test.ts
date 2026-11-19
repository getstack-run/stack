import { describe, expect, it, vi } from 'vitest';
import { jobFailureCode, reportJob, runPass, type JobReport } from './job-report.js';

function observer() {
  const reports: JobReport[] = [];
  return { reports, observe: (report: JobReport) => void reports.push(report) };
}

describe('runPass', () => {
  it('reports ok when the pass completes', async () => {
    const o = observer();
    await runPass(o.observe, 'a:b', async () => undefined, () => {});
    expect(o.reports).toEqual([{ job: 'a:b', state: 'ok' }]);
  });

  it('reports down with a fixed code when the pass throws, logs through onError and does not throw', async () => {
    const o = observer();
    const onError = vi.fn();
    await runPass(o.observe, 'a:b', async () => {
      throw new Error('provider said: key sk_live_123 is bad');
    }, onError);
    expect(o.reports).toEqual([{ job: 'a:b', state: 'down', code: 'failed' }]);
    expect(onError).toHaveBeenCalledOnce();
    expect(JSON.stringify(o.reports)).not.toContain('sk_live');
  });

  it('uses a classifier when the job has one', async () => {
    const o = observer();
    await runPass(o.observe, 'a:b', async () => { throw new Error('x'); }, () => {}, { classify: () => 'provider_refused' });
    expect(o.reports).toEqual([{ job: 'a:b', state: 'down', code: 'provider_refused' }]);
  });

  it('reports a caught-and-logged failure as down and a partial one as degraded', async () => {
    const o = observer();
    await runPass(o.observe, 'a:failed', async (pass) => pass.failed('sweep_failed'), () => {});
    await runPass(o.observe, 'a:partial', async (pass) => pass.degraded('notice_failed'), () => {});
    expect(o.reports).toEqual([
      { job: 'a:failed', state: 'down', code: 'sweep_failed' },
      { job: 'a:partial', state: 'degraded', code: 'notice_failed' },
    ]);
  });

  it('reports a pass with nothing to work on as off, and a failure outranks it', async () => {
    const o = observer();
    await runPass(o.observe, 'a:off', async (pass) => pass.off(), () => {});
    await runPass(o.observe, 'a:off2', async (pass) => { pass.off(); pass.failed(); }, () => {});
    expect(o.reports).toEqual([
      { job: 'a:off', state: 'off', code: 'not_configured' },
      { job: 'a:off2', state: 'down', code: 'failed' },
    ]);
  });

  it('never lets a throwing observer or log line change the pass', async () => {
    const throwing = (): void => {
      throw new Error('sink down');
    };
    await expect(runPass(throwing, 'a:b', async () => { throw new Error('x'); }, throwing)).resolves.toBeUndefined();
    expect(() => reportJob(throwing, { job: 'a:b', state: 'ok' })).not.toThrow();
    expect(() => reportJob(undefined, { job: 'a:b', state: 'ok' })).not.toThrow();
  });
});

describe('jobFailureCode', () => {
  it('names an unreachable Redis, else a plain failure', () => {
    expect(jobFailureCode(new Error('Connection is closed.'))).toBe('redis_unreachable');
    expect(jobFailureCode(new Error('boom'))).toBe('failed');
  });
});
