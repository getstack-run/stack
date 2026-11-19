import { describe, it, expect } from 'vitest';
import { chooseCmekKmsForWorker } from './cmek-kms-selector.js';

describe('chooseCmekKmsForWorker', () => {
  it('returns real config when AWS_REGION + AWS_KMS_KEY_ID are both set', () => {
    const sel = chooseCmekKmsForWorker({
      AWS_REGION: 'eu-north-1',
      AWS_KMS_KEY_ID: 'arn:aws:kms:eu-north-1:111111111111:key/abcdef',
      STACK_SYSTEM_OPERATOR_ID: 'op_stack_system',
      NODE_ENV: 'production',
    });
    expect(sel.kind).toBe('real');
    if (sel.kind === 'real') {
      expect(sel.config).toEqual({
        region: 'eu-north-1',
        defaultKeyId: 'arn:aws:kms:eu-north-1:111111111111:key/abcdef',
        stackSystemOperatorId: 'op_stack_system',
      });
    }
  });

  it('hard-fails in production when only AWS_REGION is set', () => {
    expect(() =>
      chooseCmekKmsForWorker({
        AWS_REGION: 'eu-north-1',
        NODE_ENV: 'production',
      }),
    ).toThrow(/CMEK migration tick requires AWS_REGION \+ AWS_KMS_KEY_ID/);
  });

  it('hard-fails in production when only AWS_KMS_KEY_ID is set', () => {
    expect(() =>
      chooseCmekKmsForWorker({
        AWS_KMS_KEY_ID: 'arn:aws:kms:eu-north-1:111111111111:key/abcdef',
        NODE_ENV: 'production',
      }),
    ).toThrow(/CMEK migration tick requires AWS_REGION \+ AWS_KMS_KEY_ID/);
  });

  it('hard-fails in production when neither AWS env is set', () => {
    expect(() => chooseCmekKmsForWorker({ NODE_ENV: 'production' })).toThrow(
      /CMEK migration tick requires AWS_REGION \+ AWS_KMS_KEY_ID/,
    );
  });

  it('error message reports which env var is missing', () => {
    expect(() => chooseCmekKmsForWorker({ AWS_REGION: 'eu-north-1', NODE_ENV: 'production' })).toThrow(
      /AWS_REGION=yes AWS_KMS_KEY_ID=no/,
    );
    expect(() => chooseCmekKmsForWorker({ AWS_KMS_KEY_ID: 'foo', NODE_ENV: 'production' })).toThrow(
      /AWS_REGION=no AWS_KMS_KEY_ID=yes/,
    );
  });

  it('skips with reason in dev when AWS env is missing', () => {
    const sel = chooseCmekKmsForWorker({ NODE_ENV: 'development' });
    expect(sel.kind).toBe('skip');
    if (sel.kind === 'skip') {
      expect(sel.reason).toMatch(/disabled/);
    }
  });

  it('skips with reason when NODE_ENV is unset (treated as dev, not prod)', () => {
    const sel = chooseCmekKmsForWorker({});
    expect(sel.kind).toBe('skip');
  });

  it('treats empty STACK_SYSTEM_OPERATOR_ID as undefined (no dogfood short-circuit configured)', () => {
    const sel = chooseCmekKmsForWorker({
      AWS_REGION: 'eu-north-1',
      AWS_KMS_KEY_ID: 'arn:aws:kms:eu-north-1:111111111111:key/abcdef',
      STACK_SYSTEM_OPERATOR_ID: '',
    });
    expect(sel.kind).toBe('real');
    if (sel.kind === 'real') {
      expect(sel.config.stackSystemOperatorId).toBeUndefined();
    }
  });

  it('passes STACK_SYSTEM_OPERATOR_ID through when set', () => {
    const sel = chooseCmekKmsForWorker({
      AWS_REGION: 'eu-north-1',
      AWS_KMS_KEY_ID: 'arn:aws:kms:eu-north-1:111111111111:key/abcdef',
      STACK_SYSTEM_OPERATOR_ID: 'op_stack_system',
    });
    if (sel.kind === 'real') {
      expect(sel.config.stackSystemOperatorId).toBe('op_stack_system');
    } else {
      expect.fail('expected real selection');
    }
  });

  it('skips the tick, even in production, when the deployment wraps keys with its own key file', () => {
    for (const env of [
      { NODE_ENV: 'production', STACK_KEY_PROVIDER: 'local' },
      { NODE_ENV: 'production', STACK_KEY_FILE: '/run/secrets/stack-kek' },
      { NODE_ENV: 'production', STACK_KEY_ENCRYPTION_KEY: 'x' },
    ]) {
      const sel = chooseCmekKmsForWorker(env);
      expect(sel.kind).toBe('skip');
      if (sel.kind === 'skip') expect(sel.reason).toMatch(/customer-managed keys/);
    }
  });

  it('still hard-fails in production when AWS KMS is the named provider and its env is missing', () => {
    expect(() => chooseCmekKmsForWorker({ NODE_ENV: 'production', STACK_KEY_PROVIDER: 'aws-kms' })).toThrow(
      /CMEK migration tick requires AWS_REGION \+ AWS_KMS_KEY_ID/,
    );
  });
});
