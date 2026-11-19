import { afterEach, describe, expect, it } from 'vitest';
import { readStaging, signinAllowed, staging, stagingRecipientAllowed } from './staging.js';

describe('readStaging', () => {
  it('is off when STACK_STAGING is unset or false, whatever the allow-list says', () => {
    expect(readStaging({})).toEqual({ enabled: false, signinAllowlist: new Set() });
    expect(readStaging({ STACK_STAGING: 'false', STAGING_SIGNIN_ALLOWLIST: '' }).enabled).toBe(false);
    expect(readStaging({ STACK_STAGING: '', STAGING_SIGNIN_ALLOWLIST: 'a@example.com' }).enabled).toBe(false);
  });

  it('reads the allow-list as exact lower-cased addresses', () => {
    const config = readStaging({
      STACK_STAGING: 'true',
      STAGING_SIGNIN_ALLOWLIST: ' Tester@Example.com, second@example.com ,,',
    });
    expect(config.enabled).toBe(true);
    expect([...config.signinAllowlist]).toEqual(['tester@example.com', 'second@example.com']);
  });

  it('refuses a staging boot with an empty or missing allow-list (fail closed)', () => {
    expect(() => readStaging({ STACK_STAGING: 'true' })).toThrow(/STAGING_SIGNIN_ALLOWLIST must name at least one address/);
    expect(() => readStaging({ STACK_STAGING: 'true', STAGING_SIGNIN_ALLOWLIST: ' , ' })).toThrow(/at least one address/);
  });

  it('refuses an entry that is not one plain address, so nothing reads as a pattern', () => {
    for (const entry of ['*@example.com', '@example.com', 'example.com', 'a b@example.com', 'Name <a@example.com>']) {
      expect(() => readStaging({ STACK_STAGING: 'true', STAGING_SIGNIN_ALLOWLIST: entry })).toThrow(/email addresses/);
    }
  });

  it('refuses any value of STACK_STAGING but true or false', () => {
    for (const value of ['1', 'TRUE', 'yes', 'on']) {
      expect(() => readStaging({ STACK_STAGING: value, STAGING_SIGNIN_ALLOWLIST: 'a@example.com' })).toThrow(/STACK_STAGING/);
    }
  });
});

describe('signinAllowed', () => {
  const config = readStaging({ STACK_STAGING: 'true', STAGING_SIGNIN_ALLOWLIST: 'tester@example.com' });

  it('lets everyone in outside staging', () => {
    expect(signinAllowed('anyone@example.org', readStaging({}))).toBe(true);
  });

  it('on staging lets in only an exact address of the list, compared lower-cased', () => {
    expect(signinAllowed('tester@example.com', config)).toBe(true);
    expect(signinAllowed('  TESTER@example.COM ', config)).toBe(true);
    expect(signinAllowed('tester@example.com.evil.test', config)).toBe(false);
    expect(signinAllowed('xtester@example.com', config)).toBe(false);
    expect(signinAllowed('tester+1@example.com', config)).toBe(false);
    expect(signinAllowed('', config)).toBe(false);
    expect(signinAllowed(null, config)).toBe(false);
    expect(signinAllowed(undefined, config)).toBe(false);
  });

  it('reads the address of a named recipient for outbound mail', () => {
    expect(stagingRecipientAllowed('Tester <tester@example.com>', config)).toBe(true);
    expect(stagingRecipientAllowed('Tester <someone@example.com>', config)).toBe(false);
  });
});

describe('staging()', () => {
  const before = { staging: process.env['STACK_STAGING'], list: process.env['STAGING_SIGNIN_ALLOWLIST'] };
  afterEach(() => {
    for (const [name, value] of [['STACK_STAGING', before.staging], ['STAGING_SIGNIN_ALLOWLIST', before.list]] as const) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  it('follows the process environment as it changes', () => {
    delete process.env['STACK_STAGING'];
    expect(staging().enabled).toBe(false);
    process.env['STACK_STAGING'] = 'true';
    process.env['STAGING_SIGNIN_ALLOWLIST'] = 'tester@example.com';
    expect(staging().enabled).toBe(true);
    expect(signinAllowed('tester@example.com')).toBe(true);
    expect(signinAllowed('other@example.com')).toBe(false);
    process.env['STAGING_SIGNIN_ALLOWLIST'] = '';
    expect(() => staging()).toThrow(/STAGING_SIGNIN_ALLOWLIST/);
  });
});
