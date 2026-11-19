import { describe, expect, it } from 'vitest';
import {
  emailDomainOf,
  entraVouchesForEmailDomain,
  normalizeDomain,
  ssoDomainRecordName,
  ssoDomainRecordValue,
  txtRecordsProve,
} from './sso-domain.js';

describe('normalizeDomain', () => {
  it('lower-cases, drops one trailing dot and trims', () => {
    expect(normalizeDomain('  Corp.Example.COM. ')).toBe('corp.example.com');
  });

  it('writes an internationalised name in its ASCII form', () => {
    expect(normalizeDomain('bücher.example')).toBe('xn--bcher-kva.example');
  });

  it.each([
    ['', 'empty'],
    ['localhost', 'one label'],
    ['com', 'one label'],
    ['10.0.0.1', 'an IPv4 address'],
    ['[::1]', 'an IPv6 literal'],
    ['example.com:8443', 'a port'],
    ['https://example.com', 'a URL'],
    ['example.com/path', 'a path'],
    ['user@example.com', 'an address'],
    ['*.example.com', 'a wildcard'],
    ['exa mple.com', 'a space'],
    ['-bad.example.com', 'a label that starts with a hyphen'],
    ['bad-.example.com', 'a label that ends with a hyphen'],
    ['a..example.com', 'an empty label'],
    ['example.c', 'a one-letter top-level label'],
    ['example.123', 'a numeric top-level label'],
    [`${'a'.repeat(64)}.example.com`, 'a label over 63 characters'],
    [`${'a.'.repeat(130)}com`, 'a name over 253 characters'],
    ['mail.corp.internal', 'a private zone'],
    ['printer.local', 'a local-only name'],
    ['app.localhost', 'a localhost name'],
    ['1.0.0.10.in-addr.arpa', 'a reverse-lookup name'],
    ['abcdefabcdefabcd.onion', 'an onion name'],
    ['corp.invalid', 'a reserved invalid name'],
    ['Corp.INTERNAL.', 'one of them, in any case and with a trailing dot'],
  ])('refuses %j (%s)', (input) => {
    expect(normalizeDomain(input)).toBeNull();
  });

  it('keeps accepting example and test, which RFC 2606 keeps out of the public DNS and the specification and its conformance kit use', () => {
    expect(normalizeDomain('corp.example')).toBe('corp.example');
    expect(normalizeDomain('verified-ab12.example.test')).toBe('verified-ab12.example.test');
  });

  it('never reads an address at a non-public name as being at a domain', () => {
    expect(emailDomainOf('ann@mail.corp.internal')).toBeNull();
  });
});

describe('emailDomainOf', () => {
  it('reads the part after the last at-sign, in canonical form', () => {
    expect(emailDomainOf(' Jane.Doe@Corp.Example.com ')).toBe('corp.example.com');
  });

  it.each(['', 'nobody', '@corp.example.com', 'jane@', 'jane@localhost', 'jane@10.0.0.1', 'jane@corp.example.com:25', 'jane@evil.example@corp.example.com', '"a@b"@corp.example.com'])(
    'finds no domain in %j',
    (input) => {
      expect(emailDomainOf(input)).toBeNull();
    },
  );
});

describe('the proof record', () => {
  it('is under the STACK label and carries the token after a fixed prefix', () => {
    expect(ssoDomainRecordName('corp.example.com')).toBe('_stack-sso.corp.example.com');
    expect(ssoDomainRecordValue('abc')).toBe('stack-sso-verification=abc');
  });

  it('is proved by a record that is the whole value, split or not, and by nothing that merely contains it', () => {
    const token = 'tok123';
    expect(txtRecordsProve([['v=spf1 -all'], ['stack-sso-verification=tok123']], token)).toBe(true);
    expect(txtRecordsProve([['stack-sso-verification=', 'tok123']], token)).toBe(true);
    expect(txtRecordsProve([['  stack-sso-verification=tok123  ']], token)).toBe(true);
    expect(txtRecordsProve([['stack-sso-verification=tok1234']], token)).toBe(false);
    expect(txtRecordsProve([['stack-sso-verification=tok12']], token)).toBe(false);
    expect(txtRecordsProve([['x stack-sso-verification=tok123']], token)).toBe(false);
    expect(txtRecordsProve([['tok123']], token)).toBe(false);
    expect(txtRecordsProve([], token)).toBe(false);
  });
});

describe('entraVouchesForEmailDomain', () => {
  const tenant = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0';
  const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;
  const claims = { tid: tenant, email: 'jane@corp.example.com', xms_edov: true };

  it('trusts the boolean true from the tenant the issuer names', () => {
    expect(entraVouchesForEmailDomain(claims, issuer)).toBe(true);
    expect(entraVouchesForEmailDomain({ ...claims, tid: tenant.toUpperCase() }, issuer)).toBe(true);
    expect(entraVouchesForEmailDomain(claims, `https://login.microsoftonline.us/${tenant}/v2.0`)).toBe(true);
  });

  it('refuses everything but the boolean true', () => {
    for (const value of ['true', 1, '1', null, false, undefined]) {
      expect(entraVouchesForEmailDomain({ ...claims, xms_edov: value }, issuer)).toBe(false);
    }
  });

  it('refuses an issuer that is not one tenant of Entra, and a token of another tenant', () => {
    for (const other of [
      `https://login.microsoftonline.com/common/v2.0`,
      `https://login.microsoftonline.com/organizations/v2.0`,
      `https://login.microsoftonline.com/${tenant}/v2.0/`,
      `https://login.microsoftonline.com/${tenant}`,
      `https://sts.windows.net/${tenant}/`,
      `https://login.microsoftonline.com.evil.example/${tenant}/v2.0`,
      `http://login.microsoftonline.com/${tenant}/v2.0`,
      `https://idp.example.com/${tenant}/v2.0`,
    ]) {
      expect(entraVouchesForEmailDomain(claims, other)).toBe(false);
    }
    expect(entraVouchesForEmailDomain({ ...claims, tid: '11111111-1111-1111-1111-111111111111' }, issuer)).toBe(false);
    expect(entraVouchesForEmailDomain({ xms_edov: true, email: claims.email }, issuer)).toBe(false);
  });

  it('needs an address to speak of', () => {
    expect(entraVouchesForEmailDomain({ tid: tenant, xms_edov: true }, issuer)).toBe(false);
    expect(entraVouchesForEmailDomain({ tid: tenant, xms_edov: true, email: ' ' }, issuer)).toBe(false);
  });
});
