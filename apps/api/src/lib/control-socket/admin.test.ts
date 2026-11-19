import { describe, expect, it, vi } from 'vitest';
import { CONTROL_ACTION_TYPES, ControlSocketAddressError } from '@stack/shared';

const net = vi.hoisted(() => ({ addresses: new Map<string, string[]>() }));
vi.mock('@stack/shared', async (importActual) => {
  const actual = await importActual<typeof import('@stack/shared')>();
  return {
    ...actual,
    resolvePublicUrl: vi.fn(async (raw: string, options?: { allowedProtocols?: string[] }) => {
      const url = actual.parsePublicUrl(raw, options);
      const addresses = net.addresses.get(url.hostname);
      if (!addresses) throw new actual.UnsafeUrlError('Cannot resolve host');
      if (addresses.some((a) => actual.isBlockedIp(a))) throw new actual.UnsafeUrlError('non-public');
      return { url, addresses: addresses.map((address) => ({ address, family: 4 })) };
    }),
  };
});

const { assertControlAddress, classifyModeChange, classifyModeSetting, hostOf, removedTypes } = await import('./admin.js');

const refused = (cause: string) => expect.objectContaining({ code: 'CONTROL_SOCKET_ADDRESS_REFUSED', details: { cause } });

describe('assertControlAddress: a set-time SSRF check', () => {
  it('accepts a public https address and returns it normalised', async () => {
    net.addresses.set('control.example.com', ['93.184.216.34']);
    await expect(assertControlAddress('  https://control.example.com/stack/decide ', false)).resolves.toBe('https://control.example.com/stack/decide');
  });

  it.each([
    ['plain http in production', 'http://control.example.com/d', 'unsafe_url'],
    ['a loopback literal', 'https://127.0.0.1/d', 'unsafe_url'],
    ['localhost', 'https://localhost/d', 'unsafe_url'],
    ['the metadata address', 'https://169.254.169.254/latest', 'unsafe_url'],
    ['a private literal', 'https://192.168.1.10/d', 'unsafe_url'],
    ['an IPv6 loopback', 'https://[::1]/d', 'unsafe_url'],
    ['an internal suffix', 'https://svc.internal/d', 'unsafe_url'],
    ['URL credentials', 'https://user:pw@control.example.com/d', 'unsafe_url'],
    ['a file URL', 'file:///etc/passwd', 'unsafe_url'],
    ['not a URL', 'control.example.com', 'unsafe_url'],
    ['a query string', 'https://control.example.com/d?token=abc', 'query_not_allowed'],
    ['a fragment', 'https://control.example.com/d#x', 'query_not_allowed'],
  ])('refuses %s', async (_name, url, cause) => {
    net.addresses.set('control.example.com', ['93.184.216.34']);
    const error = await assertControlAddress(url, false).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlSocketAddressError);
    expect(error).toEqual(refused(cause));
    expect((error as Error).message).not.toContain('abc');
  });

  it('refuses a name that resolves inside, and one that does not resolve', async () => {
    net.addresses.set('rebind.example.com', ['10.0.0.7']);
    await expect(assertControlAddress('https://rebind.example.com/d', false)).rejects.toEqual(refused('unresolvable'));
    await expect(assertControlAddress('https://nowhere.example.com/d', false)).rejects.toEqual(refused('unresolvable'));
  });

  it('allows plain http only in a development build', async () => {
    net.addresses.set('dev.example.com', ['93.184.216.34']);
    await expect(assertControlAddress('http://dev.example.com/d', true)).resolves.toBe('http://dev.example.com/d');
    await expect(assertControlAddress('http://dev.example.com/d', false)).rejects.toEqual(refused('unsafe_url'));
  });
});

describe('what loosens', () => {
  it('classifies a change of who decides', () => {
    expect(classifyModeChange('hosted', 'hosted')).toBe('unchanged');
    expect(classifyModeChange('hosted', 'none')).toBe('loosening');
    expect(classifyModeChange('remote', 'none')).toBe('loosening');
    expect(classifyModeChange('hosted', 'remote')).toBe('loosening');
    expect(classifyModeChange('none', 'hosted')).toBe('tightening');
    expect(classifyModeChange('none', 'remote')).toBe('tightening');
    expect(classifyModeChange('remote', 'hosted')).toBe('socket_change');
  });

  it('choosing none is a loosening whenever it is a change of the setting, even while controls are off', () => {
    // Controls off: nobody decides today, but the setting would outlive a later controls subscription.
    expect(classifyModeSetting({ mode_setting: 'auto', effective_mode: 'none' }, 'none')).toBe('loosening');
    expect(classifyModeSetting({ mode_setting: 'hosted', effective_mode: 'hosted' }, 'none')).toBe('loosening');
    expect(classifyModeSetting({ mode_setting: 'remote', effective_mode: 'remote' }, 'none')).toBe('loosening');
    // Already chosen: nothing changes.
    expect(classifyModeSetting({ mode_setting: 'none', effective_mode: 'none' }, 'none')).toBe('unchanged');
    // Everything else reads as who decides now.
    expect(classifyModeSetting({ mode_setting: 'none', effective_mode: 'none' }, 'hosted')).toBe('tightening');
    expect(classifyModeSetting({ mode_setting: 'remote', effective_mode: 'remote' }, 'hosted')).toBe('socket_change');
    expect(classifyModeSetting({ mode_setting: 'auto', effective_mode: 'hosted' }, 'hosted')).toBe('unchanged');
  });

  it('names the kinds that stop being checked, treating null as every kind', () => {
    expect(removedTypes(null, null)).toEqual([]);
    expect(removedTypes(['email.send'], null)).toEqual([]);
    expect(removedTypes(null, ['email.send'])).toHaveLength(CONTROL_ACTION_TYPES.length - 1);
    expect(removedTypes(['email.send', 'sms.send', 'tool.run'], ['sms.send'])).toEqual(['email.send', 'tool.run']);
    expect(removedTypes(['sms.send'], ['sms.send', 'email.send'])).toEqual([]);
  });

  it('shows a host for the approval page', () => {
    expect(hostOf('https://control.example.com:8443/decide')).toBe('control.example.com:8443');
    expect(hostOf('not a url')).toBe('the given address');
  });
});
