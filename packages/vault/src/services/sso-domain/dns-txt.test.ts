import { beforeEach, describe, expect, it, vi } from 'vitest';

const calls = vi.hoisted(() => ({
  servers: [] as string[][],
  answer: undefined as undefined | (() => Promise<string[][]>),
  cancelled: 0,
}));

// No lookup leaves this test: the resolver class of node:dns is replaced by one that answers as the test says.
vi.mock('node:dns/promises', () => ({
  Resolver: class {
    setServers(servers: string[]) {
      calls.servers.push(servers);
    }
    cancel() {
      calls.cancelled += 1;
    }
    resolveTxt() {
      return calls.answer!();
    }
  },
}));

import { DnsNameAbsentError, systemDnsTxtResolver } from './dns-txt.js';

const dnsError = (code: string) => Object.assign(new Error(code), { code });

describe('systemDnsTxtResolver', () => {
  beforeEach(() => {
    calls.servers = [];
    calls.cancelled = 0;
    calls.answer = undefined;
  });

  it('returns the records of an answer', async () => {
    calls.answer = async () => [['a', 'b'], ['c']];
    await expect(systemDnsTxtResolver().resolveTxt('_stack-sso.corp.example')).resolves.toEqual([['a', 'b'], ['c']]);
  });

  it.each(['ENOTFOUND', 'ENODATA'])('says the name is absent for %s, and for nothing else', async (code) => {
    calls.answer = async () => { throw dnsError(code); };
    await expect(systemDnsTxtResolver().resolveTxt('x.example')).rejects.toBeInstanceOf(DnsNameAbsentError);
  });

  it.each(['ESERVFAIL', 'ETIMEOUT', 'ECONNREFUSED', 'EREFUSED', 'EBADRESP', 'ECANCELLED'])('passes %s on as a failure to answer', async (code) => {
    calls.answer = async () => { throw dnsError(code); };
    const error = await systemDnsTxtResolver().resolveTxt('x.example').catch((e) => e);
    expect(error).not.toBeInstanceOf(DnsNameAbsentError);
    expect(error.code).toBe(code);
  });

  it('gives up on a name server that does not answer, within its limit', async () => {
    calls.answer = () => new Promise<string[][]>(() => undefined);
    const error = await systemDnsTxtResolver({ timeoutMs: 20 }).resolveTxt('x.example').catch((e) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(DnsNameAbsentError);
    expect(calls.cancelled).toBe(1);
  });

  it('asks the servers an install names, and the machine\'s own when it names none', async () => {
    calls.answer = async () => [];
    await systemDnsTxtResolver({ servers: ['9.9.9.9', '149.112.112.112'] }).resolveTxt('x.example');
    await systemDnsTxtResolver({ servers: [] }).resolveTxt('x.example');
    await systemDnsTxtResolver().resolveTxt('x.example');
    expect(calls.servers).toEqual([['9.9.9.9', '149.112.112.112']]);
  });
});
