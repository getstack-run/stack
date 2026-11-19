// An MCP endpoint built on the MCP TypeScript SDK, with and without sessions, must pass the
// service-mcp suite, and the suite must fail endpoints that each break one rule on purpose.

import { describe, expect, it } from 'vitest';
import { runServiceMcpSuite } from '../src/index.mjs';
import { ENDPOINT_KEY, ENDPOINT_URL, serviceEndpoint } from './service-mcp-endpoint.mjs';

const mustFailed = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);
const suite = (endpoint, extra = {}) => runServiceMcpSuite({ url: ENDPOINT_URL, headers: { 'x-api-key': ENDPOINT_KEY }, fetch: endpoint.fetch, ...extra });

for (const sessions of [true, false]) {
  it(`an MCP SDK endpoint ${sessions ? 'with' : 'without'} sessions passes the service-mcp suite`, async () => {
    const report = await suite(serviceEndpoint({ sessions }), { tool: { name: 'echo', arguments: {} } });
    expect(report.conforms, JSON.stringify(report.results.filter((r) => r.status !== 'pass'))).toBe(true);
    expect(report.results.filter((r) => r.status === 'pass').map((r) => r.id)).toEqual(sessions ? ['SM01', 'SM02', 'SM03', 'SM04', 'SM05', 'SM06'] : ['SM01', 'SM03', 'SM04', 'SM05']);
  });
}

describe('an endpoint with a defect fails the suite', () => {
  it('one that refuses initialize fails SM01', async () => {
    expect(mustFailed(await suite(serviceEndpoint({ sessions: true, defect: 'refuses_initialize' })))).toEqual(['SM01']);
  });

  it('one that gives a session id that is not visible ASCII fails SM02', async () => {
    expect(mustFailed(await suite(serviceEndpoint({ sessions: true, defect: 'bad_session_id' })))).toContain('SM02');
  });

  it('one that answers tools/list with a redirect fails SM04', async () => {
    expect(mustFailed(await suite(serviceEndpoint({ sessions: false, defect: 'redirects' })))).toEqual(['SM04']);
  });

  it('one that does not take the credential fails from the first check', async () => {
    const report = await runServiceMcpSuite({ url: ENDPOINT_URL, headers: { 'x-api-key': 'wrong' }, fetch: serviceEndpoint({ sessions: true }).fetch });
    expect(mustFailed(report)).toEqual(['SM01']);
    expect(report.conforms).toBe(false);
  });
});
