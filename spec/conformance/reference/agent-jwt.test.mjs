// The reference agent JWT (reference/agent-jwt-reference.mjs) is both halves of spec/agent-auth sections 3 and 4:
// it must pass the minter and the verifier suites. The SDK's own minter is checked against the minter suite too,
// through the key file it writes.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { formatReport, presenterFromFunction, runAgentJwtMinterSuite, runAgentJwtVerifierSuite } from '../src/index.mjs';
import { createAgentJwtVerifier, mintAgentJwt } from './agent-jwt-reference.mjs';

describe('reference agent JWT', () => {
  it('mints tokens that pass the minter suite', async () => {
    const report = await runAgentJwtMinterSuite({ mint: mintAgentJwt });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.passed).toBe(9);
  });

  it('verifies as the specification says, including a single use of every token', async () => {
    const report = await runAgentJwtVerifierSuite(presenterFromFunction(createAgentJwtVerifier()));
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped, formatReport(report)).toBe(0);
  });
});

describe('the TypeScript SDK as an agent', () => {
  it('mints tokens that pass the minter suite, from the key file it keeps for an agent', async () => {
    const home = mkdtempSync(join(tmpdir(), 'stack-agent-home-'));
    const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    try {
      const { createAgentTokenProvider } = await import('@getstackrun/sdk');
      const mint = async ({ agentId, privateJwk }) => {
        mkdirSync(join(home, '.stack', 'agents'), { recursive: true });
        const publicKey = { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x };
        writeFileSync(
          join(home, '.stack', 'agents', `${agentId}.json`),
          JSON.stringify({ agent_id: agentId, publicKey, privateKey: privateJwk, enrolled_at: Date.now() / 1000 }),
        );
        const token = createAgentTokenProvider({
          agentId,
          baseUrl: 'http://127.0.0.1:1',
          bearerProvider: async () => {
            throw new Error('no network in this test');
          },
        });
        return token();
      };
      const report = await runAgentJwtMinterSuite({ mint });
      expect(report.failed, formatReport(report)).toBe(0);
      expect(report.warnings, formatReport(report)).toBe(0);
    } finally {
      process.env.HOME = saved.HOME;
      process.env.USERPROFILE = saved.USERPROFILE;
      rmSync(home, { recursive: true, force: true });
    }
  });
});
