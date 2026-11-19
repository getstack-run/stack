import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createStackMcpServer } from './index.js';
import { encodedPathsOf, probeEveryStringArgument, rawPathInterpolations } from './path-encoding.test-support.js';

const TOOLS_DIR = join(dirname(fileURLToPath(import.meta.url)), 'tools');

// The engine's tools. The hosted tools get the same three checks in the deployment's own tests.
describe('path parameters are encoded', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('never interpolates a raw value after a slash in an API path template', () => {
    expect(rawPathInterpolations([TOOLS_DIR])).toEqual([]);
  });

  it('keeps every string argument of every tool inside its URL path segment', async () => {
    const probed = await probeEveryStringArgument(createStackMcpServer);
    // The probe must actually reach URLs, or it proves nothing.
    expect(probed).toBeGreaterThan(100);
  });

  it('encodes a representative value from each previously raw path form', async () => {
    const urls = await encodedPathsOf(createStackMcpServer, [
      { name: 'stack_update_member', arguments: { member_id: 'a?b', role: 'standard' } },
      { name: 'stack_get_dropoff_status', arguments: { dropoff_id: 'a#b' } },
    ]);
    expect(urls).toEqual([
      'http://api.test/v1/team/members/a%3Fb',
      'http://api.test/v1/dropoffs/a%23b',
    ]);
  });
});
