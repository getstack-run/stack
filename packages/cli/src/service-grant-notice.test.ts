import { beforeEach, describe, expect, it, vi } from 'vitest';
import { stderr } from 'node:process';
import { governedApi } from './governance.js';
import { printJson, printRecord } from './format.js';
import { cmdService } from './services.js';

vi.mock('./api.js', async importOriginal => ({ ...await importOriginal<object>(), api: vi.fn(async () => ({})) }));
vi.mock('./governance.js', () => ({ governedApi: vi.fn(async () => ({})) }));
vi.mock('./format.js', async importOriginal => ({ ...await importOriginal<object>(), printJson: vi.fn(), printRecord: vi.fn() }));
vi.mock('node:process', async importOriginal => ({
  ...await importOriginal<object>(),
  exit: vi.fn((code?: number) => { throw new Error(`exit ${code}`); }),
  stderr: { write: vi.fn(), isTTY: false },
}));

const GRANT = { id: 'grant_1', agent_id: 'agt_abcdefgh1234', service_connection_id: 'scon_late' };
const NOTICE = {
  policy_id: 'cpl_1',
  policy_revision: 3,
  revision_needed: 4,
  message: 'The grant is made, but this agent cannot call the connection until a revision lists it.',
};
const ARGS = ['grant', '--agent', 'agt_abcdefgh1234', '--connection', 'scon_late', '--scopes', 'read'];

beforeEach(() => vi.clearAllMocks());

describe('service grant under controls', () => {
  it('prints the grant and says beside it what the policy still needs', async () => {
    vi.mocked(governedApi).mockResolvedValueOnce({ ...GRANT, control_policy: NOTICE });
    await cmdService(ARGS);
    expect(printRecord).toHaveBeenCalledWith(GRANT);
    expect(stderr.write).toHaveBeenCalledWith(`note: ${NOTICE.message}\n`);
  });

  it('prints nothing extra when the policy needs nothing', async () => {
    vi.mocked(governedApi).mockResolvedValueOnce(GRANT);
    await cmdService(ARGS);
    expect(printRecord).toHaveBeenCalledWith(GRANT);
    expect(stderr.write).not.toHaveBeenCalled();
  });

  it('leaves the JSON answer whole', async () => {
    vi.mocked(governedApi).mockResolvedValueOnce({ ...GRANT, control_policy: NOTICE });
    await cmdService([...ARGS, '--json']);
    expect(printJson).toHaveBeenCalledWith({ ...GRANT, control_policy: NOTICE });
    expect(printRecord).not.toHaveBeenCalled();
  });
});
