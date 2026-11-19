import { env, stderr } from 'node:process';
import { openBrowser } from './auth.js';
import {
  ApiRequestError,
  requestApi,
  type ApiMethod,
  type ApiOptions,
} from './api.js';

interface GovernanceApproval {
  id: string;
  status: 'pending' | 'approved' | 'rejected' | 'consumed' | 'expired';
  expires_at: string;
}

type Request = <T>(method: ApiMethod, path: string, opts?: ApiOptions) => Promise<T>;

export interface GovernanceFlowOptions {
  request?: Request;
  open?: (url: string) => void;
  sleep?: (milliseconds: number) => Promise<void>;
  now?: () => number;
  pollIntervalMs?: number;
  interactive?: boolean;
}

function approvalFrom(error: ApiRequestError): { id: string; url: string } | null {
  if (error.code !== 'GOVERNANCE_APPROVAL_REQUIRED') return null;
  const id = error.details?.['approval_id'];
  const url = error.details?.['approval_url'];
  if (typeof id !== 'string' || typeof url !== 'string') {
    throw new Error('The API requested governance approval without an approval id and URL');
  }
  return { id, url };
}

export async function governedApi<T = unknown>(
  method: ApiMethod,
  path: string,
  opts?: ApiOptions,
  flow: GovernanceFlowOptions = {},
): Promise<T> {
  const request = flow.request ?? requestApi;
  let approval: { id: string; url: string };
  try {
    return await request<T>(method, path, opts);
  } catch (error) {
    if (!(error instanceof ApiRequestError)) throw error;
    const parsed = approvalFrom(error);
    if (!parsed) throw error;
    approval = parsed;
  }

  stderr.write(`Human approval required: ${approval.url}\n`);
  const interactive = flow.interactive ?? (stderr.isTTY === true && env['STACK_NO_BROWSER'] !== '1');
  if (interactive) (flow.open ?? openBrowser)(approval.url);
  stderr.write(`Waiting for approval ${approval.id}...\n`);

  const now = flow.now ?? Date.now;
  const sleep = flow.sleep ?? ((milliseconds: number) => new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  }));
  const pollIntervalMs = flow.pollIntervalMs ?? 2_000;
  let deadline = now() + 15 * 60_000;

  const read = async (): Promise<GovernanceApproval | undefined> => {
    const response = await request<{ approvals?: GovernanceApproval[] }>(
      'GET',
      '/v1/governance/approvals',
    );
    return response.approvals?.find((item) => item.id === approval.id);
  };
  /** What the API says of the approval once it is decided or over; undefined while it is still waiting. */
  const settled = (current: GovernanceApproval | undefined): Promise<T> | undefined => {
    if (!current) return undefined;
    if (current.status === 'approved') {
      return request<T>(method, path, {
        ...opts,
        headers: {
          ...(opts?.headers ?? {}),
          'X-Governance-Approval': approval.id,
        },
      });
    }
    if (current.status === 'rejected') throw new Error(`Governance approval ${approval.id} was rejected`);
    if (current.status === 'expired') throw new Error(`Governance approval ${approval.id} expired`);
    if (current.status === 'consumed') throw new Error(`Governance approval ${approval.id} was already used`);
    return undefined;
  };

  let last: GovernanceApproval | undefined;
  while (now() <= deadline) {
    const current = await read();
    last = current ?? last;
    if (current) {
      const expiresAt = Date.parse(current.expires_at);
      if (Number.isFinite(expiresAt)) deadline = Math.min(deadline, expiresAt);
      const done = settled(current);
      if (done) return done;
    }
    await sleep(pollIntervalMs);
  }

  // The wait is over, not necessarily the approval: it lives on the server for its own time (24 hours) and the person
  // may still decide. One last read says which it is: a decision made in the last moment is taken, and only an
  // approval the API says is expired is called expired.
  const final = await read();
  last = final ?? last;
  const done = settled(final);
  if (done) return done;
  const openUntil = last && Number.isFinite(Date.parse(last.expires_at)) && Date.parse(last.expires_at) > now()
    ? ` It stays open until ${last.expires_at}.`
    : ' It stays open for its own time.';
  throw new Error(
    `No decision was made on approval ${approval.id} while waiting.${openUntil} Approve it at ${approval.url}, then run the same command again to continue with this approval.`,
  );
}
