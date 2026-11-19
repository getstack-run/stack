import { stderr, exit } from 'node:process';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { fmtTs, printJson, printRecord, printTable } from './format.js';

// Governance approvals, read only. A step-up asks a person to approve one
// exact change; `approval show` prints one approval with its status, the hash
// of the change it covers and the link to its own page, and `approval list`
// the account's approvals, newest first. Deciding is done by a person in the
// dashboard, or confirmed in an MCP chat client, never from here.

interface ApprovalDetail {
  approval: Record<string, unknown>;
  payload_hash: string;
  approval_url: string;
}

interface ApprovalRow {
  id: string;
  action: string;
  summary: string;
  status: string;
  expires_at: string;
}

const STATUSES = ['pending', 'approved', 'rejected', 'consumed', 'expired'];

export async function cmdApproval(argv: string[]): Promise<void> {
  const args = [...argv];
  const json = !!takeFlag(args, '--json');
  const status = takeFlag(args, '--status');
  const sub = args.shift();
  const approvalId = args.shift();

  if ((sub === 'show' || sub === 'get') && approvalId) {
    const detail = await api<ApprovalDetail>('GET', `/v1/governance/approvals/${encodeURIComponent(approvalId)}`);
    if (json) return printJson(detail);
    printRecord({ ...detail.approval, payload_hash: detail.payload_hash, approval_url: detail.approval_url });
    return;
  }

  if (sub === 'list' && approvalId === undefined) {
    if (status !== undefined && (typeof status !== 'string' || !STATUSES.includes(status))) {
      stderr.write(`--status is one of ${STATUSES.join(', ')}\n`);
      exit(2);
    }
    const { approvals } = await api<{ approvals: ApprovalRow[] }>('GET', '/v1/governance/approvals');
    const shown = status === undefined ? approvals : approvals.filter((item) => item.status === status);
    if (json) return printJson({ approvals: shown });
    printTable(
      ['ID', 'ACTION', 'STATUS', 'EXPIRES', 'SUMMARY'],
      shown.map((item) => [item.id, item.action, item.status, fmtTs(item.expires_at), item.summary]),
    );
    return;
  }

  stderr.write(`usage: ${invokeHint('approval show <approval-id>')}\n       ${invokeHint('approval list [--status pending] [--json]')}\n`);
  exit(2);
}
