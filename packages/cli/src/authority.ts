import { readFileSync } from 'node:fs';
import { exit, stderr } from 'node:process';
import { api, takeFlag } from './api.js';
import { invokeHint } from './auth.js';
import { printJson, printRecord } from './format.js';

interface AuthorityRequest {
  request_id: string;
  status: 'pending' | 'rejected' | 'expired' | 'completed';
  approval_url: string;
  created_at: string;
  expires_at: string;
  completed_at?: string;
  result?: { binding_id: string };
}

function readRequest(path: string): Record<string, unknown> {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (!value || Array.isArray(value) || typeof value !== 'object') {
      throw new Error('the file must contain one JSON object');
    }
    return value as Record<string, unknown>;
  } catch (error) {
    stderr.write(`error: could not read Authority request from ${path}: ${(error as Error).message}\n`);
    exit(2);
  }
}

async function requestAuthority(args: string[], json: boolean): Promise<void> {
  const file = takeFlag(args, '--file');
  const idempotencyKey = takeFlag(args, '--idempotency-key');
  if (typeof file !== 'string' || typeof idempotencyKey !== 'string') {
    stderr.write(`usage: ${invokeHint('authority request --file <request.json> --idempotency-key <key> [--json]')}\n`);
    exit(2);
  }
  const result = await api<AuthorityRequest>('POST', '/v1/authority/enterprise-oidc/requests', {
    body: readRequest(file),
    headers: { 'Idempotency-Key': idempotencyKey },
  });
  if (json) return printJson(result);
  printRecord({
    request_id: result.request_id,
    status: result.status,
    approval_url: result.approval_url,
    expires_at: result.expires_at,
  });
}

async function requestStatus(requestId: string, json: boolean): Promise<void> {
  const result = await api<AuthorityRequest>(
    'GET',
    `/v1/authority/enterprise-oidc/requests/${encodeURIComponent(requestId)}`,
  );
  if (json) return printJson(result);
  printRecord({
    request_id: result.request_id,
    status: result.status,
    approval_url: result.approval_url,
    binding_id: result.result?.binding_id ?? '',
    expires_at: result.expires_at,
  });
}

export async function cmdAuthority(argv: string[]): Promise<void> {
  const args = [...argv];
  const json = takeFlag(args, '--json') === true;
  const subcommand = args.shift();
  if (subcommand === 'request') return requestAuthority(args, json);
  if (subcommand === 'status' && args[0]) return requestStatus(args[0], json);
  stderr.write(
    `usage: ${invokeHint('authority request --file <request.json> --idempotency-key <key> [--json]')}\n` +
    `   or: ${invokeHint('authority status <request-id> [--json]')}\n`,
  );
  exit(2);
}
