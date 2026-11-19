import { readFileSync } from 'node:fs';
import { api, takeFlag } from './api.js';
import { printJson } from './format.js';
import { Stack } from '@getstackrun/sdk';

export function readFleetRequest(args: string[]): Record<string, unknown> {
  const file = takeFlag(args, '--file');
  if (typeof file !== 'string') throw new Error('Invalid input');
  const value: unknown = JSON.parse(readFileSync(file, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid input');
  return value as Record<string, unknown>;
}

export async function cmdFleets(argv: string[]): Promise<void> {
  const args = [...argv]; takeFlag(args, '--json');
  const sub = args.shift();
  const page = takeFlag(args, '--page'); const limit = takeFlag(args, '--limit');
  const query = { ...(typeof page === 'string' ? { page } : {}), ...(typeof limit === 'string' ? { limit } : {}) };
  if (sub === 'list') return printJson(await api('GET', '/v1/fleets', { query }));
  if (sub === 'session') {
    const policyId = takeFlag(args, '--fleet-policy-id');
    return printJson(await api('POST', '/v1/fleets/session', { body: typeof policyId === 'string' ? { fleet_policy_id: policyId } : {} }));
  }
  const approval = takeFlag(args, '--governance-approval-id');
  const headers: Record<string, string> = typeof approval === 'string' ? { 'X-Governance-Approval': approval } : {};
  if (sub === 'activate') {
    const key = takeFlag(args, '--idempotency-key');
    if (typeof key !== 'string') throw new Error('Invalid input');
    headers['Idempotency-Key'] = key;
    return printJson(await api('POST', '/v1/fleets', { body: readFleetRequest(args), headers }));
  }
  const policyId = args.shift();
  if (!policyId) throw new Error('Invalid input');
  const path = `/v1/fleets/${encodeURIComponent(policyId)}`;
  if (sub === 'get') return printJson(await api('GET', path));
  if (sub === 'membership') return printJson(await api('GET', `/v1/fleets/membership/${encodeURIComponent(policyId)}`));
  if (sub === 'revise') {
    const revision = takeFlag(args, '--expected-revision'); const key = takeFlag(args, '--idempotency-key');
    if (typeof revision !== 'string' || !/^\d+$/.test(revision) || typeof key !== 'string') throw new Error('Invalid input');
    headers['If-Match'] = revision; headers['Idempotency-Key'] = key;
    return printJson(await api('PUT', path, { body: readFleetRequest(args), headers }));
  }
  if (sub === 'members') return printJson(await api('GET', `${path}/members`, { query }));
  if (sub === 'revoke-member') {
    const agentId = args.shift(); if (!agentId) throw new Error('Invalid input');
    return printJson(await api('POST', `${path}/members/${encodeURIComponent(agentId)}/revoke`, { body: {} }));
  }
  if (sub === 'revoke') return printJson(await api('POST', `${path}/revoke`, { body: {} }));
  if (sub === 'enrollment-challenge') return printJson(await api('POST', `${path}/enrollment-challenges`, { body: {} }));
  if (sub === 'enroll') return printJson(await api('POST', `${path}/enroll`, { body: readFleetRequest(args) }));
  if (sub === 'enroll-workload-local') {
    const name = takeFlag(args, '--name'); const key = takeFlag(args, '--idempotency-key');
    const token = process.env['STACK_WORKLOAD_TOKEN'];
    if (typeof name !== 'string' || typeof key !== 'string' || !token) throw new Error('Invalid input');
    const stack = new Stack({ apiKey: token });
    return printJson(await stack.fleets.enrollWorkloadLocal(policyId, { name, idempotency_key: key }));
  }
  if (sub === 'enroll-local') {
    const name = takeFlag(args, '--name'); const key = takeFlag(args, '--idempotency-key');
    if (typeof name !== 'string' || typeof key !== 'string' || !process.env['STACK_AGENT_ID']) throw new Error('Invalid input');
    const stack = new Stack({ agent_id: process.env['STACK_AGENT_ID'] });
    return printJson(await stack.fleets.enrollLocal(policyId, { name, idempotency_key: key }));
  }
  throw new Error('Invalid input');
}
