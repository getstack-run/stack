import { InviteMemberInput, UpdateMemberInput } from '@stack/shared';
import { describe, expect, it, vi } from 'vitest';
import { MemberService } from './member-service.js';

function makeSubject(activeConnectionIds: string[] = []) {
  const repo = {
    findById: vi.fn(async () => ({
      id: 'mem_test',
      operator_id: 'op_owner',
      status: 'active',
    })),
    findActiveConnectionIds: vi.fn(async () => activeConnectionIds),
    updateAccess: vi.fn(async (_id: string, data: Record<string, unknown>) => data),
  };
  return { subject: new MemberService(repo as never), repo };
}

describe('member allowed_connections wire semantics', () => {
  it('accepts null, an empty list, and explicit connection ids', () => {
    const base = { email: 'member@example.test', name: 'Member' };
    expect(InviteMemberInput.parse({ ...base, allowed_connections: null }).allowed_connections).toBeNull();
    expect(InviteMemberInput.parse({ ...base, allowed_connections: [] }).allowed_connections).toEqual([]);
    expect(
      UpdateMemberInput.parse({ allowed_connections: ['scon_one'] }).allowed_connections,
    ).toEqual(['scon_one']);
  });

  it('preserves omitted update, null unrestricted, and empty-list deny-all as distinct states', async () => {
    const { subject, repo } = makeSubject();

    await subject.updateAccess('mem_test', 'op_owner', { role: 'readonly' });
    expect(repo.updateAccess).toHaveBeenLastCalledWith('mem_test', { role: 'readonly' });

    await subject.updateAccess('mem_test', 'op_owner', { allowed_connections: null });
    expect(repo.updateAccess).toHaveBeenLastCalledWith('mem_test', { allowed_connections: null });

    await subject.updateAccess('mem_test', 'op_owner', { allowed_connections: [] });
    expect(repo.updateAccess).toHaveBeenLastCalledWith('mem_test', { allowed_connections: [] });
  });

  it('persists only active same-operator connection ids and removes duplicates', async () => {
    const { subject, repo } = makeSubject(['scon_one', 'scon_two']);

    await subject.updateAccess('mem_test', 'op_owner', {
      allowed_connections: ['scon_one', 'scon_one', 'scon_two'],
    });

    expect(repo.findActiveConnectionIds).toHaveBeenCalledWith(
      'op_owner',
      ['scon_one', 'scon_two'],
      undefined,
    );
    expect(repo.updateAccess).toHaveBeenCalledWith('mem_test', {
      allowed_connections: ['scon_one', 'scon_two'],
    });
  });

  it('rejects foreign, missing, or inactive ids without revealing which case occurred', async () => {
    const { subject, repo } = makeSubject(['scon_one']);

    await expect(
      subject.updateAccess('mem_test', 'op_owner', {
        allowed_connections: ['scon_one', 'scon_foreign_or_inactive'],
      }),
    ).rejects.toMatchObject({ statusCode: 403 });
    expect(repo.updateAccess).not.toHaveBeenCalled();
  });
});
