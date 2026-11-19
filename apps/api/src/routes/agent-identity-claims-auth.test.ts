import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { requireIdentityClaimAssignmentAuthority } from './agents.js';

const reply = {} as never;

describe('agent identity claim assignment authorization', () => {
  it('allows the operator owner', async () => {
    await expect(requireIdentityClaimAssignmentAuthority({} as never, reply)).resolves.toBeUndefined();
  });

  it('allows an admin team member', async () => {
    await expect(requireIdentityClaimAssignmentAuthority({
      memberId: 'mem_admin',
      memberRole: 'admin',
    } as never, reply)).resolves.toBeUndefined();
  });

  it.each(['standard', 'readonly'])('denies a %s team member', async (memberRole) => {
    await expect(requireIdentityClaimAssignmentAuthority({
      memberId: 'mem_member',
      memberRole,
    } as never, reply)).rejects.toThrow('operator-admin access required');
  });

  it('runs the gate only when identity claim IDs are in the patch', () => {
    const source = readFileSync(new URL('./agents.ts', import.meta.url), 'utf8');
    const route = source.slice(
      source.indexOf("'/v1/agents/:id'"),
      source.indexOf('// Unblock agent'),
    );

    expect(route).toContain('input.identity_claim_ids !== undefined');
    expect(route).toContain('requireIdentityClaimAssignmentAuthority(request, reply)');
  });
});
