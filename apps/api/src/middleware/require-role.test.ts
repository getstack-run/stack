import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';
import { requireRole } from './require-role.js';

describe('member role validation', () => {
  it.each(['unknown', '__proto__', 'constructor', '', undefined])('fails closed for role %s', (memberRole) => {
    expect(() => requireRole({ memberId: 'mem_a', memberRole } as FastifyRequest, 'standard')).toThrow();
  });
  it('allows a standard member only within their role', () => {
    const request = { memberId: 'mem_a', memberRole: 'standard' } as FastifyRequest;
    expect(() => requireRole(request, 'standard')).not.toThrow();
    expect(() => requireRole(request, 'admin')).toThrow();
  });
});
