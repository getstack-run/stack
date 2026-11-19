import { describe, it, expect } from 'vitest';
import { isTransientDbError } from './transient-db-error.js';

describe('isTransientDbError', () => {
  it('classifies postgres SQLSTATE 57P01 (admin_shutdown) as transient', () => {
    expect(isTransientDbError({ code: '57P01', message: 'terminating connection' })).toBe(true);
  });

  it('classifies ECONNRESET at top level as transient', () => {
    expect(isTransientDbError({ code: 'ECONNRESET', message: 'socket reset' })).toBe(true);
  });

  it('classifies pgbouncer phrase in top-level message as transient', () => {
    expect(isTransientDbError(new Error('pgbouncer: server connection broken'))).toBe(true);
  });

  it('classifies "connection terminated" in message as transient', () => {
    expect(isTransientDbError(new Error('connection terminated unexpectedly'))).toBe(true);
  });

  // Drizzle wraps the underlying
  // error in a "Failed query: ..." prefix and exposes the real cause via
  // err.cause. The classifier must walk the chain.
  it('classifies Drizzle "Failed query" wrapping a transient cause as transient (one level)', () => {
    const inner = new Error('Connection terminated unexpectedly') as Error & { code?: string };
    inner.code = '57P01';
    const drizzle = new Error('Failed query: select "id" from "dropoffs"') as Error & { cause?: unknown };
    drizzle.cause = inner;
    expect(isTransientDbError(drizzle)).toBe(true);
  });

  it('classifies a transient cause two levels deep (pg-pool wraps postgres-js wraps real)', () => {
    const real = { code: 'ECONNRESET', message: 'socket reset' };
    const middle = { message: 'connection lost', cause: real };
    const outer = new Error('Failed query: ...') as Error & { cause?: unknown };
    outer.cause = middle;
    expect(isTransientDbError(outer)).toBe(true);
  });

  it('does NOT classify a real domain error (no transient code, no transient phrase)', () => {
    expect(isTransientDbError(new Error('Skill not found'))).toBe(false);
  });

  it('does NOT classify a 4xx-style validation error', () => {
    const e = new Error('Schema validation failed') as Error & { code?: string };
    e.code = 'INVALID_REQUEST';
    expect(isTransientDbError(e)).toBe(false);
  });

  it('handles non-object inputs without crashing', () => {
    expect(isTransientDbError(null)).toBe(false);
    expect(isTransientDbError(undefined)).toBe(false);
    expect(isTransientDbError('string error')).toBe(false);
    expect(isTransientDbError(42)).toBe(false);
  });

  it('stops at depth=4 to avoid infinite cause loops', () => {
    // Construct a circular cause chain — the classifier must terminate.
    const a: { cause?: unknown } = {};
    const b: { cause?: unknown } = {};
    a.cause = b;
    b.cause = a;
    // No transient indicators anywhere — expect false (and no infinite loop).
    expect(isTransientDbError(a)).toBe(false);
  });
});
