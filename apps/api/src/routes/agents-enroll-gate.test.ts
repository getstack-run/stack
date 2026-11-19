import { describe, it, expect } from 'vitest';
import { enrollAcceptsPubkeyUpload } from './agents.js';

// #10 — the /enroll pubkey-upload gate. Only customer_managed agents
// may enroll a customer-held public key. stack_managed + co_signed agents have
// their keypair auto-provisioned by AgentSigner on first sign; enrolling a
// pubkey on them is invalid and used to violate the agents_key_material_
// consistency CHECK → unhandled 500 (the FamilyBot dogfooding failure). This
// pins the invariant so the guard hole (previously it only refused when a STACK
// key already existed) cannot silently reopen.

describe('enrollAcceptsPubkeyUpload', () => {
  it('accepts customer_managed', () => {
    expect(enrollAcceptsPubkeyUpload('customer_managed')).toBe(true);
  });

  it('refuses stack_managed (auto-provisioned; no enroll needed)', () => {
    expect(enrollAcceptsPubkeyUpload('stack_managed')).toBe(false);
  });

  it('refuses co_signed', () => {
    expect(enrollAcceptsPubkeyUpload('co_signed')).toBe(false);
  });

  it('is fail-closed on any unknown key_mode', () => {
    expect(enrollAcceptsPubkeyUpload('')).toBe(false);
    expect(enrollAcceptsPubkeyUpload('future_mode')).toBe(false);
  });
});
