import { z } from 'zod';

const ServiceConnectionId = z.string().min(1).max(128);

export const InviteMemberInput = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
  role: z.enum(['readonly', 'standard', 'admin']).default('standard'),
  // omitted/null = unrestricted; [] = no service connections.
  allowed_connections: z.array(ServiceConnectionId).nullable().optional(),
});
export type InviteMemberInput = z.infer<typeof InviteMemberInput>;

export const UpdateMemberInput = z.object({
  role: z.enum(['readonly', 'standard', 'admin']).optional(),
  // omitted = unchanged; null = unrestricted; [] = no service connections.
  allowed_connections: z.array(ServiceConnectionId).nullable().optional(),
});
export type UpdateMemberInput = z.infer<typeof UpdateMemberInput>;

/**
 * Forget the single sign-on binding of members, so the next verified sign-in with the identity provider now in use
 * binds them again. One member by id, or every member bound to one issuer (the `iss` of the provider that was
 * replaced). A person with a binding cannot sign in under another subject, so a customer that changes provider
 * would otherwise lock out everyone who had signed in before.
 */
export const ClearSsoBindingsInput = z.union([
  z.object({ member_id: z.string().min(1).max(128) }).strict(),
  z.object({ issuer: z.string().min(1).max(2048) }).strict(),
]);
export type ClearSsoBindingsInput = z.infer<typeof ClearSsoBindingsInput>;

/** What a clear removed: the members that had a binding, and the issuer each was bound to. */
export const ClearedSsoBinding = z.object({
  id: z.string(),
  email: z.string(),
  sso_issuer: z.string(),
});
export type ClearedSsoBinding = z.infer<typeof ClearedSsoBinding>;

export const ClearSsoBindingsResult = z.object({
  cleared: z.array(ClearedSsoBinding),
});
export type ClearSsoBindingsResult = z.infer<typeof ClearSsoBindingsResult>;
