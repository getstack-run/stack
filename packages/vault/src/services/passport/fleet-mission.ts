import {
  FleetPassportBinding,
  ForbiddenError,
  type DelegatePassportInput,
  type IssuePassportInput,
} from '@stack/shared';
import { delegatePassport } from './delegate.js';
import { issuePassportInternal } from './issue.js';
import type { PassportContext } from './types.js';

/**
 * Issue the root and the worker Passport of a fleet Mission. Only the server's
 * Mission coordinator calls this. The root token never leaves this function.
 */
export async function issueFleetMissionPassports(
  ctx: PassportContext,
  operatorId: string,
  rootInput: IssuePassportInput,
  childInput: Omit<DelegatePassportInput, 'parent_passport_token'>,
  binding: FleetPassportBinding,
  sessionId?: string,
) {
  const parsed = FleetPassportBinding.parse(binding);
  if (parsed.internal_root || rootInput.intent?.platform_intent || !rootInput.intent)
    throw new ForbiddenError();
  const root = await issuePassportInternal(
    ctx,
    operatorId,
    {
      ...rootInput,
      authority_binding_ids: [],
      mission_ids: [parsed.mission_id],
      identity_claim_ids: rootInput.identity_claim_ids ?? [],
      intent: { ...rootInput.intent, will_delegate: true },
    },
    { ...parsed, internal_root: true },
    sessionId,
  );
  return delegatePassport(
    ctx,
    operatorId,
    { ...childInput, parent_passport_token: root.token },
    true,
    rootInput.authority_binding_ids,
  );
}
