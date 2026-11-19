// The engine's entry point serves a self-managed install. A hosted machine that still points at it (a stale image
// or start command), and any process that forgot STACK_DEPLOYMENT (unset reads as hosted), must fail to boot instead
// of serving without a meter or without the licence check, so this runs before anything else of the API loads:
// before its environment is read and before any service is built, in every environment. The messages are fixed text:
// the one that says why the entry point refuses, or the boot message of the setting that is wrong (an unreadable
// STACK_DEPLOYMENT, a missing STACK_API_BASE_URL), never a value read from the environment.
import { assertEngineEntryAllowed } from '@stack/shared';

try {
  assertEngineEntryAllowed();
} catch (error) {
  const message = error instanceof Error && error.message.startsWith('[BOOT] ')
    ? error.message
    : '[BOOT] The engine entry point could not read its deployment settings.';
  console.error(message);
  process.exit(1);
}
