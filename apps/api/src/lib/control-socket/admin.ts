// Rules for changing a customer's control socket, kept apart from the routes so
// they can be tested without a server.
//
// Tightening applies at once. Anything that loosens (clearing an enforcing
// socket, unchecking an action kind, switching hosted controls to none) or that
// moves where decisions and the record go (an address, a signing secret) is a
// governance action a person approves in a signed-in browser.

import {
  CONTROL_ACTION_TYPES,
  ControlSocketAddressError,
  parsePublicUrl,
  resolvePublicUrl,
  type ControlActionType,
  type ControlDecider,
  type ControlModeSetting,
} from '@stack/shared';

/**
 * Check an address when it is set: https (http only in a development build),
 * no URL credentials, query or fragment (a secret does not belong in a stored
 * URL), a public host that resolves only to public addresses. The same check
 * runs again at every call, because DNS can change after this one.
 */
export async function assertControlAddress(raw: string, allowHttp: boolean): Promise<string> {
  const allowedProtocols = allowHttp ? ['https:', 'http:'] : ['https:'];
  let url: URL;
  try {
    url = parsePublicUrl(raw.trim(), { allowedProtocols });
  } catch {
    throw new ControlSocketAddressError('The address must be a public https URL with no credentials.', 'unsafe_url');
  }
  if (url.search || url.hash) {
    throw new ControlSocketAddressError('The address must not carry a query string or fragment; put nothing secret in it.', 'query_not_allowed');
  }
  try {
    await resolvePublicUrl(url.href, { allowedProtocols });
  } catch {
    throw new ControlSocketAddressError('The address does not resolve to a public host.', 'unresolvable');
  }
  return url.href;
}

export type ModeChange = 'unchanged' | 'tightening' | 'loosening' | 'socket_change';

/**
 * How a change of who decides compares to today. Loosening: fewer checks by
 * STACK, whether to nobody or to a server STACK cannot vouch for. Leaving a
 * customer's own server for hosted checks drops that customer's rules, so it is
 * a change of the socket; the rest add checks.
 */
export function classifyModeChange(from: ControlDecider, to: ControlDecider): ModeChange {
  if (from === to) return 'unchanged';
  if (to === 'none') return 'loosening';
  if (from === 'none') return 'tightening';
  if (from === 'hosted' && to === 'remote') return 'loosening';
  return 'socket_change';
}

/**
 * What choosing `to` is, given the customer's setting and who decides now.
 * Choosing none is a loosening whenever it changes the setting, even while
 * controls are off and nobody decides anyway: the setting outlives that state
 * and would silently switch every check off the day a controls subscription
 * starts. Anything else reads as a change of who decides.
 */
export function classifyModeSetting(
  before: { mode_setting: ControlModeSetting; effective_mode: ControlDecider },
  to: 'none' | 'hosted',
): ModeChange {
  if (to === 'none') return before.mode_setting === 'none' ? 'unchanged' : 'loosening';
  return classifyModeChange(before.effective_mode, to);
}

/** The kinds checked now but not after. Null is every kind. */
export function removedTypes(
  current: readonly ControlActionType[] | null,
  next: readonly ControlActionType[] | null,
): ControlActionType[] {
  const before = new Set<ControlActionType>(current ?? CONTROL_ACTION_TYPES);
  const after = new Set<ControlActionType>(next ?? CONTROL_ACTION_TYPES);
  return [...before].filter((type) => !after.has(type)).sort();
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return 'the given address';
  }
}
