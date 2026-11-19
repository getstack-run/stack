// What an approval covers, as plain lines a person reads before they say yes.
//
// An approval a person may confirm in the chat must show the whole change there, not a one-line title: the chat
// confirmation is the person's only look at it. These lines are built from the preview the API stored with the
// approval (derived from the request and the customer's own connections, never from the caller's words), and they
// never summarise a part away: every scope, every constraint and every host is a line of its own.
//
// What the caller wrote (a constraint's value, a name, a host) is text, and text can carry a newline and a line that
// looks like another part of the change. Every such value is put on ONE line: control and separator characters become
// a space, and a text value is shown in quotes, so nothing a caller wrote can pose as a line of its own.
//
// Pure and total: a preview of an unexpected shape gives no lines, and the caller then says it cannot show the change.

const OP_WORDS: Record<string, string> = {
  eq: 'must be',
  not_eq: 'must not be',
  in: 'must be one of',
  not_in: 'may not be',
  matches: 'must match',
  starts_with: 'must start with',
  lt: 'must be under',
  lte: 'must be at most',
  gt: 'must be over',
  gte: 'must be at least',
  exists: 'must be present',
  not_exists: 'must be absent',
};

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Control characters, DEL, NEL, the line and paragraph separators and every kind of space: anything that could end or start a line. */
// eslint-disable-next-line no-control-regex
const LINE_BREAKERS = /[\s\u0000-\u001f\u007f\u0085\u2028\u2029]+/g;

/** A text on one line: every run of control, separator and space characters becomes one space, and the ends are trimmed. */
export function oneLine(text: string): string {
  return text.replace(LINE_BREAKERS, ' ').trim();
}

/** A text value as a person reads it: on one line and in quotes (a quote inside it is escaped). */
export function quotedText(text: string): string {
  return JSON.stringify(oneLine(text));
}

const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string').map(oneLine) : [];

const plain = (value: unknown): string => (typeof value === 'string' ? oneLine(value) : '');

function constraintLine(constraint: unknown): string | null {
  if (!isObject(constraint) || typeof constraint['path'] !== 'string' || typeof constraint['op'] !== 'string') return null;
  const op = constraint['op'];
  if (op === 'any_of') {
    // Several rules, any one of which allows a call: every rule is shown in full, on this one line.
    const groups = Array.isArray(constraint['value']) ? constraint['value'] : [];
    const rules = groups.map((group) => {
      const parts = Array.isArray(group) ? group.map((leaf) => constraintLine(leaf) ?? 'a limit that cannot be shown') : [];
      return `(${parts.join('; ')})`;
    });
    return `a call may match any one of these rules: ${rules.join(' or ') || 'none that can be shown'}`;
  }
  const path = oneLine(constraint['path']);
  const words = OP_WORDS[op] ?? oneLine(op);
  if (op === 'exists' || op === 'not_exists') return `${path} ${words}`;
  const value = constraint['value'];
  const shown = Array.isArray(value)
    ? value.map((item) => (typeof item === 'string' ? quotedText(item) : oneLine(String(item)))).join(', ')
    : typeof value === 'string'
      ? quotedText(value)
      : oneLine(JSON.stringify(value) ?? '');
  return `${path} ${words} ${shown}`;
}

/**
 * The connection's own name, as the owner gave it, beside the service it is a connection of: in quotes, because it is a
 * value a person wrote. Empty for a preview that carries none (an approval asked before names were kept), which then
 * reads as it always did.
 */
function connectionTag(entry: Record<string, unknown>): string {
  const name = plain(entry['connection_name']);
  return name ? ` (${quotedText(name)})` : '';
}

function grantLines(grant: Record<string, unknown>, who: string | null): string[] {
  const service = typeof grant['service'] === 'string' ? oneLine(grant['service']) : null;
  const scopes = strings(grant['scopes']);
  if (!service || scopes.length === 0) return [];
  const lines = [`${who ? `give ${who} ` : ''}access to ${service}${connectionTag(grant)} with scopes ${scopes.join(', ')}`];
  const constraints = Array.isArray(grant['constraints']) ? grant['constraints'] : [];
  const intents = strings(grant['intents']);
  const alternatives = Array.isArray(grant['alternatives']) ? grant['alternatives'] : [];
  if (constraints.length === 0 && intents.length === 0 && alternatives.length === 0) lines.push('  with no limits on what it may do there');
  for (const constraint of constraints) {
    const line = constraintLine(constraint);
    if (line) lines.push(`  ${line}`);
  }
  for (const intent of intents) lines.push(`  limited to the named action ${intent}`);
  if (alternatives.length > 0) {
    // Rules of which any one allows a call: each is a line of its own, in full.
    lines.push('  a call may match any one of these rules:');
    alternatives.forEach((rule, index) => {
      const parts: string[] = [];
      if (isObject(rule)) {
        for (const intent of strings(rule['intents'])) parts.push(`the named action ${intent}`);
        for (const constraint of Array.isArray(rule['constraints']) ? rule['constraints'] : []) {
          parts.push(constraintLine(constraint) ?? 'a limit that cannot be shown');
        }
      }
      lines.push(`    rule ${index + 1}: ${parts.join('; ') || 'a rule that cannot be shown'}`);
    });
  }
  const flow = strings(grant['allow_data_from']);
  if (flow.length > 0) lines.push(`  content from ${flow.join(', ')} may flow into it`);
  return lines;
}

/** The lines of an `agent_setup` or `service_grant_expand` preview; none for any other action or a malformed preview. */
export function approvalScopeLines(view: { action: string; setup_preview?: unknown; grant_preview?: unknown; intent_preview?: unknown }): string[] {
  if (view.action === 'intent_approve' || view.action === 'intent_approve_payment') {
    // The API built these lines from the stored intent (each agent-written value capped, on one line, in quotes);
    // they are kept as they are, with any stray line break folded away again.
    const preview = view.intent_preview;
    if (!isObject(preview) || !Array.isArray(preview['lines'])) return [];
    const lines = preview['lines'];
    return lines.length > 0 && lines.every((line) => typeof line === 'string') ? (lines as string[]).map(oneLine) : [];
  }
  if (view.action === 'agent_setup') {
    const preview = view.setup_preview;
    if (!isObject(preview) || !isObject(preview['agent']) || !Array.isArray(preview['grants']) || !Array.isArray(preview['allowed_hosts'])) return [];
    const agent = preview['agent'];
    if (typeof agent['name'] !== 'string') return [];
    const lines = [
      `register agent ${oneLine(agent['name'])}`,
      `accountability ${plain(agent['accountability_mode'])}; on warning ${plain(agent['on_warning'])}; on critical ${plain(agent['on_critical'])}; credentials ${plain(agent['credential_access'])}`,
    ];
    for (const other of Array.isArray(agent['other_fields']) ? agent['other_fields'] : []) {
      if (isObject(other) && typeof other['field'] === 'string' && typeof other['value'] === 'string') {
        lines.push(`also sets ${oneLine(other['field'])} to ${oneLine(other['value'])}`);
      }
    }
    if (agent['eval_traffic'] === true) lines.push('marked as test traffic: warnings arrive already resolved, criticals stay live');
    for (const grant of preview['grants']) {
      if (isObject(grant)) lines.push(...grantLines(grant, 'it'));
    }
    for (const entry of preview['allowed_hosts']) {
      if (!isObject(entry)) continue;
      const hosts = strings(entry['hosts']);
      if (typeof entry['service'] === 'string' && hosts.length > 0) {
        lines.push(`allow the ${oneLine(entry['service'])} credential${connectionTag(entry)} to be sent to ${hosts.join(', ')}`);
      }
    }
    return lines;
  }
  if (view.action === 'service_grant_expand') {
    const preview = view.grant_preview;
    if (!isObject(preview)) return [];
    const agent = typeof preview['agent_id'] === 'string' ? oneLine(preview['agent_id']) : null;
    const lines = grantLines(preview, agent ? `agent ${agent}` : null);
    if (lines.length === 0) return [];
    const listing = preview['policy_listing'];
    if (isObject(listing) && typeof listing['policy_id'] === 'string') {
      lines.push(`and list this service in the agent's controls policy ${oneLine(listing['policy_id'])}, changing nothing else in it`);
    }
    return lines;
  }
  return [];
}
