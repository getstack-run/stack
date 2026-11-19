// Tool annotations and the directory profile.
//
// Every tool registered by createStackMcpServer must have an entry in the
// `annotations` of the module that registers it (an `<ID>_ANNOTATIONS` table
// beside its `register<Id>Tools`). Registration throws on a missing entry, so
// a new tool cannot ship without a title and all three hints. The tools a
// module leaves out of the directory profile, with the reason, are the
// `directoryExcluded` of the same module.
//
// Classification rule (applies to both profiles):
//
// readOnlyHint
//   true only when the tool changes no state. Audit-log rows written for
//   access are not state changes. Metering is. A POST that persists or meters
//   anything is not read-only: stack_scan (meters, records security events),
//   stack_verify_connection (updates connection status),
//   stack_simulate_intent (persists a claim by default) and
//   stack_fleet_enrollment_challenge (creates a challenge).
//
// destructiveHint (MCP: "may perform destructive updates"; false means
//   only additive updates). Always false for read-only tools.
//   true when the tool revokes, deletes, disconnects, expires, collects
//   (the payload is deleted), suspends, blocks, ends a lifecycle, or
//   overwrites or resets existing configuration so prior values are lost.
//   false when it only creates, appends, or restores.
//
// openWorldHint
//   true when the tool's own effect reaches a party or system outside the
//   caller's STACK account: a provider API (proxy, connection checks), an
//   email, SMS or webhook recipient, an identity provider, or the shared
//   skills marketplace (content written by or visible to other operators).
//   false when the effect stays inside the caller's STACK account. Messages
//   that operator-configured notification rules send later in reaction to an
//   event, and STACK's own internal sub-processors, are not counted.

export interface StackToolAnnotation {
  title: string;
  readOnlyHint: boolean;
  destructiveHint: boolean;
  openWorldHint: boolean;
}

export type McpProfile = 'standard' | 'directory';

const read = (title: string, openWorldHint = false): StackToolAnnotation => ({
  title, readOnlyHint: true, destructiveHint: false, openWorldHint,
});
const write = (title: string, openWorldHint = false): StackToolAnnotation => ({
  title, readOnlyHint: false, destructiveHint: false, openWorldHint,
});
const destructive = (title: string, openWorldHint = false): StackToolAnnotation => ({
  title, readOnlyHint: false, destructiveHint: true, openWorldHint,
});

/** The three kinds of tool, by the classification rule above. */
export const hint = { read, write, destructive } as const;

/**
 * Optional parameters removed from every directory-profile tool schema.
 * A retained directory tool with a REQUIRED parameter of this name is a
 * configuration error and registration throws.
 */
export const DIRECTORY_OMITTED_PARAMS: readonly string[] = ['passport_token'];

/** Description phrases that instruct the model or leak internal tracking. */
export const FORBIDDEN_DESCRIPTION_PATTERN =
  /call this tool first|RETRY|GET-\d+|Sub-chunk|Phase \d|BEFORE feeding/i;

/**
 * A price or an allowance written into a description. A price changes without a release of the tool list, so a
 * description says where to read it and never states it.
 */
export const PRICE_IN_DESCRIPTION_PATTERN = /\$\s?\d|\bper (?:1,000|10,000)\b|\d[\d,]*\s+(?:metered\s+)?actions? (?:a|per) month/i;
