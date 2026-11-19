import { z } from 'zod';

/**
 * intent_outcome — post-execution record of an Intent's result.
 *
 * of the Signed Primitive epic. ADR
 * at the intent claims design (Design Decision 5).
 *
 * Every Intent claim (`intent_claim`) pairs with an Outcome claim at
 * execution time. The pair is linked via `intent_claim_ref` (required).
 * Together they form the verifiable record: Intent declares what was
 * attempted, Outcome records what STACK's executor actually did and
 * what came back.
 *
 * Each Outcome variant carries TWO classes of fields:
 *
 * 1. **What STACK's executor actually did** (the `actual_*` fields).
 *    Captured at the literal execution call-site, not earlier in the
 *    code path. The Intent declares "I'll POST to api.stripe.com";
 *    the executor records what URL it ACTUALLY dialed. Lets a
 *    verifier compare declared vs actual and detect divergence
 *    (different target, different method, different parameters).
 *
 * 2. **What came back from the upstream** (status_code, latency,
 *    response hashes, etc.). The traditional "outcome" half.
 *
 * The divergence check (intent.target === outcome.actual_target,
 * intent.action === outcome.actual_method_path, hash(intent.parameters)
 * === outcome.actual_parameters_hash) is deterministic — string and
 * hash equality, no LLM, no heuristic. Any divergence is a P0
 * security signal that fires the `intent_outcome_divergence`
 * detector.
 *
 * **Producer-discipline rule** (enforced in code review + test
 * coverage): `actual_*` fields MUST be captured from the executor's
 * actual runtime state, never copied from the Intent's declared
 * values. A lazy `outcome.actual_target = intent.target` defeats the
 * divergence check entirely. The capture point is at the `fetch()`
 * call site for HTTP, at the sealed-exec dispatch site for skills,
 * at the JSON-RPC dispatch site for A2A, etc.
 *
 * **Pre-execution failures**: when the call is blocked before being
 * sent (constraint check denies it, scope mismatch, accountability
 * monotonicity violation), the executor never reaches the capture
 * site. All `actual_*` fields are null in this case. Status will be
 * 'failed' or 'cancelled' (separate from "execution attempted and
 * upstream returned an error").
 *
 * v1 ships with the FULL 6-type discriminated union locked (after
 * revision 2026-05-15: shared ActionType enum + 6th
 * a2a_dispatch variant added): skill_invocation,
 * http_call, mcp_tool, onchain_tx, task_complete, a2a_dispatch.
 *
 * **Edge cases for actual_target / actual_method_path:**
 * - HTTP redirects: `actual_target` is the URL the executor INITIATED
 *   the call to, not where it ended up after redirect chains. Same
 *   for actual_method_path.
 * - DNS / dynamic resolution: hostname, never IP. Document the
 *   hostname the executor used; let DNS resolution drift be invisible
 *   (it's a network concern, not an integrity concern).
 * - Proxy chains: actual_target is the destination the executor
 *   asked for, not corporate-proxy hops.
 *
 * **Parameter hashing canonicalization:** `actual_parameters_hash` is
 * sha256 of the canonical-JSON encoding of the parameters at
 * execution time (sorted keys, no whitespace, defaults made
 * explicit). The Intent's `parameters` field is canonicalized the
 * same way for the divergence check. Hash mismatch = divergence.
 *
 * `cost_actual` uses the same shape as `IntentClaim.estimated_cost` so
 * cost variance is directly comparable at audit time without joining.
 */

const IntentOutcomeBase = z.object({
  type: z.literal('intent_outcome'),

  /**
   * The Intent claim this outcome pairs with. Required; an outcome
   * without an originating Intent is structurally invalid.
   */
  intent_claim_ref: z.string().regex(/^pc_[\w-]+$/, 'intent_claim_ref must be a passport-claim id (pc_*)'),

  /**
   * Final status of the action. Closed enum across all outcome_types:
   * - succeeded: execution attempted and upstream returned success
   * - failed: execution attempted, upstream returned error OR blocked
   *   pre-execution (constraint denial). When pre-execution, all
   *   actual_* fields are null.
   * - cancelled: operator or system cancelled before completion
   * - timeout: action exceeded its deadline
   */
  status: z.enum(['succeeded', 'failed', 'cancelled', 'timeout']),

  /** Wall-clock duration from Intent submission to Outcome record, ms. */
  duration_ms: z.number().int().nonnegative(),

  /**
   * Actual cost incurred. Same shape as Intent.estimated_cost so
   * variance is directly comparable.
   */
  cost_actual: z.object({
    wallet_cents: z.number().nonnegative().nullable(),
    tokens: z.number().int().nonnegative().nullable(),
    gas_gwei: z.number().nonnegative().nullable(),
  }),

  /** unix ms — when STACK recorded the outcome. */
  recorded_at: z.number().int(),

  /**
   * mission binding (additive nullable
   * retrofit). Auto-resolved by producers from the passport's
   * mission_ids when exactly one is bound; left null when zero or
   * multiple missions are active (caller can pass explicit override on
   * the originating intent_claim, which the outcome inherits).
   */
  mission_ref: z.string().regex(/^ms_[\w-]+$/, 'mission_ref must be a mission_id (ms_*)').nullable().optional(),
});

/**
 * Outcome for `skill_invocation` intents. Sealed skill execution
 * (container or node:vm fallback).
 */
const SkillInvocationOutcome = IntentOutcomeBase.extend({
  outcome_type: z.literal('skill_invocation'),

  /**
   * Actual skill_id the executor ran. Captured at the sealed-exec
   * dispatch call-site. Compare to Intent.target to detect "declared
   * skill A, ran skill B" divergence. Null on pre-execution failure.
   */
  actual_skill_id: z.string().nullable(),

  /**
   * sha256 of the canonical-JSON encoded input the executor actually
   * passed to the skill (after secret redaction). Captured at the
   * dispatch call-site. Null on pre-execution failure.
   */
  actual_input_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),

  /** sha256 of the skill's encrypted output bytes (hex). Null for failed/cancelled/timeout. */
  output_envelope_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),

  /** Process exit code (container or node:vm error code). Null if not applicable. */
  exit_code: z.number().int().nullable(),
});

/**
 * Outcome for `http_call` intents. Proxied HTTP request through the
 * STACK proxy (existing) or Shroud-LITE.
 */
const HttpCallOutcome = IntentOutcomeBase.extend({
  outcome_type: z.literal('http_call'),

  /**
   * Actual URL hostname the executor dialed. Captured at the `fetch()`
   * call-site, BEFORE any redirect-following. Hostname only (not IP).
   * Compare to Intent.target. Null on pre-execution failure.
   */
  actual_target: z.string().nullable(),

  /**
   * Actual method + path the executor used. e.g. "POST /v1/charges".
   * Captured at the `fetch()` call-site. Compare to Intent.action.
   * Null on pre-execution failure.
   */
  actual_method_path: z.string().nullable(),

  /**
   * sha256 of canonical-JSON encoded parameters the executor actually
   * sent (after secret redaction). Captured at the call-site. Compare
   * to canonical-hash of Intent.parameters. Null on pre-execution
   * failure.
   */
  actual_parameters_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),

  /** Upstream HTTP status code. Null on pre-execution failure. */
  status_code: z.number().int().nullable(),

  /** sha256 of the response body (hex). Null if no body or pre-execution failure. */
  response_body_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),

  /** Upstream latency in ms (separate from duration_ms which includes STACK overhead). */
  latency_ms: z.number().int().nonnegative().nullable(),

  /** How many credential redactions fired on this call. */
  redactions_count: z.number().int().nonnegative().default(0),

  /** How many detectors fired on this call (input + output side). */
  detector_fires_count: z.number().int().nonnegative().default(0),
});

/**
 * Outcome for `mcp_tool` intents. MCP tool invocation against a
 * downstream MCP server.
 */
const McpToolOutcome = IntentOutcomeBase.extend({
  outcome_type: z.literal('mcp_tool'),

  /**
   * Actual tool name the executor invoked. Captured at the MCP
   * dispatch call-site. Compare to Intent.action. Null on
   * pre-execution failure.
   */
  actual_tool_name: z.string().nullable(),

  /**
   * sha256 of canonical-JSON encoded args the executor passed.
   * Captured at the dispatch call-site. Compare to canonical-hash of
   * Intent.parameters. Null on pre-execution failure.
   */
  actual_args_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),

  /** sha256 of the tool's structured result (hex). Null on failure. */
  tool_result_envelope_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),

  /** MCP error code if the tool returned an error. Null on success. */
  tool_error_code: z.string().nullable(),
});

/**
 * Outcome for `onchain_tx` intents. EVM transaction submission. Other
 * chain families add additively as new outcome variants.
 */
const OnchainTxOutcome = IntentOutcomeBase.extend({
  outcome_type: z.literal('onchain_tx'),

  /**
   * Actual contract address the executor submitted to (lower-case
   * 0x-prefixed). Compare to Intent.target. Null on pre-execution
   * failure.
   */
  actual_contract: z.string().regex(/^0x[0-9a-f]{40}$/).nullable(),

  /**
   * Actual function selector the executor invoked.
   * e.g. "transfer(address,uint256)". Compare to Intent.action.
   * Null on pre-execution failure.
   */
  actual_function_selector: z.string().nullable(),

  /**
   * sha256 of canonical-JSON encoded args the executor sent. Compare
   * to canonical-hash of Intent.parameters. Null on pre-execution
   * failure.
   */
  actual_args_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),

  /** Transaction hash (0x-prefixed 64-char hex). Null if submission failed pre-broadcast. */
  tx_hash: z.string().regex(/^0x[0-9a-f]{64}$/).nullable(),

  /** Block number containing the tx. Null if not yet confirmed. */
  block_number: z.number().int().nullable(),

  /** Actual gas used. Null if not yet confirmed or submission failed. */
  gas_used: z.number().int().nonnegative().nullable(),

  /** Revert reason string if the tx reverted. Null on success or pre-broadcast failure. */
  revert_reason: z.string().nullable(),
});

/**
 * Outcome for `task_complete` intents. Informational only — agent
 * declared completion of a step. No external action, no upstream
 * response, no executor capture. Only common fields apply.
 */
const TaskCompleteOutcome = IntentOutcomeBase.extend({
  outcome_type: z.literal('task_complete'),
});

/**
 * Outcome for `a2a_dispatch` intents. Peer-to-peer agent message
 * dispatch via A2A protocol (JSON-RPC over HTTP). Different semantic
 * from mcp_tool — A2A is agent-to-agent, MCP is agent-to-tool-server.
 */
const A2aDispatchOutcome = IntentOutcomeBase.extend({
  outcome_type: z.literal('a2a_dispatch'),

  /**
   * Actual destination agent id the executor dispatched to (in the
   * receiving operator's namespace). Compare to Intent.target.
   * Null on pre-execution failure.
   */
  actual_target_agent: z.string().nullable(),

  /**
   * Actual A2A method invoked (e.g. 'tasks/send', 'tasks/get').
   * Compare to Intent.action. Null on pre-execution failure.
   */
  actual_method: z.string().nullable(),

  /**
   * sha256 of canonical-JSON encoded JSON-RPC args the executor sent.
   * Compare to canonical-hash of Intent.parameters. Null on
   * pre-execution failure.
   */
  actual_args_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),

  /** A2A task_id assigned by the receiving agent. Null on submission failure. */
  remote_task_id: z.string().nullable(),

  /** A2A task lifecycle state at outcome record time. */
  task_state: z.enum(['pending', 'in_progress', 'completed', 'failed', 'cancelled']).nullable(),

  /** sha256 of the A2A task's structured result envelope. Null until completed. */
  task_result_envelope_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
});

export const IntentOutcomeClaim = z.discriminatedUnion('outcome_type', [
  SkillInvocationOutcome,
  HttpCallOutcome,
  McpToolOutcome,
  OnchainTxOutcome,
  TaskCompleteOutcome,
  A2aDispatchOutcome,
]);

export type IntentOutcomeClaim = z.infer<typeof IntentOutcomeClaim>;
