import type { FastifyInstance } from 'fastify';
import { approvalWaitSeverity } from '../lib/approval-wait-severity.js';
import { z } from 'zod';
import { beginAgentRuntime, normalizedFleetOperation } from '../lib/agent-runtime.js';
import { decideControl } from '../lib/control-decision.js';
import { controlTargets } from '../lib/control-socket/targets.js';
import {
  CreateDropoffInput,
  sha256,
  ids,
  ForbiddenError,
  StackError,
  deployment,
} from '@stack/shared';
import type { Services } from '../config/services.js';
import { createAuthMiddleware } from '../middleware/auth.js';
import { auditCtx } from '../middleware/audit.js';
import { meterAction } from '../middleware/meter.js';
import { requireRole } from '../middleware/require-role.js';
import { assertDropoffAgentBinding } from '../lib/dropoff-authority.js';
import { announceDeposit } from '../lib/dropoff-deposited.js';
import { computeDepositProvenance } from '../lib/provenance.js';
import {
  completeRuntimeAuthorityUse,
  enforceRuntimeAuthority,
  markRuntimeAuthorityDispatched,
  runtimeAuthorityFailureResult,
  runtimeAuthorityRequestIdFromHeaders,
} from '../lib/runtime-authority.js';

/**
 * A2A (Agent-to-Agent) protocol mapper. Part of the Signed
 * Primitive epic. Wraps the existing @stack/dropoff service in the
 * A2A wire shape (Google/IBM-led agent-to-agent protocol).
 *
 * What A2A buys: protocol-level interop with agent frameworks that
 * already speak A2A (LangChain agents, CrewAI, AutoGen, and the
 * growing list of A2A-aware tooling). They can `tasks/send` to a
 * STACK-hosted agent without learning STACK's native dropoff API.
 *
 * What we ship in v1:
 *   - AgentCard at /.well-known/agent.json — platform-level
 *     descriptor advertising STACK as an A2A endpoint.
 *   - JSON-RPC 2.0 endpoint at /v1/a2a/jsonrpc with methods:
 *     tasks/send, tasks/get, tasks/cancel.
 *   - Mapping to dropoff service for storage, state transitions,
 *     and tamper-evident audit.
 *
 * STACK extensions (carried in A2A `metadata`):
 *   - metadata.stack_from_agent — sender agent ID (required on send)
 *   - metadata.stack_to_agent   — recipient agent ID (required on send)
 *   Both must belong to the authenticated operator. Cross-operator
 *   A2A federation is a v2 concern (needs an external-agent identity
 *   model first, likely SPIFFE/WIMSE-rooted).
 *
 * What's deferred to v2:
 *   - Per-agent AgentCards (today's card is platform-level; v2 hosts
 *     /agents/:id/.well-known/agent.json per agent).
 *   - tasks/sendSubscribe SSE streams (today's send is unary).
 *   - tasks/pushNotification/set webhook config.
 *   - File and Data parts richer than base64 inlined in the message.
 *   - True synchronous request/response (today is async one-shot via
 *     drop-off; the receiver collects later and there's no auto-reply
 *     channel back to the caller through the same task).
 */

const A2A_PROTOCOL_VERSION = '0.2.1';
const JSONRPC_VERSION = '2.0';

// A JSON-RPC id is a string, a number or null. Anything else cannot be echoed
// back as a valid id, so it is reported as null rather than rejecting an
// otherwise well-formed request.
const JsonRpcId = z.union([z.string(), z.number(), z.null()]).optional().catch(null);

// Envelope of an inbound JSON-RPC 2.0 request. `params` is only meaningful
// as an object; any other shape is handled like an absent `params`, which the
// method handlers already answer with an invalid-params error.
const JsonRpcRequestSchema = z.object({
  jsonrpc: z.literal(JSONRPC_VERSION),
  id: JsonRpcId,
  method: z.string(),
  params: z
    .unknown()
    .transform((value) => {
      const record = z.record(z.string(), z.unknown()).safeParse(value);
      return record.success ? record.data : undefined;
    }),
});

type JsonRpcRequest = z.infer<typeof JsonRpcRequestSchema>;

// Used only to echo a request id back on an invalid envelope.
const JsonRpcIdProbe = z.object({ id: JsonRpcId });

interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

function rpcResult(id: string | number | null | undefined, result: unknown) {
  return { jsonrpc: JSONRPC_VERSION, id: id ?? null, result };
}

function rpcError(id: string | number | null | undefined, code: number, message: string, data?: unknown) {
  return { jsonrpc: JSONRPC_VERSION, id: id ?? null, error: { code, message, ...(data !== undefined ? { data } : {}) } };
}

// JSON-RPC 2.0 standard error codes used here. (PARSE_ERROR -32700 and
// INTERNAL_ERROR -32603 are part of the spec but not used in this
// dispatcher — Fastify handles JSON parse failures before reaching us
// and we let internal exceptions propagate to the global error handler.)
const RPC_INVALID_REQUEST = -32600;
const RPC_METHOD_NOT_FOUND = -32601;
const RPC_INVALID_PARAMS = -32602;
// A2A-defined error codes (per spec).
const A2A_TASK_NOT_FOUND = -32001;
const A2A_TASK_NOT_CANCELABLE = -32002;

/** Map dropoff status to A2A TaskState. */
function dropoffStatusToA2aState(status: string): 'submitted' | 'working' | 'completed' | 'canceled' | 'failed' {
  switch (status) {
    case 'created':
      return 'submitted';
    case 'deposited':
      return 'working';
    case 'collected':
      return 'completed';
    case 'expired':
      return 'failed';
    default:
      return 'failed';
  }
}

/**
 * Public AgentCard endpoint registered separately under the no-auth
 * section in server.ts. Discovery of STACK's A2A capabilities.
 */
export const A2A_CARD_DESCRIPTION =
  'A2A endpoint for agent-to-agent messaging routed through STACK\'s schema-validated, encrypted drop-off layer.';

/** The card's description: the engine's sentence, behind the deployment's own line when it has one. */
export function a2aCardDescription(tagline?: string): string {
  return tagline ? `${tagline} ${A2A_CARD_DESCRIPTION}` : A2A_CARD_DESCRIPTION;
}

export function registerA2aAgentCardRoute(app: FastifyInstance, _services: Services, options: { tagline?: string } = {}) {
  const description = a2aCardDescription(options.tagline);
  app.get('/.well-known/agent.json', async (_req, reply) => {
    return reply.send({
      name: 'STACK',
      description,
      url: `${deployment().apiBaseUrl}/v1/a2a/jsonrpc`,
      provider: {
        organization: deployment().passportIssuer,
        url: deployment().siteUrl,
      },
      version: A2A_PROTOCOL_VERSION,
      defaultInputModes: ['text', 'data'],
      defaultOutputModes: ['text', 'data'],
      capabilities: {
        streaming: false,                 // v2: tasks/sendSubscribe
        pushNotifications: false,         // v2: tasks/pushNotification/set
        stateTransitionHistory: false,    // v2: Task.history
      },
      authentication: {
        // A2A spec is auth-agnostic. STACK uses its own auth surfaces.
        schemes: ['bearer', 'operator_api_key'],
      },
      skills: [
        {
          id: 'stack.dropoff.relay',
          name: 'Drop-off relay',
          description:
            'Forward an A2A task to a STACK-hosted agent via the schema-validated ' +
            'drop-off layer. Sender + recipient identified via metadata.stack_from_agent ' +
            'and metadata.stack_to_agent.',
          tags: ['messaging', 'dropoff'],
        },
      ],
    });
  });
}

/**
 * Auth-protected JSON-RPC dispatch. Mounted in the operator-scoped
 * section of server.ts. Standard STACK auth resolves request.operatorId.
 */
export function registerA2aRpcRoute(app: FastifyInstance, services: Services) {
  const auth = createAuthMiddleware(services);

  app.post('/v1/a2a/jsonrpc', { preHandler: auth }, async (request, reply) => {
    const envelope = JsonRpcRequestSchema.safeParse(request.body);
    if (!envelope.success) {
      const probe = JsonRpcIdProbe.safeParse(request.body);
      return reply
        .code(400)
        .send(rpcError(probe.success ? (probe.data.id ?? null) : null, RPC_INVALID_REQUEST, 'Invalid JSON-RPC envelope'));
    }
    const body = envelope.data;

    try {
      if (body.method === 'tasks/send') {
        return await handleTasksSend(services, request, reply, body);
      }
      if (body.method === 'tasks/get') {
        return await handleTasksGet(services, request, reply, body);
      }
      if (body.method === 'tasks/cancel') {
        return await handleTasksCancel(services, request, reply, body);
      }
      return reply.send(rpcError(body.id, RPC_METHOD_NOT_FOUND, `Unknown method "${body.method}"`));
    } catch (err) {
      const sentinelError = mapStackErrorToRpc(err);
      if (sentinelError) {
        return reply.send(rpcError(body.id, sentinelError.code, sentinelError.message, sentinelError.data));
      }
      throw err;
    }
  });
}

export function mapStackErrorToRpc(err: unknown): JsonRpcError | null {
  if (err instanceof StackError) {
    if (err.code === 'NOT_FOUND') {
      return { code: A2A_TASK_NOT_FOUND, message: 'Task not found' };
    }
    if (
      err.code === 'DROPOFF_ALREADY_COLLECTED' ||
      err.code === 'DROPOFF_EXPIRED' ||
      err.code === 'CONFLICT'
    ) {
      return { code: A2A_TASK_NOT_CANCELABLE, message: 'Task cannot be changed' };
    }
    return { code: RPC_INVALID_PARAMS, message: 'Invalid task request' };
  }
  return null;
}

async function handleTasksSend(
  services: Services,
  request: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
  body: JsonRpcRequest,
) {
  requireRole(request, 'standard');
  const params = body.params ?? {};
  const taskId = typeof params['id'] === 'string' ? (params['id'] as string) : ids.dropoff();
  const sessionId = typeof params['sessionId'] === 'string' ? (params['sessionId'] as string) : null;
  const message = params['message'];
  const metadata = (params['metadata'] ?? {}) as Record<string, unknown>;
  const fromAgent = typeof metadata['stack_from_agent'] === 'string' ? (metadata['stack_from_agent'] as string) : null;
  const toAgent = typeof metadata['stack_to_agent'] === 'string' ? (metadata['stack_to_agent'] as string) : null;

  if (!message || typeof message !== 'object') {
    return reply.send(rpcError(body.id, RPC_INVALID_PARAMS, 'params.message is required'));
  }
  if (!fromAgent || !toAgent) {
    return reply.send(
      rpcError(
        body.id,
        RPC_INVALID_PARAMS,
        'params.metadata.stack_from_agent and stack_to_agent are required (STACK extension)',
      ),
    );
  }

  // Hoist passport-id extraction so the agent-ownership denial path
  // can use it before the agent.getById throws.
  const suppliedPassportId =
    typeof metadata['stack_passport_id'] === 'string'
      ? (metadata['stack_passport_id'] as string)
      : null;
  const suppliedMissionId =
    typeof metadata['stack_mission_id'] === 'string'
      ? (metadata['stack_mission_id'] as string)
      : null;

  assertDropoffAgentBinding(request, fromAgent);
  if (request.passportContext && suppliedPassportId && suppliedPassportId !== request.passportContext.jti) {
    throw new ForbiddenError('Passport cannot authorize this drop-off attribution');
  }
  const passportId = request.passportContext?.jti ?? suppliedPassportId;

  // Verify the sender before trusting the Passport reference. The recipient
  // is tenant-checked after authority evaluation, before billing or writes.
  // capture the sender agent so we can read its
  // accountability_mode for the gate + the intent_claim payload (the
  // line-307 hardcoded 'standard' was a real correctness bug; the
  // a2a wire shape never carries the JWT so we read mode from the
  // agent row).
  const fromAgentRecord = await services.agent.getById(fromAgent, request.operatorId);

  let dispatchPassportRow: Awaited<ReturnType<typeof services.passport.findByJti>> | null = null;
  if (passportId) {
    dispatchPassportRow = await services.passport.findByJti(passportId) ?? null;
    if (!dispatchPassportRow) throw new ForbiddenError('Invalid task request');
  }

  // Mission admission, before authority evaluation, metering or any write.
  // A2A maps onto drop-offs inside STACK, so the Mission's service scope does
  // not apply (requestedService 'stack:a2a', internal); its lifecycle,
  // duration and caps do. The Mission it returns attributes everything below.
  const a2aAccountabilityMode = ((fromAgentRecord?.accountability_mode ?? 'standard') as
    | 'enforced'
    | 'logged'
    | 'standard');
  const runtime = await beginAgentRuntime(services, request, { agentId: fromAgent, passportId,
    explicitMissionId: suppliedMissionId, producer: 'a2a', requestedService: 'stack:a2a', internal: true,
    targetId: toAgent, action: 'tasks/send', normalizedRequest: normalizedFleetOperation('tasks/send', { from_agent: fromAgent, to_agent: toAgent, message }),
    bytes: Buffer.byteLength(JSON.stringify(message)), accountability: a2aAccountabilityMode,
    denial: { intentType: 'a2a_dispatch', namedIntent: 'stack:a2a:tasks_send', parameters: { to_agent: toAgent } } });
  const fleetAdmission = runtime?.fleet ?? null;
  const authorityMissionRef = runtime?.missionId ?? null;
  // An account's agents work together, so a task between them stays open; the
  // customer's decider is asked like for any action, before any write or authority use.
  await decideControl(services, request, {
    action: 'a2a.send', scope: 'agent', agentId: fromAgent, runtime,
    target: controlTargets.a2aSend({ toAgent, messageBytes: Buffer.byteLength(JSON.stringify(message)) }),
  });

  // The A2A message payload deposited onto the drop-off. The full A2A
  // Message object (role + parts + sessionId) is preserved so the receiver
  // can reconstruct A2A semantics on collect.
  const payload = {
    message,
    sessionId,
    a2a_task_id: taskId,
    metadata,
  };
  // Where the message's content came from, matched against what the
  // sender's Mission has read, so the receiver inherits the ORIGINAL sources
  // when it collects. Before any authority use, allocation or write; with
  // controls on it refuses (503) if it cannot be established.
  // lib/provenance.ts.
  const provenance = await computeDepositProvenance(services, {
    operatorId: request.operatorId, agentId: fromAgent, passportJti: runtime?.passportJti ?? null,
    missionId: authorityMissionRef, payload, producer: 'a2a', mode: runtime?.accountability,
  });

  const start = Date.now();

  // A2A producer migration. CR2 from the
  // ADR closes the chunk D gap (A2A shipped without claim
  // emission). Claims attach to a passport; the A2A wire format
  // doesn't natively carry one, so we accept an opt-in
  // `metadata.stack_passport_id` STACK extension. When absent, the
  // dropoff write happens as before with no claim emission; when
  // present, we dual-write an Intent + Outcome pair with the dropoff
  // id as the remote_task_id.
  const argsCanonical = JSON.stringify({ message, sessionId }, (_k, v) => v);
  const argsHash = sha256(argsCanonical);

  // Map to dropoff. Use a permissive schema since A2A messages are
  // arbitrary-shape; the safety gate is at the receiver's collection
  // logic, not the transport.
  let runtimeAuthorityDecision: Awaited<ReturnType<typeof enforceRuntimeAuthority>> = {
    enforced: false,
  };
  if (passportId) {
    const authorityAgentId = request.passportContext?.agent_id ?? dispatchPassportRow?.agent_id;
    if (!authorityAgentId) throw new ForbiddenError('Invalid task request');
    runtimeAuthorityDecision = await enforceRuntimeAuthority(services.authority, {
      operatorId: request.operatorId,
      passportJti: passportId,
      agentId: authorityAgentId,
      authenticatedAgentId: request.agentId ?? null,
      receiverRequestId: runtimeAuthorityRequestIdFromHeaders(request.headers),
      ...(authorityMissionRef ? { missionId: authorityMissionRef } : {}),
      boundary: {
        kind: 'a2a',
        receiverAgentId: toAgent,
      },
      normalizedRequest: {
        method: 'tasks/send',
        task_id: taskId,
        session_id: sessionId,
        from_agent: fromAgent,
        to_agent: toAgent,
        message,
        metadata,
        resource_type: 'agent',
        resource_ref: toAgent,
      },
      verificationMode: 'proxy_mediated',
    });
  }
  // Resolve the tenant-owned recipient only after the authority chokepoint.
  // Legacy Passports still reach this check via { enforced: false }.
  await services.agent.getById(toAgent, request.operatorId);
  await meterAction(services, request);

  // universal approval gate (a2a variant).
  // Mode comes from the sender agent row (A2A v1 wire shape carries
  // only the opaque passport id, not the JWT). Bug fix: pre-2.4 we
  // hardcoded accountability='standard' on the intent_claim payload
  // (a2a.ts:307) — meant enforced-mode agents NEVER triggered the
  // gate, only logged-mode behaviour worked. Now reads the actual
  // agent mode.
  const a2aApprovalIdHeader = request.headers['x-intent-approval-id'] as string | undefined;
  let a2aGateApprovalId: string | undefined;
  let a2aGateIntentClaimId: string | undefined;
  if (a2aAccountabilityMode === 'enforced' && passportId) {
    const passportSessionId = dispatchPassportRow?.session_id ?? '';
    const gate = await services.approvalGate.check({
      ...(fleetAdmission ? { policyAuthorization: fleetAdmission.authorization } : {}),
      passportJti: passportId,
      agentId: fromAgent,
      missionId: authorityMissionRef,
      operatorId: request.operatorId,
      sessionId: passportSessionId,
      accountabilityMode: 'enforced',
      approvalIdHeader: a2aApprovalIdHeader,
    });
    if (!gate.allowed) {
      const attemptedIntent: import('@stack/shared').IntentClaim = gate.intentClaim ?? {
        type: 'intent_claim',
        intent_type: 'a2a_dispatch',
        agent_id: fromAgent,
        named_intent: 'stack:a2a:tasks_send',
        target: toAgent,
        action: 'tasks/send',
        parameters: { args_hash: argsHash },
        estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
        accountability: 'enforced',
        reason: null,
        requires: [],
        user_subject: request.memberId ? `mem:${request.memberId}` : null,
        mission_ref: authorityMissionRef,
        submitted_at: Date.now(),
      };
      try {
        await services.claimRegistry.recordIntentDenial({
          operatorId: request.operatorId,
          passportJti: passportId,
          attemptedIntent,
          denialReason: gate.reason === 'requires_unmet' ? 'requires_unmet' : 'scope_mismatch',
          message: gate.message,
          metadata: { ...gate.metadata },
        });
      } catch (err) {
        console.error('[agent-to-agent] intent_denial emission failed at gate:', safeErrorSummary(err));
      }
      try {
        await services.securityEvent.record({
          operatorId: request.operatorId,
          agentId: fromAgent,
          passportJti: passportId,
          signalType: 'credential_outside_scope',
          // Waiting on the person, or no approval yet, is a warning; another's approval or a replay stays critical.
          severity: approvalWaitSeverity(gate.reason),
          message: `Approval gate denied A2A dispatch: ${gate.message}`,
          metadata: { ...gate.metadata, from_agent: fromAgent, to_agent: toAgent },
        });
      } catch (err) {
        console.error('[agent-to-agent] security_event emission failed at gate:', safeErrorSummary(err));
      }
      return reply.code(403).send(
        rpcError(body.id, RPC_INVALID_PARAMS, gate.message),
      );
    }
    if (!gate.skipped && !fleetAdmission) {
      // Per-producer comparator (D9): intent_type === 'a2a_dispatch',
      // target === toAgent, parameters.args_hash === argsHash.
      const approved = gate.intentClaim;
      const approvedParams = approved.parameters as { args_hash?: unknown };
      const approvedArgs =
        typeof approvedParams.args_hash === 'string' ? approvedParams.args_hash : undefined;
      let mismatch: { field: string; expected: unknown; actual: unknown } | null = null;
      if (approved.intent_type !== 'a2a_dispatch') {
        mismatch = { field: 'intent_type', expected: approved.intent_type, actual: 'a2a_dispatch' };
      } else if (approved.target !== toAgent) {
        mismatch = { field: 'target', expected: approved.target, actual: toAgent };
      } else if (approvedArgs !== undefined && approvedArgs !== argsHash) {
        mismatch = { field: 'args_hash', expected: approvedArgs, actual: argsHash };
      }
      if (mismatch) {
        try {
          await services.claimRegistry.recordIntentDenial({
            operatorId: request.operatorId,
            passportJti: passportId,
            attemptedIntent: approved,
            denialReason: 'scope_mismatch',
            message: `A2A call does not match approved intent (field=${mismatch.field})`,
            metadata: {
              approval_id: gate.approvalId,
              gate_reason: 'call_mismatch',
              field_mismatch: mismatch,
            },
          });
        } catch (err) {
          console.error('[agent-to-agent] intent_denial emission failed for call_mismatch:', safeErrorSummary(err));
        }
        return reply.code(403).send(
          rpcError(
            body.id,
            RPC_INVALID_PARAMS,
            `A2A call does not match approved intent (field=${mismatch.field})`,
          ),
        );
      }
      a2aGateApprovalId = gate.approvalId;
      a2aGateIntentClaimId = gate.intentClaimId;
    }
  }

  // Allocate the transport resource only after every authority and approval
  // gate has admitted the dispatch. Denied calls cannot leave orphan dropoffs.
  if (fleetAdmission) {
    a2aGateIntentClaimId = fleetAdmission.authorization.intentClaimId;
    await services.fleetAdmission.dispatch(fleetAdmission, 0);
  }
  const createInput = CreateDropoffInput.parse({
    from_agent: fromAgent,
    to_agent: toAgent,
    schema: { type: 'object' },
  });
  await markRuntimeAuthorityDispatched(
    services.authority,
    request.operatorId,
    runtimeAuthorityDecision,
  );
  let dropoff: Awaited<ReturnType<typeof services.dropoff.create>>;
  try {
    dropoff = await services.db.transaction(async (tx) => {
      const created = await services.dropoff.create(request.operatorId, createInput, tx);
      await services.audit.write({
        ctx: auditCtx(request, {
          agent_id: fromAgent,
          ...(passportId ? { passport_jti: passportId } : {}),
        }),
        layer: 'dropoff',
        action: 'dropoff.create',
        outcome: 'success',
        duration_ms: Date.now() - start,
      }, tx);
      return created;
    });
  } catch (err) {
    try {
      await completeRuntimeAuthorityUse(
        services.authority,
        request.operatorId,
        runtimeAuthorityDecision,
        'failed',
        runtimeAuthorityFailureResult(err),
      );
    } catch (finalizationError) {
      request.log.error(
        { code: (finalizationError as { code?: unknown })?.code ?? 'AUTHORITY_FINALIZATION_FAILED' },
        '[authority] failed to finalize A2A allocation failure',
      );
    }
    throw err;
  }

  // Emit Intent BEFORE the deposit so a deposit failure still leaves a
  // signed record of the attempt (paired with a 'failed' Outcome).
  // Skipped when no passport extension provided.
  //
  // when the approval gate admitted this call, reuse
  // the gate-approved intent_claim_id so the outcome chains to it
  // directly (no duplicate intent_claim row). Otherwise fall back to
  // synthesising the intent_claim as in 1.18.
  let intentClaimId: string | null = a2aGateIntentClaimId ?? null;
  if (!intentClaimId && passportId) {
    try {
      const intentResult = await services.claimRegistry.registerClaim({
        operatorId: request.operatorId,
        passportJti: passportId,
        claimType: 'intent_claim',
        payload: {
          type: 'intent_claim',
          intent_type: 'a2a_dispatch',
          agent_id: fromAgent,
          named_intent: 'stack:a2a:tasks_send',
          target: toAgent,
          action: 'tasks/send',
          parameters: { args_hash: argsHash, ...(sessionId ? { session_id: sessionId } : {}) },
          estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
          // bug fix — was hardcoded 'standard'. Now
          // reflects the sender agent's actual mode.
          accountability: a2aAccountabilityMode,
          reason: null,
          requires: [],
          user_subject: request.memberId ? `mem:${request.memberId}` : null,
          mission_ref: authorityMissionRef,
          submitted_at: Date.now(),
        },
      });
      intentClaimId = intentResult.claimId;
    } catch (err) {
      console.error('intent_claim emission failed:', safeErrorSummary(err));
    }
  }

  // Deposit the A2A message payload (built above, with its provenance).
  try {
    await services.db.transaction(async (tx) => {
      await services.dropoff.deposit(
        dropoff.id,
        request.operatorId,
        fromAgent,
        payload,
        authorityMissionRef,
        tx,
        provenance as unknown as Record<string, unknown>,
      );
      await services.audit.write({
        ctx: auditCtx(request, {
          agent_id: fromAgent,
          ...(passportId ? { passport_jti: passportId } : {}),
        }),
        layer: 'dropoff',
        action: 'dropoff.deposit',
        outcome: 'success',
        duration_ms: Date.now() - start,
        payload_hash: sha256(JSON.stringify(payload)),
      }, tx);
    });
  } catch (err) {
    // Failure path Outcome — pair the Intent with a 'failed' record
    // before rethrowing. Best-effort: registry throw is logged.
    let failureOutcomeClaimId: string | null = null;
    if (intentClaimId && passportId) {
      try {
        const outcomeResult = await services.claimRegistry.registerClaim({
          operatorId: request.operatorId,
          passportJti: passportId,
          claimType: 'intent_outcome',
          payload: {
            type: 'intent_outcome',
            intent_claim_ref: intentClaimId,
            status: 'failed',
            duration_ms: Date.now() - start,
            cost_actual: { wallet_cents: 0, tokens: null, gas_gwei: null },
            recorded_at: Date.now(),
            outcome_type: 'a2a_dispatch',
            actual_target_agent: null,
            actual_method: null,
            actual_args_hash: null,
            remote_task_id: null,
            task_state: null,
            task_result_envelope_hash: null,
          },
        });
        failureOutcomeClaimId = outcomeResult.claimId;
      } catch (outcomeErr) {
        console.error('failure-path intent_outcome emission failed:', safeErrorSummary(outcomeErr));
      }
    }
    try {
      await completeRuntimeAuthorityUse(
        services.authority,
        request.operatorId,
        runtimeAuthorityDecision,
        'failed',
        runtimeAuthorityFailureResult(err),
        { intentClaimId, outcomeClaimId: failureOutcomeClaimId },
      );
    } catch (finalizationError) {
      request.log.error(
        { code: (finalizationError as { code?: unknown })?.code ?? 'AUTHORITY_FINALIZATION_FAILED' },
        '[authority] failed to finalize A2A deposit failure',
      );
    }
    throw err;
  }

  // The task is deposited and committed: the receiving agent is woken, as for any drop-off.
  await announceDeposit(services, {
    operatorId: request.operatorId,
    dropoffId: dropoff.id,
    fromAgentId: fromAgent,
    toAgentIds: [toAgent],
  }, request.log);

  // Success-path Outcome — captured AT the dispatch site, so
  // actual_target_agent + actual_method + actual_args_hash reflect what
  // the executor actually sent (vs. the Intent's declared values).
  let outcomeClaimId: string | null = null;
  if (intentClaimId && passportId) {
    try {
      const outcomeResult = await services.claimRegistry.registerClaim({
        operatorId: request.operatorId,
        passportJti: passportId,
        claimType: 'intent_outcome',
        payload: {
          type: 'intent_outcome',
          intent_claim_ref: intentClaimId,
          // Dispatch succeeded; the receiver collects later. Task state
          // 'pending' reflects the dropoff's pre-collection state.
          status: 'succeeded',
          duration_ms: Date.now() - start,
          cost_actual: { wallet_cents: 0, tokens: null, gas_gwei: null },
          recorded_at: Date.now(),
          outcome_type: 'a2a_dispatch',
          actual_target_agent: toAgent,
          actual_method: 'tasks/send',
          actual_args_hash: argsHash,
          remote_task_id: dropoff.id,
          task_state: 'pending',
          task_result_envelope_hash: null,
        },
      });
      outcomeClaimId = outcomeResult.claimId;
    } catch (err) {
      console.error('success-path intent_outcome emission failed:', safeErrorSummary(err));
    }
  }

  const responseBody = rpcResult(body.id, {
    id: dropoff.id,
    sessionId,
    status: {
      state: 'submitted',
      timestamp: new Date().toISOString(),
    },
    metadata: {
      ...metadata,
      stack_dropoff_id: dropoff.id,
    },
  });
  await completeRuntimeAuthorityUse(
    services.authority,
    request.operatorId,
    runtimeAuthorityDecision,
    'succeeded',
    { status: 200, body: responseBody },
    { intentClaimId, outcomeClaimId },
  );

  // flip approval to 'consumed' after successful
  // dispatch. The receiver collects later via the dropoff lifecycle;
  // dispatch success is the boundary we consume on.
  if (a2aGateApprovalId) {
    try {
      await services.approvalGate.markConsumed(a2aGateApprovalId);
    } catch (err) {
      console.error('[agent-to-agent] markConsumed failed:', safeErrorSummary(err));
    }
  }

  await services.audit.write({
    ctx: auditCtx(request, { agent_id: fromAgent }),
    layer: 'dropoff',
    action: 'a2a.tasks.send',
    outcome: 'success',
    duration_ms: Date.now() - start,
    payload_hash: sha256(JSON.stringify(payload)),
  });

  // A2A Task response — state 'submitted' since the receiver hasn't
  // collected yet. Receiver collection transitions state to 'completed'
  // via the dropoff lifecycle.
  return reply.send(responseBody);
}

async function handleTasksGet(
  services: Services,
  request: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
  body: JsonRpcRequest,
) {
  const params = body.params ?? {};
  const taskId = typeof params['id'] === 'string' ? (params['id'] as string) : null;
  if (!taskId) {
    return reply.send(rpcError(body.id, RPC_INVALID_PARAMS, 'params.id is required'));
  }

  const status = await services.dropoff.getStatus(taskId, request.operatorId, request.agentId);
  const state = dropoffStatusToA2aState(status.status);

  return reply.send(
    rpcResult(body.id, {
      id: status.id,
      status: {
        state,
        timestamp: (status.collected_at ?? status.deposited_at ?? status.created_at).toISOString(),
      },
      metadata: {
        stack_dropoff_id: status.id,
        stack_from_agent: status.from_agent,
        stack_to_agent: status.to_agent,
        stack_expires_at: status.expires_at.toISOString(),
      },
    }),
  );
}

async function handleTasksCancel(
  services: Services,
  request: import('fastify').FastifyRequest,
  reply: import('fastify').FastifyReply,
  body: JsonRpcRequest,
) {
  requireRole(request, 'standard');
  const params = body.params ?? {};
  const taskId = typeof params['id'] === 'string' ? (params['id'] as string) : null;
  if (!taskId) {
    return reply.send(rpcError(body.id, RPC_INVALID_PARAMS, 'params.id is required'));
  }

  const start = Date.now();
  const expired = await services.db.transaction(async (tx) => {
    const result = await services.dropoff.expire(
      taskId,
      request.operatorId,
      request.agentId,
      tx,
    );
    await services.audit.write({
      ctx: auditCtx(request, {
        ...(request.agentId ? { agent_id: request.agentId } : {}),
        ...(request.passportContext ? { passport_jti: request.passportContext.jti } : {}),
      }),
      layer: 'dropoff',
      action: 'a2a.tasks.cancel',
      outcome: 'success',
      duration_ms: Date.now() - start,
    }, tx);
    return result;
  });

  return reply.send(
    rpcResult(body.id, {
      id: expired?.id ?? taskId,
      status: {
        state: 'canceled',
        timestamp: new Date().toISOString(),
      },
    }),
  );
}

// Re-export so future server.ts can wire silently.
export const A2A_PROTOCOL_VERSION_EXPORTED = A2A_PROTOCOL_VERSION;
import { safeErrorSummary } from '@stack/shared';
