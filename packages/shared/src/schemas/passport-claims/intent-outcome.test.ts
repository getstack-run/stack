import { describe, it, expect } from 'vitest';
import { IntentOutcomeClaim, PASSPORT_CLAIM_SCHEMAS } from './index.js';

const baseFields = {
  type: 'intent_outcome' as const,
  intent_claim_ref: 'pc_abc123',
  status: 'succeeded' as const,
  duration_ms: 250,
  cost_actual: {
    wallet_cents: 5,
    tokens: null,
    gas_gwei: null,
  },
  recorded_at: 1_726_000_000_000,
};

describe('IntentOutcomeClaim — skill_invocation', () => {
  it('accepts a valid skill_invocation outcome with all actual_* fields', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'skill_invocation',
        actual_skill_id: 'sk_summarise_v1',
        actual_input_hash: 'a'.repeat(64),
        output_envelope_hash: 'a'.repeat(64),
        exit_code: 0,
      }),
    ).not.toThrow();
  });

  it('accepts pre-execution failure with all actual_* fields null', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        status: 'failed',
        outcome_type: 'skill_invocation',
        actual_skill_id: null,
        actual_input_hash: null,
        output_envelope_hash: null,
        exit_code: null,
      }),
    ).not.toThrow();
  });

  it('rejects malformed actual_input_hash', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'skill_invocation',
        actual_skill_id: 'sk_summarise_v1',
        actual_input_hash: 'not-hex',
        output_envelope_hash: 'a'.repeat(64),
        exit_code: 0,
      }),
    ).toThrow();
  });
});

describe('IntentOutcomeClaim — http_call', () => {
  it('accepts a valid http_call outcome with all actual_* fields', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'http_call',
        actual_target: 'api.stripe.com',
        actual_method_path: 'POST /v1/charges',
        actual_parameters_hash: 'a'.repeat(64),
        status_code: 200,
        response_body_hash: 'b'.repeat(64),
        latency_ms: 120,
        redactions_count: 2,
        detector_fires_count: 0,
      }),
    ).not.toThrow();
  });

  it('accepts pre-execution failure with actual_* null', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        status: 'failed',
        outcome_type: 'http_call',
        actual_target: null,
        actual_method_path: null,
        actual_parameters_hash: null,
        status_code: null,
        response_body_hash: null,
        latency_ms: null,
        redactions_count: 0,
        detector_fires_count: 0,
      }),
    ).not.toThrow();
  });

  it('defaults redactions_count and detector_fires_count to 0', () => {
    const parsed = IntentOutcomeClaim.parse({
      ...baseFields,
      outcome_type: 'http_call',
      actual_target: 'api.stripe.com',
      actual_method_path: 'POST /v1/charges',
      actual_parameters_hash: 'a'.repeat(64),
      status_code: 200,
      response_body_hash: 'b'.repeat(64),
      latency_ms: 120,
    });
    expect(parsed.outcome_type).toBe('http_call');
    if (parsed.outcome_type === 'http_call') {
      expect(parsed.redactions_count).toBe(0);
      expect(parsed.detector_fires_count).toBe(0);
    }
  });

  it('rejects negative latency_ms', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'http_call',
        actual_target: 'api.stripe.com',
        actual_method_path: 'POST /v1/charges',
        actual_parameters_hash: 'a'.repeat(64),
        status_code: 200,
        response_body_hash: null,
        latency_ms: -1,
      }),
    ).toThrow();
  });

  it('rejects malformed actual_parameters_hash', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'http_call',
        actual_target: 'api.stripe.com',
        actual_method_path: 'POST /v1/charges',
        actual_parameters_hash: 'not-hex',
        status_code: 200,
        response_body_hash: null,
        latency_ms: 120,
      }),
    ).toThrow();
  });
});

describe('IntentOutcomeClaim — mcp_tool', () => {
  it('accepts a valid mcp_tool outcome with all actual_* fields', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'mcp_tool',
        actual_tool_name: 'send_message',
        actual_args_hash: 'a'.repeat(64),
        tool_result_envelope_hash: 'c'.repeat(64),
        tool_error_code: null,
      }),
    ).not.toThrow();
  });

  it('accepts a failed mcp_tool outcome with error code and null actual_*', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        status: 'failed',
        outcome_type: 'mcp_tool',
        actual_tool_name: null,
        actual_args_hash: null,
        tool_result_envelope_hash: null,
        tool_error_code: 'invalid_params',
      }),
    ).not.toThrow();
  });
});

describe('IntentOutcomeClaim — onchain_tx', () => {
  it('accepts a confirmed onchain_tx outcome with all actual_* fields', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'onchain_tx',
        cost_actual: {
          wallet_cents: 10,
          tokens: null,
          gas_gwei: 21000,
        },
        actual_contract: '0x' + 'a'.repeat(40),
        actual_function_selector: 'transfer(address,uint256)',
        actual_args_hash: 'b'.repeat(64),
        tx_hash: '0x' + 'd'.repeat(64),
        block_number: 18_500_000,
        gas_used: 21000,
        revert_reason: null,
      }),
    ).not.toThrow();
  });

  it('accepts a pre-broadcast failure (null tx_hash and null actual_*)', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        status: 'failed',
        outcome_type: 'onchain_tx',
        actual_contract: null,
        actual_function_selector: null,
        actual_args_hash: null,
        tx_hash: null,
        block_number: null,
        gas_used: null,
        revert_reason: null,
      }),
    ).not.toThrow();
  });

  it('accepts a reverted tx with revert_reason', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        status: 'failed',
        outcome_type: 'onchain_tx',
        actual_contract: '0x' + 'a'.repeat(40),
        actual_function_selector: 'transfer(address,uint256)',
        actual_args_hash: 'b'.repeat(64),
        tx_hash: '0x' + 'd'.repeat(64),
        block_number: 18_500_000,
        gas_used: 30000,
        revert_reason: 'ERC20: insufficient balance',
      }),
    ).not.toThrow();
  });

  it('rejects malformed actual_contract (missing 0x or wrong length)', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'onchain_tx',
        actual_contract: 'a'.repeat(40),
        actual_function_selector: 'transfer(address,uint256)',
        actual_args_hash: 'b'.repeat(64),
        tx_hash: null,
        block_number: null,
        gas_used: null,
        revert_reason: null,
      }),
    ).toThrow();
  });

  it('rejects uppercase actual_contract (must be lowercase)', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'onchain_tx',
        actual_contract: '0x' + 'A'.repeat(40),
        actual_function_selector: 'transfer(address,uint256)',
        actual_args_hash: 'b'.repeat(64),
        tx_hash: null,
        block_number: null,
        gas_used: null,
        revert_reason: null,
      }),
    ).toThrow();
  });
});

describe('IntentOutcomeClaim — task_complete', () => {
  it('accepts a task_complete outcome with only common fields', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        cost_actual: {
          wallet_cents: null,
          tokens: null,
          gas_gwei: null,
        },
        outcome_type: 'task_complete',
      }),
    ).not.toThrow();
  });
});

describe('IntentOutcomeClaim — a2a_dispatch (new in shared-enum revision)', () => {
  it('accepts a valid a2a_dispatch outcome with all actual_* fields', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'a2a_dispatch',
        actual_target_agent: 'ag_remote_xyz',
        actual_method: 'tasks/send',
        actual_args_hash: 'a'.repeat(64),
        remote_task_id: 'task_remote_001',
        task_state: 'pending',
        task_result_envelope_hash: null,
      }),
    ).not.toThrow();
  });

  it('accepts a completed a2a task with result envelope hash', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'a2a_dispatch',
        actual_target_agent: 'ag_remote_xyz',
        actual_method: 'tasks/send',
        actual_args_hash: 'a'.repeat(64),
        remote_task_id: 'task_remote_001',
        task_state: 'completed',
        task_result_envelope_hash: 'f'.repeat(64),
      }),
    ).not.toThrow();
  });

  it('accepts a pre-execution failure with all actual_* null', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        status: 'failed',
        outcome_type: 'a2a_dispatch',
        actual_target_agent: null,
        actual_method: null,
        actual_args_hash: null,
        remote_task_id: null,
        task_state: null,
        task_result_envelope_hash: null,
      }),
    ).not.toThrow();
  });

  it('rejects unknown task_state', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'a2a_dispatch',
        actual_target_agent: 'ag_remote_xyz',
        actual_method: 'tasks/send',
        actual_args_hash: 'a'.repeat(64),
        remote_task_id: 'task_remote_001',
        task_state: 'queued' as never,
        task_result_envelope_hash: null,
      }),
    ).toThrow();
  });
});

describe('IntentOutcomeClaim — common rules', () => {
  it('rejects malformed intent_claim_ref', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        intent_claim_ref: 'not-a-claim',
        outcome_type: 'task_complete',
      }),
    ).toThrow();
  });

  it('rejects unknown status', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        status: 'partial' as never,
        outcome_type: 'task_complete',
      }),
    ).toThrow();
  });

  it('rejects negative duration_ms', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        duration_ms: -100,
        outcome_type: 'task_complete',
      }),
    ).toThrow();
  });

  it('is registered in PASSPORT_CLAIM_SCHEMAS', () => {
    expect(PASSPORT_CLAIM_SCHEMAS.intent_outcome).toBe(IntentOutcomeClaim);
  });

  // mission_ref retrofit
  it('accepts mission_ref as a valid mission_id', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'task_complete',
        mission_ref: 'ms_run_42',
      }),
    ).not.toThrow();
  });

  it('accepts mission_ref omitted (additive nullable optional)', () => {
    expect(() =>
      IntentOutcomeClaim.parse({ ...baseFields, outcome_type: 'task_complete' }),
    ).not.toThrow();
  });

  it('rejects mission_ref with wrong prefix', () => {
    expect(() =>
      IntentOutcomeClaim.parse({
        ...baseFields,
        outcome_type: 'task_complete',
        mission_ref: 'pc_old_shape',
      }),
    ).toThrow();
  });
});
