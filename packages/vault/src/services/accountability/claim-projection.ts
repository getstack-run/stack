// The dashboard /reviews detail consumes a flat, snake_case wire shape
// for each attached intent_simulation / intent_outcome. body_json
// already holds the parsed payload (drizzle decodes jsonb at read
// time); we project only the fields the dashboard renders.

export interface ClaimRowForProjection {
  claim_id: string;
  type: string;
  issued_at_ms: number | null;
  body_json: Record<string, unknown>;
}

export function projectSimulationClaim(row: ClaimRowForProjection) {
  const body = row.body_json;
  return {
    claim_id: row.claim_id,
    issued_at_ms: row.issued_at_ms ?? 0,
    intent_claim_ref: typeof body['intent_claim_ref'] === 'string' ? (body['intent_claim_ref'] as string) : null,
    allowed: body['allowed'] === true,
    denial_reasons: Array.isArray(body['denial_reasons']) ? (body['denial_reasons'] as string[]) : [],
    simulated_cost: body['simulated_cost'] ?? null,
    simulated_at: typeof body['simulated_at'] === 'number' ? (body['simulated_at'] as number) : 0,
  };
}

export function projectOutcomeClaim(row: ClaimRowForProjection) {
  const body = row.body_json;
  return {
    claim_id: row.claim_id,
    issued_at_ms: row.issued_at_ms ?? 0,
    intent_claim_ref: typeof body['intent_claim_ref'] === 'string' ? (body['intent_claim_ref'] as string) : null,
    outcome_type: typeof body['outcome_type'] === 'string' ? (body['outcome_type'] as string) : null,
    status: typeof body['status'] === 'string' ? (body['status'] as string) : null,
    // The full body is included so the dashboard can render
    // outcome-type-specific fields (http status, skill output, etc.)
    // without us having to enumerate every variant here.
    body: body,
  };
}
