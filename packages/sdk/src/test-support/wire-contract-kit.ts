import { afterEach, describe, expect, it, vi } from 'vitest';
import { Stack } from '../index.js';
import type { PolicyDefinition } from '../services/control-policies.js';

/**
 * What the wire-contract tests share: the stubbed API, the fixtures and the runner that checks one SDK call's body
 * against the schema the API parses it with. The engine's cases are in `wire-contract.test.ts`; the hosted
 * product's are beside them under `hosted/`.
 */

export interface SchemaLike {
  safeParse(value: unknown): { success: boolean; error?: { issues: unknown[] } };
}

// The slice of a Zod schema this test walks to find the declared keys.
export interface Walkable {
  shape?: Record<string, unknown>;
  _def?: { schema?: Walkable; innerType?: Walkable };
}

export function declaredKeys(schema: unknown): Set<string> {
  let node = schema as Walkable | undefined;
  while (node && !node.shape) node = node._def?.schema ?? node._def?.innerType;
  if (!node?.shape) throw new Error('wire-contract: cannot find the object shape of the schema');
  return new Set(Object.keys(node.shape));
}

export interface Captured {
  method: string;
  path: string;
  body: Record<string, unknown> | undefined;
  headers: Record<string, string>;
}

export const BASE_URL = 'http://api.fixture';

/** Unsigned JWT with a far-future exp; the SDK only decodes it, never verifies. */
export function fakeJwt(claims: Record<string, unknown> = {}, expiresInSeconds = 900): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  return `${encode({ alg: 'none' })}.${encode({ exp, ...claims })}.sig`;
}

export function stubApi(): Captured[] {
  const calls: Captured[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: { method?: string; body?: string; headers?: Record<string, string> }) => {
      calls.push({
        method: init.method ?? 'GET',
        path: new URL(url).pathname,
        body: init.body ? (JSON.parse(init.body) as Record<string, unknown>) : undefined,
        headers: init.headers ?? {},
      });
      const reply = { token: fakeJwt(), jti: 'pas_x', expires_at: '2030-01-01T00:00:00.000Z' };
      return new Response(JSON.stringify(reply), { status: 200, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

export function newStack(): Stack {
  return new Stack({ apiKey: 'sk_live_contract_test', baseUrl: BASE_URL });
}

/** A policy that uses every section the SDK type declares, so a renamed key fails the API schema. */
export const POLICY: PolicyDefinition = {
  name: 'Support agent',
  connections: {
    mode: 'listed',
    rules: [{
      id: 'mail-to-customers',
      effect: 'allow',
      access: {
        connection_id: 'scon_abcdefgh',
        intents: [{ name: 'resend.send_email', params: {} }],
        constraints: [{ path: 'body.to', op: 'in', value: ['a@example.com'] }],
      },
    }, {
      id: 'mail-per-job',
      effect: 'allow',
      recipients: 'per_mission',
      access: { connection_id: 'scon_abcdefgh', intents: [{ name: 'resend.send_email', params: {} }] },
    }],
  },
  actions: { kinds: { 'card.checkout': 'review', 'wallet.payment': 'deny' } },
  recipients: { email: ['@example.com'], sms: ['+46701740605'], call: ['+46701740605'] },
  spend: { max_per_action_cents: 500, limits: [{ kind: 'day', unit: 'cents', limit: 5_000 }], max_concurrent: 4 },
  review: { over_cents: 200 },
  surfaces: {
    models: { allowed: ['claude-*'], max_cost_per_call_cents: 50 },
    browser: { hosts: ['*.example.com'] },
    card: { merchants: ['shop.example.com'], max_amount_cents: 1_000 },
    wallet: { payees: ['0x' + 'a'.repeat(40)], max_amount_cents: 1_000 },
    workspace: { max_timeout_seconds: 60 },
    tools: { allowed: ['search/*'] },
  },
};

export interface Contract {
  name: string;
  call: (stack: Stack) => Promise<unknown>;
  method: 'POST' | 'PATCH' | 'PUT';
  path: string;
  schema: SchemaLike;
  /** Select the part of the body the schema describes (default: the whole body). */
  select?: (body: Record<string, unknown>) => unknown;
  /** Body keys the route reads outside the schema. */
  extraKeys?: string[];
}

export const ACCOUNT_ID = 'acct_0123456789abcdef0123456789abcdef';
export const DRIVE_FILE_ID = 'drv_0123456789abcdef';
export const MISSION_ID = 'ms_contract1';
export const AGENT_ID = 'agt_contract1';
export const CONNECTION_ID = 'scon_contract1';
export const ISSUE_INPUT = {
  agent_id: AGENT_ID,
  mission_ids: [MISSION_ID] as [string],
  ttl_seconds: 600,
  scopes: [{ service_connection_id: CONNECTION_ID, scopes: ['chat:write'], allow_data_from: ['slack'] }],
  intent: { summary: 'Triage the inbox', services: ['slack'] },
  authority_binding_ids: ['abn_contract1'],
};
export const PARENT_TOKEN = fakeJwt({
  stk: { services: [{ service_name: 'slack', connection_id: CONNECTION_ID, scopes: ['chat:write'] }] },
});
export const FLEET_ACCESS = { connection_id: CONNECTION_ID, scopes: ['chat:write'] };
export const FLEET_LIMITS = { max_actions: 100, max_concurrent_actions: 2, max_duration_seconds: 3600 };
export const FLEET_POLICY = {
  name: 'support-fleet',
  rules: [{ id: 'slack-post', effect: 'allow' as const, access: FLEET_ACCESS }],
  limits: FLEET_LIMITS,
  window_seconds: 3600,
  max_members: 10,
  max_enrollments_per_hour: 10,
  identity_lease_seconds: 3600,
  provisioner_agent_ids: [AGENT_ID],
  expires_at: '2030-01-01T00:00:00.000Z',
};
export const ENROLLMENT = {
  idempotency_key: 'enroll-key-0001',
  name: 'worker-1',
  public_key: { kty: 'OKP' as const, crv: 'Ed25519' as const, x: 'A'.repeat(43) },
  challenge_id: 'chal_contract1',
  proof: 'proof',
};

/** Registers one test per contract: the verb, the path, the body against the API schema, and no key the schema does not declare. */
export function registerContracts(title: string, contracts: Contract[], extra?: () => void): void {
  describe(title, () => {
    afterEach(() => {
      vi.unstubAllGlobals();
      vi.restoreAllMocks();
    });

    it.each(contracts.map((contract) => [contract.name, contract] as const))('%s', async (_name, contract) => {
      const calls = stubApi();
      await contract.call(newStack());

      const sent = calls.find((call) => call.method === contract.method && call.path === contract.path);
      expect(sent, `${contract.name}: no ${contract.method} ${contract.path} request was made; saw ${calls.map((c) => `${c.method} ${c.path}`).join(', ') || 'none'}`).toBeDefined();
      const body = sent!.body;
      expect(body, `${contract.name}: request had no body`).toBeDefined();

      const checked = contract.select ? contract.select(body!) : body;
      const parsed = contract.schema.safeParse(checked);
      expect(parsed.success, `${contract.name}: the API schema rejects the body ${JSON.stringify(checked)}: ${JSON.stringify(parsed.error?.issues)}`).toBe(true);

      if (checked && typeof checked === 'object') {
        const declared = declaredKeys(contract.schema);
        const allowed = new Set([...declared, ...(contract.extraKeys ?? [])]);
        const undeclared = Object.keys(checked).filter((key) => !allowed.has(key));
        expect(undeclared, `${contract.name}: body fields the API schema does not declare (the API drops them): ${undeclared.join(', ')}`).toEqual([]);
      }
    });

    extra?.();
  });
}
