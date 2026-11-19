import { describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import { errorHandler } from '../middleware/error-handler.js';
import { registerAuthorityReceiverRoutes } from './authority.js';

const digest = `sha256:${'a'.repeat(64)}`;

function presentationRequest(agentProof = 'agent.proof.signature') {
  return {
    signed_request: 'receiver.request.signature',
    agent_proof: agentProof,
    passport: 'write-only-passport',
    authority_ref: {
      binding_id: 'abn_one',
      binding_version: 1,
      binding_claim_id: 'pc_binding_one',
      binding_digest: digest,
      receiver_id: 'rcv_one',
      receiver_profile_version_id: 'apv_receiver_one',
      expires_at: 1_800_000_000,
    },
    receiver_profile_version_id: 'apv_receiver_one',
    receiver_request_id: 'receiver_request_one_01',
    mission_id: null,
    action_uri: 'urn:stack:tax:return:submit',
    resource_hash: digest,
    request_hash: digest,
    normalized_request: { tax_year: 2026 },
    requested_facts: [{ fact_id: 'se.personal_number', mode: 'issuer_evidence' }],
    nonce: 'receiver_nonce_1234567890',
    issued_at: 1_700_000_000,
    expires_at: 1_700_000_060,
  };
}

describe('STACK direct-post JWT v1 agent proof boundary', () => {
  it('passes the required write-only agent proof to the authority service without echoing it', async () => {
    const app = Fastify();
    let received: Record<string, unknown> | null = null;
    registerAuthorityReceiverRoutes(app, {
      authority: {
        authenticateReceiverRequest: async () => ({
          receiverId: 'rcv_one', keyId: 'receiver-key-one', jti: 'receiver-jti-one',
          expiresAt: new Date('2030-01-01T00:00:00.000Z'), payload: {},
        }),
        createPresentationRequest: async (_auth: unknown, input: Record<string, unknown>) => {
          received = input;
          return {
            id: 'prs_one', authority_use_id: 'aus_one', status: 'delivered',
            disclosure_manifest: [], proof_refs: [], expires_at: '2030-01-01T00:00:00.000Z',
          };
        },
      },
    } as never);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/authority/presentation-requests',
      headers: { authorization: 'STACK-Receiver receiver.assertion.signature' },
      payload: presentationRequest(),
    });
    await app.close();

    expect(response.statusCode).toBe(202);
    expect(received).toMatchObject({ agent_proof: 'agent.proof.signature' });
    expect(response.body).not.toContain('agent.proof.signature');
    expect(response.body).not.toContain('write-only-passport');
    expect(response.body).not.toContain('se.personal_number');
  });

  it('rejects a missing agent proof before creating a presentation', async () => {
    const app = Fastify();
    let created = false;
    registerAuthorityReceiverRoutes(app, {
      authority: {
        authenticateReceiverRequest: async () => ({
          receiverId: 'rcv_one', keyId: 'receiver-key-one', jti: 'receiver-jti-one',
          expiresAt: new Date('2030-01-01T00:00:00.000Z'), payload: {},
        }),
        createPresentationRequest: async () => {
          created = true;
          return {};
        },
      },
    } as never);
    const body = presentationRequest() as Record<string, unknown>;
    delete body.agent_proof;

    const response = await app.inject({
      method: 'POST',
      url: '/v1/authority/presentation-requests',
      headers: { authorization: 'STACK-Receiver receiver.assertion.signature' },
      payload: body,
    });
    await app.close();

    expect(response.statusCode).toBeGreaterThanOrEqual(400);
    expect(created).toBe(false);
  });

  it('binds receiver authentication to the exact agent proof in the request body hash', async () => {
    const app = Fastify();
    const bodyHashes: string[] = [];
    registerAuthorityReceiverRoutes(app, {
      authority: {
        authenticateReceiverRequest: async (input: { bodyHash: string }) => {
          bodyHashes.push(input.bodyHash);
          return {
            receiverId: 'rcv_one', keyId: 'receiver-key-one', jti: `receiver-jti-${bodyHashes.length}`,
            expiresAt: new Date('2030-01-01T00:00:00.000Z'), payload: {},
          };
        },
        createPresentationRequest: async () => ({
          id: 'prs_one', authority_use_id: 'aus_one', status: 'delivered',
          disclosure_manifest: [], proof_refs: [], expires_at: '2030-01-01T00:00:00.000Z',
        }),
      },
    } as never);

    for (const agentProof of ['agent.proof.signature', 'different.proof.signature']) {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/authority/presentation-requests',
        headers: { authorization: 'STACK-Receiver receiver.assertion.signature' },
        payload: presentationRequest(agentProof),
      });
      expect(response.statusCode).toBe(202);
    }
    await app.close();

    expect(bodyHashes).toHaveLength(2);
    expect(bodyHashes[0]).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(bodyHashes[1]).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(bodyHashes[0]).not.toBe(bodyHashes[1]);
  });

  it.each([
    ['delivery_endpoint', 'https://attacker.invalid/callback'],
    ['proof_version', 99],
    ['proof_id', 'prf_caller_selected'],
    ['operator_id', 'op_foreign'],
  ])('rejects caller-selected native presentation field %s before disclosure', async (field, value) => {
    const app = Fastify();
    app.setErrorHandler(errorHandler);
    let created = false;
    registerAuthorityReceiverRoutes(app, {
      authority: {
        authenticateReceiverRequest: async () => ({
          receiverId: 'rcv_one', keyId: 'receiver-key-one', jti: 'receiver-jti-one',
          expiresAt: new Date('2030-01-01T00:00:00.000Z'), payload: {},
        }),
        createPresentationRequest: async () => {
          created = true;
          return {};
        },
      },
    } as never);

    const response = await app.inject({
      method: 'POST', url: '/v1/authority/presentation-requests',
      headers: { authorization: 'STACK-Receiver receiver.assertion.signature' },
      payload: { ...presentationRequest(), [field]: value },
    });
    await app.close();

    expect(response.statusCode).toBe(400);
    expect(created).toBe(false);
    expect(response.body).not.toContain(String(value));
  });

  it('does not echo write-only presentation data from an unexpected service failure', async () => {
    const app = Fastify({ logger: false });
    app.setErrorHandler(errorHandler);
    registerAuthorityReceiverRoutes(app, {
      authority: {
        authenticateReceiverRequest: async () => ({
          receiverId: 'rcv_one', keyId: 'receiver-key-one', jti: 'receiver-jti-one',
          expiresAt: new Date('2030-01-01T00:00:00.000Z'), payload: {},
        }),
        createPresentationRequest: async () => {
          throw new Error('adapter failed while handling personal number 190001019999');
        },
      },
    } as never);

    const response = await app.inject({
      method: 'POST', url: '/v1/authority/presentation-requests',
      headers: { authorization: 'STACK-Receiver receiver.assertion.signature' },
      payload: presentationRequest('agent.proof.190001019999'),
    });
    await app.close();

    expect(response.statusCode).toBe(503);
    expect(response.body).not.toMatch(/190001019999|agent\.proof|write-only-passport|normalized_request/);
  });
});
