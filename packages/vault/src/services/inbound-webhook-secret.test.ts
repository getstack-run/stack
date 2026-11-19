import { CmekRevokedError } from '@stack/shared';
import { describe, expect, it, vi } from 'vitest';
import { CmekMigrationWorker } from './cmek-migration-worker.js';
import {
  DOWNSTREAM_SECRET_PURPOSE,
  LEGACY_WEBHOOK_SECRET_PURPOSE,
  openDownstreamSecret,
  webhookSecretContext,
} from './inbound-webhook-secret.js';

type Context = Record<string, string>;

/**
 * A key service that seals a value to the context it was given and refuses any other, with the kind of error a
 * real provider raises (not a message the service could match on).
 */
function fakeKms() {
  const seal = (plain: Buffer, context: Context) => Buffer.from(JSON.stringify({ context, plain: plain.toString('base64') }));
  return {
    seal,
    open(sealed: string, context: Context): Buffer {
      const parsed = JSON.parse(Buffer.from(sealed, 'base64').toString('utf8')) as { context: Context; plain: string };
      if (JSON.stringify(parsed.context) !== JSON.stringify(context)) throw new Error('InvalidCiphertextException');
      return Buffer.from(parsed.plain, 'base64');
    },
    service: {
      decryptDirect: vi.fn(async (ciphertext: Buffer, options?: { expectedContext?: Context }) => {
        const parsed = JSON.parse(ciphertext.toString('utf8')) as { context: Context; plain: string };
        if (JSON.stringify(parsed.context) !== JSON.stringify(options?.expectedContext)) throw new Error('InvalidCiphertextException');
        return Buffer.from(parsed.plain, 'base64');
      }),
      encryptDirect: vi.fn(async (plain: Buffer, options: { context: Context }) => seal(plain, options.context)),
    },
  };
}

const OPERATOR = 'op_a';

describe('openDownstreamSecret', () => {
  it('opens a secret under the current purpose, and one made before the rename under the earlier one', async () => {
    const kms = fakeKms();
    const current = kms.seal(Buffer.from('new-secret'), webhookSecretContext(OPERATOR, 'iwh_1', DOWNSTREAM_SECRET_PURPOSE)).toString('base64');
    const earlier = kms.seal(Buffer.from('old-secret'), webhookSecretContext(OPERATOR, 'iwh_2', LEGACY_WEBHOOK_SECRET_PURPOSE)).toString('base64');
    const a = await openDownstreamSecret(kms.service, { operatorId: OPERATOR, webhookId: 'iwh_1', sealed: current, allowLegacy: true });
    const b = await openDownstreamSecret(kms.service, { operatorId: OPERATOR, webhookId: 'iwh_2', sealed: earlier, allowLegacy: true });
    expect([a.plain.toString(), a.purpose]).toEqual(['new-secret', DOWNSTREAM_SECRET_PURPOSE]);
    expect([b.plain.toString(), b.purpose]).toEqual(['old-secret', LEGACY_WEBHOOK_SECRET_PURPOSE]);
  });

  it('does not offer the earlier purpose unless asked, and throws the first error when neither opens', async () => {
    const kms = fakeKms();
    const earlier = kms.seal(Buffer.from('old-secret'), webhookSecretContext(OPERATOR, 'iwh_2', LEGACY_WEBHOOK_SECRET_PURPOSE)).toString('base64');
    await expect(openDownstreamSecret(kms.service, { operatorId: OPERATOR, webhookId: 'iwh_2', sealed: earlier, allowLegacy: false })).rejects.toThrow('InvalidCiphertextException');
    expect(kms.service.decryptDirect).toHaveBeenCalledTimes(1);
    kms.service.decryptDirect.mockClear();
    // Sealed for another webhook: neither purpose opens it.
    await expect(openDownstreamSecret(kms.service, { operatorId: OPERATOR, webhookId: 'iwh_other', sealed: earlier, allowLegacy: true })).rejects.toThrow('InvalidCiphertextException');
    expect(kms.service.decryptDirect).toHaveBeenCalledTimes(2);
  });

  it('stops at a revoked customer key without trying the earlier purpose', async () => {
    const decryptDirect = vi.fn(async () => {
      throw new CmekRevokedError(OPERATOR);
    });
    await expect(openDownstreamSecret({ decryptDirect } as never, { operatorId: OPERATOR, webhookId: 'iwh_1', sealed: Buffer.from('x').toString('base64'), allowLegacy: true })).rejects.toBeInstanceOf(CmekRevokedError);
    expect(decryptDirect).toHaveBeenCalledTimes(1);
  });
});

describe('the customer-managed key migration of inbound webhooks', () => {
  function build(rows: Array<Record<string, unknown>>) {
    const kms = fakeKms();
    const updates: Array<Record<string, string>> = [];
    const db = {
      select: () => ({
        from: () => ({
          where: () => Object.assign(Promise.resolve([{ count: rows.length }]), {
            limit: () => ({ offset: async () => rows.map((row) => ({ ...row })) }),
          }),
        }),
      }),
      update: () => ({
        set: (values: Record<string, string>) => ({
          where: async () => {
            updates.push(values);
          },
        }),
      }),
    };
    const migrationRepo = { markRunning: vi.fn(async () => undefined), bumpProgress: vi.fn(async () => undefined), markCompleted: vi.fn(async () => undefined) };
    const worker = new CmekMigrationWorker({ db, kms: kms.service, migrationRepo, operatorRepo: {}, stackSystemOperatorId: 'op_stack_system' } as never);
    const run = () => (worker as unknown as { migrateInboundWebhooks(operator: string, row: { id: string }): Promise<void> }).migrateInboundWebhooks(OPERATOR, { id: 'cmkm_1' });
    return { kms, updates, run, migrationRepo };
  }

  const seal = (kms: ReturnType<typeof fakeKms>, id: string, plain: string, purpose: string) =>
    kms.seal(Buffer.from(plain), { operator_id: OPERATOR, webhook_id: id, purpose }).toString('base64');

  it('moves a row made after the keys were separated and a row made before, each under the purpose it carries', async () => {
    const source = fakeKms();
    const rows = [
      {
        id: 'iwh_new',
        webhook_secret_encrypted: seal(source, 'iwh_new', 'downstream-new', DOWNSTREAM_SECRET_PURPOSE),
        webhook_secret_previous_encrypted: seal(source, 'iwh_new', 'downstream-before-rotation', DOWNSTREAM_SECRET_PURPOSE),
        provider_signing_secret_encrypted: seal(source, 'iwh_new', 'whsec_incoming', 'inbound_provider_signing_secret'),
      },
      {
        id: 'iwh_old',
        webhook_secret_encrypted: seal(source, 'iwh_old', 'downstream-old', LEGACY_WEBHOOK_SECRET_PURPOSE),
        webhook_secret_previous_encrypted: null,
        provider_signing_secret_encrypted: seal(source, 'iwh_old', 'whsec_incoming_old', 'inbound_provider_signing_secret'),
      },
    ];
    const { kms, updates, run, migrationRepo } = build(rows);
    await run();

    const column = (name: string) => updates.filter((values) => name in values).map((values) => values[name]!);
    const [currentNew, currentOld] = column('webhook_secret_encrypted');
    expect(kms.open(currentNew!, { operator_id: OPERATOR, webhook_id: 'iwh_new', purpose: DOWNSTREAM_SECRET_PURPOSE }).toString()).toBe('downstream-new');
    expect(kms.open(currentOld!, { operator_id: OPERATOR, webhook_id: 'iwh_old', purpose: LEGACY_WEBHOOK_SECRET_PURPOSE }).toString()).toBe('downstream-old');
    const [previous] = column('webhook_secret_previous_encrypted');
    expect(kms.open(previous!, { operator_id: OPERATOR, webhook_id: 'iwh_new', purpose: DOWNSTREAM_SECRET_PURPOSE }).toString()).toBe('downstream-before-rotation');
    const [providerNew, providerOld] = column('provider_signing_secret_encrypted');
    expect(kms.open(providerNew!, { operator_id: OPERATOR, webhook_id: 'iwh_new', purpose: 'inbound_provider_signing_secret' }).toString()).toBe('whsec_incoming');
    expect(kms.open(providerOld!, { operator_id: OPERATOR, webhook_id: 'iwh_old', purpose: 'inbound_provider_signing_secret' }).toString()).toBe('whsec_incoming_old');
    expect(migrationRepo.markCompleted).toHaveBeenCalledTimes(1);
  });

  it('stops on a row that opens under neither purpose and writes nothing for it', async () => {
    const source = fakeKms();
    const rows = [
      {
        id: 'iwh_broken',
        webhook_secret_encrypted: seal(source, 'iwh_someone_else', 'not-this-rows', DOWNSTREAM_SECRET_PURPOSE),
        webhook_secret_previous_encrypted: null,
        provider_signing_secret_encrypted: null,
      },
    ];
    const { updates, run, migrationRepo } = build(rows);
    await expect(run()).rejects.toThrow('InvalidCiphertextException');
    expect(updates).toEqual([]);
    expect(migrationRepo.markCompleted).not.toHaveBeenCalled();
  });
});
