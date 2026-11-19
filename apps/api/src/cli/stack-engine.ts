/**
 * stack-engine: the commands an operator of a self-managed install runs on the
 * machine, not through the API.
 *
 *   stack-engine licence verify [<key> | --file <path>]
 *       Check a licence key against STACK's built-in public keys, offline.
 *       With no argument it reads STACK_LICENCE_KEY or STACK_LICENCE_KEY_FILE.
 *       Exit 0 when the key is valid now, 1 when it is not.
 *
 *   stack-engine keys generate --dir <directory>
 *       Write the install's secrets as files (mode 0600, never overwritten):
 *       the key-encryption key, the passport signing key and the API key
 *       pepper. Prints where they are, never what they hold.
 *
 *   stack-engine operator create --email <address>
 *       Create an operator and print its API key, once.
 *
 *   stack-engine approvals list
 *   stack-engine approvals approve <approval_id>
 *   stack-engine approvals reject <approval_id>
 *       Decide the changes an operator's key may request but not approve for
 *       itself (registering an agent, loosening a detector, a held action).
 *       An install has no browser Console of its own, so the person with
 *       access to the machine decides here, as the account's owner; the
 *       decision is recorded in the audit chain as made by `host_admin`.
 *
 *   stack-engine archive init
 *       Create the audit archive bucket if it does not exist yet, waiting for
 *       the object store to come up. Used by the Compose install, whose store
 *       starts empty; a managed bucket already exists and is left alone.
 *
 *   stack-engine erasures reapply [--apply]
 *       After a restore from a snapshot: put every erasure on the list of erased
 *       accounts back in force. What lives outside the database (in a hosted
 *       deployment, an account's memory graph) is deleted again; an account
 *       whose row is back in the database is reported, and with --apply erased
 *       again. Exit 0 when every erasure is in force, 1 when something is left
 *       to do (see docs/self-managed/operations.md).
 *
 *   stack-engine doctor
 *       Check the install's configuration and its dependencies (database,
 *       migrations, Redis, key service, audit archive, email, licence).
 *
 * The commands read the same environment the API reads.
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSecretFiles } from '@stack/shared';

function option(args: string[], name: string): string | undefined {
  const at = args.indexOf(`--${name}`);
  return at >= 0 ? args[at + 1] : undefined;
}

function out(line = ''): void {
  process.stdout.write(`${line}\n`);
}

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

async function licenceVerify(args: string[]): Promise<number> {
  const { verifyLicence, licenceGrants, LICENCE_FEATURES } = await import('@stack/shared');
  const file = option(args, 'file');
  const inline = args.find((a) => a.startsWith('STACKLIC'));
  let key: string | undefined = inline;
  if (!key && file) {
    try {
      key = readFileSync(file, 'utf8');
    } catch {
      fail('The licence file cannot be read.');
    }
  }
  key ??= process.env['STACK_LICENCE_KEY'] ?? (process.env['STACK_LICENCE_KEY_FILE'] ? readFileSync(process.env['STACK_LICENCE_KEY_FILE'], 'utf8') : undefined);
  const state = verifyLicence(key);
  const now = new Date();
  if (state.status === 'none') {
    out('No licence key given. The install runs with every enterprise feature off.');
    return 1;
  }
  if (state.status === 'invalid') {
    out(`The licence key is refused: ${state.reason}.`);
    return 1;
  }
  out(`Customer:  ${state.claims.customer}`);
  out(`Issued:    ${state.claims.issued_at}`);
  out(`Expires:   ${state.claims.expires_at}`);
  out(`Features:  ${LICENCE_FEATURES.filter((f) => licenceGrants(state, f, now)).join(', ') || 'none'}`);
  if (state.status === 'expired') {
    out('Status:    expired. The install runs with every enterprise feature off.');
    return 1;
  }
  out('Status:    valid');
  return 0;
}

function writeSecret(path: string, content: string): void {
  // `wx`: never overwrite a secret that is already there.
  writeFileSync(path, content, { mode: 0o600, flag: 'wx' });
}

async function keysGenerate(args: string[]): Promise<number> {
  const dir = option(args, 'dir');
  if (!dir) fail('keys generate needs --dir <directory>');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const targets = {
    kek: join(dir, 'stack-kek'),
    signing: join(dir, 'session-signing-key.pem'),
    pepper: join(dir, 'api-key-pepper'),
  };
  for (const path of Object.values(targets)) {
    if (existsSync(path)) fail(`${path} already exists; refusing to overwrite a secret.`);
  }
  writeSecret(targets.kek, `${randomBytes(32).toString('hex')}\n`);
  const { privateKey } = generateKeyPairSync('ed25519');
  writeSecret(targets.signing, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
  writeSecret(targets.pepper, `${randomBytes(32).toString('hex')}\n`);
  out('Wrote three secrets (mode 0600):');
  out(`  ${targets.kek}      the key-encryption key: STACK_KEY_FILE`);
  out(`  ${targets.signing}   the passport signing key: SESSION_SIGNING_KEY_FILE`);
  out(`  ${targets.pepper}     the API key pepper: API_KEY_PEPPER (set it to this file's content)`);
  out('Back them up. Losing the key-encryption key makes every stored credential unreadable.');
  return 0;
}

async function operatorCreate(args: string[]): Promise<number> {
  const email = option(args, 'email');
  if (!email) fail('operator create needs --email <address>');
  const { createDb } = await import('@stack/shared');
  const { createSelfManagedOperator } = await import('../config/self-managed.js');
  const db = createDb(process.env['DATABASE_URL'] ?? fail('DATABASE_URL is not set.'));
  try {
    const { operatorId, apiKey } = await createSelfManagedOperator(db, { email });
    out(`Operator: ${operatorId}`);
    out(`API key:  ${apiKey}`);
    out('This key is shown once. Only its hash is stored.');
    return 0;
  } catch (err) {
    const code = (err as { code?: string; cause?: { code?: string } }).code ?? (err as { cause?: { code?: string } }).cause?.code;
    // Never the query: it carries the key's hash.
    process.stderr.write(`Could not create the operator: ${code === '23505' ? 'that email already has one' : 'the database refused it'}\n`);
    return 1;
  }
}

async function erasures(command: string | undefined, args: string[]): Promise<number> {
  if (command !== 'reapply') fail('usage: erasures reapply [--apply]');
  const { createServices } = await import('../config/services.js');
  const services = await createServices(null);
  const apply = args.includes('--apply');
  const report = await services.operatorErasure.reapplyErasures({ apply });
  out(`Looked at ${report.checked} erased account(s).`);
  for (const [code, count] of Object.entries(report.removed)) out(`Removed what a restore brought back (${code}): ${count} account(s).`);
  if (report.present.length > 0) {
    out(`${report.present.length} erased account(s) are back in the database: the database was restored to before their erasure.`);
    if (apply) out(`Erased again: ${report.reerased}. Still waiting to finish: ${report.pending.length} (the erasure retries them by itself).`);
    else out('Run this again with --apply to erase them again, with everything they hold.');
  }
  for (const failure of report.failed) out(`Could not run ${failure.code} for ${failure.operator_id}: run this again once it can.`);
  const done = report.failed.length === 0 && report.pending.length === 0 && (apply || report.present.length === 0);
  if (done) out('Every erasure on the list is in force.');
  return done ? 0 : 1;
}

async function approvals(command: string | undefined, args: string[]): Promise<number> {
  const { createServices } = await import('../config/services.js');
  const { governanceApprovals } = await import('@stack/shared');
  const { and, eq, gt } = await import('drizzle-orm');
  const services = await createServices(null);
  if (command === 'list') {
    const rows = await services.db
      .select()
      .from(governanceApprovals)
      .where(and(eq(governanceApprovals.status, 'pending'), gt(governanceApprovals.expires_at, new Date())));
    if (rows.length === 0) out('No approvals are waiting.');
    for (const row of rows) {
      out(`${row.id}  ${row.action}  ${row.operator_id}  expires ${row.expires_at.toISOString()}`);
      out(`    ${row.summary}`);
    }
    return 0;
  }
  if (command !== 'approve' && command !== 'reject') fail('usage: approvals list | approve <id> | reject <id>');
  const approvalId = args[0] ?? fail(`approvals ${command} needs an approval id`);
  const [row] = await services.db.select().from(governanceApprovals).where(eq(governanceApprovals.id, approvalId)).limit(1);
  if (!row) fail('No such approval.');
  const result = await services.operatorDecision.decideGovernance({
    operatorId: row.operator_id,
    approvalId,
    decision: command,
    // The account's owner: whoever holds this machine holds the account.
    authoredBy: { kind: 'operator_owner', operator_id: row.operator_id },
    auditContext: {
      trace_id: `host-${approvalId}`,
      span_id: approvalId,
      operator_id: row.operator_id,
      agent_id: 'host_admin',
      passport_jti: 'none',
    },
  });
  out(`${command === 'approve' ? 'Approved' : 'Rejected'}: ${result.approval.id} (${row.action}). The caller retries with X-Governance-Approval: ${approvalId}`);
  return 0;
}

type Check = { name: string; run: () => Promise<string> };

async function archiveInit(): Promise<number> {
  const bucket = process.env['AUDIT_ARCHIVE_BUCKET'];
  if (!bucket) fail('set AUDIT_ARCHIVE_BUCKET');
  const endpoint = process.env['AUDIT_ARCHIVE_ENDPOINT'];
  const region = process.env['AUDIT_ARCHIVE_REGION'] ?? process.env['AWS_REGION'] ?? 'us-east-1';
  const { S3Client, HeadBucketCommand, CreateBucketCommand } = await import('@aws-sdk/client-s3');
  const client = new S3Client({ region, ...(endpoint ? { endpoint, forcePathStyle: true } : {}) });
  const deadline = Date.now() + 90_000;
  for (;;) {
    try {
      try {
        await client.send(new HeadBucketCommand({ Bucket: bucket }));
        out(`Archive bucket ${bucket} exists.`);
        return 0;
      } catch {
        await client.send(new CreateBucketCommand({ Bucket: bucket }));
        out(`Created archive bucket ${bucket}.`);
        return 0;
      }
    } catch (err) {
      if (Date.now() > deadline) {
        process.stderr.write(`The archive store did not accept the bucket: ${(err as Error).name}\n`);
        return 1;
      }
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
}

async function doctor(): Promise<number> {
  const checks: Check[] = [
    {
      name: 'deployment',
      run: async () => {
        const { deployment } = await import('@stack/shared');
        const d = deployment();
        if (!d.selfManaged) throw new Error('STACK_DEPLOYMENT is not self_managed');
        return `self-managed, ${d.apiBaseUrl}, issuer ${d.passportIssuer}`;
      },
    },
    {
      name: 'secrets',
      run: async () => {
        const pepper = process.env['API_KEY_PEPPER'] ?? '';
        if (Buffer.byteLength(pepper) < 32) throw new Error('API_KEY_PEPPER must be at least 32 bytes');
        if (!process.env['SESSION_SIGNING_KEY_FILE'] && !process.env['SESSION_SIGNING_KEY_WRAPPED']) {
          throw new Error('set SESSION_SIGNING_KEY_FILE (or SESSION_SIGNING_KEY_WRAPPED)');
        }
        return 'pepper and signing key are set';
      },
    },
    {
      name: 'key service',
      run: async () => {
        const { KmsService, keyProviderEnvFrom, selectKeyProvider } = await import('@stack/vault');
        const selection = selectKeyProvider(keyProviderEnvFrom(process.env));
        if (selection.kind === 'none') throw new Error('no key provider: set STACK_KEY_FILE or AWS_KMS_KEY_ID');
        const kms = new KmsService(selection.config);
        // A real round trip, bound to a context, proves the key is the one that wrapped the data.
        const probe = await kms.encrypt('doctor', { operator_id: 'doctor', purpose: 'probe' });
        if ((await kms.decrypt(probe.ciphertext, { operator_id: 'doctor', purpose: 'probe' })) !== 'doctor') {
          throw new Error('the key service did not round-trip');
        }
        return `${kms.providerKind}${selection.kind === 'local' ? ` (key ${selection.provider.fingerprints()[0]})` : ''}`;
      },
    },
    {
      name: 'database',
      run: async () => {
        const { createDb } = await import('@stack/shared');
        const { sql } = await import('drizzle-orm');
        const db = createDb(process.env['DATABASE_URL'] ?? fail('DATABASE_URL is not set.'));
        await db.execute(sql`select 1`);
        const journalPath = join(fileURLToPath(new URL('.', import.meta.url)), '../../../../packages/shared/drizzle/meta/_journal.json');
        const expected = (JSON.parse(readFileSync(journalPath, 'utf8')) as { entries: unknown[] }).entries.length;
        const rows = (await db.execute(sql`select count(*)::int as n from drizzle.__drizzle_migrations`)) as unknown as Array<{ n: number }>;
        const applied = rows[0]?.n ?? 0;
        if (applied < expected) throw new Error(`${applied} of ${expected} migrations applied: run the migration step`);
        return `reachable, ${applied} migrations applied`;
      },
    },
    {
      name: 'redis',
      run: async () => {
        const { createRedis } = await import('../config/wiring/infra.js');
        const redis = await createRedis(process.env['REDIS_URL'] ?? fail('REDIS_URL is not set.'));
        try {
          await redis.ping();
        } finally {
          redis.disconnect();
        }
        return 'reachable';
      },
    },
    {
      name: 'audit archive',
      run: async () => {
        const { createApiObjectStore } = await import('../config/object-store.js');
        const store = await createApiObjectStore();
        if (!store.durable) throw new Error('no durable store: set AUDIT_ARCHIVE_BUCKET (an S3-compatible bucket)');
        await store.check();
        return store.description;
      },
    },
    {
      name: 'email',
      run: async () => {
        const { resolveEmailTransport } = await import('../config/email-transport.js');
        const t = resolveEmailTransport({
          selfManaged: true,
          transport: process.env['STACK_EMAIL_TRANSPORT'],
          resendKey: process.env['RESEND_API_KEY'],
          smtpUrl: process.env['SMTP_URL'],
          smtpHost: process.env['SMTP_HOST'],
          smtpPort: process.env['SMTP_PORT'],
          smtpUser: process.env['SMTP_USER'],
          smtpPassword: process.env['SMTP_PASSWORD'],
          smtpSecure: process.env['SMTP_SECURE'],
          smtpAllowInsecure: process.env['SMTP_ALLOW_INSECURE'],
          emailFrom: process.env['EMAIL_FROM'],
          replyTo: process.env['RESEND_REPLY_TO'],
        });
        return t.kind === 'none' ? 'none (no email leaves this install)' : t.kind;
      },
    },
    {
      name: 'licence',
      run: async () => {
        const { createFeatureGate } = await import('../config/licence-service.js');
        const snapshot = createFeatureGate(false).snapshot();
        return snapshot.licence === 'valid'
          ? `valid for ${snapshot.customer} until ${snapshot.expires_at}`
          : `${snapshot.licence}${snapshot.reason ? ` (${snapshot.reason})` : ''}: enterprise features are off`;
      },
    },
  ];
  let failed = 0;
  for (const check of checks) {
    try {
      out(`ok    ${check.name.padEnd(14)} ${await check.run()}`);
    } catch (err) {
      failed++;
      out(`FAIL  ${check.name.padEnd(14)} ${(err as Error).message}`);
    }
  }
  return failed === 0 ? 0 : 1;
}

async function main(): Promise<number> {
  const [group, command, ...rest] = process.argv.slice(2);
  // Commands that touch the install read its settings, including mounted secrets;
  // generating the secrets and checking a licence need none.
  if (group === 'operator' || group === 'doctor' || group === 'approvals' || group === 'archive' || group === 'erasures') loadSecretFiles();
  if (group === 'licence' && command === 'verify') return licenceVerify(rest);
  if (group === 'keys' && command === 'generate') return keysGenerate(rest);
  if (group === 'operator' && command === 'create') return operatorCreate(rest);
  if (group === 'approvals') return approvals(command, rest);
  if (group === 'erasures') return erasures(command, rest);
  if (group === 'archive' && command === 'init') return archiveInit();
  if (group === 'doctor') return doctor();
  out('usage: stack-engine licence verify | keys generate | operator create | approvals list|approve|reject | archive init | erasures reapply | doctor');
  return 2;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  });
