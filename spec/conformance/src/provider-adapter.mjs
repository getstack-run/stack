// Conformance suite for a PROVIDER ADAPTER (spec/provider-interface/SPEC.md).
// You give it an adapter wired to a double of your provider (an in-memory fake
// or a sandbox account); it runs the adapter through the contract the caller
// relies on: shape of results, crash safety, idempotent close, public-only
// details, classified failures.
//
// The double needs no features beyond what the adapter already needs. The more
// handles you provide, the more the suite can check; a check that needs a
// handle you did not provide is reported as skipped, never as passed.
//
//   runProviderAdapterSuite({
//     adapter,                       // the adapter under test
//     createsResources,              // false for an adapter that creates nothing per piece at the provider (default true)
//     context(n),                    // optional: a PieceContext for the n-th piece (n = 1, 2, ...)
//     provider: {
//       resourceCount(),             // how many resources the double holds for the customer
//       arm(kind),                   // make the next open() fail as 'retryable' | 'permanent' | 'awaiting_customer' | 'not_configured'
//       failures: ['retryable'],     // which of those the double can arm (default: all four)
//       disarm(),                    // clear an armed failure
//       secrets: ['...'],            // credential values the double knows; none may appear in outputs
//     },
//   })

import { assert, assertEqual, fail, runChecks, skip } from './harness.mjs';

export const ACCOUNT_PIECE_KINDS = ['passport', 'inbox', 'phone', 'models', 'tools', 'browser', 'card', 'wallet', 'making', 'workspace'];
const ERROR_CLASSES = ['RetryablePieceError', 'PermanentPieceError', 'AwaitingCustomerError', 'PieceNotConfiguredError'];
const FAILURE_TO_CLASS = {
  retryable: 'RetryablePieceError',
  permanent: 'PermanentPieceError',
  awaiting_customer: 'AwaitingCustomerError',
  not_configured: 'PieceNotConfiguredError',
};
const CODE_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,63}$/i;
const SECRET_KEY = /(secret|password|passwd|api[_-]?key|private[_-]?key|access[_-]?token|auth[_-]?token|bearer|credential)/i;

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const inner of Object.values(value)) deepFreeze(inner);
  }
  return value;
}

function strings(value, path = '', out = []) {
  if (typeof value === 'string') out.push({ path, value });
  else if (Array.isArray(value)) value.forEach((v, i) => strings(v, `${path}[${i}]`, out));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) strings(v, path ? `${path}.${k}` : k, out);
  return out;
}

function keys(value, path = '', out = []) {
  if (Array.isArray(value)) value.forEach((v, i) => keys(v, `${path}[${i}]`, out));
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      out.push({ path: path ? `${path}.${k}` : k, key: k, value: v });
      keys(v, path ? `${path}.${k}` : k, out);
    }
  }
  return out;
}

function classOf(error) {
  const name = error?.name;
  return ERROR_CLASSES.includes(name) ? name : null;
}

/**
 * @param {{
 *   adapter: any,
 *   createsResources?: boolean,
 *   context?: (n: number) => any,
 *   provider?: { resourceCount?: () => number | Promise<number>, arm?: (kind: string) => unknown, failures?: string[], disarm?: () => unknown, secrets?: string[] },
 * }} options
 */
export async function runProviderAdapterSuite(options) {
  const { adapter, provider = {}, createsResources = true } = options;
  const secrets = (provider.secrets ?? []).filter((s) => typeof s === 'string' && s.length >= 6);
  const contexts = new Map();
  const ctx = (n) => {
    if (!contexts.has(n)) {
      const made = options.context
        ? options.context(n)
        : {
            operatorId: 'op_conformance',
            accountId: `acct_conformance_${n}`,
            agentId: 'agt_conformance',
            pieceId: `apc_conformance_${n}`,
            request: { name: 'conformance-agent' },
          };
      contexts.set(n, deepFreeze(structuredClone(made)));
    }
    return contexts.get(n);
  };
  const count = async () => (provider.resourceCount ? provider.resourceCount() : null);
  const opened = new Map();

  async function open(n) {
    const result = await adapter.open(ctx(n));
    opened.set(n, result);
    return result;
  }

  function assertResult(result, what) {
    assert(result && typeof result === 'object', `${what} did not return an object`);
    assert(typeof result.providerResourceId === 'string' && result.providerResourceId.length > 0, `${what}: providerResourceId is not a non-empty string`);
    assert(result.details && typeof result.details === 'object' && !Array.isArray(result.details), `${what}: details is not a plain object`);
    try {
      JSON.stringify(result.details);
    } catch {
      fail(`${what}: details cannot be serialised as JSON`);
    }
  }

  function assertNoSecrets(texts, what) {
    for (const secret of secrets) {
      for (const text of texts) assert(!text.includes(secret), `${what} contains a credential value of the provider`);
    }
  }

  const checks = [
    {
      id: 'A01', level: 'MUST', title: 'declares a known kind and a provider name',
      async run() {
        assert(ACCOUNT_PIECE_KINDS.includes(adapter.kind), `kind ${JSON.stringify(adapter.kind)} is not one of ${ACCOUNT_PIECE_KINDS.join(', ')}`);
        assert(typeof adapter.provider === 'string' && adapter.provider.length > 0, 'provider is not a non-empty string');
        for (const method of ['find', 'open', 'close']) assert(typeof adapter[method] === 'function', `${method} is not a function`);
        assert(adapter.afterClose === undefined || typeof adapter.afterClose === 'function', 'afterClose is neither absent nor a function');
      },
    },
    {
      id: 'A02', level: 'MUST', title: 'find returns null for a piece that was never opened, with no side effect at the provider',
      async run() {
        const before = await count();
        const found = await adapter.find(ctx(1));
        assertEqual(found, null, 'find on a fresh piece');
        const after = await count();
        if (before !== null) assertEqual(after, before, 'resources held by the provider after find');
      },
    },
    {
      id: 'A03', level: 'MUST', title: 'open returns a resource id and public details',
      async run() {
        assertResult(await open(1), 'open');
      },
    },
    {
      id: 'A04', level: 'MUST', title: 'details hold no credential, token or key',
      async run() {
        const result = opened.get(1) ?? (await open(1));
        assertNoSecrets(strings(result.details).map((s) => s.value), 'details');
        for (const { path, key, value } of keys(result.details)) {
          assert(!(SECRET_KEY.test(key) && typeof value === 'string' && value.length > 0), `details.${path} looks like a secret`);
        }
      },
    },
    {
      id: 'A05', level: 'MUST', title: 'find after open returns the same resource',
      async run() {
        if (!createsResources) return skip('the adapter creates nothing per piece, so find has nothing to return');
        const first = opened.get(1) ?? (await open(1));
        const found = await adapter.find(ctx(1));
        assert(found !== null, 'find returned null for a piece that was opened');
        assertResult(found, 'find');
        assertEqual(found.providerResourceId, first.providerResourceId, 'providerResourceId from find');
      },
    },
    {
      id: 'A06', level: 'MUST', title: 'a second open after a lost write does not create a second resource',
      async run() {
        if (!createsResources) {
          const first = opened.get(1) ?? (await open(1));
          const again = await adapter.open(ctx(1));
          assertEqual(again.providerResourceId, first.providerResourceId, 'providerResourceId from the repeated open');
          if (provider.resourceCount) assertEqual(await count(), 0, 'resources held by the provider (the adapter creates none)');
          return;
        }
        if (!provider.resourceCount) return skip('provider.resourceCount was not provided');
        const first = opened.get(1) ?? (await open(1));
        const before = await count();
        let again;
        try {
          again = await adapter.open(ctx(1));
        } catch (error) {
          fail(`open on a piece that already has its resource threw ${error?.name ?? 'an error'}: it must adopt the existing resource`);
        }
        assertEqual(await count(), before, 'resources held by the provider after a repeated open');
        assertEqual(again.providerResourceId, first.providerResourceId, 'providerResourceId from the repeated open');
      },
    },
    {
      id: 'A07', level: 'MUST', title: 'different pieces get different resources',
      async run() {
        if (!createsResources) return skip('the adapter creates nothing per piece, so pieces may share one marker');
        const first = opened.get(1) ?? (await open(1));
        const second = await open(2);
        assertResult(second, 'open of the second piece');
        assert(second.providerResourceId !== first.providerResourceId, 'two pieces share one resource');
        const found = await adapter.find(ctx(2));
        assertEqual(found?.providerResourceId, second.providerResourceId, 'find for the second piece');
        const stillFirst = await adapter.find(ctx(1));
        assertEqual(stillFirst?.providerResourceId, first.providerResourceId, 'find for the first piece');
      },
    },
    {
      id: 'A08', level: 'MUST', title: 'ignores request fields it does not know (the context is frozen, so a write to it throws)',
      async run() {
        const made = options.context ? options.context(3) : { operatorId: 'op_conformance', accountId: 'acct_conformance_3', agentId: 'agt_conformance', pieceId: 'apc_conformance_3', request: { name: 'conformance-agent' } };
        const withFuture = deepFreeze({ ...structuredClone(made), request: { ...structuredClone(made.request), future_piece: { anything: true } } });
        contexts.set(3, withFuture);
        assertResult(await open(3), 'open with an unknown request field');
      },
    },
    {
      id: 'A09', level: 'MUST', title: 'close succeeds, and succeeds again when the resource is already gone',
      async run() {
        const first = opened.get(1) ?? (await open(1));
        await adapter.close({ ...ctx(1), providerResourceId: first.providerResourceId });
        await adapter.close({ ...ctx(1), providerResourceId: first.providerResourceId });
      },
    },
    {
      id: 'A10', level: 'MUST', title: 'close succeeds for a resource id the provider does not know',
      async run() {
        await adapter.close({ ...ctx(1), providerResourceId: 'conformance_unknown_resource' });
      },
    },
    {
      id: 'A11', level: 'SHOULD', title: 'find returns null after the resource is closed',
      async run() {
        const found = await adapter.find(ctx(1));
        assertEqual(found, null, 'find after close');
      },
    },
    {
      id: 'A12', level: 'MUST', title: 'afterClose, when present, is idempotent and never throws',
      async run() {
        if (!adapter.afterClose) return skip('the adapter has no afterClose');
        await adapter.afterClose(ctx(1));
        await adapter.afterClose(ctx(1));
      },
    },
    {
      id: 'A13', level: 'MUST', title: 'closing a piece leaves no resource behind',
      async run() {
        if (!createsResources) return skip('the adapter creates nothing per piece');
        if (!provider.resourceCount) return skip('provider.resourceCount was not provided');
        for (const n of [2, 3]) {
          const result = opened.get(n);
          if (result) await adapter.close({ ...ctx(n), providerResourceId: result.providerResourceId });
        }
        assertEqual(await count(), 0, 'resources held by the provider after every piece was closed');
      },
    },
  ];

  for (const [failure, className] of Object.entries(FAILURE_TO_CLASS)) {
    checks.push({
      id: `F-${failure}`, level: 'MUST', title: `a ${failure.replace('_', ' ')} failure at the provider is thrown as ${className}, with a safe code and no secret`,
      async run() {
        if (!provider.arm) return skip('provider.arm was not provided');
        if (provider.failures && !provider.failures.includes(failure)) return skip(`the provider double cannot be armed to fail as ${failure}`);
        const n = 10 + Object.keys(FAILURE_TO_CLASS).indexOf(failure);
        const before = await count();
        await provider.arm(failure);
        let thrown;
        try {
          await adapter.open(ctx(n));
        } catch (error) {
          thrown = error;
        } finally {
          await provider.disarm?.();
        }
        assert(thrown !== undefined, 'open succeeded although the provider was armed to fail');
        assertEqual(classOf(thrown), className, 'class of the error');
        assert(typeof thrown.code === 'string' && CODE_PATTERN.test(thrown.code), `code ${JSON.stringify(thrown.code)} is not a safe code`);
        assertNoSecrets([String(thrown.message), String(thrown.code), ...strings(thrown.details ?? {}).map((s) => s.value)], 'the error');
        if (failure === 'awaiting_customer') assert(thrown.details && typeof thrown.details === 'object', 'AwaitingCustomerError carries no details object');
        if (before !== null && failure !== 'awaiting_customer') assertEqual(await count(), before, 'resources held by the provider after a failed open');
        if (failure === 'retryable') {
          // The retry that follows must converge on one resource.
          const result = await adapter.open(ctx(n));
          assertResult(result, 'open on retry');
          opened.set(n, result);
          if (before !== null && createsResources) assertEqual(await count(), before + 1, 'resources held by the provider after the retry');
          await adapter.close({ ...ctx(n), providerResourceId: result.providerResourceId });
        }
      },
    });
  }

  const report = await runChecks(`provider adapter (${adapter.kind ?? 'unknown kind'}/${adapter.provider ?? 'unknown provider'})`, checks);
  // Whatever a failing run left open is closed, so a double is reusable.
  for (const [n, result] of opened) {
    try {
      await adapter.close({ ...ctx(n), providerResourceId: result.providerResourceId });
    } catch {
      /* best effort */
    }
  }
  return report;
}
