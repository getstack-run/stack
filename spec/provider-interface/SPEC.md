# STACK Provider Interface

**Specification:** STACK Provider Interface
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

An agent account is made of **pieces**: an inbox, a phone number, model access, paid tools, a workspace, a browser, a card, a wallet, a way to have things made and the agent's own Passport. Each piece is opened and closed at a provider by an **adapter**. This document defines the interface an adapter implements, the errors it uses to say what went wrong, and the behaviour an adapter MUST have so that the caller can open and close pieces reliably, retry safely, and never leave a resource behind at a provider. A supplier that wants its service to be an account piece writes an adapter to this interface and runs the conformance kit against it.

The TypeScript definition is the package `@getstackrun/provider-interface` in [`src/index.ts`](src/index.ts). This text and that file describe the same contract.

Contents: 1 Conventions, 2 Model, 3 The interface, 4 Outcomes, 5 Crash safety and idempotency, 6 Details and secrets, 7 Configuration, 8 How the reference caller behaves, 9 Reference registry, 10 Security considerations, 11 Machine-readable schema, 12 Conformance.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The **caller** is the component that drives pieces (in the reference implementation, the provisioner that runs in the API and worker processes). An **adapter** is an object implementing `AccountPieceAdapter`. A **piece** is one row of an account: a kind, a state and, once opened, the provider's id for its resource.

## 2. Model

A piece has a state: `pending` (not yet open, or waiting), `ready`, `paused`, `failed`, `closing` and `closed`. The caller moves it; the adapter never records state. For one piece the caller:

1. calls `find`, and if that returns a resource, marks the piece ready with it;
2. otherwise calls `open`, and marks the piece ready with its result;
3. when the account closes, calls `close` with the recorded resource id (or with the id `find` returns if no id was recorded), marks the piece closed, then calls `afterClose` once.

Attempts are leased and may run in any process, may be repeated after a crash, and are never concurrent for one piece. An adapter MUST NOT hold state between calls that the next call cannot rebuild from the provider or from its inputs.

## 3. The interface

```ts
interface AccountPieceAdapter<TRequest = AccountOpenRequest> {
  readonly kind: AccountPieceKind;
  readonly provider: string;
  find(ctx: PieceContext<TRequest>): Promise<PieceOpenResult | null>;
  open(ctx: PieceContext<TRequest>): Promise<PieceOpenResult>;
  close(ctx: PieceContext<TRequest> & { providerResourceId: string }): Promise<void>;
  afterClose?(ctx: PieceContext<TRequest>): Promise<void>;
}

interface PieceContext<TRequest> {
  operatorId: string;   // the customer
  accountId: string;
  agentId: string;
  pieceId: string;      // stable for the life of the piece
  request: TRequest;    // the validated request that opened the account
}

interface PieceOpenResult {
  providerResourceId: string;           // non-empty
  details: Record<string, unknown>;     // public, non-secret facts
}
```

- `kind` is one of the kinds in section 9. `provider` is a short stable identifier of the provider and MUST NOT change between calls.
- `request` has the shape in [`schemas/OpenAgentAccountInput.json`](schemas/OpenAgentAccountInput.json). An adapter reads the part that concerns its kind (`inbox`, `phone`, `wallet`, ...) and MUST ignore the rest, including fields added in later versions.

**`find(ctx)`** returns the resource already created for this piece, or `null`. It MUST have no side effect at the provider. It MUST return the same `providerResourceId` as the `open` that created the resource, and equivalent `details`. It MAY throw `AwaitingCustomerError` when the resource exists but waits on the customer. An adapter that creates nothing at the provider for a piece (the piece uses a resource shared by every account, or opening only checks that the provider is configured) returns `null` from `find` every time; the caller then calls `open` on every attempt, so such an `open` MUST be idempotent and MUST create nothing.

**`open(ctx)`** creates the resource and returns its id and public details. The caller has just called `find` and received `null`. `open` MUST be safe to call again after a crash (section 5).

**`close(ctx)`** releases the resource at the provider. It MUST succeed when the resource is already gone (a second call, a resource deleted by hand), and MUST NOT leave the resource billing.

**`afterClose(ctx)`** is optional. It runs after the piece is marked closed, for clean-up that needs every piece of the customer to be closed first (closing the customer's account at the provider, for example). It MUST be idempotent and MUST NOT throw; the caller logs and ignores anything it throws.

## 4. Outcomes

Every outcome other than success is a thrown error of one of four classes. All carry a stable `code` (a short identifier, `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`) that is stored on the piece and shown to the customer, and a `message` that is **never stored** (provider responses can contain secrets).

| Class | Meaning | Caller's behaviour |
|---|---|---|
| `RetryablePieceError` | A transient provider failure: 5xx, 429, 408, a timeout, an unreachable host. | `open`: the attempt counts; retried with back-off; the piece fails after the attempt limit. `close`: retried without limit. |
| `PermanentPieceError` | No retry can fix it: the provider refused the request, an input is missing. | `open`: the piece fails at once. `close`: the piece is marked failed. |
| `AwaitingCustomerError(code, message, details, providerResourceId?)` | The piece waits on a step only the customer can take. `details` are public facts, typically the link to act on. `providerResourceId` is set when the provider already holds something for the piece. | `open`: the piece stays pending with `code` and `details`; no attempt is consumed; rechecked on a schedule. `close`: retried; if `find` throws it, its `providerResourceId` is the resource to close. |
| `PieceNotConfiguredError(code?, message?)` | The operator's own credentials or settings for this provider are not present on this deployment. | The piece stays pending with the code (default `provider_not_configured`) and is rechecked; no attempt is consumed. |

Any other error is treated as permanent: its `code`, when it is a string matching the pattern above, is recorded; its message is dropped. An adapter SHOULD therefore classify its own failures rather than let a raw network error escape.

Classification guidance: an HTTP status of 500 or above, 429 and 408, and connection failures and timeouts are retryable; other 4xx statuses are permanent, with a code derived from the provider's own error code, never from its message.

## 5. Crash safety and idempotency

The caller can crash between the provider call and writing its result. To make that harmless:

- The adapter MUST derive every name, key or idempotency token it sends to the provider from `pieceId` (and, if needed, `accountId`), never from a random value or the clock, so that a retried `open` addresses the same resource.
- `find` MUST be able to recognise the resource a crashed `open` created, using only those derived values and the provider's own listing or lookup.
- `open` MUST NOT create a second resource when one already exists for the piece. If the provider rejects the create because the resource exists (a conflict), `open` MUST adopt the existing resource, provided it belongs to this piece and this customer.
- `close` MUST be safe to repeat.

A resource that exists at the provider and that no piece row accounts for is a defect of the adapter, because the customer will be billed for it.

An adapter that creates nothing per piece has nothing to leave behind. Its `providerResourceId` MAY be a marker shared by several pieces, and its `close` MAY only withdraw access.

## 6. Details and secrets

`details` is shown to the agent and the customer. It MUST contain only facts that are public to them: an email address, a phone number, a wallet address, a link. It MUST NOT contain an API key, a token, a password, a private key or anything that grants access. Secrets the adapter needs for the provider (the operator's credentials, a per-customer sub-account credential) are the adapter's own concern and MUST be stored encrypted, not in `details` and not in an error.

An adapter MUST NOT put a secret in an error `code` or `message`.

## 7. Configuration

An adapter whose provider is not set up on this deployment MUST throw `PieceNotConfiguredError` from `open` rather than fail, crash at start-up, or pretend to succeed. `find` throws it too when it needs the provider to answer; it MAY return `null` when it can tell without the provider that no resource exists. It MUST NOT return a fabricated resource in a production deployment. A deployment that has no adapter for a kind at all is treated the same way by the caller: the piece waits as not configured.

## 8. How the reference caller behaves

This section is informative. It tells an adapter author what to expect.

<!-- spec:generated:provider-constants -->

| Constant | Value |
|---|---|
| Open attempts before a piece fails | 5 |
| Recheck of a piece waiting on the customer | 120 s |

<!-- /spec:generated -->

Back-off between retried attempts starts at 30 seconds, doubles each attempt and is capped at one hour. A piece waiting as not configured is looked at again every ten minutes. Attempts are leased for five minutes: a call that outlives its lease may be repeated by another process, which is a further reason for section 5.

When an account closes, pieces are closed in a fixed order (section 9) so that whatever can spend money is released first, then whatever can act in the world, then the inbound channels, and the account's Passport last.

## 9. Reference registry

The reference registry holds one adapter per kind and refuses an adapter whose `provider` differs from the one it expects for that kind. Other registries MAY allow several providers for a kind; the contract above does not depend on it. The kinds and the teardown order:

<!-- spec:generated:provider-piece-kinds -->

| Kind | Close order |
|---|---|
| `passport` | 11 |
| `inbox` | 10 |
| `phone` | 9 |
| `models` | 4 |
| `tools` | 5 |
| `browser` | 7 |
| `card` | 2 |
| `wallet` | 1 |
| `making` | 3 |
| `workspace` | 6 |

<!-- /spec:generated -->

The `passport` piece is the account's own and has no provider: it is ready once the agent can be issued a Passport under the account's standing Mission, and closing it has nothing to release.

## 10. Security considerations

- Treat every response from the provider as untrusted. Do not copy provider text into `details`, `code` or `message` without validating it.
- Do not log credentials. Do not include request bodies that carry them in errors.
- An adapter acts with the operator's authority at the provider. It MUST scope what it creates to the one customer and piece in `ctx` and MUST NOT list, read or modify resources of other customers.
- `close` is destructive and idempotent by design; an adapter MUST verify, before deleting, that the resource named by `providerResourceId` belongs to this customer.
- Cost control belongs to the caller and the provider account (spend caps), not to the adapter; an adapter SHOULD still set the provider's own caps when the provider offers them.

## 11. Machine-readable schema

[`schemas/OpenAgentAccountInput.json`](schemas/OpenAgentAccountInput.json) (draft-07) is generated from the reference implementation and describes `PieceContext.request`. The TypeScript types are in [`src/index.ts`](src/index.ts).

## 12. Conformance

The kit in [`../conformance/`](../conformance/README.md) runs an adapter through the behaviour in sections 3 to 7 against a provider double that the adapter's author supplies: it checks the shape of results, that `find` after `open` returns the same resource, that a repeated `open` after a lost write does not create a second resource, that `close` can be repeated, that failures are classified into the four classes, and that no secret appears in `details`, a code or a message.
