# STACK's network services (client only)

A self-managed install can use two services STACK operates. Both are off unless `STACK_NETWORK_URL` and `STACK_NETWORK_KEY` are set, and each has its own switch. The install is a client: it opens the connections, nothing connects in. The services themselves are STACK's hosted layer: they run on STACK's servers and are not part of this repository, which holds only the client; this page is what the install does.

Without them the install runs the built-in detection rules (all of L1 and L2) and has no L3. **L3, the model classifier, runs only through STACK's network, with a licence key (or a STACK account's API key).** The install has no classifier of its own: the engine carries no classifier prompt and makes no model call for detection, and a model provider's key set in the install does not add one.

## What authenticates the install

`STACK_NETWORK_KEY` is sent as `Authorization: Bearer <key>` over https, and is one of two things:

- **A STACK account's API key.** The calls are billed to that account.
- **The install's licence key** (`STACKLIC1.<payload>.<signature>`, the one in `STACK_LICENCE_KEY`), when STACK issued it to a STACK account. The licence names that account in a signed claim, and the calls are billed to it. A licence key is accepted for these two calls only (the rule set and the classifier); it cannot countersign a passport or publish a revocation, which need the install's own key. A licence that has expired is refused. Setting the licence as `STACK_NETWORK_KEY` (or `STACK_NETWORK_KEY_FILE`) is the install's choice: **an install with a licence and no network settings sends nothing to STACK.**

A licence is a bearer secret, so treat it like one. If it leaks, the STACK account it was issued to can revoke it before it expires: `npx @getstackrun/cli network licence revoke --licence-file <path>` (or the key on standard input; it is never an argument), or `stack.network.licences.revoke(key)` in the SDKs. The key carries its own id, STACK checks that id against the list of revoked keys on every request, and a revoked key is refused from the next call. If STACK cannot make that check, the call is refused with a retriable 503 rather than let through. A licence key that carries no id cannot be revoked and is not accepted by the network; ask STACK for a new one. Revoking is an owner or admin decision (never an agent's), is never charged, and shows in the account's record as `network.licence.revoke`. A revoked key still works for the enterprise features it grants offline, which need no network; get a new key to replace it.

## Live detection rules (`STACK_NETWORK_RULES`, on when configured)

`POST <url>/v1/network/detection/rules` with an empty JSON object, hourly. The answer:

```json
{ "version": "2026-10-22.1", "revision": 7, "expires_at": "...", "statement": "<compact JWS>" }
```

- The statement is a JWS (`typ` `stack-detection-rules+jwt`, audience `stack:detection-rules`) signed by STACK's deployment key. The install checks it against STACK's published keys (`<url>/v1/network/jwks.json`); an unsigned, wrongly signed or expired statement is refused.
- A set only moves forward: its `revision` must be at least the one held.
- A set is trusted until it expires and for 30 days at most. After that the built-in rules alone apply.
- A rule is an input rule (a prompt-injection pattern) or an output rule. The install applies the input rules to what it scans, compiled by a linear-time engine (RE2) and treated as data only. A pattern RE2 refuses (lookahead, back references) or one over 512 characters is dropped, and a set of more than 500 rules is refused.
- A fetch that fails keeps the rules in force.

The rules are extra L1 and L2 patterns for every operator, named `network:<id>` in security events. An operator who turned the detector off is not scanned by them. Each fetch is one metered action on the key's account.

## The hosted L3 classifier (`STACK_NETWORK_CLASSIFIER`, off unless true)

`POST <url>/v1/network/detection/classify` with `{ "content": "<sampled content>" }`. The answer carries the rule match, if any, and the classifier's verdict, confidence and reasoning; the install turns the classifier's part into an L3 verdict. **The content leaves your install.** What is sent: the sampled text only. Not sent: the prompt, the operator or agent, any identifier. STACK keeps none of it.

This is the only L3 an install has. It needs `STACK_NETWORK_URL` and a key that STACK accepts for it (a licence key issued to a STACK account, or the account's API key); without them the switch has nothing to call and the install stays at L1 and L2. A failed call, or an answer without a classifier verdict, degrades to the L1 and L2 verdict. Each call is one metered action on the key's account, and the model call is billed at the provider's cost.

## Grading intent deviation

An install grades each checkout's declared intent against what the agent did in one of two ways, and with neither intent_deviation is off.

1. **Your own model** (`STACK_INTENT_MODEL_URL`, `STACK_INTENT_MODEL_NAME` and, when the endpoint takes one, `STACK_INTENT_MODEL_KEY`). The install asks an OpenAI-compatible chat completions endpoint (`POST <url>/chat/completions`) that you name, with the same prompt, answer format and thresholds a hosted checkout is graded with (a score of 0.4 or more is a warning, 0.7 or more critical). The URL is https, or http on the same machine for a model you run yourself. What is sent to your endpoint is the passport's declared intent (its summary and services) and what the agent did (the services it used, every tool call, the action count and the checkout's summary), and no passport, agent, operator or Mission identifier. It needs no STACK account, and nothing goes to STACK. Where your own model is set it is used and STACK's network is not asked.
2. **STACK's network**, only with `STACK_NETWORK_CLASSIFIER` on and no model of your own: at each checkout, `POST <url>/v1/network/detection/intent-deviation` with the same facts, one metered action and the model call at cost. There is no limit on how many services or tool calls a checkout holds; the request as a whole is bounded by a body size limit.

A grader that cannot answer (a refusal, a timeout, an answer it cannot read) adds no flag, and a checkout never waits on it for a refusal.
