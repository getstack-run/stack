# STACK conformance kit

Runnable tests you point at your own implementation to find out whether it conforms to the STACK specifications in [`../`](../README.md). It plays the other side of each protocol: it signs requests, mints tokens, builds packs, drives adapters, and checks what your implementation does with them, including what it must refuse.

Thirty-two suites:

| Suite | You supply | Specification |
|---|---|---|
| `catalogue` | A catalogue document (a file), or the URL of the file your server serves | [Catalogue](../catalogue/SPEC.md) |
| `decision` | The URL of your decision server and a test signing secret | [Control Socket Protocol](../control-socket/SPEC.md), section 4 |
| `events` | The URL of your events receiver and a test signing secret | [Control Socket Protocol](../control-socket/SPEC.md), section 7 |
| `webhooks` | The URL of your webhook receiver and a test signing secret, or a function that verifies one request | [Webhooks](../webhooks/SPEC.md), sections 4 and 5 |
| `authority` | A receiver of STACK's authority protocol: a module (or a program) that signs its calls, requests and receipts and opens presentations, and/or the URL of its delivery endpoint | [Authority Receiver Protocol](../authority-receiver/SPEC.md) |
| `wallet` | A wallet payment client (a function that builds and signs the request), and/or the endpoint of a test relay and its test wallet | [Wallet Payment Relay](../wallet-relay/SPEC.md) |
| `x402` | The URL of a priced path on a test agent site, and/or a function that pays a 402 | [Agent Site Payments](../agent-site-payments/SPEC.md) |
| `passport` | A function (or a program) that verifies a Passport offline | [Passport](../passport/SPEC.md), section 9.1 |
| `provider` | An adapter wired to a double of your provider | [Provider Interface](../provider-interface/SPEC.md) |
| `record` | A function (or a program) that verifies an evidence pack | [Record Format](../record/SPEC.md), section 8 |
| `credentials` | A `.stack` directory a client wrote, or a client that can write and read one | [Credentials Files](../credentials-files/SPEC.md) |
| `rest-api` | The base URL of a server of the REST API; for the deeper checks a test API key and a way to decide an approval | [REST API](../rest-api/SPEC.md) |
| `web-bot-auth` | A signer, a site's verifier or a served key directory (any of the three) | [Web Bot Auth Profile](../web-bot-auth/SPEC.md) |
| `partner` | The URL of a test instance and a test partner's key | [Partner API](../partner/SPEC.md) |
| `a2a` | The origin of a server and a test caller's credentials, or the URL of an agent's signed card | [A2A Profile](../a2a/SPEC.md) |
| `mcp-listing` | A function that opens a session on your MCP server, and its catalog | [MCP Tool Definitions](../mcp-tools/SPEC.md), section 11 |
| `service-mcp` | The address of your service's MCP endpoint and the credential header STACK would send | [Service MCP Calls](../service-mcp/SPEC.md) |
| `network-verifier` | A function (or a program) that verifies the network's signed objects, and optionally an install's signer | [Network](../network/SPEC.md), sections 4 to 6 and 8 to 12 |
| `network-service` | The base address of a network service, and optionally a registered install's id and private key | [Network](../network/SPEC.md), sections 3 to 13 |
| `agent-jwt` | An agent-side minter (an SDK), a server-side verifier (a function), or a running server and an agent enrolled on it | [Agent Runtime Sign-in](../agent-auth/SPEC.md), sections 3 and 4 |
| `agent-enrollment` | The address and test credential of a test instance, and a way to decide an approval | [Agent Runtime Sign-in](../agent-auth/SPEC.md), section 5, and [Agent Keys](../agent-keys/SPEC.md), section 4 |
| `fleet-enrollment` | The same | [Agent Runtime Sign-in](../agent-auth/SPEC.md), section 6 |
| `agent-keys` | The helper that signs a claim with an agent's key, or a function that verifies one | [Agent Keys](../agent-keys/SPEC.md), sections 5 and 6 |
| `workload-token` | A function that accepts a SPIFFE JWT-SVID or a WIMSE token under a configuration and a key set | [Workload Identity Exchange](../workload-identity/SPEC.md), sections 4 and 7 |
| `workload-exchange` | The address of a test instance | [Workload Identity Exchange](../workload-identity/SPEC.md), sections 6 and 8 |
| `oauth` | The address of a test instance with OAuth on | [OAuth Server Profile](../oauth-profile/SPEC.md) |
| `oauth-client-metadata` | A function that checks a client metadata document | [OAuth Server Profile](../oauth-profile/SPEC.md), sections 4.1 and 4.3 |
| `passport-online` | The address and test credential of a test instance, a way to decide an approval, and optionally a subscription to its revocation channel | [Passport](../passport/SPEC.md), sections 8 to 11 |
| `agent-identity` | The origin of a server and the handles of a test agent (its key id, site and id, and optionally a closed one and one switched off), and/or a function that verifies a statement | [Agent Identity](../agent-identity/SPEC.md) |
| `siem-exporter` | A harness that drives an exporter of the security-monitoring export: the kit plays the syslog and HTTPS collectors | [Security Monitoring Export](../siem-export/SPEC.md), sections 3 to 8 and 10 |
| `siem-collector` | A harness that starts a collector of the export: the kit plays the exporter | [Security Monitoring Export](../siem-export/SPEC.md), section 9 |
| `sso-login` | The address of a test deployment's API and a function that connects the kit's identity provider to an account of it: the kit plays the browser and the provider | [Single Sign-on Profile](../sso-login/SPEC.md) |

Every check is a **MUST** (a failure means you do not conform) or a **SHOULD** (a failure is a warning). The run exits `0` when no MUST failed.

The kit needs Node 22 or later and nothing else: it does not use any STACK package to judge your implementation.

## Run it

```bash
# A decision server or events receiver, started with a TEST secret
npx @getstackrun/conformance decision --url https://localhost:8787/stack/decide --secret whsec_...
npx @getstackrun/conformance events   --url https://localhost:8787/stack/events --secret whsec_...

# Any receiver of STACK webhooks (wake-ups, notifications, forwards, revocation pushes): a URL, or a verifier function
npx @getstackrun/conformance webhooks --url https://localhost:8787/stack/webhook --secret whsec_...
npx @getstackrun/conformance webhooks --module ./my-verifier.mjs --secret whsec_...

# An authority receiver: a module that exports createReceiver(config), or any program (JSON in on stdin, JSON out on stdout)
npx @getstackrun/conformance authority --module ./my-receiver.mjs
npx @getstackrun/conformance authority --command ./my-receiver
# ... and/or a deployed delivery endpoint, with the public JWK of its response-encryption key
npx @getstackrun/conformance authority --delivery-url https://localhost:8787/direct-post --delivery-key ./encryption-public-jwk.json

# A wallet payment client (a module exporting build(...)), and/or a test relay with a test wallet described in a file
npx @getstackrun/conformance wallet --module ./my-wallet-client.mjs
npx @getstackrun/conformance wallet --url https://localhost:8787/v1/accounts/acct_test/wallet/payments --wallet ./test-wallet.json --header "Authorization: Bearer <test agent credential>"

# An agent site's priced path (add --accepts-test-payments when its facilitator takes the kit's test payments), and/or a buyer module exporting pay(...)
npx @getstackrun/conformance x402 --url https://localhost:8080/reports/42
npx @getstackrun/conformance x402 --module ./my-buyer.mjs

# A Passport verifier: a module that exports verify(token, { jwks, issuer, audience })
npx @getstackrun/conformance passport --module ./my-verifier.mjs
# ... or any program, in any language: JSON in on stdin, JSON out on stdout
npx @getstackrun/conformance passport --command ./my-verifier

# A record verifier, at conformance level 1, 2 or 3
npx @getstackrun/conformance record --module ./my-verifier.mjs --level 2
npx @getstackrun/conformance record --command stack-verify --level 2

# A provider adapter: a module whose default export returns { adapter, provider, ... }
npx @getstackrun/conformance provider --module ./my-adapter-harness.mjs

# A network verifier (a module that exports verify(kind, token, ctx), and optionally signer), or a program in any language
npx @getstackrun/conformance network-verifier --module ./my-network.mjs
npx @getstackrun/conformance network-verifier --command ./my-network

# A network service: the public calls alone, or the whole flow of one test install (it countersigns and revokes an invented agent)
npx @getstackrun/conformance network-service --url https://localhost:8080
npx @getstackrun/conformance network-service --url https://localhost:8080 --install-id ins_... --install-key ./install-key.pem

# A catalogue: the document alone, or the URL that serves it (which also checks the ETag and the 304)
npx @getstackrun/conformance catalogue --file ./catalogue.json
npx @getstackrun/conformance catalogue --url https://localhost:8080/v1/catalogue --header "Authorization: Bearer <test key>"
# Also judge one account's part (what it says about the account's tools) against the document
npx @getstackrun/conformance catalogue --file ./catalogue.json --account-view ./account.json

# The local files of a client (~/.stack): judge a directory it wrote, or give a module that writes and reads them (exports write,
# writeAgentKey and read; see "Program interfaces").
npx @getstackrun/conformance credentials --dir ~/.stack
npx @getstackrun/conformance credentials --module ./my-client.mjs

# A server of the REST API. The envelope, the reading of a request and the refusal of a bad credential need no credential;
# with a TEST key the governance step-up runs end to end. --approve-command is whatever lets a person decide an approval on
# your deployment ({id} is replaced by the approval id); --probes is a JSON file of requests that make your server answer a
# 402, a refusal of a control and a refused cost cap (see "Program interfaces").
npx @getstackrun/conformance rest-api --url https://localhost:3000 --api-key <test key> --approve-command 'your-tool approvals approve {id}' --probes ./probes.json
# Web Bot Auth: a signer, a site's verifier, a key directory served at an address (any of them, together or apart)
npx @getstackrun/conformance web-bot-auth --signer ./my-signer.mjs
npx @getstackrun/conformance web-bot-auth --verifier ./my-verifier.mjs
npx @getstackrun/conformance web-bot-auth --directory-url https://your.host

# The partner API on a TEST instance, with a test partner's key. Add a mailbox you own to also invite a customer and release an account
npx @getstackrun/conformance partner --url https://your.test --key sk_live_... --non-partner-key sk_live_... --invite-email you@your.mailbox --release-email you@your.mailbox

# An A2A endpoint: its card without credentials, the envelope, and (with two agents of the test caller) the task flow
npx @getstackrun/conformance a2a --url https://your.host --header "Authorization: Bearer <test key>" --from-agent agt_... --to-agent agt_...

# The tool listing of an MCP server: a module that opens a session, judged against the specification's catalog
npx @getstackrun/conformance mcp-listing --module ./open-session.mjs --catalog ./tools.json

# A service's MCP endpoint, sent exactly what STACK sends when an agent lists or calls its tools
npx @getstackrun/conformance service-mcp --url https://your.host/mcp --header "X-API-Key: <test key>" --tool <a safe tool> --tool-arguments '{}'


# Agent sign-in: the agent JWT, from the agent's side (a minter) and from a server's (a function, or a running server)
npx @getstackrun/conformance agent-jwt --minter ./my-minter.mjs
npx @getstackrun/conformance agent-jwt --verifier ./my-verifier.mjs
npx @getstackrun/conformance agent-jwt --url https://localhost:3001 --agent agt_... --key ./agent-private.jwk
# Key enrollment, fleet enrollment, and Passport verification, revocation and delegation, on a TEST instance
npx @getstackrun/conformance agent-enrollment --url https://localhost:3001 --header "Authorization: Bearer <test key>" --approve-command "stack-engine approvals approve"
npx @getstackrun/conformance fleet-enrollment --url https://localhost:3001 --header "Authorization: Bearer <test key>" --approve-command "stack-engine approvals approve"
npx @getstackrun/conformance passport-online  --url https://localhost:3001 --header "Authorization: Bearer <test key>" --approve-command "stack-engine approvals approve"

# The security-monitoring export: an exporter (a module whose default export builds the harness) judged by collectors the kit plays,
# and a collector (a module whose default export starts it) judged by an exporter the kit plays (see "Program interfaces")
npx @getstackrun/conformance siem-exporter --module ./my-exporter-harness.mjs [--transports udp,tcp,tls,https]
npx @getstackrun/conformance siem-collector --module ./my-collector-harness.mjs

# Single sign-on on a TEST deployment: the kit serves an identity provider on this machine and signs in through the deployment.
# --configure-command connects that provider to an account of the deployment (the connection as JSON on its standard input)
npx @getstackrun/conformance sso-login --url https://localhost:3001 --configure-command "your-tool connect-sso"
# A deployment that lets an account prove an e-mail domain in DNS (section 9.5) gives the kit three more functions, with --module:
# the module exports configure(connection) and domains = { verified, verifiedElsewhere, recordRemoved }, each async ({ domain }) => void.
# Without them the four checks of verified domains are skipped.
npx @getstackrun/conformance sso-login --url https://localhost:3001 --module ./connect-sso.mjs

# Per-agent keys: the helper that signs a claim with an agent's key, and a verifier of such a claim
npx @getstackrun/conformance agent-keys --signer ./my-signer.mjs
npx @getstackrun/conformance agent-keys --verifier ./my-verifier.mjs

# Workload identity: the acceptance of a SPIFFE JWT-SVID or a WIMSE token, and the exchange on a test instance
npx @getstackrun/conformance workload-token --module ./my-acceptor.mjs
npx @getstackrun/conformance workload-exchange --url https://localhost:3001

# The OAuth server profile, and the check of a client metadata document
npx @getstackrun/conformance oauth --url https://localhost:3001
npx @getstackrun/conformance oauth-client-metadata --module ./my-check.mjs


# An agent identity server (the lookup, the signed statement, the agent's machine files) with the handles of a test agent in a file,
# and/or a verifier function judged against the kit's vectors (see "Program interfaces")
npx @getstackrun/conformance agent-identity --url https://your.host --agent ./test-agents.json
npx @getstackrun/conformance agent-identity --verifier ./my-verifier.mjs
```

`--json` prints a machine-readable report. In a checkout of this repository, replace `npx @getstackrun/conformance` with `node spec/conformance/bin/stack-conformance.mjs`.

### Safety

The `catalogue` suite only reads: it fetches the file and, with a URL, asks again with a validator. Give it a test credential that can read the catalogue and nothing else.

The `partner` suite creates things on the instance you give it: partner-managed accounts (closed at the end), an agent and a webhook under one, and, only with `--invite-email` or `--release-email`, an invitation or a release to that address (withdrawn at the end). It sends mail to no address but the ones you name, and the invitation and release checks that run without one are the ones that must be refused before anything is sent. The checks of what a completed claim and a claim that did not clear look like to the partner need a function of yours (`completeClaim`, `failClaim`) and so run through the library only: a claim is the customer's own card and sanctions check, which a test instance has to be able to finish or fail on request. Use a test instance and a test partner, never a production key. The `a2a` suite sends tasks between two agents of the test caller and cancels them. The `siem-exporter` suite starts a UDP socket, a TCP server, a TLS server and an HTTPS server on this machine (127.0.0.1, with certificates of their own that exist only for the run) and sends nothing anywhere else; the harness you give it writes test rows to a store you can discard. The `siem-collector` suite sends test records (`op_conformance`) to the addresses your harness starts, and to nothing else. The `sso-login` suite listens on this machine as an identity provider and, through the deployment you point it at, creates people at example.test addresses in the account your `configure` connects (nothing is sent to those addresses); the issuer is an address on this machine, so the deployment must be a development build or a test install whose provider guard allows one, never production. The `agent-identity` suite only reads: it makes lookups and fetches an agent's files, and creates nothing; `--probe-rate-limit` sends up to 200 lookups from one source to meet the server's limit, so use it on a test instance and last. The `web-bot-auth` suite fetches a directory you point it at and signs nothing with a key of yours; its test key is the public key of RFC 9421.

The `decision`, `events` and `webhooks` suites send signed requests to the URL you give them. Use a test instance and a test secret, never a production secret: the kit proves it can make your server answer, and a secret you give it is a secret it could use. The requests are synthetic (`op_conformance`) and nothing is done on anyone's behalf. The events suite sends events for that operator; point it at a store you can discard.

The `rest-api` suite sends a few requests without a credential and, with a key, asks the server for one gated change (and, with `--approve-command`, completes it): by default it registers two test agents and asks to unblock them, or, when the server gates registering an agent, asks to register one. It removes the agents it made when it ends. Use a test instance and a key of a test account, never a production key.
The suites that run against a server (`agent-enrollment`, `fleet-enrollment`, `passport-online`, `workload-exchange`, `oauth`, and `agent-jwt` with `--url`) register agents, open Missions, issue and revoke Passports and register OAuth clients on the instance you give them, and never remove them. Use an instance you can discard, and the credential of a test operator. Registering an agent and enrolling a key are acts a credential cannot approve for itself, so the server answers `403 GOVERNANCE_APPROVAL_REQUIRED` with an approval id; `--approve-command` is the program the kit runs, with that id as its last argument, to have a person's decision made (on an engine install, `stack-engine approvals approve`); it must exit `0` once the approval is decided. The server limits enrollment, issuing and verifying to a few calls a minute, and the kit waits for each window it is told about, so a full run takes several minutes. `oauth` makes more registrations than the hourly limit allows on its last check, and `workload-exchange` goes over the per-second limit on its last check, on purpose; `--no-rate-limit-checks` leaves both out, for a second run against the same instance.

## Program interfaces

**Agent JWT minter.** A module whose default export (or `mint`) is `({ agentId, privateJwk }) => token`: it signs a new agent JWT with the private key (an Ed25519 JWK with `d`) for the agent. **Agent JWT verifier function.** A module whose default export (or `verify`) is `(token, { agentId, publicJwk }) => claims`: it resolves for a token it accepts and rejects for any other, keeps its own memory of the jti of every token it accepted, and rejects a repeat with an error whose `code` is `AGENT_JWT_REPLAYED` (a SHOULD). `publicJwk` is `null` for an agent that has no key.

**Agent claim signer and verifier.** A signer module exports `sign({ envelope, privateJwk, agentId, alg? })`, which returns the base64url COSE_Sign1 message and throws when given an `alg` it does not implement. A verifier module exports `verify(message, { jwks, agentId })`, which returns `{ valid: boolean }` (throwing counts as not valid).

**Workload token acceptor.** A module that exports `accept({ kind, token, config, jwks })` for `kind` `spiffe` or `wimse`: `config` is `{ trust_domain, audience }` or `{ issuer_uri, audience }` (`audience` null accepts any) and `jwks` the issuer's key set. It resolves with `{ subject, issuer, audience?, not_after }` or throws, with the reason of the specification as `error.code` (checked as a SHOULD).

**Client metadata check.** A module that exports `validate(clientId, document)`, which returns `{ client_id, client_name, redirect_uris, grant_types }` or throws, and optionally `isMetadataClientId(clientId)`.

**Passport verifier program.** The kit starts it once per token, writes one JSON object to stdin, `{ "token", "jwks", "issuer", "audience" }`, and reads one from stdout: `{ "valid": true, "claims": { ... } }` or `{ "valid": false }`. The exit code is ignored. The `claims` object is the token's payload (it needs `jti` and `stk`).

**Record verifier program.** The kit writes a pack to a temporary file and runs `<program> [args...] <pack.json> [--strict] [--ignore-unknown] [--air-gap] --json`. It must print the `VerifyResult` of the specification as JSON on stdout. The reference command is `stack-verify`.

**Webhook verifier function.** A module whose default export (or `verify`) is `({ headers, body, secrets, now }) => boolean | { ok }`: `headers` has lower-case names, `body` is the raw string, `secrets` the secrets the receiver holds, and `now` the clock in unix seconds it must use in place of its own. Return `true` for a message to accept, `false` to refuse. A verifier with no memory of ids fails the one SHOULD about repeats (`W20`), which a URL receiver is not asked about.

**Authority receiver.** A module whose default export (or `createReceiver`) takes a configuration (the receiver's identifier and keys, the STACK origin and the STACK keys it trusts) and returns `authorization`, `signPresentationRequest`, `signReceipt`, `openPresentation` and `verificationDocument` ([section 15.1 of the specification](../authority-receiver/SPEC.md)). A program reads `{ op, config, input }` as JSON on stdin and writes `{ "result": ... }` or `{ "error": ... }`. A deployed delivery endpoint is configured as section 15.2 says. A receiver with no memory between calls fails the one SHOULD about a repeated presentation (`A48`).

**Wallet client.** A module whose default export (or `build`) takes `{ appId, walletId, from, to, valueAtomic, validAfter, validBefore, nonce, sign }` and returns `{ typed_data, agent_signature }`; `sign(string)` is the kit's and returns the base64 DER signature of the kit's test key. **Wallet relay.** A test wallet file `{ address, walletId, appId, perPaymentCapAtomic, dailyCapAtomic?, agentKeyPkcs8 }`, where `agentKeyPkcs8` is the base64 PKCS#8 DER of the test agent key the wallet was registered with; with a `provider.sentCount` handle (the library) the kit also checks that no refused payment reached the key service. The relay must pass requests on only to a double or a test network.

**x402 buyer.** A module whose default export (or `pay`) takes `{ paymentRequired, paymentRequiredHeader, payer, sign, now }` and returns the value of the `PAYMENT-SIGNATURE` header; `sign({ domain, types, primaryType, message })` is the kit's and returns a `0x` signature. A site under test must have no facilitator that settles for real.
**Credentials files client.** A module that exports any of `write({ home, dir, credentials })` (write this sign-in the way your client does, treating `home` as the home directory), `writeAgentKey({ home, dir, agentId })` (generate and store the key of that agent) and `read({ home, dir })` (return the sign-in your client would use from the files in `dir`, or null). The kit gives `home` and `dir` a fresh temporary directory for each check, and judges what is left there. A check whose function is missing is skipped.

**REST API probes.** A JSON file (or the `probes` option of `runRestApiSuite`) of requests that make your server answer what the suite cannot cause on its own, each `{ "method", "path", "body"?, "headers"? }` sent with your test key:

```json
{
  "payment": { "method": "POST", "path": "/v1/team/members", "body": { "email": "a@example.test", "role": "admin" }, "code": "LICENCE_REQUIRED" },
  "controls": [ { "code": "CONTROL_DENIED", "method": "POST", "path": "/v1/your/route", "body": {} } ],
  "costCap": { "mode": "own_key", "method": "POST", "path": "/v1/llm/openai/images", "headers": { "x-passport-token": "..." }, "body": { "prompt": "a cat" } },
  "perJob": { "unbounded": { "method": "PUT", "path": "/v1/your/policy", "body": {} }, "policy": { "method": "PUT", "path": "/v1/your/policy", "body": {} }, "unpinned": { "method": "POST", "path": "/v1/your/send", "body": {} }, "stranger": { "method": "POST", "path": "/v1/your/send", "body": {} }, "pinned": { "method": "POST", "path": "/v1/your/send", "body": {} }, "recipients": ["stranger@example.test"] }
}
```

`payment` is a request your server answers with `402`; `controls` has one request for each refusal of a control your deployment can make (`CONTROL_DENIED`, `CONTROL_LIMIT_EXCEEDED`, `CONTROL_SOCKET_UNAVAILABLE`, `CONTROL_UNAVAILABLE`); `costCap` is a model call your server admits, without the cap header (the suite adds it), and whether it runs on the customer's own key (`own_key`: the cap is refused as unavailable; `own_key_ignored`: the cap is ignored and the call goes on) or on a key of the deployment's own (`deployment_key`: refused when the worst case is above one cent, or held at the cap). `perJob` makes the suite judge section 7.4 of the REST API specification (recipients set per job): `unbounded` writes a policy whose send rule names no recipients and is refused `UNBOUNDED_SEND_RULE`, `policy` writes the same rule with `recipients` set to `per_mission` and is accepted, `unpinned` is a send inside a Mission that pins no one (refused `CONTROL_DENIED` with `rule.code` `recipients_not_pinned`), `stranger` is a send inside a Mission to someone it did not pin (`recipient_not_allowed`), `pinned` is a send to the recipient the Mission pinned (not refused for its recipients), and `recipients` lists values a refusal must not repeat. The suite asks for one gated change. By default it registers two test agents (`conformance-asked-<nonce>` and `conformance-other-<nonce>`) and asks to unblock each, which a server gates whether or not it gates registration; when registering an agent is itself answered with a request for a person's approval, it asks for that instead. The two requests differ in what they change, because the suite checks that an approval for one is refused for the other and that each approval works once. The agents it made are removed (`DELETE /v1/agents/{id}`) when the suite ends. A server that gates something else names it in the same file, `"stepUp": { "asked": { "method": "POST", "path": "/v1/your/route", "body": {} }, "other": { "method": "POST", "path": "/v1/your/other-route", "body": {} } }`; from code, the option `stepUp(variant, nonce)` does the same, and the suite then makes and removes nothing. The suite also takes `protectedPath` (default `/v1/operators/me`) and `jsonPath` (default `/v1/passports/verify`).


**Network implementation.** A module whose default export (or named exports) is `{ verify, signer? }`. `verify(kind, token, { jwks, now, passport?, heldRevision? })` resolves when it accepts the token and rejects when it does not: `kind` is `countersignature`, `revocation_list`, `verified` or `detection_rules`, `now` is the clock in unix seconds it must use, `passport` is the passport a countersignature covers, and `heldRevision` the highest rule set revision the caller already runs. The optional `revoked(listToken, { install, keyId, passportDigest, agent }, { jwks, now })` verifies a signed revocation list and answers whether it covers a countersigned passport with those facts, matching on the subject AND the install (it must never answer true for an entry of another install or one with none). The optional `signer` is `{ keyProof({ installId, nonce, privateKeyPem, now }), proof({ installId, claims, privateKeyPem, now }) }`, each returning a compact JWS. A program is started once per call and reads one JSON object on stdin, `{ "op": "verify", "kind", "token", "jwks", "now", "passport"?, "held_revision"? }`, writing `{ "valid": boolean }`; `{ "op": "revoked", "token", "held": { "install", "key_id", "passport_digest", "agent" }, "jwks", "now" }`, writing `{ "revoked": boolean }`; for signing `{ "op": "key_proof" | "proof", "install_id", "nonce" | "claims", "private_key_pem", "now" }`, writing `{ "token": "<compact JWS>" }`. Without a signer the signer checks are skipped, never passed.

**Network service.** `network-service` signs an install's requests with the private key you give it (a PKCS#8 PEM; the service must already hold the public half under that install id), so use a test install of a test instance: the flow countersigns passports and publishes the revocation of an agent with a random name. With no install it makes only the public calls, and the flow checks are reported as skipped.

**Provider adapter harness.** A module whose default export (or `createHarness`) returns the options of `runProviderAdapterSuite`:

```js
export default function createHarness() {
  const provider = new MyProviderDouble();          // an in-memory fake, or a sandbox account
  return {
    adapter: new MyAdapter(provider),
    createsResources: true,                         // false if opening creates nothing at the provider per piece
    context: (n) => ({ operatorId, accountId, agentId, pieceId: `apc_${n}`, request: { name: 'Scout' } }),
    provider: {
      resourceCount: () => provider.resources.size, // lets the kit check for duplicates and leaks
      arm: (kind) => provider.failNextCreate(kind), // 'retryable' | 'permanent' | 'awaiting_customer' | 'not_configured'
      failures: ['retryable', 'permanent'],         // the ones your double can produce
      disarm: () => provider.reset(),
      secrets: [provider.apiKey],                   // credential values that must never appear in details or errors
    },
  };
}
```

A check that needs a handle you did not provide is reported as **skipped**, never as passed.

## Use it as a library

```js
import { runDecisionServerSuite, formatReport } from '@getstackrun/conformance';

const report = await runDecisionServerSuite({ url, secret });
console.log(formatReport(report));
if (!report.conforms) process.exit(1);
```

`report.results` lists every check with its id, level, status and detail.

**Web Bot Auth signer.** A module whose default export returns `{ sign({ method, url, now, directoryOrigin }), publicJwk: { x } }`: `sign` returns the `Signature`, `Signature-Input` and, when it names a directory, `Signature-Agent` headers for that request, `now` is a `Date` it must sign at, `directoryOrigin` a string or `null`. **Verifier.** A module whose default export (or `verify`) is `({ method, url, headers, now, fetch }) => boolean | { ok }`: the request as the site received it, the clock in unix seconds, and a `fetch` that serves the key directories the kit publishes (a site that fetches with its own HTTP client is not judged; give it this one).

**Agent identity server.** The handles of the test agents as a JSON file given with `--agent` (or the options of `runAgentIdentitySuite`): `{ "known": { "key_id", "site", "agent_id", "showName"?, "name"? }, "closed"?: { "agent_id", "key_id"?, "site"? }, "hidden"?: { "key_id", "site", "agent_id" } }`. `known` is an agent in use, found by all three; `showName` says whether its owner shows its name, and `name` is the name then; `closed` is a closed agent and `hidden` one whose owner switched the public answer off. The issuer's keys are read from `/v1/.well-known/jwks.json` on the server unless `jwks` is given. A check that needs a handle you did not give is skipped. **Agent identity verifier.** A module whose default export (or `verify`) is `(statement, { jwks, now, issuer, expect }) => claims`: it returns the claims of a statement that is right, and throws (or returns `false` or `{ ok: false }`) for any other. `now` is a `Date` it must check at, `jwks` the key set and `expect` the lookup the statement has to answer (`{ key_id }`, `{ site }` or `{ agent_id }`). The vectors are `fixtures/agent-identity/vectors.json`.

**Security-monitoring exporter harness.** A module whose default export (or `createExporter`) takes `{ syslog: { url } | null, http: { url, token } | null, caPem, streams, canary }` and resolves with `{ emit(records), pass(), close() }`: the collectors to send to (the kit's), the certificate authority to trust for TLS and HTTPS (or none), the streams to export, and a string to put in every field of a source row that is not public, which must never arrive. `emit` makes records of the specification's model appear in the exporter's source (a database, a queue); `pass` runs one delivery pass and may reject when a collector fails it. The first `pass` is the moment the exporter starts: records emitted before it are history and must not be sent, and a record emitted after it must be sent at the next (a harness whose exporter waits for rows to settle gives it a clock that is an hour ahead). A check that needs a transport you did not list in `--transports` is skipped. **Collector harness.** A module whose default export (or `createCollector`) takes `{ token }` and resolves with `{ udp?: { host, port }, tcp?: { host, port }, tls?: { host, port, ca }, https?: { url, ca }, records(), close() }`: the addresses the collector listens on (the HTTPS one requires `Authorization: Bearer <token>`), the certificate authority a client must trust for the TLS and HTTPS ones, and `records()`, which resolves with the records it holds, as objects. A check that needs an address you did not give is skipped. **Single sign-on connection.** A module that exports `configure({ issuer, client_id, client_secret, redirect_uri, slug })`, or a program the kit runs with that object as JSON on its standard input, which connects the kit's identity provider to an account of the test deployment, enabled, under the slug, and exits `0` when it has. The account must be on a plan that has single sign-on. The kit never redeems a handoff reference.

**MCP session.** A module whose default export is `async ({ audience, pieces, profile }) => session`, with `listTools()`, `callTool(name, args)`, `onToolListChanged(handler)`, and `setPieces(pieces)` to make the account's pieces change (without it the three change checks are skipped). `audience` is `agent` or `owner`, `profile` `standard` or `directory`; `reference/mcp-listing.test.mjs` shows one over the MCP TypeScript SDK.

## What the reference implementations do

The reference implementations in this repository run these same suites in continuous integration:

- `examples/control-socket` (the example decision server and events receiver) passes `decision` and `events` with no warnings.
- `@getstackrun/sdk` (`verifyPassportOffline`) passes `passport`.
- `@getstackrun/sdk` (`verifyWebhook`, with a replay guard) and the `getstack` Python package (`verify_webhook`) pass `webhooks`, as a function.
- `@getstackrun/verify` passes `record` at level 2, as a library and as the `stack-verify` command.
- `@getstackrun/sdk` (`InstallKey` and the `verify*` functions of its network module) passes `network-verifier`, signer included, as a library and through the command interface; `reference/network-service.mjs`, an in-memory service written from the specification alone, passes `network-service`, public calls and the whole flow of an install.
- `reference/reference-adapter.mjs`, an adapter for a fake provider that keeps its resources in memory and implements the [provider interface](../provider-interface/SPEC.md), passes `provider`, as a library and through `stack-conformance provider --module`. Start an adapter of your own from it.
- `reference/rest-api-server.mjs`, a small server of the wire contract of the REST API (the envelope, the reading of a request, the step-up, a 402, the refusals of controls, the cost cap) that keeps everything in memory, passes `rest-api` with every check run. The engine passes it too, started the way the engine image is started (`apps/api/src/rest-api.conformance.postgres.test.ts`).
- `reference/web-bot-auth-reference.mjs` (a signer, a verifier and a directory, over `node:crypto` alone) passes `web-bot-auth` as all three; STACK's own signer, key service and three directories pass it in the continuous integration of STACK's hosted service. `fixtures/web-bot-auth/vectors.json` holds the published vectors and the profile's own, built by `scripts/build-web-bot-auth-vectors.mjs` (`--check` fails on a difference). The published vectors come from RFC 9421 and draft-meunier-web-bot-auth-architecture, copyright the IETF Trust and the document authors, their code components used under the BSD-3-Clause licence per the IETF Trust Legal Provisions (`NOTICE`).
- `reference/partner-reference.mjs` (the partner API over an in-memory store) passes `partner`, including a completed claim and a claim that does not clear; STACK's own routes pass it against a real database.
- `reference/a2a-reference.mjs` (the card, the signed card of an agent and the endpoint) passes `a2a`.
- `reference/mcp-listing-reference.mjs` (an MCP server over the SDK that lists by the rules of section 11) passes `mcp-listing`, and so does the MCP server of the engine.
- `reference/service-mcp-endpoint.mjs` (an MCP endpoint over the SDK, with sessions and without) passes `service-mcp`, and the suite fails endpoints that refuse `initialize`, give a session id that is not visible ASCII, answer with a redirect or do not take the credential.
- `reference/agent-identity-reference.mjs` (a server of the lookup, the signed statement and an agent's files, and a verifier, over `node:crypto` alone) passes `agent-identity` as both, and the suite fails each of sixteen servers and twelve verifiers that break one rule on purpose; STACK's own routes pass the server checks against a real database, and the verifiers of its SDKs pass the verifier checks. `fixtures/agent-identity/vectors.json` is built by `scripts/build-agent-identity-vectors.mjs` (`--check` fails on a difference).
- The fixture `fixtures/catalogue/valid.json` and a document built by the reference builder pass `catalogue`; the suite fails documents and servers with one deliberate defect each.
- `reference/authority-receiver.mjs`, a small receiver that signs and opens every message of the authority protocol, passes `authority` as a library, as a program (`reference/authority-receiver-command.mjs`) and, with a delivery endpoint around `openPresentation`, over HTTP. STACK's own protocol implementation is tested against it in both directions, and a stock JOSE library reads the test vectors.
- `reference/wallet-client.mjs` (the SDK's signing helper) passes `wallet` as a client, and `reference/wallet-relay-server.mjs`, a relay for one wallet in front of a key service that only counts what reaches it, passes it as a relay. STACK's own relay passes the relay checks with its own key service client.
- `reference/x402-client.mjs` passes `x402` as a buyer and `reference/x402-site-server.mjs`, a site with one priced path and a facilitator that accepts every well-formed authorisation, passes it as a site. STACK's own site payment gate passes the site checks, the whole exchange included.
- `reference/agent-jwt-reference.mjs` (a minter and a verifier of the agent JWT, with the single-use record of each jti) passes both halves of `agent-jwt`; the minter of `@getstackrun/sdk` passes the minter half.
- `@getstackrun/sdk` (`signClaimEnvelope`) passes the signer half of `agent-keys`, and `reference/agent-claim-reference.mjs` passes the verifier half.
- `reference/workload-token-reference.mjs` passes `workload-token`, and `reference/oauth-client-metadata-reference.mjs` passes `oauth-client-metadata`.
- `reference/identity-server-reference.mjs`, an in-memory server written from the specifications alone (agent key enrollment with tickets and rotation, fleet enrollment through a provisioner, Passport issue, online verification, revocation and delegation, the key sets and the `stack:revoked` channel, with a person's approval given by a function), passes `agent-enrollment`, `fleet-enrollment` and `passport-online` with every check run; the three suites fail each of its forty defective variants (a challenge that can be used twice, a signature nobody checks, an approval good for any key, a ticket that works again, a revoked Passport that still verifies, a delegation that escalates, and so on), which `reference/identity-reference.test.mjs` requires.
- `reference/siem-reference.mjs`, an exporter over an in-memory source and a collector that listens on UDP, TCP, TLS and HTTPS and keeps what it receives, both written from the specification with Node's own modules, pass `siem-exporter` and `siem-collector` with every check run; the suites fail each of eighteen defective exporters (a wrong priority, structured data that is not escaped, newline framing, a count in characters, an oversize datagram, history replayed, no bearer token, a certificate that is not checked, a redirect followed, a position that moves on failure, a leaked field, reversed or doubled records and so on) and each of twelve defective collectors (no deduplication, deduplication by id alone, newline splitting, no token check, the record read from the structured data, an answer before the batch is stored, a refused unknown member, a redirect and so on), which `reference/siem-reference.test.mjs` requires. The engine's own exporter (`apps/api/src/config/siem-export.ts`) passes `siem-exporter` over a real database (`apps/api/src/config/siem-export.conformance.postgres.test.ts`).
- `reference/sso-login-reference.mjs`, a relying party written from the specification with Node's own modules (the start, the callback, discovery, the key set and the ID token checks, the handoff), passes `sso-login` with every check run; the suite fails each of its twenty-eight defective variants (an ID token with `alg` none accepted, an HMAC token keyed with the public key, no nonce, issuer, audience or expiry check, a callback not bound to the browser, a state that can be used twice, the secret in the authorization request and so on), which `reference/sso-login-reference.test.mjs` requires. The engine's identity routes pass it against a real database and Redis (`apps/api/src/routes/identity-flows/sso-login.conformance.postgres.test.ts`).
- The engine, `apps/api` booted the way the engine image boots it, passes `agent-jwt` (over HTTP), `agent-enrollment`, `fleet-enrollment`, `workload-exchange`, `oauth` and `passport-online` with its revocation channel (`apps/api/src/identity-conformance.postgres.test.ts`), and the engine's validators pass `workload-token` and `oauth-client-metadata`.

The tests for the kit itself, in `reference/negative-controls.test.mjs`, run every suite against implementations that each have one deliberate defect (a decision server that does not check signatures, a Passport verifier that accepts `alg: none`, a record verifier that calls everything valid, an adapter that leaks a credential, an agent JWT verifier that forgets a token it has seen, a workload acceptor that lets the token choose its algorithm, an OAuth server that advertises a client secret) and require the suite to fail them. A kit that cannot fail a broken implementation would certify anything.

## Fixtures

`../network/test-vectors.json` holds the test vectors of the network specification: every signed object, the proofs an install signs and the cases a verifier must refuse. They are built from public test keys by `scripts/build-network-vectors.mjs` (it needs only Node; running it twice writes the same bytes; `--check` fails on a difference), from the builders in `src/network-vectors.mjs` that the `network-verifier` suite mints its own tokens with.

`fixtures/record/` holds the evidence packs for the `record` suite: one valid pack and tampered variants, with the outcome a conforming verifier must report in `expected.json`. They are built from the specification alone by `scripts/build-record-fixtures.mjs` (deterministic: running it twice writes the same bytes; `--check` fails on a difference). The keys in them are for these fixtures only.

`fixtures/authority/` holds the test vectors of the authority receiver protocol (`vectors.json`: every signed and encrypted message as exact bytes with the inputs that make it) and the STACK test key it signs presentations with (`stack-jwks.json`). They are built from the specification alone by `scripts/build-authority-vectors.mjs` (deterministic; `--check` fails on a difference).


`fixtures/identity/vectors.json` holds test vectors for implementers who cannot run the suites as a JavaScript module: agent JWTs (presented in order, with the clock fixed at `now`), claims signed with an agent's key, workload tokens with their key sets and configurations, and client metadata documents, each with the verdict (and, for a workload token, the reason) a conforming implementation gives it. `scripts/build-identity-vectors.mjs` writes it from the specifications alone, deterministically (`--check` fails on a difference); the reference implementations and the engine are judged by it in their tests.

## Licence

Apache-2.0. See `LICENSE`.
