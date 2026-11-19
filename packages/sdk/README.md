# @getstackrun/sdk

Official JavaScript / TypeScript SDK for [STACK](https://getstack.run) - the runtime control plane for AI agents.

> This package is also the target for our `@getstack/sdk` scope claim (pending). Once settled, `@getstackrun/sdk` will be deprecated with a pointer to the new name.

STACK sits between your agent and everything it touches. Short-lived, scoped passports replace long-lived API keys. Every outbound call routes through a proxy that enforces scope and parameter constraints. A hash-chained audit log records every decision. A single call kills any passport globally in under 60 seconds.

## Docs for agents

How-to guides for every STACK service and for controls are published as markdown. The list is at https://getstack.run/llms.txt, and one service's guide is at https://getstack.run/docs/account/<service>.md (for example https://getstack.run/docs/account/email.md).

## Install

```bash
npm install @getstackrun/sdk
```

Requires Node.js 18 or newer. Works in Deno, Bun, and browsers via native `fetch`.

## Quick start

Sign in once on your machine — the SDK reads credentials from `~/.stack/credentials.json` automatically:

```bash
npx -y @getstackrun/cli auth login
```

```ts
import { Stack } from '@getstackrun/sdk';

// No constructor args — reads ~/.stack/credentials.json (OAuth refresh token).
const stack = new Stack();

// 1. Register an agent (one-time)
const agent = await stack.agents.register({ name: 'support-bot' });

// 2. In your agent runtime, switch to per-agent keypair mode
const agentStack = new Stack({ agent_id: agent.id });
// First run: generates an Ed25519 keypair locally + enrolls the public
// half via /v1/agents/<id>/enroll. Persisted at ~/.stack/agents/<id>.json
// (mode 0600). Every subsequent call signs a fresh 60-second JWT.

// 3. Open a Mission and issue its short-lived passport in one call.
//    Every passport carries exactly one Mission and never outlives it.
const { mission_id, passport } = await agentStack.missions.start({
  agent_id: agent.id,
  mission: {
    intent_summary: 'Answer one customer ticket',
    intent_services: ['slack', 'github'],
    expires_in_seconds: 3600,
  },
  passport: { ttl_seconds: 900 },
});

// 4. Every outbound call routes through the proxy
await agentStack.proxy.request({
  service: 'slack',
  method: 'POST',
  url: 'https://slack.com/api/chat.postMessage',
  body: { channel: 'C0123', text: 'Ticket resolved' },
  connection: 'Work', // only when the service has several connections: a name (any case) or an scon_ id
}, { passportToken: passport.token });

// A second connection of a service needs its own name; rename one at any time.
await stack.services.connectCustom({ name: 'Acme', credential: key, allowed_hosts: ['api.acme.example'], connection_name: 'Personal' });
await stack.services.rename('scon_...', 'Work');

// 5. Complete the Mission when done. This also revokes its passport.
await agentStack.missions.complete(mission_id);
```

## Authentication

The SDK resolves a credential in this order:

1. **`~/.stack/credentials.json`** - an OAuth refresh token written by `npx @getstackrun/cli auth login`, exchanged for a short-lived access token
2. **Interactive browser login** - only in a terminal, when there is no stored sign-in

With the `agent_id` option set, every request instead carries a fresh 60-second JWT signed with that agent's local keypair.

If the SDK performs its own first-run browser login, its default OAuth scope
covers the core agent runtime rather than every SDK method. A deliberate
management flow can request an exact broader set with
`new Stack({ oauthScope: 'team:read team:write' })`. This option applies only
to a new interactive login; refresh tokens cannot widen an existing family.

See [the auth model](https://getstack.run/docs/security/stack-auth) for the full auth model and [the agent keys page](https://getstack.run/docs/security/agent-keys) for the per-agent keypair story.

## Offline passport verification

Downstream services that only need cryptographic validity (no revocation awareness) can verify a passport using the public JWKS — no network round-trip to STACK per request.

```ts
import { verifyPassportOffline } from '@getstackrun/sdk';

// Mode 1: fetch JWKS once per process
const claims = await verifyPassportOffline(token, {
  jwksUrl: 'https://api.getstack.run/v1/.well-known/jwks.json',
});

// Mode 2: fully air-gapped with a pre-fetched public key
const claims2 = await verifyPassportOffline(token, {
  publicJwk: { kty: 'OKP', crv: 'Ed25519', x: '...', kid: 'stack-passport-v1', alg: 'EdDSA', use: 'sig' },
});
```

For revocation-aware verdicts, combine with a short cache against `POST /v1/passports/verify` or subscribe to the `stack:revoked` Redis pub/sub channel.

## What the SDK wraps

`new Stack()` exposes one property per API area.

| Property | Typical use |
|---|---|
| `stack.agents` | Register (a new agent starts `logged`), set up an agent with its first grants and hosts as one approval, list, update, delete, unblock agents; dismiss an agent's open warnings; read an agent's permissions |
| `stack.passports` | Issue, verify, delegate, refresh, revoke passports; checkpoints, checkouts and review decisions |
| `stack.missions` | Start (open and issue a passport in one call), open, renew, complete, revoke Missions; activity and Operator reviews |
| `stack.authority` | Authority principals, proofs, bindings, receivers and evidence reads |
| `stack.services` | Connect OAuth / custom credentials, one-time connect links (`createConnectLink`, `getConnectLink`, `listConnectLinks`), grant agent access |
| `stack.credentials` | Retrieve decrypted credentials (agent-side) |
| `stack.proxy` | Make outbound HTTP calls; scope and constraints enforced server-side; read an operation's delivery state |
| `stack.llm` | LLM gateway: Anthropic and OpenAI call shapes, any OpenRouter model and endpoint (`openrouter.request(method, path, options)` and `openrouter.requestBytes(...)` for an answer that is a file; `openrouter.chat.completions` stays), images on your own OpenAI key (`openai.images.generate`), plus usage queries. On an agent account's STACK key, `maxCostCents` is the most a call holds (a cost above it is taken from the account's credit at once) and the call is charged what OpenRouter reports it cost |
| `stack.dropoffs` | Schema-validated, encrypted agent-to-agent data transfer |
| `stack.skills` | Publish and invoke marketplace skills; skill requests |
| `stack.intents` | Simulate, submit, approve and reject intents |
| `stack.fleets` | Fleet policies, workload enrollment and membership |
| `stack.identity` | Verification sessions, claims, providers, service requirements |
| `stack.team` | Team members, roles, and service access |
| `stack.deliveryMethods` | Email, SMS, webhook destinations |
| `stack.notifications` | Rules mapping events to destinations |
| `stack.securityEvents` | List and resolve real-time detector signals |
| `stack.detectorConfig` | Read and change detector configuration |
| `stack.piiConfig` | Read and change PII redaction configuration |
| `stack.scan` | Scan retrieved content for prompt injection |
| `stack.audit` | List audit entries, read the chain head, verify the hash chain |
| `stack.evidencePacks` | Export, read, download and list portable Signed records |
| `stack.usage` | Action usage against the plan allowance |
| `stack.governance` | Read one governance approval: `getApproval` (status, payload hash, link; a person decides it) |
| `stack.billing` | Agent-account subscriptions: platform and controls checkout, status, resume without controls |
| `stack.inboundWebhooks` | Hosted inbound webhooks scanned before they are forwarded |
| `stack.accounts` | Agent accounts: open, read, close; messages, mail (to several people, with copies and attachments, reply and forward) and texts, the agent's own Telegram bot, live calls (place one, or answer or decline one that rings on the account's number; held by the agent with `say`, `pressKeys`, `setCallVoice`, `hangUp` or the live WebSocket stream `live`, or by STACK's model with `on_behalf_of` and a `brief`; the account's call voice and voicemail greeting), paid tools, workspaces (a machine with a shell and git), browser and card checkout, wallet payments, your own mail domains |
| `stack.chatChannels` | The Telegram, text and Slack identities an owner approves small held payments from (within the limits set in the policy; off by default), and STACK's Slack app |
| `stack.website` | An agent account's website: publish a bundle (`siteFiles` builds one), add your own domain, price paths in USDC, suspend and resume, report a site |
| `stack.payments` | Getting paid: connect your own Stripe with a restricted key, payment links and checkout sessions, payments received on card and USDC |
| `stack.drive` | The agent drive: upload, list, read, update and delete files, and share one through a signed, expiring download link (every file is untrusted content) |
| `stack.messageAccess` | Whether agents read the messages of every message account of the customer or only their own, and whether they may only read; for the account and per agent (owner or admin) |
| `stack.memory` | Account memory, a graph of facts with the time each held (Graphiti's own tools): add an episode, add a fact, search entities and facts, read and delete episodes and facts; the owner turns it on or off |
| `stack.controlSocket` | Your own server decides your agents' actions and receives their record: addresses, signing secrets, checked action kinds, decisions made |
| `stack.network` | The STACK network: register self-hosted installs and their keys, stop a key or install at once, publish and follow revocations across companies, check countersigned passports and the STACK-verified statement |
| `stack.controlPolicies` | Policies for hosted controls: read, create, revise, delete, start from an agent's current access, simulate a call, read revisions |
| `stack.controlReviews` | Actions a policy held for a person: list and read (a person decides each through its approval link) |
| `stack.partner` | Partner operators only: `connect`, `connections`, `tenants`, `mintOutboundPassport` |

`stack.issuePassport(input)` issues a passport and returns a `PassportSession` that refreshes its token shortly before it expires.

## The STACK network

A self-hosted install can have STACK countersign the passports it issues, so another company trusts them without trusting the install, and can use STACK's live detection rules and classifier. An install holds no account credential: it signs each request with its own key.

```ts
import { Stack, InstallKey, InstallClient, verifyCountersignedPassport } from '@getstackrun/sdk';

// The owner, with their account credential: register the install and its key.
const install = await stack.network.installs.register('office');
const key = await InstallKey.generate();
await stack.network.installs.registerKey(install.id, key);
// Without a dashboard session this first throws GovernanceApprovalRequiredError: a person approves the key
// in a browser, then call again with { governanceApprovalId }. Keep the private key: await key.toPem().

// The install, with its own key.
const client = new InstallClient({ installId: install.id, key });
const rules = await client.rules();                       // signed rule set, checked against STACK's keys
const verdict = await client.classify(retrievedContent);  // the content leaves the install; STACK keeps none of it
const { countersignature } = await client.countersign({ passport, agent: 'support-bot' });

// A counterparty, with only STACK's public keys. No network to STACK needed.
const jwks = await stack.network.jwks();
await verifyCountersignedPassport({ countersignature, passport, jwks });
// A live answer, with revocation:
await stack.network.verify({ countersignature, passport });
```

Offline checks (`verifyCountersignedPassport`, `verifyRevocationList`, `verifyVerifiedStatement`, `verifyDetectionRules`) cannot see a revocation made after issue; use `stack.network.verify` or the signed revocation list for that. Formats: `packages/shared/src/schemas/network.ts` and the test vectors in `spec/network/test-vectors.json`, in the STACK repository.

## Control socket

Point your agents' actions at your own server: it is asked to allow or refuse each checked action, and an events address receives their whole record, signed. Changing an address, rotating a secret and anything that loosens a control is a decision a person approves first; without a dashboard session the call throws `GovernanceApprovalRequiredError`, and once the person approves at `approvalUrl` the same call goes through with `governanceApprovalId`.

```ts
// The signing secret comes back once, when it is created. Store it now. (A browser sign-in, which is
// OAuth, is never given it: `secret` is null and `secret_reveal.url` is a single-use Console link where
// the signed-in person reads it once.)
const { secret } = await stack.controlSocket.setDecisionAddress(
  { url: 'https://control.example.com/decide', timeout_ms: 1000 },
  { governanceApprovalId }, // after a person approved the first attempt
);
const check = await stack.controlSocket.verify('decision'); // passes: your server now decides
await stack.controlSocket.setCheckedTypes(['email.send', 'card.checkout']);
const { decisions } = await stack.controlSocket.decisions.list({ verdict: 'deny', limit: 20 });
```

`get`, `setDecisionAddress`, `setEventsAddress`, `clear`, `verify`, `test`, `rotateSecret`, `setMode` (`'none'` or `'hosted'`), `setOnUnavailable` (`'refuse'` or `'allow'`: what happens when your own server does not answer in time) and `setCheckedTypes` (a list, or `null` for every kind) and `decisions.list` / `decisions.get` cover the whole surface.

On your server, verify the request and sign the answer with the two helpers (Standard Webhooks, no dependency beyond `node:crypto`). Verify the raw body exactly as received:

```ts
import { verifyControlSocketRequest, signControlSocketAnswer } from '@getstackrun/sdk';

app.post('/decide', async (req, reply) => {
  const check = verifyControlSocketRequest({ headers: req.headers, body: req.rawBody, secret: process.env.STACK_CONTROL_SECRET! });
  if (!check.ok) return reply.status(401).send();
  const { request } = check;
  const verdict = request.action.type === 'card.checkout' ? 'deny' : 'allow';
  const signed = signControlSocketAnswer({
    decisionId: request.decision_id,
    requestDigest: request.request_digest,
    verdict,
    ...(verdict === 'deny' ? { reason: { code: 'card_not_allowed' } } : {}),
    secrets: [process.env.STACK_CONTROL_SECRET!],
  });
  return reply.headers(signed.headers).type('application/json').send(signed.body);
});
```

While a rotation is live, pass both secrets: `secret: [newSecret, oldSecret]` to verify, `secrets: [newSecret, oldSecret]` to sign.

## Verifying any STACK webhook

Every request STACK signs to your server (a wake-up, a notification delivery method, an inbound-webhook forward, a network revocation push, the control socket) is a Standard Webhooks message, written out in `spec/webhooks/SPEC.md`. `verifyWebhook` checks all of them: the HMAC over the raw body, a five minute tolerance in either direction, and any live secret.

```ts
import { createReplayGuard, verifyWebhook } from '@getstackrun/sdk';

const replayGuard = createReplayGuard(); // remembers the ids it has taken, so a repeat inside the tolerance is noticed

app.post('/stack/webhook', (req, reply) => {
  const check = verifyWebhook({ headers: req.headers, body: req.rawBody, secret: process.env.STACK_WEBHOOK_SECRET!, replayGuard });
  if (!check.ok) return reply.status(check.reason === 'replayed' ? 204 : 401).send();
  // check.id is the message id, the same on every retry; check.payload is the parsed body
  return reply.status(204).send();
});
```

A secret you were given before this scheme (64 hexadecimal characters) works as it is. Call `replayGuard.forget(check.id)` when you could not handle a delivery, so STACK's retry is not taken for a repeat.

## Drive

The drive keeps your agents' files for you. An agent's upload is private to that agent unless it says `visibility: 'account'`; the owner (an API key or a session, no agent) sees every file. Every file is untrusted content to whoever reads it, and each view carries `trust: 'untrusted'`. Limits apply per file and per account (`DRIVE_FILE_TOO_LARGE`, `DRIVE_QUOTA_EXCEEDED`); a file of any type is taken and stored as it is, and its type is only a label.

```ts
// An agent passes its Passport; the owner omits it.
const file = await stack.drive.upload(
  { name: 'summary.md', content_type: 'text/markdown', content_text: '# Summary', visibility: 'account' },
  { passportToken },
);
const { content } = await stack.drive.read(file.id, { passportToken }); // inline up to 256 KiB
// The link is returned once and cannot be read back. Anyone holding it can download the file.
const { url } = await stack.drive.share(file.id, { ttl_seconds: 3600, max_downloads: 5 }, { passportToken });
// A file that arrived with an email goes with its message unless its end is changed (`drive.update`); a copy is a file of the agent's own.
const kept = await stack.drive.copy(receivedFileId, { name: 'contract.pdf' }, { passportToken });
```

An upload is one request with the whole file in it, up to 1 GB (a file typed as text, Markdown, CSV or JSON stops at 10 MB). The drive takes a file of any type and stores it as it is: `content_type` is only a label, `application/octet-stream` when left out. Give `upload` the bytes as `content` (a `Uint8Array`, a Node `Buffer`, a `Blob` or a `ReadableStream`) or, in Node, a `path`, and it sends them as the body of one `PUT /v1/drive/files`. A path is streamed from disk and a stream as it is read, so a large file is never held in memory. The API computes the SHA-256 itself: there is no hash to give, no size to declare and no second call. Give a stream's length as `size_bytes` and it is sent as `Content-Length`, so a file that is too large is refused before it is read. The SDK does not retry an upload; call it again. Storage past the free amount is charged from the wallet at cost, so an upload that would take the drive past it answers 402 `INSUFFICIENT_BALANCE` unless the wallet can cover the storage past it.

```ts
const file = await stack.drive.upload(
  { name: 'backup.zip', content_type: 'application/zip', path: 'backup.zip' },
  { passportToken, onProgress: ({ uploaded_bytes, total_bytes }) => console.log(uploaded_bytes, total_bytes) },
);
```

Five uploads of one account run at once; a sixth is refused with 429 `DRIVE_TOO_MANY_UPLOADS` until one has finished. A program that cannot send a body itself, an agent that only has tools, asks for a one-time upload URL with `createUploadLink` (one metered action) and sends the bytes there with `uploadToLink(link, { path })` or `curl -T ./file '<url>'`. The URL is a secret, works once and lasts 30 minutes, and the PUT carries no credential; a used, expired or foreign URL answers 404 `DRIVE_UPLOAD_LINK_INVALID`. It is never put in an error.

If the wallet cannot pay for the storage past the free amount, the drive is read-only from that day: uploads, edits and new share links answer 409 `DRIVE_READ_ONLY`, while reading, downloading, listing and deleting still work and existing share links keep working. `list` shows it as `usage.storage_unpaid` (`since`, `delete_on`, `over_bytes`; `null` when in good standing). The owner is emailed on day 0, day 30 and day 60, and on day 90 the newest files past the free amount are deleted. Topping up the wallet to cover what is due, or deleting files until the drive is within its free amount, lifts the read-only state at once and ends the countdown.

`upload`, `createUploadLink`, `uploadToLink`, `list`, `get`, `read`, `update`, `delete`, `share`, `links` and `revokeLink` cover the whole surface. A share link allows the downloads you name (any number from one; 100 when you name none) and is refused with 409 `DRIVE_LINKS_PAUSED` while STACK has paused the account's links after a download spike. A drop-off hands files over too: `dropoffs.deposit(id, agentId, payload, { driveFiles: [file.id] })` opens them to the collector, and `dropoffs.collect` returns them as `drive_files`.

## Email

```ts
// To several people, with copies and attachments. A drive file goes by its id; a small file goes inline as base64.
await stack.accounts.sendEmail(accountId, {
  to: ['ana@example.com', 'ben@example.com'],
  cc: ['carol@example.com'],
  bcc: ['audit@example.com'],
  subject: 'Quarterly report',
  body: 'The report is attached.',
  attachments: [
    { file_id: driveFileId },
    { filename: 'notes.txt', content_type: 'text/plain', content_base64: 'aGVsbG8=' },
  ],
}, { passportToken });

// Answer or forward an email the account received, by its message id.
await stack.accounts.replyEmail(accountId, messageId, { body: 'Thanks, done.', reply_all: true }, { passportToken });
await stack.accounts.forwardEmail(accountId, messageId, { to: 'dan@example.com', body: 'For your records.' }, { passportToken });
```

The mail provider takes one To address, so the first `to` address is the message's To and any further ones are delivered as Cc. The answer (`AccountEmailSent`) lists `to`, `cc`, `bcc` and the `attachments` as sent. Attachments come to at most 25 MB in all, and inline files to at most 10 MB; a larger file is attached from the drive by `file_id` (`EMAIL_ATTACHMENTS_TOO_LARGE`, `EmailAttachmentsTooLargeError`). `replyEmail` answers in the received email's thread, quoting it unless `include_quote` is `false`, to the person who wrote it (every address its From names, when it names several), and with `reply_all` to everyone else it was sent to as well. With only `bcc` given, the To is the account's own address, and the account's own address may be a recipient like any other. `forwardEmail` sends a new email, in no thread, with the original's text unless `include_quote` is `false` and, unless `include_attachments` is `false`, the attachments that were kept. A message that is not a received email, was withheld, or names no sender throws `EmailMessageNotAnswerableError`. An address left out (an entry of the original that is not one plain address) is named in the answer's `dropped`. A subject is one line. An inline file may be of any type, as in the drive, an empty one included. A received email lists its attachments in `content.attachments`: each has a `file_id` (a drive file, private to the receiving agent and untrusted) or a `not_saved` reason; the email is kept either way. A received file is deleted with its message: `drive.copy` keeps it.

### Search messages and message access

`stack.accounts.messages.search({ agentId, channel, sender, recipient, threadId, after, before, q, limit, cursor })` searches every message the caller may read, across the customer's message accounts and channels, newest first. Each hit is a summary without the body (`stack.accounts.messages.get` reads one). The window is the last 30 days unless `after` and `before` (ISO 8601 with an offset) say otherwise; a search on `q`, `sender`, `recipient` or `threadId` needs a window of at most 90 days. `stack.accounts.messages.readAttachment(accountId, messageId, fileId)` reads a file a message carries, with the same answer as `drive.read`; the content is untrusted. A memory fact learned from messages lists their ids in `source_message_ids`.

`stack.messageAccess` sets what agents may do with those messages, for the account and per agent (`get(agentId?)`, `set(values, agentId?)`, `clear(agentId, keys)`). `read_teammates` (default `true`) lets an agent read the messages of every message account of the customer; `false` limits it to its own. `messages_read_only` (default `false`), when `true`, lets an agent read but not send, reply, forward, text or post from any account. An agent's own value wins over the account's. Owner or admin only; an agent is refused, and a change applies at once with no approval.

```ts
await stack.messageAccess.set({ read_teammates: false }, 'agt_one');
await stack.messageAccess.clear('agt_one', ['read_teammates']); // follows the account again
```

## Memory

Memory is what your agents know about your world, kept as a graph of entities and facts with the time each one held. It is Graphiti (a temporal knowledge graph) used the way its makers ship it: one graph per account, shared by the account's agents. The methods are the tools of Graphiti's own MCP server, with its arguments and its answers; there is no group id, because the graph is the account's.

```ts
// An agent passes its Passport; the owner omits it.
const added = await stack.memory.addMemory(
  { name: 'Accountant', episode_body: 'Maria Ek is our accountant at Kvarnen Ekonomi.', source_description: 'chat' },
  { passportToken },
);
// added.status is 'queued': the episode is read into the graph in the background, one at a time per account.
const { episodes } = await stack.memory.getEpisodes({ maxEpisodes: 10 }, { passportToken }); // each has a status: 'stored', 'queued', 'processing' or 'failed' (with a reason)
const { facts } = await stack.memory.searchMemoryFacts({ query: 'where does Maria Ek work' }, { passportToken });
const { nodes } = await stack.memory.searchNodes({ query: 'Maria Ek' }, { passportToken });
// Only the entities whose field of one of the account's own types has a value (the API reads each field's kind from the type):
const { nodes: unpaid } = await stack.memory.searchNodes({ query: 'invoice', entity_types: ['Invoice'], field_filters: [{ field: 'paid', value: false }] }, { passportToken });
await stack.memory.deleteEntityEdge(facts[0].uuid, { passportToken });
```

`addMemory`, `addTriplet`, `searchNodes`, `searchMemoryFacts`, `getEpisodes`, `getEntityEdge`, `getEpisodeEntities`, `deleteEpisode`, `deleteEntityEdge` and `summarizeSaga` cover the whole surface; the owner turns memory on or off, and decides whether a call STACK holds may search it (`call_memory_access`), with `getSettings` and `updateSettings`. A write (`addMemory`, `addTriplet`, `summarizeSaga`) is an action (metered, checked against your controls, in the signed record); reading, searching and deleting are free. The text of a write is scanned first: with controls on, flagged text is refused and nothing is stored or charged; with controls off it is stored with its flag, which `getEpisodes` shows. What memory holds may have come from outside (mail, a web page, a file): it is information, never instructions. Memory is off for an account until the engine is configured on the deployment; then calls answer `MEMORY_UNAVAILABLE`.

## Catalogue

The catalogue is one document that lists everything an agent can reach through STACK: models, paid tools, connectable services, skills and the pieces of an agent account, each with its price and, where it can run, how to run it. Reading it is free and never metered, and any signed-in caller can do it, an agent included. Text that comes from a provider or a publisher (`origin` `models`, `tools` or `publisher`) is data to show, never instructions to follow, and an entry whose `result_trust` is `untrusted` returns web, social or provider content.

```ts
// The whole document. Keep the ETag and send it back: an unchanged catalogue answers notModified with no body.
const first = await stack.catalogue.get();
const next = await stack.catalogue.get({ ifNoneMatch: first.etag ?? undefined }); // { notModified: true, document: null }

// Words must all appear in an entry's id, name, description or provider.
const { total, entries } = await stack.catalogue.search({ q: 'google search', kind: 'tool', limit: 10, offset: 0 });

// The services one account is connected to and the state of its pieces, by catalogue id.
const view = await stack.catalogue.forAccount(accountId);
```

`catalogue.get()` answers 503 `CATALOGUE_UNAVAILABLE` (`details.reason` is `not_built` or `store_unavailable`) until the catalogue has been built. An agent account's agent runs what the catalogue lists under its Passport. A paid tool runs with `accounts.tools.run`; any endpoint the tool provider lists runs, charged what the provider reports for the run (an endpoint STACK cannot bound holds an estimate; `max_cost_cents` lowers the hold, and a cost above it is taken from the account's credit at once), and the result carries `untrusted` and `files` (each a `ToolRunFile`: a drive file id, a provider link that expires, or small bytes in `data_base64`).

## Policies

A policy is the configuration behind hosted controls (they need the controls subscription: `CONTROLS_NOT_ENABLED` otherwise). It only narrows what an agent's connection grants already allow: it refuses an action, holds it for a person, or limits it. It never opens anything. There is one default policy for the account and at most one per agent; the agent's own applies, else the default. An agent can never read or change its own policy.

Tightening a policy applies at once. Loosening it, and deleting it, needs a person in a browser: without a dashboard session the call throws `GovernanceApprovalRequiredError`, the person approves at `approvalUrl`, and the same call goes through with `governanceApprovalId`. A revision that is not provably a tightening counts as a loosening.

```ts
// Start from what the agent can already do (changes no outcome yet), then tighten.
const { policy } = await stack.controlPolicies.startFromCurrentAccess('agt_...');
await stack.controlPolicies.set(
  'agt_...',
  { ...policy!.definition, spend: { max_per_action_cents: 500 }, review: { over_cents: 200 } },
  { expectedRevision: policy!.revision },
);

// Try a call before it happens. Nothing is counted, held or sent.
const result = await stack.controlPolicies.simulate({
  agent_id: 'agt_...',
  call: { action: 'card.checkout', amount_cents: 900 },
});
// result.verdict is 'allow', 'review' or 'deny'; result.refusal names the rule.

// Actions held for a person wait here; the person decides at approval_url.
const { reviews } = await stack.controlReviews.list();
```

`controlPolicies` has `list`, `get` (`'default'` or an agent id), `set` (`'default'` or an agent id, a definition, `{ expectedRevision }`: omit it to create, pass the revision you read to revise), `delete`, `startFromCurrentAccess`, `simulate` and `revisions`; `set`, `delete` and `startFromCurrentAccess` take `{ governanceApprovalId }`. `controlReviews` has `list` (`{ status: 'pending' | 'all', limit }`) and `get`. There is no call that decides a review.

### Recipients set per job

A policy send rule can say its recipients are set per job: each Mission names who it may send to. Put `recipients: 'per_mission'` on an `allow` rule that names a send intent with a recipient field, and the rule allows a send only inside a Mission that pins every recipient field with an exact value, and only to those values. A Mission without the pin is refused (`recipients_not_pinned`); a send to someone else is refused (`recipient_not_allowed`). A delegated Passport carries the same Mission, so it carries the same recipients; the per-job rules of the agent the Mission was opened for apply to it too. A send rule that names no recipients and is not set per job is refused when written (`UnboundedSendRuleError`).

The account's own email, texts and calls take the same word. A policy's `recipients.email`, `recipients.sms` and `recipients.call` are each a list or `'per_mission'`. Under `'per_mission'` a send must name the stored message it answers with `reply_to_message` (`sendEmail`, `sendSms` and `calls.place` take it), and every recipient must be whoever wrote that message. A send that names no message is refused (`recipients_not_pinned`), a send to anyone else is refused (`recipient_not_allowed`), and an id that is not one of the account's received messages is 404. `replyEmail` answers the message in its path, so it takes no such field; `forwardEmail` is not covered. Changing a list to `'per_mission'` or back is a loosening and waits for a person in a browser; setting `'per_mission'` where there was no rule is a tightening.

```ts
await stack.controlPolicies.set('agt_...', {
  name: 'Support agent',
  connections: {
    mode: 'listed',
    rules: [{
      id: 'mail-per-job',
      effect: 'allow',
      recipients: 'per_mission',
      access: { connection_id: 'scon_...', intents: [{ name: 'resend.send_email' }] },
    }],
  },
});

// Recipients: who this Mission may send to. A policy rule that leaves recipients to each Mission allows a send only to these.
const { mission_id } = await stack.missions.open({
  agent_id: 'agt_...',
  intent_summary: 'Answer one customer',
  recipients: ['ana@example.com'],
});

// Reply to a message: pins the Mission to the sender of this message, so the agent can answer that person and no one else.
await stack.missions.start({
  agent_id: 'agt_...',
  mission: { intent_summary: 'Answer the incoming message', reply_to_message: 'msg_...' },
});

// Try a call with what a Mission pinned.
await stack.controlPolicies.simulate({
  agent_id: 'agt_...',
  call: { action: 'email.send', mission_id, target: { to: 'ana@example.com' } },
});
```

`recipients` lists exact addresses, numbers or ids (an address may be in any case) and applies at every recipient field a send names. `recipient_pins` is `[{ path, op: 'eq' | 'in', value }]` with one pin per path: `path` is `'*'` (every recipient field a send names, a recipient inside the URL included: the path or one of its segments) or a request field such as `body.to`, `derived.email.recipients` or `url.pathname`; up to 64 pins and 1,000 recipients a list. `reply_to_message` is the id of a message the agent's account received, or of an incoming call it answered or declined (a readable email, text, voicemail or call, else 404 `NOT_FOUND`); it combines with `recipients` into one list. The owner adds to a running Mission's pins with `missions.addRecipients(missionId, { recipients, recipient_pins, reply_to_message })`, and `missions.get` returns them as `recipient_pins` (an array, or null).

A refused action reaches the agent as `ControlDeniedError`. Its `rule` says which rule of the policy refused (`section`, `rule`, `code`, never a value from the call), and an action held for a person carries `retry.ref`: once the person approves, send the same action again with the header `X-Control-Ref: <ref>`. A spend limit reached while paying throws `ControlLimitExceededError`, and a policy that allows a send without naming who receives it throws `UnboundedSendRuleError`.

## Error handling

Every non-2xx API response is thrown as a `StackError` with the HTTP `status`, the API's stable machine `code` (`HTTP_<status>` when the response carries none), a `message` and optional `details`. `NOT_AUTHENTICATED` (401) means no credential could be resolved. Branch on `err.status` and `err.code`:

```ts
import { StackError, MissionNotLiveError } from '@getstackrun/sdk';

try {
  await stack.passports.verify(token);
} catch (err) {
  if (err instanceof StackError && err.code === 'PASSPORT_REVOKED') {
    // issue a fresh passport
  } else {
    throw err;
  }
}
```

`@getstackrun/sdk` exports these error classes:

| Class | `code` | Notes |
|---|---|---|
| `StackError` | the API's | Base class; fields `code`, `status`, `details` |
| `MissionNotLiveError` | `MISSION_NOT_LIVE` | Thrown by `PassportSession.getToken()` when a refresh is refused because the passport's Mission is completed, revoked, expired or missing. Carries `missionId`, `state` and the original `refusal`. Retrying cannot succeed: open a new Mission and issue a new passport. |
| `NotFoundError` | `NOT_FOUND` | Status 404 subclass. The HTTP client does not throw it; API 404s arrive as `StackError` with `status === 404`. |
| `ForbiddenError` | `FORBIDDEN` | Status 403 subclass. Not thrown by the HTTP client; check `status === 403`. |
| `ValidationError` | `VALIDATION_ERROR` | Status 400 subclass. Not thrown by the HTTP client; check `status === 400`. |
| `GovernanceApprovalRequiredError` | `GOVERNANCE_APPROVAL_REQUIRED` | Thrown by the HTTP client. Carries `approvalId` and `approvalUrl`: a human approves at the link, then retry the same call with `governanceApprovalId`. |
| `GovernanceApprovalStateError` | `GOVERNANCE_APPROVAL_PENDING`, `_REJECTED`, `_EXPIRED` | Thrown by the HTTP client when a retry names an approval it cannot use. Carries `approvalId` and `approvalStatus` (`pending`, `rejected`, `expired`): wait while it is pending; otherwise make the call again without the approval to ask for a new one. |
| `AccountPieceNotReadyError` | `ACCOUNT_PIECE_NOT_READY` | Thrown by the HTTP client. Carries `accountId`, `piece` and `state`; read the account to see when the piece is ready. |
| `AgentBudgetExceededError` | `AGENT_BUDGET_EXCEEDED` | Thrown by the HTTP client. Carries `accountId` and `remainingCents`. |
| `ProviderCapacityUnavailableError` | `PROVIDER_CAPACITY_UNAVAILABLE` | Thrown by the HTTP client. A provider declined STACK's own account, or STACK paused its own spend at Twilio; nothing was charged. Carries `provider`; retry in a few minutes. |
| `BrowserTimeUsedUpError` | `BROWSER_TIME_USED_UP` | Thrown by the HTTP client. This month's browser time is spent; nothing was charged. Carries `provider`; browsers are available again when the month turns, so do not retry before. |
| `BrowserSessionLengthRefusedError` | `BROWSER_SESSION_LENGTH_REFUSED` | Thrown by the HTTP client. The browser plan does not allow a session this long; nothing was charged and retrying does not help. Carries `provider`. |
| `AccountCallFailedError` | `ACCOUNT_CALL_FAILED` | Thrown by the HTTP client. Carries `reason` and `retryable`: when `retryable`, the call may have been placed, so read the account's calls before retrying. |
| `DestinationNotAvailableError` | `DESTINATION_NOT_AVAILABLE` | Thrown by the HTTP client (422). Texts and calls to this number are not available: Twilio has no price for the destination (`reason` `no_price`) or does not allow it from the account's number (`reason` `refused_by_twilio`: its geographic permissions or high-risk number blocking). Nothing was charged. |
| `ToolPriceRefusedError` | `TOOL_PRICE_REFUSED` | Thrown by the HTTP client. A paid tool run refused before it is held (`max_results` out of range, an input too deep); nothing was held. Carries `reason`. |
| `ToolsUnavailableError` | `TOOLS_UNAVAILABLE` | Thrown by the HTTP client. Paid tools are unavailable on STACK's side; nothing was charged. Carries `reason`. |
| `ToolRunRejectedError` | `TOOL_RUN_REJECTED` | Thrown by the HTTP client. The tool provider refused the input; inspect the endpoint first. Carries `providerStatus`. |
| `BudgetNeedsControlsError` | `BUDGET_NEEDS_CONTROLS` | Thrown by the HTTP client. A per-agent monthly budget needs controls; open without one (prepaid credit is the limit) or turn controls on. |
| `PlatformSubscriptionRequiredError` | `PLATFORM_SUBSCRIPTION_REQUIRED` | Thrown by the HTTP client. Every agent call, an agent account's or not, needs the platform subscription trialing or active (an account that does not need one never does). Carries `subscriptionStatus`; the message says how to start the plan. |
| `RecipientOptedOutError` | `RECIPIENT_OPTED_OUT` | Thrown by the HTTP client. The number is on the do-not-contact list (it texted STOP), so texts and calls to it are refused. Carries `accountId`. The owner, an admin or the account's agent reads the list with `stack.accounts.optOuts.list()`; the owner or an admin takes a number off with `remove(id)`. |
| `SharedMailDailyLimitError` | `SHARED_MAIL_DAILY_LIMIT` | Thrown by the HTTP client. The day's recipients on the shared agent domain are used up (every To, Cc and Bcc address counts; 20 a day in a customer's first 14 days, then 100); it resets at midnight UTC. Carries `limit`. |
| `EmailAttachmentsTooLargeError` | `EMAIL_ATTACHMENTS_TOO_LARGE` | Thrown by the HTTP client. The attached files come to more than the mail provider takes in one email (25 MB); nothing was sent. Carries `totalBytes` and `limitBytes`. |
| `EmailMessageNotAnswerableError` | `EMAIL_MESSAGE_NOT_ANSWERABLE` | Thrown by the HTTP client on a reply or forward. The message is not a received email, was withheld, or names no sender; nothing was sent. Carries `reason` (`not_email`, `withheld`, `not_received` or `no_sender`). |
| `UnboundedSendRuleError` | `UNBOUNDED_SEND_RULE` | Thrown by the HTTP client. A policy allows a send without naming who receives it. Carries `rules`, one entry per offending rule with its `unboundPaths`; bind those fields, set the rule's recipients to `"per_mission"` so each Mission names them, or set the rule to review or deny. |
| `ControlDeniedError` | `CONTROL_DENIED` | Thrown by the HTTP client. Your controls refused the action; nothing was charged. Carries `decisionId`, `reasonCode` (`recipients_not_pinned` when the Mission does not name who it may send to, `recipient_not_allowed` for someone it did not name), `rule` (which policy rule refused: `policyId`, `policyRevision`, `section`, `rule`, `code`, `detail`; null when your own server refused) and `retry` (`ref`, `afterSeconds`) for an action held for a person. |
| `ControlLimitExceededError` | `CONTROL_LIMIT_EXCEEDED` | Thrown by the HTTP client. A limit of your policy was reached while the action was being paid for; nothing was reserved or charged. Carries `limit` (`window`, `unit`), `remaining` and `maxPerActionCents`. |
| `ControlsNotEnabledError` | `CONTROLS_NOT_ENABLED` | Thrown by the HTTP client. Policies need hosted controls, which are not on for this account. |
| `WebsitePublishRejectedError` | `WEBSITE_PUBLISH_REJECTED` | Thrown by the HTTP client. The publish scan found something STACK does not host, so nothing went live. Carries `findings` (`code`, `path`); a `scanner_unavailable` finding means retry later. |
| `WebsiteLimitExceededError` | `WEBSITE_LIMIT_EXCEEDED` | Thrown by the HTTP client. Carries `limit` and `max`. |
| `WebsiteSuspendedError` | `WEBSITE_SUSPENDED` | Thrown by the HTTP client. The site is suspended or taken down; carries `state` and `by`. |
| `WebsiteHostnameUnavailableError` | `WEBSITE_HOSTNAME_UNAVAILABLE` | Thrown by the HTTP client. The address is taken, is not a name STACK can serve, or is not proven yet; carries `reason`. |
| `ConnectionAmbiguousError` | `CONNECTION_AMBIGUOUS` | Thrown by the HTTP client, and by `serviceMcpUrlOf` when a service's connections have different MCP addresses. The service has several connections and the call named none; `connections` lists `{ id, name }`, repeat the call with `connection` set to one.
| `PaymentConnectionRequiredError` | `PAYMENT_CONNECTION_REQUIRED` | Thrown by the HTTP client. The account has no active Stripe connection; the customer connects their own Stripe first (`payments.startStripe`). |
| `StripeRequestFailedError` | `STRIPE_REQUEST_FAILED` | Thrown by the HTTP client. Stripe refused or failed a call made with the customer's key; nothing was created. Carries `kind` (`permission`, `rejected`, `unavailable`) and `providerStatus`. |

There is no revoked-passport or insufficient-credits class. `stack.passports.verify` throws a `StackError` with `code: 'PASSPORT_REVOKED'` (401) for a revoked passport (and `code: 'PASSPORT_INVALID'`, 401, for a token that is not a passport of this deployment), and `verifyPassportOffline` throws a plain `Error` when a token fails its checks.

Full catalog: [docs/reference/errors](https://getstack.run/docs/reference/errors).

## Documentation

- Getting started: https://getstack.run/docs/getting-started
- Concepts: https://getstack.run/docs/concepts/passports
- API reference: https://getstack.run/docs/api/passports
- MCP tools (alternative to the SDK): https://getstack.run/docs/mcp-tools

## License

MIT
