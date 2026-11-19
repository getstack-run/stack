# STACK Credentials Files

**Specification:** STACK Credentials Files
**Version:** 1.0.0
**Status:** Stable
**Licence:** Apache-2.0

The command line and the SDKs keep two kinds of file on the machine they run on, under `.stack/` in the person's home directory: the operator's **sign-in** (`credentials.json`), which every client reads to get an access token without asking the person again, and an **agent key** for each agent that runs there (`agents/<agent_id>.json`), which the agent signs its requests with. They are written by one program and read by another (the command line signs in, the TypeScript and Python SDKs use the sign-in, an agent enrolled by one is run by another), so their shape and the rules for touching them are the contract between the clients. This document defines both files, the lock that keeps two processes from rotating a sign-in at once, and what a client does with each.

Contents: 1 Conventions, 2 Where the files are, 3 The operator sign-in, 4 Using and renewing the sign-in, 5 The lock, 6 The agent key, 7 Using the key, 8 Which credential a client uses, 9 Security considerations, 10 Conformance, 11 Machine-readable schemas.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. A **client** is any program that reads or writes these files: the STACK command line, an SDK, or a tool of your own. A **writer** creates or changes a file; a **reader** uses one. A client conforms if it satisfies every MUST that is addressed to a writer when it writes and to a reader when it reads. Times are unix time in whole seconds.

## 2. Where the files are

Everything is under `.stack/` in the home directory of the person running the client (`os.homedir()` in Node, `~` in Python; on Windows the user profile). There is no other location and no setting that moves it.

| Path | What it is |
|---|---|
| `.stack/credentials.json` | The operator's sign-in (section 3). |
| `.stack/credentials.lock` | The lock of section 5. Present only while a client renews the sign-in. |
| `.stack/agents/<agent_id>.json` | An agent's key (section 6). One file per agent; the name is the file's `agent_id` and nothing else. |

A writer MUST create `.stack/` and `.stack/agents/` if they are missing. A client MUST NOT write anything else of its own into these directories that a reader could mistake for one of these files.

Both files are JSON: one object, UTF-8, written with any whitespace. A reader MUST ignore fields it does not know, and a writer that changes a file MUST keep the fields it does not know (a client of a later version may have added them).

## 3. The operator sign-in

`.stack/credentials.json` is [`schemas/StoredOperatorCredentials.json`](schemas/StoredOperatorCredentials.json):

| Field | Type | Meaning |
|---|---|---|
| `client_id` | string, not empty | The OAuth client this install registered (dynamic client registration, RFC 7591): one client id for each install of a client, so a refresh token's family and its revocation belong to one machine. |
| `refresh_token` | string, not empty | The current refresh token. It is a bearer secret: whoever reads it can sign in as the operator until it is revoked or expires. |
| `issued_at` | integer | When `refresh_token` was stored. |
| `refresh_expires_at` | integer | When the sign-in is treated as over: 30 days after `issued_at`, renewed with every exchange. After it a client does not use the file and the person signs in again. |
| `operator_email` | string, optional | The signed-in operator's email, for display. Absent when it could not be read. It is never a credential. |
| `scope` | string | The space-separated OAuth scopes the sign-in was granted. A refresh-token family can never be widened: more scope is a new sign-in. |

A reader MUST NOT use a file that is not a JSON object with a non-empty string `client_id` and a non-empty string `refresh_token`: it is no sign-in, and the client goes on to the next source of credentials (section 8). A reader MUST also treat a file it cannot read or parse as no sign-in, and MUST NOT delete it for that.

## 4. Using and renewing the sign-in

A client turns the sign-in into an access token with the OAuth refresh grant:

```
POST <api base url>/oauth/token
content-type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh_token>&client_id=<client_id>
```

A `200` answer is `{ "access_token", "refresh_token", "expires_in", ... }`. The access token lives for `expires_in` seconds (about five minutes): a client keeps it in memory and asks again about 30 seconds before it ends. It MUST NOT write the access token to disk.

**Every exchange rotates the refresh token.** The server accepts a refresh token once; the answer carries the next one and the old one is dead. So a client that has received a new `refresh_token` MUST write it into `credentials.json` (with a new `issued_at` and `refresh_expires_at`, and every other field as it was) before it makes another exchange, and MUST NOT use the old one again. A server that sees a refresh token used a second time treats the family as stolen and revokes all of it, which signs out every client on the machine: this is why renewing is done under the lock of section 5, and why a client re-reads the file after taking the lock and before it posts.

A refusal of the exchange (any status other than `200`) means the sign-in is over. The client reports it, does not retry the same token, and does not delete the file.

**Signing out** is `POST <api base url>/oauth/revoke` with `token=<refresh_token>&client_id=<client_id>` (a form, best effort) and then deleting the file. A network failure does not stop the file being deleted.

## 5. The lock

Two processes that renew at the same moment would both post the same refresh token. The clients take a lock first.

- The lock is the file `.stack/credentials.lock`, created with an exclusive create (`O_CREAT | O_EXCL`), containing the holder's process id in decimal. A client that cannot create it because it exists waits 50 milliseconds and tries again, for up to 5 seconds.
- A lock file whose modification time is more than 30 seconds old is stale (its holder died): any client may delete it and try again.
- The holder deletes the file when it is done, whether the renewal succeeded or not.
- After taking the lock a client MUST read `credentials.json` again. A process that held it before may have rotated the token while this one waited.
- A client that cannot create the lock for any reason other than that it exists (permission, a full disk), or that waited out the 5 seconds, MAY go on without it. That is the risk the lock removes; it is not a reason to stop.

A client that renews MUST use this lock. A client that does not renew (it only reads the file to learn who is signed in) needs none.

## 6. The agent key

`.stack/agents/<agent_id>.json` is [`schemas/StoredAgentKey.json`](schemas/StoredAgentKey.json):

| Field | Type | Meaning |
|---|---|---|
| `agent_id` | string | The agent the key belongs to: `agt_` and the id the API gave it. While an enrolment is not finished the key is kept under a temporary id, `fleet_` and 64 hexadecimal characters; once the API names the agent the key is written again under its own id, and the file of the temporary id MAY be deleted. It MUST equal the file's name without `.json`. |
| `publicKey` | object | An Ed25519 public key as a JSON Web Key (RFC 8037): `kty` `OKP`, `crv` `Ed25519`, `x` the base64url (no padding) of the 32 bytes. |
| `privateKey` | object | The same key with `d`, the base64url of the 32 secret bytes. The public part (`kty`, `crv`, `x`) MUST be the same as `publicKey` and `x` MUST be the public key of `d`. |
| `enrolled_at` | integer | When the key was enrolled (or generated, for an enrolment that is not finished). Whole seconds, so that every client reads every file. |

The key is made on the machine (the API never sees `d`): the client generates the pair, asks the API for a challenge (`POST /v1/agents/{id}/enrollment-challenge`), signs it with the new key (`Ed25519` over the challenge text, base64url) and enrols the public key (`POST /v1/agents/{id}/enroll`). It writes the file once the API has accepted the key. A key that was never enrolled is useless, and a key that was enrolled and lost cannot be recovered: the agent's key is rotated by an operator.

A reader SHOULD NOT use a file whose `agent_id` is not its name, or whose `privateKey` does not match its `publicKey`: what it signs would be refused.

## 7. Using the key

An agent authenticates a request by presenting a token signed with its key as the bearer credential. A client mints one for each request:

<!-- spec:generated:credentials-agent-jwt -->

| Constant | Value |
|---|---|
| Issuer (`iss`) | `stack-sdk` |
| Audience (`aud`) | `stack:agent` |
| Lifetime the clients mint | 60 s (1 min) |
| Longest lifetime a server accepts | 120 s (2 min) |

<!-- /spec:generated -->

| Part | Value |
|---|---|
| Header | `alg` is `EdDSA`. |
| `iss` | The issuer above. |
| `sub` | The `agent_id`. |
| `aud` | The audience above. |
| `iat`, `nbf` | The time it was signed. |
| `exp` | `iat` plus the lifetime the clients mint. A server refuses a token that lives longer than its limit, even if it is signed. |
| `jti` | A random value unique to this token (`aj_` and 128 bits from a cryptographically secure generator, base64url). A server accepts a `jti` once: presenting a token again, a retry included, is refused `AGENT_JWT_REPLAYED`, so a client signs a new token for every request. |

A client MUST NOT send a key, a token it will use again, or the contents of either file anywhere but to the API it signed in to, and MUST NOT log them.

## 8. Which credential a client uses

An SDK or the command line that was not given a credential looks for one in this order and uses the first that it finds:

1. A credential the caller gave it (an API key, or an agent id to run as that agent).
2. The environment variable `STACK_API_KEY`.
3. The sign-in of section 3, renewed as section 4 says.
4. For an SDK run at an interactive terminal (a terminal, not a CI job): a browser sign-in that creates the file of section 3.

When an agent id is given, requests are signed with the key of section 6 (7), and the credential found above is used only to enrol an agent that has no key yet. The base URL is `STACK_API_URL`, or the hosted default.

## 9. Security considerations

- **Mode.** The files hold a bearer secret and a private key. A writer MUST create each of them, and the lock, readable and writable by their owner only (mode `0600` on a system that has modes) and MUST NOT create one with a looser mode and tighten it afterwards: a file made with the default mode is readable by others until the change. A writer that rewrites an existing file MUST leave it `0600`. On Windows the user profile's own permissions apply.
- **Atomic writes.** A writer SHOULD write a new agent key to a temporary file in the same directory (created `0600`, never overwriting) and rename it, so that a reader never sees half a key. The sign-in is rewritten in place under the lock.
- **One file, one machine.** The sign-in and the keys are per machine. A client MUST NOT copy them elsewhere, put them in a repository, or send them to anyone. An install image, a container layer or a backup that holds them holds the credentials.
- **Revocation.** Signing out revokes the refresh token at the server. An agent's key is revoked by the operator at the API; deleting the file only removes the local copy.
- **Rotation is the defence against theft.** A stolen refresh token is used once at most before the legitimate client's next exchange shows the reuse and ends the family. A client that refuses to rotate (that keeps using one refresh token) defeats it.
- **Display.** `operator_email` is for display. A client MUST NOT decide anything by it.

## 10. Conformance

The `credentials` suite of the [conformance kit](../conformance/README.md) judges the files a client leaves and what a client does with the files it is given. Given a directory (a `.stack/` a client wrote), it validates each file against the schemas, the name, the key pair and the mode. Given a writer, it has the client write a sign-in and an agent key into a fresh directory and judges what it wrote; given a reader, it gives the client good and bad files and checks what it uses. `@getstackrun/sdk` is a reference writer and reader of both files and passes the suite.

## 11. Machine-readable schemas

| File | What it is |
|---|---|
| [`schemas/StoredOperatorCredentials.json`](schemas/StoredOperatorCredentials.json) | `credentials.json`. |
| [`schemas/StoredAgentKey.json`](schemas/StoredAgentKey.json) | `agents/<agent_id>.json`. |
