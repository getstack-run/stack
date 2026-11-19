# Changelog: STACK Credentials Files

This specification follows semantic versioning. A new optional field is a minor version: clients ignore fields they do not know and keep them when they rewrite a file. A change to a field's meaning, to where a file is, or to what a client must do with it is a major version.

## 1.0.0 - 2026-10-24

Initial public release.

- `~/.stack/credentials.json`, the operator's sign-in, and `~/.stack/agents/<agent_id>.json`, an agent's Ed25519 key, as JSON Schemas generated from the code.
- The refresh exchange and its rotation (the file is rewritten with the new refresh token before the next exchange), signing out, and the 30 day expiry.
- The lock at `~/.stack/credentials.lock`: an exclusive create holding the process id, 50 millisecond retries for 5 seconds, a stale lock after 30 seconds, and a read of the file after the lock is taken.
- How an agent's key is made, enrolled and used to sign a token for each request.
- The order of credentials a client tries, and the file modes and writes the files need.

Clients were made to agree with this text: every client creates the sign-in readable by its owner only (it was created with the default mode and tightened after), every client that renews takes the lock (the SDKs did not), a file without a client id and a refresh token is no sign-in in every client, and an agent key's `enrolled_at` is whole seconds in every client (the Python SDK kept the API's ISO 8601 text, and the TypeScript SDK a fraction).
