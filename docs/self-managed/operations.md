# Operating a self-managed install

## The command

`stack-engine` is in the API image (`docker compose exec api stack-engine ...`, `kubectl exec deploy/<release>-api -- stack-engine ...`). It reads the install's own settings.

| Command | |
|---|---|
| `doctor` | Checks the deployment settings, the secrets, a wrap and unwrap through the key service, the database and its migrations, Redis, the archive, email and the licence. Exit 1 on any failure. |
| `operator create --email <address>` | Creates an operator and prints its API key once. An install has no sign-up page. |
| `approvals list`, `approve <id>`, `reject <id>` | See [approvals](#approvals). |
| `licence verify [<key>]` | See [licence](licence.md). |
| `archive init` | Creates the archive bucket if it is missing, waiting for the store to come up. The Compose install runs it for you; a managed bucket already exists. |
| `erasures reapply [--apply]` | After you restore the database from a backup: puts every account erasure back in force. An erased account is recorded in `erased_operators` (its id and the time, nothing else); a backup taken before the erasure brings the account back. The command looks at that list and reports any erased account whose row is back; with `--apply` it erases them again, with everything they hold (this cannot be undone, so read what it names first). Run it after every restore, until it exits 0. |
| `keys generate --dir <dir>` | Writes the key-encryption key, the signing key and the pepper as files. Never overwrites. |

## Approvals

Some requests an operator's key may make but not approve for itself: loosening a detector, widening a service grant, unblocking an agent, a held action. The API answers `403 GOVERNANCE_APPROVAL_REQUIRED` with an approval id. On STACK's hosted deployment a person decides in a browser. An install has no browser Console, so the person with access to the machine decides:

```
stack-engine approvals list
stack-engine approvals approve gvr_...
```

and the caller retries the same request with `X-Governance-Approval: <id>`. The approval binds the exact request, is single use and expires. The decision is made as the account's owner and recorded in that account's audit chain as made by `host_admin`. This is the same boundary the hosted deployment draws: a bearer credential cannot approve its own request, and whoever can run commands on the machine could change the database anyway.

## Starting, upgrading

Database changes are their own step and run before the new version starts: the `migrate` service in Compose, the pre-upgrade Job in the chart, or `node apps/api/dist/db/migrate.js` with `DATABASE_URL` set. Migrations only add: nothing an earlier version reads is dropped or renamed, so rolling back is redeploying the earlier image.

`GET /health` on the API answers 200 when it can reach Postgres and Redis (503 with the dependency named when not). The MCP server and the worker answer `/health` while they are alive; they do not probe their dependencies.

## Back up

- **Postgres.** Everything but the next two.
- **The key-encryption key, the signing key and the pepper**, apart from the database. Without the key-encryption key every stored credential is unreadable. Without the signing key, tokens already issued stop verifying (see the next section for rotation). The pepper keys the stored API-key hashes.
- **The archive bucket.** Older audit history lives there after the worker archives it. Evidence packs read from it.

## Rotating keys

- **Key-encryption key.** Put the new key first in `STACK_KEY_FILE`, keep the old below it. New data is wrapped under the new key, old data is unwrapped under the old. Re-wrapping existing data is not automated: drop the old key only when nothing is wrapped under it.
- **Signing key.** Set a new `DEPLOYMENT_SIGNING_KID`, keep the retired public key in `TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON` (API and worker identical).
- **API key pepper.** Not rotated in place.

## Security-monitoring connector

With a licence that includes `siem`, set `STACK_SIEM_SYSLOG_URL` and/or `STACK_SIEM_HTTP_URL`. Records are sent in order, from the moment export first runs, and again when a collector failed them, so a collector that is down is caught up and a record can arrive twice: each carries its id, and a collector drops a repeat by the pair of stream and id. Syslog is RFC 5424 (over UDP, or TCP and TLS with octet counting); HTTP is newline-delimited JSON with the bearer token. Only HTTPS is acknowledged: a datagram the network drops, or bytes a TCP collector lost after taking them, are not seen and not sent again, so a collector that must not lose a record uses HTTPS. Only the public fields of a row are sent. One API machine exports at a time. The formats, the delivery rules and what a collector must do are the open specification `spec/siem-export/SPEC.md`, and the `siem-collector` suite of `spec/conformance` tests a collector against it.

## What the install talks to

By default: your Postgres, Redis and archive, and the services your agents call through the proxy. Nothing goes to STACK. Only if you set them: `STACK_NETWORK_URL` (STACK's network services), `SENTRY_DSN`, an SMTP server or Resend, and the OAuth providers you configure. The images contain no analytics. Email footers and links name your own address and load no remote images.

## Supply chain

`.github/workflows/engine-images.yml` of the public repository (github.com/getstack-run/stack) builds the three images from a tag, and only there (the workflow refuses to publish from any other repository), with an SBOM and build provenance attached, pushes them, and signs each by digest with keyless cosign. Verify before running:

```
cosign verify ghcr.io/getstack-run/stack-engine-api@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/getstack-run/stack/.github/workflows/engine-images.yml@refs/tags/engine-v.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign download sbom ghcr.io/getstack-run/stack-engine-api@sha256:<digest>
```

Pin Helm and Compose to the digest.

## Verifying a release of this install

`pnpm --filter @stack/api build` then `pnpm --filter @stack/api exec vitest run src/self-managed.smoke.postgres.test.ts src/self-managed.proxy.postgres.test.ts` against a dedicated test database and Redis. The first boots the built server, worker and MCP server in production mode with no hosting-platform token, no AWS KMS and no Resend, issues a passport, checks the record's chain, the licence gates and the doctor. The second sends a call through the proxy to a local echo server and checks that the credential reaches it and the record verifies.
