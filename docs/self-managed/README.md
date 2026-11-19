# Self-managed STACK

The engine's source, issues and releases are in the public repository, github.com/getstack-run/stack.

The engine, run on your own infrastructure: passports and Missions, the credential proxy, the model gateway, connections, drop-offs, agent-to-agent calls, the pattern detectors, controls (policies, limits, held actions, reviews, the control socket), the audit record and the worker. It needs nothing from STACK's cloud to start.

What it does not include: agent accounts and their pieces, billing, the skills marketplace and a Console. Sealed skill scripts do not run (there is no script runner), and skills stay network-only.

## What an install needs

| Dependency | Why | Notes |
|---|---|---|
| Postgres 17 (the version STACK tests against) | all state | `DATABASE_URL`. Migrations are a separate step. |
| Valkey 8 or Redis 7 | revocation flags, locks, caches | `REDIS_URL`. The Compose file runs Valkey (BSD-3-Clause); the engine is tested against it. Redis 7.2 and earlier are also BSD; later Redis releases carry other licences, which are yours to read. |
| An S3-compatible bucket | the audit archive and evidence packs | `AUDIT_ARCHIVE_*`. SeaweedFS (the Compose default), R2, Tigris, S3. Production refuses to start without a durable store. |
| A key-encryption key | wraps every stored credential | a file (`STACK_KEY_FILE`) or AWS KMS. See [configuration](configuration.md#keys). |
| A signing key | signs passports and records | `SESSION_SIGNING_KEY_FILE`. |
| A public address | issuer of tokens, OAuth discovery, links | `STACK_API_BASE_URL`, https. |

It does not need an account with STACK or any service STACK runs. AWS KMS (for the key-encryption key), Resend (for email) and OpenRouter (for model calls) are settings you may use, not requirements, and email is optional (SMTP, Resend or none).

## Install

Single host, with Docker Compose: `deploy/compose/` (`init-secrets.sh`, `compose.yml`, `env.example`).

```
cd deploy/compose
./init-secrets.sh          # secrets as files, and a .env to edit
$EDITOR .env               # set STACK_API_BASE_URL
docker compose up -d       # migrations run first, as their own step
docker compose exec api stack-engine doctor
docker compose exec api stack-engine operator create --email you@example.com
```

Kubernetes: the Helm chart in `deploy/helm/stack-engine/`. Postgres, Redis and the bucket are yours; the chart runs the API, the worker and the MCP server and applies migrations as a Job before each install and upgrade. Its secrets come from one existing Secret (keys listed in `values.yaml`).

Images: one Dockerfile, three targets (`deploy/docker/Dockerfile`: `api`, `worker`, `mcp`). Each runs as an unprivileged user and holds only compiled output. Release images are built with an SBOM and build provenance and signed (see [operations](operations.md#supply-chain)).

## Then

- The operator's API key is the owner credential. Agents and the SDK, CLI and MCP tools use the same API.
- A key cannot approve what it requests (unblocking an agent, loosening a detector, a held action): the person at the machine decides with `stack-engine approvals`. See [operations](operations.md#approvals).
- The API is specified: every route the engine serves is in [`spec/rest-api/openapi.json`](../../spec/rest-api/openapi.json) (OpenAPI 3.1), and [`spec/rest-api/SPEC.md`](../../spec/rest-api/SPEC.md) says what they share: the error body and codes, the step-up above, `402`, rate limits. The conformance kit (`spec/conformance`, suite `rest-api`) tests a server against it. The files the CLI and SDKs keep under `~/.stack` are [`spec/credentials-files`](../../spec/credentials-files/SPEC.md).
- The enterprise features need a licence key. Without one the install runs, with them off. See [licence](licence.md).
- Live detection rules and the hosted classifier are optional network services; L3 exists only through them. See [network services](network-services.md).

## Known gaps

Stated plainly, because they decide whether this fits:

1. **The proxy sends only to public https addresses.** Its address guard refuses private and loopback destinations and plain http, as on STACK's hosted deployment. An agent cannot yet reach an internal service through the proxy. There is no setting for it: allowing private networks changes the proxy's SSRF posture and needs its own design and review.
2. **No browser Console.** Approvals are decided on the machine, sign-in is by API key, and OAuth consent (used by MCP clients and the CLI's device flow) needs a page at `DASHBOARD_URL` that this release does not ship. Use API keys and passports.
3. **Customer-managed keys (CMEK) need AWS KMS.** With a key file there is no customer key service behind it.
4. **MCP tools for parts the install does not serve** (accounts, billing, skills) are listed by the MCP server and answer not found.
5. **No SCIM.** "User provisioning" is the creation of a member at their first single sign-on; there is no directory sync.
