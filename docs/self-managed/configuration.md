# Configuration

Every setting is an environment variable. A secret may be given as a file instead: set `NAME_FILE=/path` and the file's content (its trailing newline dropped) becomes `NAME`. Setting both is refused. Settings read this way: `API_KEY_PEPPER`, `DATABASE_URL`, `REDIS_URL`, `SESSION_SIGNING_KEY`, `STACK_KEY_ENCRYPTION_KEY`, `STACK_LICENCE_KEY`, `STACK_NETWORK_KEY`, `STACK_INTENT_MODEL_KEY`, `STACK_SIEM_HTTP_TOKEN`, `MCP_ELICITATION_ATTESTATION_KEY`, `SMTP_PASSWORD`, `SMTP_URL`, `RESEND_API_KEY`, `OPENROUTER_API_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.

The API, the worker and the MCP server read the same variables; give the API and the worker identical values for everything marked shared.

## Deployment

| Variable | Default | |
|---|---|---|
| `STACK_DEPLOYMENT` | `hosted` | `self_managed` turns this install into a self-managed one: STACK's own hosted features (accounts, billing and the services built on them) are off, and no cloud KMS or mail service is required. The install's own programs (the API, the worker and the MCP server) refuse to start unless it is `self_managed`, in every environment; any other value is refused. |
| `NODE_ENV` | `development` | Set `production`. |
| `STACK_API_BASE_URL` | none | **Required.** https origin, no path (http only for localhost). |
| `STACK_MCP_BASE_URL` | the API origin | Where the MCP server is reached. Its resources are `<origin>/mcp` and `<origin>/directory`. |
| `DASHBOARD_URL` | the API origin | Where people approve things, if you run a page for it. Used in links. |
| `STACK_ISSUER` | the host of `STACK_API_BASE_URL` | The `iss` of passports, sessions and OAuth tokens. Changing it invalidates tokens already issued. |
| `API_PORT` | `3000` (`8080` in the image) | |
| `STACK_SECURITY_CONTACT` | none | An address or link that emails about an account change name for "if this was not you". With none set, those emails send the person to your administrator. |
| `STACK_STAGING` | `false` | `true` makes the install a test copy: only the addresses in `STAGING_SIGNIN_ALLOWLIST` can sign in, be given an account or a membership, or be sent email, and every API and MCP answer carries `X-Robots-Tag: noindex, nofollow`. Any value other than `true` or `false` is refused. |
| `STAGING_SIGNIN_ALLOWLIST` | none | With `STACK_STAGING=true`, the exact email addresses allowed in, comma separated and compared lower-cased. Empty, or an entry that is not one address, is refused at boot. |

`STACK_SITE_URL` names the site of STACK's own hosted deployment; a self-managed install that sets it is refused, as its site is `DASHBOARD_URL`.

Nothing a self-managed install signs or links contains `getstack.run`. Two published namespaces remain by design: the claim schema identifiers (`https://getstack.run/schemas/passport-claims/v1/...`) are the public specification's names, and every evidence pack carries an inline copy of the schemas, so verifying one needs no network.

## Keys

| Variable | |
|---|---|
| `STACK_KEY_PROVIDER` | `local` or `aws-kms`. Chosen from what is set when omitted; both set with no choice named is refused. |
| `STACK_KEY_FILE` | Path of a file with the key-encryption key: 64 hex characters or base64 of 32 random bytes. One key per line; the first wraps, every one unwraps (rotation: put the new key first, keep the old below it until nothing is wrapped under it). `#` starts a comment. |
| `STACK_KEY_ENCRYPTION_KEY` | The same, inline. Not both. |
| `AWS_KMS_KEY_ID`, `AWS_REGION`, `STACK_SYSTEM_OPERATOR_ID` | AWS KMS instead. |
| `SESSION_SIGNING_KEY_FILE` | Path of an Ed25519 PEM. Accepted only by a self-managed install. (`SESSION_SIGNING_KEY_WRAPPED`, wrapped by the key service, also works.) |
| `API_KEY_PEPPER` | 32 or more bytes, **shared** by the API and the worker. Required in production. |
| `MCP_ELICITATION_ATTESTATION_KEY` | 32 or more bytes, shared by the API and the MCP server. Without it, in-chat approval is off. |

`stack-engine keys generate --dir <dir>` writes the key-encryption key, the signing key and the pepper as files (mode 0600, never overwritten). A lost key-encryption key makes every stored credential unreadable: back it up apart from the database.

The base64 stand-in used in development (`STACK_ALLOW_INSECURE_DEV_KMS`) is refused in production whatever else is set.

## Storage

| Variable | |
|---|---|
| `DATABASE_URL`, `REDIS_URL` | Required. |
| `AUDIT_ARCHIVE_BUCKET` | Required in production. |
| `AUDIT_ARCHIVE_ENDPOINT` | Empty for AWS S3; the service URL for an S3-compatible store (path-style). |
| `AUDIT_ARCHIVE_REGION` | |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | The bucket's credentials. |
| `AUDIT_HOT_WINDOW_DAYS` | Days of audit kept in Postgres before the worker archives them. |

## Email

`STACK_EMAIL_TRANSPORT`: `none` (default when nothing is set), `smtp` or `resend`.

- `smtp`: `SMTP_URL` (`smtps://user:pass@host:465`, or `smtp://` for STARTTLS on 587), or `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_SECURE`; and `EMAIL_FROM`. The connection is encrypted and the certificate verified; plain SMTP is accepted only to localhost, or with `SMTP_ALLOW_INSECURE=true`.
- `resend`: `RESEND_API_KEY`, `RESEND_FROM_*`, and optionally `RESEND_REPLY_TO` and `RESEND_LIST_UNSUBSCRIBE`.
- `none`: nothing is sent. A flow that needs mail says so. Inviting a member returns the invitation's token and link to the admin instead of mailing it. Email notification channels are unavailable.

## Features and network

| Variable | |
|---|---|
| `STACK_LICENCE_KEY` / `STACK_LICENCE_KEY_FILE` | See [licence](licence.md). The file is read again every day. |
| `STACK_NETWORK_URL`, `STACK_NETWORK_KEY` | STACK's network services (together or not at all). See [network services](network-services.md). |
| `STACK_NETWORK_RULES` | Live detection rules. Default true when configured. |
| `STACK_NETWORK_CLASSIFIER` | The hosted L3 classifier, the only L3 an install has. Default **false**: it sends content to STACK, and needs `STACK_NETWORK_URL` and a licence or API key. |
| `STACK_INTENT_MODEL_URL`, `STACK_INTENT_MODEL_NAME`, `STACK_INTENT_MODEL_KEY` | A model of your own that grades intent deviation at each checkout: an OpenAI-compatible chat completions endpoint (`<url>/chat/completions`), the model to ask there, and its key (optional, for an endpoint that takes none). URL and name together or not at all. https, or http on this machine. See [network services](network-services.md). |
| `STACK_SIEM_SYSLOG_URL` | `udp://`, `tcp://` or `tls://host:port`. Licensed. |
| `STACK_SIEM_HTTP_URL`, `STACK_SIEM_HTTP_TOKEN` | https collector, bearer token. Licensed. |
| `STACK_SIEM_STREAMS` | `security` (default), `audit`, or both. |
| `STACK_SIEM_TLS_CA_FILE` | An extra CA for the collector. |
| `SSO_DNS_SERVERS` | Name servers (addresses, comma separated) that look up the DNS records proving an e-mail domain for single sign-on. Empty: the machine's own resolver. Needs a name server that answers for your public domains. |

## Left as they were

`OAUTH_ENABLED`, `OAUTH_SCOPE_ENFORCEMENT` (must be on when OAuth is on in production), `DEPLOYMENT_SIGNING_KID`, `TRUSTED_HISTORICAL_DEPLOYMENT_JWKS_JSON`, `ALLOWED_ORIGINS`, `PER_OPERATOR_CLAIM_SIGNING_ENABLED`, `SENTRY_DSN` (off unless you set it), `OAUTH_MICROSOFT_TENANT` (the tenant a Microsoft OAuth app signs in against when the app was saved without one, `common` by default; an install connects services by OAuth through the apps its operators save at `/v1/oauth-apps`, one Google app covering every Google service and one Microsoft app Outlook and Teams, and any service with an API key or token connects with no app). `FLY_API_TOKEN` and the runner settings turn on the isolated script runner for installs that have one; nothing else uses them.
