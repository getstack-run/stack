# Licence key

The engine is source-available under the Fair Core License. Without a key a self-managed install runs the whole engine. A key unlocks the enterprise features.

## What a key grants

| Feature | What it turns on |
|---|---|
| `sso` | Identity-provider (OIDC) configuration and sign-in through it; company sign-in for Authority. |
| `provisioning` | A member created at their first single sign-on. (An existing member can always sign in. There is no directory sync.) |
| `roles` | Member roles beyond owner and member: `admin` and `readonly`. Without it every member acts as a plain member; an admin member is narrowed to member, a read-only member stays read-only. |
| `siem` | The security-monitoring connector: security events and the audit stream to a syslog or HTTPS collector. |
| `evidence_exports` | Signed evidence packs and dossiers (compliance reports). `GET /v1/audit/export` is never gated. |
| `partners` | Partner-managed account routes (`/v1/partner/*`: opening accounts, inviting the customer, releasing an account). |
| `lts` | Long-term-support versions. Informational: it gates no code. |

A feature that is off answers `402 LICENCE_REQUIRED` with `details.feature`. Nothing else changes, and nothing is deleted.

## The key

`STACKLIC1.<payload>.<signature>`. The payload is base64url JSON: customer, issue and expiry dates, features, the id of the STACK licence key that signed it and, for a key issued to a STACK account, that account and the key's own id (`jti`), which lets that account revoke the key for STACK's network services (see [network services](network-services.md)). The signature is Ed25519 over `stack-licence-v1\n` plus the payload text. STACK's public licence keys are built into the code, so a key is checked offline: no account, no network, nothing sent to STACK.

Set it as `STACK_LICENCE_KEY` or `STACK_LICENCE_KEY_FILE` (not both). The file is read again every day, so a renewed key takes effect without a restart. The install checks at boot and daily, and again on every use against the clock, so a key stops granting at its expiry instant.

- No key, an unreadable file, a key that is refused or expired: the install keeps running with every enterprise feature off, and logs it once.
- Unknown features in a newer key are ignored by an older build.

## Using it with STACK's network

A key STACK issued to a STACK account carries that account as a signed claim (`operator_id`). If you set the key as `STACK_NETWORK_KEY`, STACK accepts it for live detection rules and the hosted classifier and bills the account (see [network services](network-services.md)). Leaving that out keeps the install fully offline.

## Reading it

```
stack-engine licence verify <key>          # or --file <path>, or the environment's
curl -H "Authorization: Bearer <operator key>" https://<install>/v1/licence
```

Both show the customer, the dates and the features, never the key. Exit 0 from the CLI means valid now.

## Not a security boundary

The code runs on your machine; a licence is how the build knows what you are licensed for, and how an expired or altered key stops granting it. Binding a key to a domain, seat counts and revocation are not implemented.
