# STACK Wallet Payment Relay

**Specification:** STACK Wallet Payment Relay
**Version:** 1.1.0
**Status:** Stable
**Licence:** Apache-2.0

An agent account can have a wallet that belongs to its owner and is signed for by the agent's own key. When the agent wants to pay, it asks STACK to pass one signed payment request on to the wallet's key service, and STACK passes it on only if the owner's rules allow it. STACK holds no key to any wallet: it can refuse a payment and it can pass one on unchanged, and it can do nothing else with the money. This document defines the one request an agent sends, how the agent signs it, what STACK checks before it passes the request on, and what comes back. The party that pays is the owner's wallet; the party that gets paid (a seller that takes an x402 payment, see [STACK Agent Site Payments](../agent-site-payments/SPEC.md)) only ever sees the result.

Contents: 1 Conventions, 2 Overview, 3 The wallet, 4 The agent key and its signature, 5 The request, 6 What STACK checks, 7 The result, 8 Errors, 9 Security considerations, 10 Conformance, 11 Machine-readable schemas.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only when, they appear in capitals. Roles: the **agent** is the AI agent of an agent account and its software (a client library); **STACK** is the relay; the **key service** is the wallet provider that holds the owner's wallet and makes the signature the wallet is asked for; the **owner** is the person or organisation that owns the wallet; the **payee** is whoever receives the money. A client implementation conforms to this specification if it satisfies every MUST in sections 4 and 5. A relay implementation conforms if it satisfies every MUST in sections 5 to 8. The conformance kit in [`../conformance/`](../conformance/README.md) (the `wallet` suite) tests both.

## 2. Overview

1. The owner has opened an agent account with a wallet and given STACK the agent's **public** key. The wallet lives with the key service, is owned by the owner (STACK never holds the owner's credential), and has the agent's key as its only signer, with one policy: only a USDC transfer authorisation on Base, up to a per-payment cap when the wallet has one.
2. The agent builds a **transfer authorisation** (EIP-3009, `TransferWithAuthorization`, as a typed-data request) for the payee and signs the key service's signing request with its own key.
3. The agent sends the typed data and its signature to STACK (section 5).
4. STACK checks the agent, the account, the owner's controls, the shape and limits of the payment and the signature, reserves the amount in the account's budget, and only then passes the signing request, with the agent's signature, to the key service (section 6).
5. The key service checks the agent's signature and the wallet's policy and returns the wallet's signature over the authorisation. STACK returns it (section 7).
6. The agent presents the signed authorisation to the payee, for example in an x402 payment header. The payee (or its facilitator) submits it on chain. STACK learns whether it was used by reading the wallet's transfers, and settles or releases the amount in the account's budget.

A payment that any check refuses is never sent to the key service.

## 3. The wallet

An account with a wallet shows it in the `details` of its wallet piece (`GET /v1/accounts/{account_id}`):

| Field | Meaning |
|---|---|
| `address` | The wallet's address (`0x` and 40 hexadecimal digits). The `from` of every payment. |
| `chain_id`, `network`, `token`, `token_address` | `8453`, `base`, `USDC` and the address of native USDC on Base, `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`. |
| `wallet_id`, `privy_app_id` | The identifiers of the wallet and of the application at the key service, needed to build the signing request (section 4). |
| `owner`, `signer` | `customer`, and that the signer is the agent key alone. |
| `per_payment_cap_usdc`, `daily_cap_usdc` | The most one payment may be, and the most the wallet may authorise in any rolling 24 hours; each is a string of USDC or `null` for none. Caps are optional, STACK sets no maximum, and they are applied only while the owner has controls (section 6, items 3, 6 and 8): with none, or without controls, the wallet's own USDC balance is the limit. |
| `payments` | `active` or `stopped`. |

The agent's key is a P-256 key pair the agent makes and keeps on its own side. Only the public key, as an uncompressed SEC1 point (65 bytes, first byte `0x04`) in base64, is given to STACK (in the `wallet.agent_public_key` of the request that opens the account). The private key MUST NOT be made, stored or used by a machine that STACK operates.

## 4. The agent key and its signature

The agent signs the exact request the key service will receive. The string it signs is the canonical JSON (RFC 8785; the payment contains only strings and integers) of

```json
{
  "version": 1,
  "method": "POST",
  "url": "https://api.privy.io/v1/wallets/<wallet_id>/rpc",
  "body": { "method": "eth_signTypedData_v4", "params": { "typed_data": <typed_data of section 5.1> } },
  "headers": { "privy-app-id": "<privy_app_id>" }
}
```

with `wallet_id` percent-encoded as a URL path segment. The signature is ECDSA over P-256 with SHA-256 of the UTF-8 bytes of that string, in DER form (ASN.1 `SEQUENCE { r, s }`), base64 with padding. It is the key service's own *authorization signature* scheme: a signature made for any other string, or by any other key, is refused by the key service and by STACK.

A client MUST sign exactly the string above for the typed data it sends, and MUST send exactly one signature.

## 5. The request

`POST /v1/accounts/{account_id}/wallet/payments`, authenticated as the account's own agent: `Authorization: Bearer <agent credential>` (its Passport, or the short-lived agent token its client library makes). The body is a JSON object with exactly these two members:

| Member | Meaning |
|---|---|
| `typed_data` | The typed-data request of section 5.1. |
| `agent_signature` | The signature of section 4: 60 to 120 base64 characters, with up to two `=` of padding. |

### 5.1 The typed data

`typed_data` MUST be exactly this object shape (no other member at any level, in any order):

```json
{
  "domain": { "name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
  "types": { "TransferWithAuthorization": [
    { "name": "from", "type": "address" }, { "name": "to", "type": "address" }, { "name": "value", "type": "uint256" },
    { "name": "validAfter", "type": "uint256" }, { "name": "validBefore", "type": "uint256" }, { "name": "nonce", "type": "bytes32" }
  ] },
  "primary_type": "TransferWithAuthorization",
  "message": { "from": "0x…", "to": "0x…", "value": "1000000", "validAfter": "0", "validBefore": "1790000300", "nonce": "0x…" }
}
```

- `chainId` is the JSON number `8453`; `types` has the one entry above, in that order, and no `EIP712Domain` entry.
- `from` is the account's wallet address; `to` is the payee, an address that is not the zero address. Addresses are `0x` and 40 hexadecimal digits.
- `value`, `validAfter` and `validBefore` are decimal strings of an unsigned 256-bit integer with no leading zeros; `value` is an amount of USDC in atomic units (six decimals: `1000000` is one USDC) and is more than zero.
- `nonce` is `0x` and 64 hexadecimal digits, from a source of at least 128 bits of randomness, new for every payment.
- `validAfter` is before `validBefore`; `validBefore` is in the future and at most 600 seconds after the time of the request.

A payment is identified by its **payload hash**: the EIP-712 digest of the authorisation, `keccak256(0x1901 || domainSeparator || structHash)` over the domain above and the struct `TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)` (EIP-3009), written as `0x` and 64 lowercase hexadecimal digits. Two requests with the same hash are the same authorisation however they were written. The domain separator is `0x02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f` and the struct type hash is `0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267`. Example: from `0x1111111111111111111111111111111111111111`, to `0x2222222222222222222222222222222222222222`, value `1000000`, validAfter `0`, validBefore `1790000300` and nonce `0x` followed by `ab` thirty-two times hash to `0x291e5b9cfec26046187f836fe4ef54a9b2192553443d4ed33d39a3ca876083fc`.

## 6. What STACK checks

STACK refuses the request, and never contacts the key service, unless every one of these holds. They run in this order; a refusal stops the rest. The schema errors come first (section 8).

1. **The agent.** The credential is the account's own agent's, its Passport is live and carries exactly one live Mission (the account's standing Mission), and the agent has not been blocked.
2. **The meter.** The action is counted once on the owner's meter; an owner that may not use the meter is refused before anything else happens.
3. **The owner's controls.** When the owner has controls, they decide the payment (spend rules, per-payee limits, a payment held for approval, including approval from a chat). A denial or an unavailable decider refuses the payment and nothing is charged. Separately, when the owner's trust setting for the agent is "Ask me first", the payment waits for the owner: the first request is refused `CONTROL_DENIED` with `details.reason_code` `review_required` and `details.retry.ref`, and once the owner has approved that exact payment the agent sends the same `typed_data` and `agent_signature` again with the header `X-Control-Ref` set to the reference; the approval is spent when the payment is passed on and given back when it is not. A payment that a later check refuses never asks the owner.
4. **The shape.** The typed data is exactly that of section 5.1, for Base USDC, the payee is not the zero address and the amount is more than zero.
5. **The account.** It exists for the owner the agent belongs to and is the agent's own, is open, its wallet piece is ready and active, spending is not frozen, the wallet is open, and its signer is the agent alone.
6. **The payer, the cap and the window.** `from` is the account's wallet; when the owner has controls and the wallet has a per-payment cap, `value` is at most it; the authorisation window is as in section 5.1.
7. **The signature.** `agent_signature` verifies, under the public key STACK holds for the account, over the string of section 4 for exactly this typed data.
8. **Replay and the daily cap.** Under one lock on the wallet: the payload hash has not been passed on before (one authorisation, once), and, when the owner has controls and the wallet has a daily cap, the amount does not take the wallet's authorisations in the last 24 hours past it.
9. **The budget.** The amount, rounded up to whole cents at one USDC to one dollar, is reserved in the account's budget (the owner's credit and the controls' limits); a refusal there rolls everything back.

Then STACK sends the signing request of section 4 to the key service with `privy-authorization-signature` set to the agent's signature, unchanged. STACK adds no fee, no payee and no other amount. If the key service refuses, the reservation is released and the payment is not recorded as passed on.

The reservation stays until STACK knows how the authorisation ended: from `validBefore` and a margin of 30 minutes it reads the wallet's transfers at the key service; a matching transfer settles the reservation, none releases it, and if the key service cannot be read for 24 hours after `validBefore` the amount is counted as spent.

## 7. The result

`201`:

```json
{
  "payment_id": "...",
  "payload_hash": "0x291e5b9c…",
  "signature": "0x…",
  "from": "0x1111111111111111111111111111111111111111",
  "to": "0x2222222222222222222222222222222222222222",
  "amount_atomic": "1000000",
  "amount_cents": 100,
  "valid_before": "1790000300"
}
```

`signature` is the wallet's EIP-712 signature (`0x`, 130 hexadecimal digits: `r`, `s`, `v`) over the authorisation: with `typed_data.message` and `typed_data.domain` it is the x402 `exact` payment authorisation the payee accepts. It is valid until `valid_before`. `amount_cents` is what was reserved. The result is returned once for the request; a second request for the same authorisation is refused as a replay (section 8), so an agent that lost a result signs a new authorisation with a new nonce.

## 8. Errors

Every error is `{ "error": { "code", "message", "details" } }`. A client keys on `code` and, for `WALLET_PAYMENT_REFUSED`, on `details.reason`; the message is for people.

| Status | `code` | When |
|---|---|---|
| `400` | `VALIDATION_ERROR` | The body is not `{ typed_data, agent_signature }` with a signature of the form of section 5. |
| `400` | `WALLET_PAYMENT_REFUSED` | `details.reason` `unsupported_typed_data` (not exactly the shape of section 5.1, or a value of zero), `not_base_usdc` (the domain is not USDC on Base), `authorization_window` (expired, more than 600 seconds ahead, or `validAfter` not before `validBefore`), `wrong_payer` (`from` is not the account's wallet). |
| `401`, `403` | `INVALID_API_KEY`, `FORBIDDEN` | The credential is not an agent's, the agent is not the account's, its Passport has no single live Mission, or it was blocked. |
| `402` | `PLATFORM_SUBSCRIPTION_REQUIRED`, `SPEND_FROZEN`, `AGENT_BUDGET_EXCEEDED` | The meter, a spending freeze or the budget (section 6, items 2, 5 and 9). |
| `403` | `WALLET_PAYMENT_REFUSED` | `details.reason` `over_per_payment_cap`, `over_daily_cap`, `agent_signature_invalid`, `wallet_closed`, `wallet_signer_unsupported` (a wallet opened with another signer shape: close it and open a new one), `provider_refused` (the key service refused under the wallet's policy). |
| `403` | `CONTROL_DENIED`, `CONTROL_LIMIT_EXCEEDED`, `CONTROL_SOCKET_UNAVAILABLE` | The owner's controls (section 6, item 3); see the [Control Socket Protocol](../control-socket/SPEC.md). |
| `404` | `NOT_FOUND` | No such account for this owner. |
| `409` | `ACCOUNT_PIECE_NOT_READY`, `WALLET_PAYMENT_REFUSED` | The wallet is not ready; `details.reason` `replayed`: STACK passes each authorisation on once. |
| `501` | `NOT_CONFIGURED` | This deployment has no wallet provider. |
| `502` | `WALLET_PAYMENT_REFUSED` | `details.reason` `provider_error`: the key service did not sign; the reservation was released; sign a new authorisation with a new nonce. |
| `503` | `CONTROL_UNAVAILABLE` | The owner's hosted controls could not decide. |

## 9. Security considerations

**STACK holds no key.** The wallet's only signer is the agent's key. STACK cannot sign for the wallet and cannot add a signer to it: only its owner can change the signers, in their own session with the key service. Closing the account, revoking the agent's Passport, ending its Mission, blocking the agent or freezing spend stops the next payment at once; none of them needs the key service.

**The relay can only refuse.** It passes on the agent's own request and signature unchanged. What the key service enforces on its own (the transfer type, Base USDC, and the per-payment cap the wallet had when it opened, if it had one: the rule at the key service belongs to the owner, so a cap changed later is held by STACK's relay) holds even if STACK's checks are bypassed; what only STACK enforces (the daily cap, the budget, the owner's controls and approvals, replay) does not. An attacker who held both STACK's credential at the key service and an agent's key could send payments there directly, within the per-payment cap.

**Replay.** An authorisation is identified by its digest and passed on once. A seller, in turn, SHOULD refuse a nonce it has seen (the chain does as well: an EIP-3009 nonce is used once by the token contract).

**The key stays with the agent.** A client library MUST refuse to make or load the key where it runs inside an environment STACK operates, MUST NOT print or log it, and SHOULD keep it in the agent owner's own secret store.

**Amounts.** USDC is counted one to one with US dollars, rounded up to a whole cent in the budget, so the budget never counts less than moved.

## 10. Conformance

The `wallet` suite of the [conformance kit](../conformance/README.md) has two parts, and either can be run alone.

**A client** (section 4 and 5): a function `buildPayment({ appId, walletId, from, to, valueAtomic, validAfter, validBefore, nonce, sign })` that returns `{ typed_data, agent_signature }`. `sign(string)` is given by the kit: it signs with a key of the kit's and records what it was asked to sign. The kit checks the shape of `typed_data` field by field, that the string handed to `sign` is exactly the one of section 4, and that `agent_signature` is the signature `sign` returned, and that it verifies.

**A relay** (sections 5 to 8): the URL of the endpoint of a test instance and a description of its test wallet: the address, the wallet and application identifiers, the per-payment cap, optionally the daily cap, and the test agent key (PKCS#8, base64) whose public half the wallet was registered with. The instance passes what it accepts on only to a double or a test network. The kit sends correct payments and payments with one thing wrong, and checks the status and `details.reason` of each answer and, when the instance can say so, that a refused payment never reached the key service.

The reference client is the one of `@getstackrun/sdk` (`signWalletPayment`); STACK's own relay passes the relay part in the private repository's tests.

## 11. Machine-readable schemas

[`schemas/WalletPaymentInput.json`](schemas/WalletPaymentInput.json) is the body of section 5, generated from the reference implementation. The typed-data shape of section 5.1 is enforced by the relay, not by the schema, and the conformance kit tests it.
