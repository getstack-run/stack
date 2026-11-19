# Changelog: STACK Wallet Payment Relay

This specification follows semantic versioning. A new refusal reason is a minor version: a client keys on `code` and ignores a `details.reason` it does not know.

## 1.1.0 - 2026-11-12

Caps become optional and a controls feature, and a payment can wait for the owner. Nothing a client sends changes.

- `per_payment_cap_usdc` and `daily_cap_usdc` may be `null`: no cap, and the wallet's own balance is the limit. There is no maximum.
- The caps are applied only while the owner has controls (section 6, items 6 and 8). Without controls no cap is applied, even when values are stored.
- With the owner's trust setting at "Ask me first", a payment waits for the owner (section 6, item 3): `CONTROL_DENIED` with `review_required` and a `retry.ref`, then the same request again with `X-Control-Ref`. Trusting agents never waits.
- The rule at the key service has no amount condition when the wallet has no per-payment cap.

## 1.0.0 - 2026-10-24

Initial public release. The wire contract of the one request an agent sends to pay from its owner's wallet.

- The wallet as the owner's, with the agent's own key as its only signer, and what STACK holds (nothing).
- The signature the agent makes over the signing request, byte for byte, and the typed data it may send: a USDC `TransferWithAuthorization` on Base and nothing else.
- The payload hash (the EIP-712 digest of the authorisation) with its domain separator, struct type hash and an example.
- The nine checks STACK makes in order, before and after the owner's controls, and that a refused payment never reaches the key service.
- The result, the settlement of the reserved amount, the closed set of refusal reasons with their statuses, and the security considerations.
