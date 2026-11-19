# Changelog: STACK Agent Site Payments (x402)

This specification follows semantic versioning. Support for another network, asset or x402 scheme is a minor version: a client picks the entry of `accepts` it can pay and ignores the rest.

## 1.0.0 - 2026-10-24

Initial public release. What a paying client sees and sends on an agent site's priced path, and what the site answers.

- The `402` with the requirements in `PAYMENT-REQUIRED`: x402 version 2, the `exact` scheme, USDC on Base (and Base Sepolia on a test site), paid to the agent's own wallet.
- The payment in `PAYMENT-SIGNATURE`: the chosen entry unchanged and an EIP-3009 transfer authorisation with its signature.
- The checks of the site in order, the claim that lets one authorisation be used once, and the answers.
- Settlement only after the agent's site code answered `2xx`, `PAYMENT-RESPONSE` on success and failure, the reason codes, and that the signature header never reaches the agent's own code.
