# Changelog: STACK Authority Receiver Protocol

This specification follows semantic versioning. The protocol it defines carries its own version (`stack.direct_post.jwt`, `"1"`), which changes only in a major version of this specification. New optional members, new disclosure modes and new proof or approval methods are minor versions: receivers ignore what they do not know and STACK does not send a receiver a mode its profile does not list.

## 1.0.0 - 2026-10-24

Initial public release. The wire contract between an outside receiver and STACK, written from the implementation.

- Receivers, their three kinds of key (request signing, response encryption, receipt signing), origin verification through `/.well-known/stack-receiver.json`, and the receiver profile.
- The one-use call assertion (`Authorization: STACK-Receiver <JWS>`) bound to the method, the path and the canonical body, and its uniform failure.
- The presentation request: the signed request, the agent's proof of possession, the Passport and the checks STACK makes, including that a receiver gets exactly the facts its profile requires and no more.
- Delivery of the presentation as a form POST of a compact JWE (`ECDH-ES+A256KW`, `A256GCM`) around a JWS signed by STACK, the five disclosure modes and what a receiver must check before it relies on one.
- Status checks, receipts with a committed result, and reading a presentation request.
- The proof provider callback envelope and the OpenID Connect requirements of the enterprise approval, with its request API.
- Error codes, security considerations, and the receiver functions the conformance suite tests.
- One behaviour made single: the `request_hash` of a status check is the digest over the receiver request id and the normalized request, as it is in a presentation request (before, a status check hashed the normalized request alone).
