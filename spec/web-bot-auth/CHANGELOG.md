# Changelog: STACK Web Bot Auth Profile

This specification follows semantic versioning. A new optional parameter, a new component a signer MAY cover, or a new optional directory member is a minor version: a site ignores what it does not know. A change that makes a signature or a directory that conformed stop conforming is a major version. The profile follows individual IETF drafts that the working group is replacing; a change of the drafts that STACK follows is recorded here.

## 1.1.0 - 2026-10-25

- The directory of one account's keys is served by STACK on its own domain, under the agent's id (`/v1/agent-identity/agents/{agent_id}/http-message-signatures-directory`), public and signed for the host asked with 86400 seconds of validity. It is no longer served by the agent's site, and the authenticated call that read it for a site to publish (`GET /v1/accounts/{id}/signing-keys/directory`) is removed: an agent's site serves only what the agent publishes. A signer, a site that checks a request and the public directory are unchanged.

## 1.0.0 - 2026-10-24

- Initial public release. The profile of RFC 9421 and the Web Bot Auth drafts that STACK follows when it signs the outbound requests of an agent's account: Ed25519, `@authority`, `@method` and `@path` covered, `Signature-Agent` as a dictionary member with the signature's label and covered, `created`, `keyid`, `alg`, `expires`, `nonce` and `tag="web-bot-auth"` in that order, five minutes of validity.
- The signature base, written out exactly, with test vectors: RFC 9421 appendix B.2.6, the architecture draft appendix A.2 and two vectors of the profile (`conformance/fixtures/web-bot-auth/vectors.json`, built by a public script).
- Keys: the JWK thumbprint as `keyid` and `kid`, one key in use per account, a retired key published for 48 hours, keys unpublished when the account closes.
- The key directory: path, media type, JWK Set body (`kid`, `use`, `nbf`, `exp`), the signature of the response over `("@authority";req)` with the directory tag, the directory of STACK's API and the directory an account's site serves, with the same body and parameters.
- The calls to read an account's keys, rotate them (owner or administrator only) and read its signed directory for a host.
- What a site must do to check a request, and the security considerations.
