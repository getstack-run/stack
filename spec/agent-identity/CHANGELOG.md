# Changelog: STACK Agent Identity

This specification follows semantic versioning. A new optional member of the answer or of a fact, a new way to ask, or a new machine file is a minor version: an asker ignores what it does not know, and the version of the statement's claim (`identity.v`) stays 1. A change that makes a statement or a server that conformed stop conforming (a fact that changes meaning, a different type or audience, a new required member) is a major version and a new `identity.v`.

## 1.0.0 - 2026-10-25

- Initial public release. The public lookup on the server's own origin, by the key id of a signed request, the host name of an agent's site or the agent's id; the answer with the agent (id, status, and its name only when its owner shows it), the owner's standing as two yes-or-no facts (identity verified and good standing) and the lookup echoed, as a compact signed statement and as the same facts in plain JSON.
- The signed statement: EdDSA under the deployment's signing key and its JWKS, the protected `typ` `stack-agent-identity+jwt` and the audience `stack:agent-identity` that no Passport has, five minutes of validity, the claims written out exactly, test vectors built by a public script.
- What an answer never carries, the one answer given for an agent that is unknown, closed, still opening or switched off, and the rule that a host name never confirms a closed agent.
- The machine files an agent has on the server's origin instead of on its site: its signed A2A card, its MCP server card and its Web Bot Auth key directory.
- The owner's two switches (`enabled`, on by default; `show_name`, off by default) and their routes.
- What an asker must do to verify a statement, and the security and privacy considerations.
