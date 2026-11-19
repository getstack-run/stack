# STACK specifications

These are the written, versioned specifications of the interfaces STACK exposes to the rest of the world: what a Passport is and how to check one, how a customer's own server decides what an agent may do, what a provider adapter must implement to become part of an agent account, what a verifiable record looks like, which tools STACK offers to AI clients, and the catalogue of everything an agent can use through its account. They are open: anyone may implement them, and a test kit lets an implementer prove that they have.

The specifications are licensed under the Apache License 2.0 (see [LICENSING.md](LICENSING.md)). The software that implements them in this repository is licensed as that document describes.

## The specifications

<!-- spec:generated:spec-index -->

| Specification | Version | History |
|---|---|---|
| [STACK Passport](passport/SPEC.md) | 1.3.0 | [changelog](passport/CHANGELOG.md) |
| [STACK Control Socket Protocol](control-socket/SPEC.md) | 1.2.0 | [changelog](control-socket/CHANGELOG.md) |
| [STACK Provider Interface](provider-interface/SPEC.md) | 1.0.0 | [changelog](provider-interface/CHANGELOG.md) |
| [STACK Record Format](record/SPEC.md) | 1.0.0 | [changelog](record/CHANGELOG.md) |
| [STACK MCP Tool Definitions](mcp-tools/SPEC.md) | 2.3.1 | [changelog](mcp-tools/CHANGELOG.md) |
| [STACK Catalogue](catalogue/SPEC.md) | 1.4.0 | [changelog](catalogue/CHANGELOG.md) |
| [STACK Webhooks](webhooks/SPEC.md) | 2.0.0 | [changelog](webhooks/CHANGELOG.md) |
| [STACK Authority Receiver Protocol](authority-receiver/SPEC.md) | 1.0.0 | [changelog](authority-receiver/CHANGELOG.md) |
| [STACK Wallet Payment Relay](wallet-relay/SPEC.md) | 1.1.0 | [changelog](wallet-relay/CHANGELOG.md) |
| [STACK Agent Site Payments (x402)](agent-site-payments/SPEC.md) | 1.0.0 | [changelog](agent-site-payments/CHANGELOG.md) |
| [STACK REST API](rest-api/SPEC.md) | 2.4.1 | [changelog](rest-api/CHANGELOG.md) |
| [STACK Credentials Files](credentials-files/SPEC.md) | 1.0.0 | [changelog](credentials-files/CHANGELOG.md) |
| [STACK Web Bot Auth Profile](web-bot-auth/SPEC.md) | 1.1.0 | [changelog](web-bot-auth/CHANGELOG.md) |
| [STACK Partner API](partner/SPEC.md) | 2.1.0 | [changelog](partner/CHANGELOG.md) |
| [STACK A2A Profile](a2a/SPEC.md) | 1.1.0 | [changelog](a2a/CHANGELOG.md) |
| [STACK Service MCP Calls](service-mcp/SPEC.md) | 1.0.0 | [changelog](service-mcp/CHANGELOG.md) |
| [STACK Network](network/SPEC.md) | 1.0.0 | [changelog](network/CHANGELOG.md) |
| [STACK Agent Runtime Sign-in](agent-auth/SPEC.md) | 1.0.0 | [changelog](agent-auth/CHANGELOG.md) |
| [STACK Agent Keys](agent-keys/SPEC.md) | 1.0.0 | [changelog](agent-keys/CHANGELOG.md) |
| [STACK Workload Identity Exchange](workload-identity/SPEC.md) | 1.0.0 | [changelog](workload-identity/CHANGELOG.md) |
| [STACK OAuth Server Profile](oauth-profile/SPEC.md) | 2.0.0 | [changelog](oauth-profile/CHANGELOG.md) |
| [STACK Agent Identity](agent-identity/SPEC.md) | 1.0.0 | [changelog](agent-identity/CHANGELOG.md) |
| [STACK Security Monitoring Export](siem-export/SPEC.md) | 1.0.0 | [changelog](siem-export/CHANGELOG.md) |
| [STACK Single Sign-on Profile](sso-login/SPEC.md) | 1.3.1 | [changelog](sso-login/CHANGELOG.md) |

<!-- /spec:generated -->

| Folder | What it defines |
|---|---|
| [`passport/`](passport/SPEC.md) | The Passport token, its claims and scopes, lifetimes, delegation rules, offline and online verification, and the revocation channel. |
| [`control-socket/`](control-socket/SPEC.md) | The decision exchange between STACK and a customer's own server, Standard Webhooks signing, timeouts and failure handling, and the signed events stream with its gap markers. |
| [`provider-interface/`](provider-interface/SPEC.md) | The adapter contract an account piece implements (`find`, `open`, `close`), its error classes and crash-safety rules. |
| [`record/`](record/SPEC.md) | Signed claims, the audit hash chain and evidence packs, and what an offline verifier must check. |
| [`mcp-tools/`](mcp-tools/SPEC.md) | The MCP tool catalog, generated from the code: names, schemas, annotations and profiles. |
| [`webhooks/`](webhooks/SPEC.md) | The one signing scheme for every request STACK sends to someone else's server (Standard Webhooks): headers, signed string, secrets and rotation, receiver rules, retries and the body of each kind of request. |
| [`authority-receiver/`](authority-receiver/SPEC.md) | How an outside receiver (an authority, a bank, any service that asks for information about an agent's owner) opens a presentation request, gets only what it asked for, checks it and answers with a signed receipt; the proof provider callback and the enterprise OpenID Connect approval. |
| [`wallet-relay/`](wallet-relay/SPEC.md) | The one request an agent sends to pay from its owner's wallet: the typed data it may send, the signature it makes with its own key, the checks STACK makes before it passes the request on, and the result. STACK holds no key to the wallet. |
| [`agent-site-payments/`](agent-site-payments/SPEC.md) | The HTTP 402 payment exchange (x402 version 2, USDC on Base) an agent's website offers on a priced path: the requirements, the payment header, what the site checks, settlement after the page is served, and the reason codes. |
| [`catalogue/`](catalogue/SPEC.md) | The catalogue of everything an agent can use through its account: the document, its prices, trust markings, version and caching, how an entry is run, and what a publisher does with provider text. |
| [`rest-api/`](rest-api/SPEC.md) | The REST API: the OpenAPI document of every route the engine serves, the error envelope and the error codes, the governance step-up, the refusals of a customer's controls, the `402` answers and the model cost cap. |
| [`credentials-files/`](credentials-files/SPEC.md) | The local files of the command line and the SDKs under `~/.stack`: the operator's sign-in and an agent's key, how a refresh token is rotated under a lock, and how an agent signs its requests. |
| [`web-bot-auth/`](web-bot-auth/SPEC.md) | The profile of RFC 9421 and the Web Bot Auth drafts STACK signs an agent's outbound requests with: covered components, parameters, keys, the signed key directory, key management, and what a site that checks must do. |
| [`partner/`](partner/SPEC.md) | The partner API: partner-managed accounts opened under the partner's own reference, the customer's invitation, releasing an account to its customer, an account's inbound webhooks and the passports issued under an account. |
| [`a2a/`](a2a/SPEC.md) | The A2A profile: the agent cards STACK serves, the JSON-RPC endpoint, `tasks/send`, `tasks/get` and `tasks/cancel`, task states and errors. |
| [`service-mcp/`](service-mcp/SPEC.md) | What STACK sends to a connected service's MCP endpoint when an agent lists or calls its tools: the session around each call, the headers, the limits, and what the endpoint must answer. |
| [`network/`](network/SPEC.md) | The services a self-hosted install or a counterparty calls: install keys and the signed install proof, countersigned passports, the STACK-verified statement, the signed revocation list and its push, detection rules and the classifier, and licence key revocation, with test vectors. |
| [`agent-auth/`](agent-auth/SPEC.md) | How an agent signs in from its own machine: key enrollment by proof of possession, the 60-second agent JWT (issuer `stack-sdk`) and the checks on it, and fleet enrollment of workers. |
| [`agent-keys/`](agent-keys/SPEC.md) | An agent's key identifier and public key set, and how a customer who holds the key signs a claim envelope and how a verifier checks it. |
| [`workload-identity/`](workload-identity/SPEC.md) | Exchanging a SPIFFE JWT-SVID or a WIMSE Workload Identity Token for a Passport, what a deployment configures to trust an issuer, and workload enrollment into a fleet. |
| [`oauth-profile/`](oauth-profile/SPEC.md) | What STACK's OAuth authorization server implements, as a profile of the RFCs: discovery, client metadata documents, PKCE, scopes, token lifetimes, rotation and revocation. |
| [`siem-export/`](siem-export/SPEC.md) | The security-monitoring export of a self-managed install: the record of the two streams, delivery and what "took" means for each transport, RFC 5424 syslog over UDP, TCP and TLS, newline-delimited JSON over HTTPS with a bearer token, what a collector must do, and how failures are retried. |
| [`sso-login/`](sso-login/SPEC.md) | Single sign-on through a customer's own OpenID provider, as a profile of OpenID Connect Core: the sign-in address and the slug that names the organisation, the authentication request, the callback and the state bound to the browser, the token request, the ID token checks, finding the person, the 60 second single-use handoff, and what the provider must provide. |
| [`agent-identity/`](agent-identity/SPEC.md) | Who an agent is, answered on request on STACK's own domain: the lookup by key id, site or id, the answer and the statement STACK signs (the agent, its status and the owner's standing as two yes-or-no facts), what it never carries, the one answer for an agent that is not found, the machine files an agent has there (its signed A2A card, MCP server card and key directory) and the owner's switches. |

Each folder holds `SPEC.md` (normative text), `CHANGELOG.md` and, where the code has a schema, `schemas/` with JSON Schemas (draft-07) generated from the reference implementation.

## Conformance

[`conformance/`](conformance/README.md) is a test kit you point at your own implementation: a decision server, an events receiver, a Passport verifier, a provider adapter, a record verifier, a catalogue document, an agent's sign-in and key enrollment, a verifier of a workload identity token, an OAuth server, and a server's Passport verification, revocation and delegation. The reference implementations in this repository run the same tests in continuous integration. The kit also judges a security-monitoring exporter and collector, a single sign-on relying party, a Web Bot Auth signer, site or key directory, a partner API, an A2A endpoint, the services and signed objects of the network, the tool listing of an MCP server, and an agent identity server or verifier.

## Versioning

Every specification has a semantic version (`MAJOR.MINOR.PATCH`) stated in its `SPEC.md` and recorded in its `CHANGELOG.md`.

- **Major**: a change that makes a conforming implementation stop conforming.
- **Minor**: an addition that conforming implementations can ignore (an optional field, a new action kind, a new tool).
- **Patch**: a correction of wording that changes no behaviour.

Wire formats that carry their own version (`"version": "1"`, `pack_version`, `envelope_version`) change only in a major version of the specification, and each version of a wire format stays additive for at least 24 months after its first release.

## Generated parts

JSON Schemas, the MCP tool catalog and the tables of constants inside the specifications are written by `scripts/generate-spec.mjs` from the code. `node scripts/generate-spec.mjs --check` fails if anything differs from what the code produces; it runs in continuous integration. Do not edit generated files by hand.

## Reporting a problem

A defect in a specification (an ambiguity, a contradiction between the text and the schema, a missing case) is reported as an issue. A security problem is reported as described in `SECURITY.md` at the root of the repository.
