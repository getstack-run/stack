# STACK

STACK is one runtime boundary between an AI agent and the systems it uses: a signed Passport that says who the agent is and what it may do, credentials injected so the agent does not hold them, detectors on what flows through, a record of everything it does that anyone can verify offline, and revocation.

This repository holds the parts of STACK you can read, build on and run, in layers under different licences:

- The written specifications, the conformance kit, the command line, the verifier for signed records and the examples are under the Apache License 2.0.
- The TypeScript and Python SDKs are under the MIT License.
- The engine, the software that runs STACK on your own servers (the API, the worker, the MCP server and the packaging to run them), is source-available under the Fair Core License. Each version turns into the Apache License 2.0 two years after it is published (see `spec/LICENSING.md`).

## What is here

- `spec`: The written specifications, their JSON Schemas, the conformance kit and its fixtures. Licence: Apache-2.0.
- `packages/sdk`: The TypeScript SDK. Licence: MIT.
- `sdk-python`: The Python SDK. Licence: MIT.
- `packages/cli`: The command-line client. Licence: Apache-2.0.
- `packages/verifier`: The offline verifier for signed records. Licence: Apache-2.0.
- `examples/control-socket`: The example decision server. Licence: Apache-2.0.
- `tsconfig.base.json`, `turbo.json`, `.dockerignore`, `.prettierrc`, `tooling/build-stamp.mjs`, `tooling/build-stamp.d.mts`, `pnpm-workspace.yaml`: The build scaffold the packages above share. Licence: Apache-2.0.
- `apps/api`, `apps/worker`, `apps/mcp-server`, `packages/shared`, `packages/vault`, `packages/dropoff`, `packages/mcp-server`, `deploy`, `docs/self-managed`, `.github/workflows/engine-images.yml`, `scripts/licence-dev.mjs`: The engine, under the Fair Core License: the rail (passports, Missions, proxy, model gateway, MCP server, connections, drop-offs, agent-to-agent), the pattern detectors with their built-in rules, the controls (policy engine, limits, held actions, reviews, approvals, the control socket), the record, the worker, and the self-managed packaging. STACK's hosted business (accounts and their pieces, billing, the skills marketplace and the Console glue) is not part of this repository; the engine reaches none of it except through the seams it declares (see docs/self-managed/README.md). Memory (the knowledge graph and its engine) is hosted only: it is part of the account, and the engine app is not exported. The STACK network's server side (installs, countersignatures, cross-company revocation, the detection and classify services, licence revocation) is STACK's paid hosted layer and is not exported either: the engine keeps only the client that calls it with a licence key. Licence: FCL-1.0-ALv2.
- `scripts/generate-spec.mjs`, `scripts/generate-spec-identity.mjs`, `scripts/generate-spec-interfaces.mjs`, `scripts/generate-spec.test.mjs`, `scripts/lib/rest-api-spec.mjs`, `scripts/lib/route-scope-hook.mjs`, `scripts/rest-api-spec.test.mjs`: Tooling that needs the engine to run: the generator of the specification's schemas and tool catalog. Licence: Apache-2.0.

Licences differ by folder. `LICENSE` at the root lists them and each folder carries its own `LICENSE`; the full texts are in `LICENSES/`. What each licence means for you is in `spec/LICENSING.md`.

## Start here

- **Build an implementation of a specification.** Read [`spec/`](spec/README.md): the Passport, the control socket protocol, the provider interface, the record format and the MCP tool catalog. Run the [conformance kit](spec/conformance/README.md) against what you build.
- **Verify a signed record offline**, without trusting STACK:

  ```bash
  npx @getstackrun/verify pack.json
  ```

- **Write your own control server**, the server that decides what your agents may do: start from [`examples/control-socket`](examples/control-socket/README.md).
- **Use the SDKs and the command line**: [`packages/sdk`](packages/sdk/README.md), [`sdk-python`](sdk-python/README.md), [`packages/cli`](packages/cli/README.md).

## Building

Node 22 or later and pnpm (the version pinned in `package.json`) are required.

```bash
pnpm install
pnpm build
pnpm test
```

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) first: contributions need a signed [contributor licence agreement](CLA.md). Report a vulnerability as [SECURITY.md](SECURITY.md) describes, never in a public issue. Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md). The name and logo are covered by the [trademark policy](TRADEMARKS.md).

Repository: https://github.com/getstack-run/stack
