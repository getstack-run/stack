# Changelog: STACK Service MCP Calls

This specification follows semantic versioning. A major version changes what a conforming endpoint must accept or answer; a minor version adds optional headers or methods that existing endpoints can ignore; a patch version corrects wording.

## 1.0.0 - 2026-11-08

Initial public release.

- What STACK sends to a connected service's MCP endpoint for one call from an agent: `initialize`, `notifications/initialized`, the call, and the end of the session, with the headers of each.
- What the endpoint must answer, the limits STACK holds it to, and what this version does not define.
- The `service-mcp` suite of the conformance kit.
