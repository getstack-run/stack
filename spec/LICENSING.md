# Licensing

This repository is licensed in layers. Each folder has one licence, stated in the `LICENSE` file at the root and in the folder; the full texts are in `LICENSES/`.

| Layer | Folders | Licence |
|---|---|---|
| Specifications, conformance kit, example decision server | `spec/`, `examples/` | Apache License 2.0 |
| Command line, verifier | `packages/cli`, `packages/verifier` | Apache License 2.0 |
| SDKs | `packages/sdk` (TypeScript), `sdk-python` (Python) | MIT License |
| Engine | The folders the root `LICENSE` lists under the Fair Core License: the API, the worker and the MCP server in `apps/`, the shared, vault, drop-off and MCP packages in `packages/`, `deploy/`, and `docs/self-managed/` | Fair Core License 1.0, ALv2 future licence (FCL-1.0-ALv2) |

The copyright holder of every layer is Tomi Lupsakko, 2026. The specifications and everything an implementer needs to talk to STACK, or to replace a part of it, are under permissive licences: you can build a competing implementation of any specification, a verifier, a decision server or a provider adapter, and use the SDKs in a commercial product, with no permission and no payment. The engine, the software that runs the service, is source-available under a licence that lets anyone read, run, modify and redistribute it for any purpose except a competing commercial product or service, and that turns into the Apache License 2.0 two years after each version is made available.

Contributions are accepted under the [Contributor Licence Agreement](../CLA.md), which leaves the contributor the copyright and lets the maintainer relicense. See [CONTRIBUTING.md](../CONTRIBUTING.md).

## The Fair Core License

The text in `LICENSES/FCL-1.0-ALv2.md` is the publisher's, unmodified apart from the copyright notice, and was compared with the published text at <https://fcl.dev/> (source: <https://github.com/keygen-sh/fcl.dev>) on 21 October 2026. The licence was drafted by Heather Meeker and contributed by Keygen, and is a derivative of the Functional Source License (Sentry) with terms from the Elastic License 2.0.

This page summarises the licence and quotes it where the wording matters. If this page and the licence differ, the licence governs.

**Version.** There is one version, 1.0, in two variants that differ only in the open source licence it turns into: `FCL-1.0-ALv2` (Apache 2.0) and `FCL-1.0-MIT` (MIT). This repository uses the Apache 2.0 variant, which matches its other licences. The licence has no SPDX identifier, so package manifests say `SEE LICENSE IN LICENSE` and file-level tags, if used, are `LicenseRef-FCL-1.0-ALv2`. It is not an OSI-approved open source licence; it is a Fair Source licence that converts to one.

**The Software.** The licence defines it this way:

> The "Software" is each version of the software that we make available under these Terms and Conditions, as indicated by our inclusion of these Terms and Conditions with the Software.

So the licence, and its two-year clock, applies to each version separately.

**What it allows.** The grant is:

> Subject to your compliance with this License Grant and the Limitations, Patents, Redistribution and Trademark clauses below, we hereby grant you the right to use, copy, modify, create derivative works, publicly perform, publicly display and redistribute the Software for any Permitted Purpose identified below.

A Permitted Purpose is any purpose other than a Competing Use:

> A Competing Use means making the Software available to others in a commercial product or service that:
>
> 1. substitutes for the Software;
> 2. substitutes for any other product or service we offer using the Software that exists as of the date we make the Software available; or
> 3. offers the same or substantially similar functionality as the Software.

and the licence lists what is specifically a Permitted Purpose: "for your internal use and access", "for non-commercial education", "for non-commercial research", and "in connection with professional services that you provide to a licensee using the Software in accordance with these Terms and Conditions". Running STACK for your own agents, on your own servers, for your own use is internal use and access. Whether something else is a Competing Use is decided by the text above, not by this page.

**Key-gated features.** The licence says:

> You must not move, change, disable, or circumvent the license key functionality in the Software; or modify any portion of the Software protected by the license key to:
>
> 1. enable access to the protected functionality without a valid license key; or
> 2. remove the protected functionality.

So the engine features that a licence key unlocks stay gated while the FCL governs that version.

**Conversion.** Every version also carries this grant:

> We hereby irrevocably grant you an additional license to use the Software, under the Apache License, Version 2.0, that is effective on the second anniversary of the date we make the Software available. On or after that date, you may use the Software under the Apache License, Version 2.0 [...]

The grant covers "the Software", which is each version with everything in it, including the key-gated features; it is not limited to the part of the code that needs no key. From the second anniversary of the date a version was made available, that version may be used under Apache 2.0, which has no key restriction. The clock runs per version: a later version starts its own two years, and an earlier version converts earlier. Every public release is tagged on the day it is published, so the date each version was made available is on record.

**Patents.** The patent wording is narrow:

> To the extent your use for a Permitted Purpose would necessarily infringe our patents, the license grant above includes a license under our patents. If you make a claim against any party that the Software infringes or contributes to the infringement of any patent, then your patent license to the Software ends immediately.

It is not the broad, express patent grant of Apache 2.0 section 3, and it covers only uses for a Permitted Purpose. Once a version converts, Apache 2.0 applies to it, with that licence's own patent grant and termination clause.

**Redistribution.**

> The Terms and Conditions apply to all copies, modifications and derivatives of the Software.
>
> If you redistribute any copies, modifications or derivatives of the Software, you must include a copy of or a link to these Terms and Conditions and not remove any copyright or other proprietary notices provided in or with the Software.

**Disclaimer.** The software is provided "as is" without warranties, and the licensor has no liability to you arising out of or related to the Software, including indirect, special, incidental or consequential damages. The licence adds that if the disclaimer section is unenforceable under applicable law, "the licenses granted herein are void".

**Trademarks.**

> Except for displaying the License Details and identifying us as the origin of the Software, you have no right under these Terms and Conditions to use our trademarks, trade names, service marks or product names.

**Fit for this project.** Features unlocked by a licence key (single sign-on and user provisioning, roles, security-monitoring connectors, signed evidence exports and compliance reports, partner features, long-term support versions) can sit in the same code base and the same licence as the rest of the engine, which is what the FCL is designed for, and they become Apache 2.0 after two years. STACK's hosted detection rules, classifier and network services are not part of the Software and are not licensed here.
