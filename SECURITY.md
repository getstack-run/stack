# Security

STACK handles credentials, identities and payment instructions on behalf of AI agents. Reports about its security are taken seriously and handled privately.

## Reporting a vulnerability

Do not open a public issue or pull request. Report privately through the contact details at https://getstack.run/security. Include the affected part (a specification, the SDKs, the command line, the verifier, the engine), the steps to reproduce, and the impact you observed. Do not send credentials or personal data.

We confirm receipt, ask for anything missing, limit the report to the people who must investigate it, and revoke exposed credentials before deeper investigation when the report shows active risk. Please give us a reasonable time to fix a problem before you disclose it, and tell us if you intend to publish.

## What is in scope

- Credential exposure or decryption outside the intended customer.
- Passport forgery, scope widening through delegation, or revocation not taking effect.
- A flaw in a specification that makes a conforming implementation insecure (for example a signature check that can be bypassed by following the text).
- Tampering with a signed record that the verifier does not detect.
- A way to make the control socket allow an action its owner's server did not allow.
- Cross-customer data access.

## What is not

Findings that need physical access to a machine, social engineering of maintainers, volumetric denial of service, or missing hardening headers on a page that holds no data.

## Supported versions

The latest released version of each package, and the current specification versions listed in `spec/README.md`.

## Your own implementations

If you find that the conformance kit accepts an implementation that is insecure, that is a vulnerability in the kit: report it the same way.
