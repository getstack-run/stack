# Contributing

Thank you for helping. This file says how to propose a change, and what you agree to when you do.

## Agree to the contributor licence agreement first

The code in this repository is licensed under more than one licence (see `LICENSE`), and the maintainers need to be able to keep it licensed sensibly as the project grows: for example by moving a part of it to a different open licence, or by offering it under additional terms. To make that possible, every contribution is made under the [Contributor Licence Agreement](CLA.md) in this repository. You keep the copyright in what you write; the agreement gives the maintainers the right to use it under the project's licences and to relicense it.

To agree, open your pull request. The CLA Assistant, an app installed on this repository, comments on it with a link the first time. Follow the link, sign in with your GitHub account, fill in the short form and tick the box; the check on the pull request turns green. You sign once, and it covers your later pull requests until you withdraw it for future contributions in writing. A pull request cannot be merged until the agreement is on record.

If you contribute on behalf of an employer or client, you must be authorised to agree for them: signing says you are, or that they have no rights in what you contribute. There is no separate form for companies.

Issues, comments and discussion posts are not contributions under the agreement and need no signature. Only what you submit in a pull request is.

Sign off every commit with `git commit -s` (a `Signed-off-by:` line with your real name and an address you can be reached at). It states that you wrote the change or have the right to submit it.

## Making a change

1. Open an issue first for anything larger than a fix, so we can say early whether it fits.
2. Fork, branch from `main`, and keep the change to one purpose.
3. Run the checks for the part you changed:

   ```bash
   pnpm install
   pnpm lint
   pnpm typecheck
   pnpm test
   ```

   The Python SDK has its own: `cd sdk-python && ruff check . && ruff format --check . && mypy src && python -m pytest -q`.
4. A change to a specification (`spec/`) is a change to a public contract. Say what it changes for implementers, add an entry to that specification's `CHANGELOG.md`, and bump its version according to `spec/README.md`. Schemas and the MCP tool catalog are generated: change the code, not the generated files.
5. A change to behaviour comes with a test that fails without it.
6. Open the pull request. A maintainer reviews it; we may ask for changes.

## What we will not merge

- Code you do not have the right to contribute.
- Credentials, tokens, keys or personal data, even as test data. Use clearly fake values.
- A change that weakens a security property (for example by passing an untrusted value where a verified one is required) without a reason we can document.
- Generated files edited by hand.

## Licences of what you contribute

A contribution to a folder is licensed under the licence of that folder, as the root `LICENSE` lists it, and also under the agreement above. Do not copy code into the repository from a project whose licence does not allow it.

## Conduct and security

Be kind and be direct; the [code of conduct](CODE_OF_CONDUCT.md) applies in every space of the project. Report a security problem as [SECURITY.md](SECURITY.md) says, not in an issue.
