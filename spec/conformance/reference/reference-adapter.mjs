// The reference provider adapter: an adapter for a fake provider that keeps its resources in memory, written to
// the provider interface (spec/provider-interface/SPEC.md). It is what the kit's own tests run the `provider`
// suite against, and a starting point for an adapter of your own: it shows the four things the suite checks, which are
// that `find` has no side effect, that `open` is safe to repeat after a crash, that `close` succeeds when the
// resource is already gone, and that every failure is one of the four error classes with a code and no credential in
// its message.
//
// Run it through the command line, the way you would run your own:
//
//   node bin/stack-conformance.mjs provider --module reference/reference-adapter.mjs
//
// The adapter and the fake provider are `makeInboxDouble('none')` in doubles.mjs, where the same code is also
// built with one deliberate defect at a time to show that the suite fails each of them.

import { makeInboxDouble } from './doubles.mjs';

/** The harness the command line expects: the options of `runProviderAdapterSuite`. */
export default function createHarness() {
  return makeInboxDouble('none');
}
