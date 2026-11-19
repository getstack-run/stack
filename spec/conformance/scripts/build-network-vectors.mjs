#!/usr/bin/env node
// Writes (or, with --check, verifies) spec/network/test-vectors.json: the test
// vectors of the STACK network specification, produced from the public test keys
// in ../src/network-vectors.mjs with Node's crypto and nothing else. Running it
// twice writes the same bytes, on any machine.
//
//   node spec/conformance/scripts/build-network-vectors.mjs
//   node spec/conformance/scripts/build-network-vectors.mjs --check

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildNetworkVectors } from '../src/network-vectors.mjs';

const target = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'network', 'test-vectors.json');
const text = `${JSON.stringify(buildNetworkVectors(), null, 2)}\n`;

if (process.argv.includes('--check')) {
  const current = existsSync(target) ? readFileSync(target, 'utf8').replaceAll('\r\n', '\n') : null;
  if (current !== text) {
    console.error('spec/network/test-vectors.json differs from what the generator produces: run `node spec/conformance/scripts/build-network-vectors.mjs`.');
    process.exit(1);
  }
  console.log('spec/network/test-vectors.json is current');
} else {
  writeFileSync(target, text, 'utf8');
  console.log('wrote spec/network/test-vectors.json');
}
