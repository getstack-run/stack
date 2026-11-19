#!/usr/bin/env node
// The reference receiver as a program: reads one JSON object `{ op, config, input }` on
// stdin and writes `{ "result": ... }` or `{ "error": "..." }` on stdout. This is the
// shape `stack-conformance authority --command` drives, so a receiver in any language
// can be tested by writing this one small adapter around it.

import { createReceiver } from './authority-receiver.mjs';

let text = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) text += chunk;

try {
  const { op, config, input } = JSON.parse(text);
  const receiver = createReceiver(config);
  let result;
  switch (op) {
    case 'authorization': result = receiver.authorization(input); break;
    case 'signPresentationRequest': result = receiver.signPresentationRequest(input.fields, { now: input.now }); break;
    case 'signReceipt': result = receiver.signReceipt(input); break;
    case 'openPresentation': result = receiver.openPresentation(input.jwe, { now: input.now, expected: input.expected }); break;
    case 'verificationDocument': result = receiver.verificationDocument(input); break;
    default: throw new Error(`unknown op ${op}`);
  }
  process.stdout.write(JSON.stringify({ result }));
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
}
