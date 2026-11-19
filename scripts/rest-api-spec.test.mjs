// node --test scripts/rest-api-spec.test.mjs
//
// The OpenAPI document of the engine's routes (spec/rest-api/openapi.json) is generated, and `generate-spec --check` proves it
// is current. These tests prove it is a sound OpenAPI 3.1 document of the engine: its references resolve, every path
// parameter of a template is declared and nothing else is, every operation id is unique, every operation says whether it
// takes a bearer credential, and the one error body in it is the one the specification publishes. They also read the
// source scan of the error codes on its own, and the module hook the generator loads the built API with.

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (path) => JSON.parse(readFileSync(join(ROOT, path), 'utf8'));
const document = read('spec/rest-api/openapi.json');
const { errorCodes, topLevelNamesForTest } = await import(pathToFileURL(join(ROOT, 'scripts/lib/rest-api-spec.mjs')).href).then(async (lib) => ({
  errorCodes: lib.errorCodes,
  topLevelNamesForTest: (await import(pathToFileURL(join(ROOT, 'scripts/lib/route-scope-hook.mjs')).href)).topLevelNames,
}));

const operations = Object.entries(document.paths).flatMap(([path, item]) => Object.entries(item).map(([method, operation]) => ({ path, method, operation })));

test('it is an OpenAPI 3.1 document in the draft-07 dialect the rest of the specification publishes', () => {
  assert.equal(document.openapi, '3.1.0');
  assert.equal(document.jsonSchemaDialect, 'http://json-schema.org/draft-07/schema#');
  assert.equal(document.info.license.identifier, 'Apache-2.0');
  assert.ok(operations.length > 250, `${operations.length} operations`);
});

test('every reference resolves', () => {
  const missing = [];
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (node && typeof node === 'object') {
      if (typeof node.$ref === 'string') {
        const target = node.$ref.replace(/^#\//, '').split('/').reduce((value, key) => value?.[key], document);
        if (target === undefined) missing.push(node.$ref);
      }
      Object.values(node).forEach(walk);
    }
  };
  walk(document);
  assert.deepEqual(missing, []);
});

test('every path parameter of a template is declared, and nothing else is declared as one', () => {
  for (const { path, method, operation } of operations) {
    const templated = [...path.matchAll(/\{([^}]+)\}/g)].map((match) => match[1]).sort();
    const declared = (operation.parameters ?? []).filter((parameter) => parameter.in === 'path').map((parameter) => parameter.name).sort();
    assert.deepEqual(declared, templated, `${method} ${path}`);
    for (const parameter of operation.parameters ?? []) {
      if (parameter.in === 'path') assert.equal(parameter.required, true, `${method} ${path} ${parameter.name}`);
    }
  }
});

test('every operation has a unique id, a tag, a security entry and a response', () => {
  const ids = operations.map(({ operation }) => operation.operationId);
  assert.equal(new Set(ids).size, ids.length);
  for (const { path, method, operation } of operations) {
    assert.match(operation.operationId, /^[a-z][A-Za-z0-9]*$/, `${method} ${path}`);
    assert.ok(operation.tags.length > 0, `${method} ${path}`);
    assert.ok(Array.isArray(operation.security), `${method} ${path}`);
    assert.ok(Object.keys(operation.responses).length > 0, `${method} ${path}`);
  }
});

test('an operation that takes a body says what it is, or says that it does not', () => {
  for (const { path, method, operation } of operations) {
    if (!['post', 'put', 'patch'].includes(method)) continue;
    assert.ok(operation.requestBody || operation['x-stack-body'] === 'not described', `${method} ${path}`);
  }
});

test('the error body in the document is the published envelope', () => {
  const published = read('spec/rest-api/schemas/ErrorEnvelope.json');
  const { $schema, $id, title, ...body } = published;
  assert.ok($schema && $id && title === 'ErrorEnvelope');
  assert.deepEqual(document.components.schemas.ErrorEnvelope, body);
});

test('the request bodies of the engine are the schemas its handlers parse with', () => {
  const body = (method, path) => document.paths[path][method].requestBody.content['application/json'].schema;
  const create = body('post', '/v1/dropoffs');
  assert.ok(create.$ref.startsWith('#/components/schemas/'));
  const resolved = document.components.schemas[create.$ref.split('/').pop()];
  assert.equal(resolved.type, 'object');
  assert.ok(resolved.required.includes('from_agent'));
  // A drop-off names one recipient or several: neither is required by the schema itself, the handler asks for exactly one of them.
  assert.ok(resolved.properties.to_agent && resolved.properties.to_agents);
  // A handler that reads its body with more than one schema accepts what any of them accepts.
  assert.ok(Array.isArray(body('post', '/v1/missions').anyOf));
});

test('the document names no route of STACK\'s own deployment', () => {
  const hostedOnly = ['/v1/billing', '/v1/accounts', '/v1/admin', '/v1/skills', '/v1/drive', '/v1/memory', '/v1/network'];
  for (const prefix of hostedOnly) {
    assert.equal(Object.keys(document.paths).filter((path) => path === prefix || path.startsWith(`${prefix}/`)).length, 0, prefix);
  }
});

test('the scan of error codes reads a code from every form the source raises one in', () => {
  const codes = new Map(errorCodes(ROOT).map((entry) => [entry.code, entry.statuses]));
  assert.deepEqual(codes.get('GOVERNANCE_APPROVAL_REQUIRED'), [403]); // super(message, 'CODE', 403, details)
  assert.deepEqual(codes.get('WORKLOAD_TOKEN_EXPIRED'), [401]); // ['CODE', 401] in a table
  assert.deepEqual(codes.get('INTERNAL_ERROR'), [500]); // an envelope a handler writes, with the status that sends it
  assert.deepEqual(codes.get('OIDC_CONFIG_EXISTS'), [409]); // super(message, TABLE_CODES[kind], 409)
  assert.ok(!codes.has('NOT_AN_ERROR_CODE'));
  // Nothing of the hosted layer is read: the public repository reads the same files.
  assert.ok(!codes.has('INSUFFICIENT_CREDITS'));
});

test('the module hook names every constant and import of a built module', () => {
  const names = topLevelNamesForTest([
    "import { a, b as c, type D } from './x.js';",
    "import e from 'e';",
    "import * as f from 'f';",
    "import g, { h } from 'g';",
    'const Local = 1;',
    'export const Exported = 2;',
    '  const indented = 3;',
  ].join('\n'));
  assert.deepEqual(names.sort(), ['Exported', 'Local', 'a', 'c', 'D', 'e', 'f', 'g', 'h'].sort());
});

// The hosted document stays in the private repository: the exporter stops at a src/hosted folder, so a document that
// lives in one is never in the public tree. (Runs where the exporter's manifest is: the private repository only.)
const MANIFEST = join(ROOT, 'scripts', 'public-repo', 'manifest.json');
test("the document of the routes only STACK's own deployment serves is under a folder the public export never carries", { skip: !existsSync(MANIFEST) }, () => {
  const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
  const hostedDocument = 'apps/api/src/hosted/openapi.hosted.json';
  assert.ok(existsSync(join(ROOT, hostedDocument)), 'the hosted document is missing');
  assert.ok(manifest.hosted_boundary.segments.some((segment) => `/${hostedDocument}`.includes(`/${segment}/`)), 'no hosted boundary segment contains the hosted document');
  // And no group lists it for export.
  const listed = manifest.groups.flatMap((group) => group.include ?? []);
  assert.ok(!listed.includes(hostedDocument), 'the manifest lists the hosted document for export');
});
