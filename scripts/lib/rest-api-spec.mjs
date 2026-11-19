// The REST API specification, written from the code.
//
//   routeTables()        the routes the built API registers, from the same registration the server runs
//                        (apps/api/src/route-table.ts), for the engine and, when the hosted layer is present, for STACK's own
//   createSourceAnalyser()  what the source of a route file says about each route: the schemas its handler parses the body,
//                        the query and the path parameters with, and the success status it answers
//   buildOpenApi()       one OpenAPI 3.1 document from a route table, the OAuth ceiling of each route and the schemas
//   errorCodes()         every error code the engine's source raises, with the status it raises it with
//
// The generator (scripts/generate-spec.mjs) writes spec/rest-api/openapi.json from the engine's routes, and in the
// private build a second document of the routes only STACK's own deployment serves. A route with no entry cannot
// exist: the document is the route table.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createRequire, register } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';

export const OPENAPI_VERSION = '3.1.0';
/** The dialect of every schema in the document: the same draft the rest of the specification publishes. */
export const SCHEMA_DIALECT = 'http://json-schema.org/draft-07/schema#';

const PARSERS = new Set(['parse', 'safeParse', 'parseAsync', 'safeParseAsync']);
const METHODS = new Set(['get', 'post', 'put', 'patch', 'delete']);

// ─── Reading the built API ──────────────────────────────────────────

/**
 * The route tables of the built API. The engine's lists what `startApi(null)` registers; with the hosted layer present,
 * `hosted` lists what STACK's own deployment registers, so its routes only are `hosted` minus `engine`.
 * Everything runs with services that answer nothing: no server starts and no connection opens.
 */
export async function routeTables(root, { hostedLayer }) {
  // The settings that decide which routes exist (OAuth is optional in an install and on in the hosted deployment).
  // The listing needs the configuration to be well formed and nothing else: no value here is used to reach anything.
  process.env.OAUTH_ENABLED = 'true';
  process.env.STACK_DEPLOYMENT = 'self_managed';
  process.env.STACK_API_BASE_URL = 'http://localhost:3000';
  const dist = join(root, 'apps', 'api', 'dist');
  if (!existsSync(join(dist, 'route-table.js'))) throw new Error('apps/api/dist/route-table.js is missing: run `pnpm exec turbo build` first');
  register(pathToFileURL(join(root, 'scripts', 'lib', 'route-scope-hook.mjs')).href);
  const table = await import(pathToFileURL(join(dist, 'route-table.js')).href);
  const scopesModule = await import(pathToFileURL(join(dist, 'middleware', 'oauth-scope.js')).href);
  const engine = await table.collectRouteTable(null);
  let hosted = null;
  let hostedScopes = {};
  if (hostedLayer && existsSync(join(dist, 'hosted', 'extension.js'))) {
    const extension = await import(pathToFileURL(join(dist, 'hosted', 'extension.js')).href);
    hosted = await table.collectRouteTable(extension.hostedApiExtension());
    const routeScopes = await import(pathToFileURL(join(dist, 'hosted', 'middleware', 'route-scopes.js')).href);
    hostedScopes = routeScopes.HOSTED_ROUTE_SCOPES;
  }
  return { engine, hosted, scopes: { ...scopesModule.ENGINE_ROUTE_SCOPES, ...hostedScopes }, dist };
}

/** The module scope of a route file's built module: its constants and imports by name (see route-scope-hook.mjs). */
export async function moduleScope(dist, file) {
  const rel = file.replace(/^apps\/api\/src\//, '').replace(/\.ts$/, '.js');
  const path = join(dist, rel);
  if (!existsSync(path)) return null;
  const loaded = await import(pathToFileURL(path).href);
  return loaded.__stackScope ?? null;
}

// ─── Reading the source of a route file ─────────────────────────────

const isZod = (value) => value !== null && typeof value === 'object' && typeof value.safeParse === 'function' && value._def !== undefined;

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function literalPath(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return { path: node.text, pattern: null };
  if (ts.isTemplateExpression(node)) {
    // `/v1/passports/${action}`: every substitution stands for one path segment.
    let text = node.head.text;
    let source = escapeRegExp(node.head.text);
    for (const span of node.templateSpans) {
      text += `\${}${span.literal.text}`;
      source += `[^/]+${escapeRegExp(span.literal.text)}`;
    }
    return { path: text, pattern: new RegExp(`${source}$`) };
  }
  return null;
}

const unwrap = (node) => {
  let current = node;
  for (;;) {
    if (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isNonNullExpression(current) || ts.isSatisfiesExpression(current)) current = current.expression;
    else if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) current = current.left;
    else return current;
  }
};

/** `Name` or `ns.Name`: the schemas a route names. A computed expression is left unresolved. */
function schemaName(expression) {
  const text = expression.getText();
  return /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/.test(text) ? text : null;
}

const ROLES = ['body', 'query', 'params'];
const emptyFacts = () => ({ body: [], query: [], params: [], statuses: [] });

/**
 * Reads the source of the API's route files. For each route a file registers it says which schemas the handler parses
 * the body, the query and the path parameters with, and the status it answers on success. A handler that hands the
 * request (or its body, query or parameters) to a function, in its own file or in one it imports from a relative path,
 * is followed into that function, to a depth of five, because the parse is often there. Each schema is reported with
 * the file it is named in, since a constant of the same name can mean different things in different files.
 */
export function createSourceAnalyser(root) {
  const files = new Map();
  const abs = (file) => join(root, file);

  const load = (file) => {
    if (files.has(file)) return files.get(file);
    const path = abs(file);
    if (!existsSync(path)) {
      files.set(file, null);
      return null;
    }
    const source = ts.createSourceFile(file, readFileSync(path, 'utf8'), ts.ScriptTarget.ES2022, true);
    const functions = new Map();
    const imports = new Map();
    // A helper is often declared inside the function that registers the routes: every named function of the file counts.
    const collect = (node) => {
      if (ts.isFunctionDeclaration(node) && node.name && node.body && !functions.has(node.name.text)) functions.set(node.name.text, node);
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) && !functions.has(node.name.text)) {
        functions.set(node.name.text, node.initializer);
      }
      ts.forEachChild(node, collect);
    };
    collect(source);
    for (const statement of source.statements) {
      if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings)) {
        for (const element of statement.importClause.namedBindings.elements) {
          imports.set(element.name.text, { specifier: statement.moduleSpecifier.text, imported: (element.propertyName ?? element.name).text });
        }
      }
    }
    const entry = { file, source, functions, imports };
    files.set(file, entry);
    return entry;
  };

  /** The file a relative import names, from the repository root, or null. */
  const resolveImport = (fromFile, specifier) => {
    if (!specifier.startsWith('.')) return null;
    const base = join(fromFile, '..', specifier.replace(/\.js$/, '')).replaceAll('\\', '/');
    for (const candidate of [`${base}.ts`, `${base}/index.ts`]) if (existsSync(abs(candidate))) return candidate;
    return null;
  };

  /** What a function does with the request, the body, the query and the parameters it is given. */
  const inspect = (file, fn, taint, depth, seen) => {
    const out = emptyFacts();
    const roleOf = (expression) => {
      const node = unwrap(expression);
      if (ts.isIdentifier(node)) {
        if (taint.request.has(node.text)) return 'request';
        for (const role of ROLES) if (taint[role].has(node.text)) return role;
        return null;
      }
      if (ts.isPropertyAccessExpression(node) && ROLES.includes(node.name.text) && ts.isIdentifier(unwrap(node.expression)) && taint.request.has(unwrap(node.expression).text)) return node.name.text;
      return null;
    };
    const containsRole = (expression) => {
      let found = null;
      const visit = (n) => {
        if (found) return;
        const role = ts.isExpression(n) ? roleOf(n) : null;
        if (role && role !== 'request') { found = role; return; }
        ts.forEachChild(n, visit);
      };
      visit(expression);
      return found;
    };

    const visit = (node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const role = roleOf(node.initializer);
        if (role === 'request') taint.request.add(node.name.text);
        else if (role) taint[role].add(node.name.text);
      }
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        if (ts.isPropertyAccessExpression(callee)) {
          if (PARSERS.has(callee.name.text) && node.arguments.length > 0) {
            const role = containsRole(node.arguments[0]);
            const name = schemaName(callee.expression);
            if (role && name) out[role].push({ name, file });
          }
          if ((callee.name.text === 'status' || callee.name.text === 'code') && node.arguments.length === 1 && ts.isNumericLiteral(node.arguments[0])) {
            out.statuses.push(Number(node.arguments[0].text));
          }
        } else if (ts.isIdentifier(callee) && depth < 5) {
          const here = load(file);
          let target = here.functions.has(callee.text) ? { file, fn: here.functions.get(callee.text), name: callee.text } : null;
          if (!target && here.imports.has(callee.text)) {
            const { specifier, imported } = here.imports.get(callee.text);
            const other = resolveImport(file, specifier);
            const loaded = other ? load(other) : null;
            if (loaded?.functions.has(imported)) target = { file: other, fn: loaded.functions.get(imported), name: imported };
          }
          if (target) {
            const next = { request: new Set(), body: new Set(), query: new Set(), params: new Set() };
            let passes = false;
            node.arguments.forEach((argument, index) => {
              const role = roleOf(argument);
              const parameter = target.fn.parameters[index];
              if (role && parameter && ts.isIdentifier(parameter.name)) {
                (role === 'request' ? next.request : next[role]).add(parameter.name.text);
                passes = true;
              }
            });
            const key = `${target.file}:${target.name}:${[...next.request, '|', ...next.body, '|', ...next.query, '|', ...next.params].join(',')}`;
            if (passes && !seen.has(key)) {
              const inner = inspect(target.file, target.fn, next, depth + 1, new Set([...seen, key]));
              for (const part of Object.keys(out)) out[part].push(...inner[part]);
            }
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    if (fn.body) visit(fn.body);
    return out;
  };

  /** The registrations of one route file, each with what its handler reads. */
  const registrationsOf = (file) => {
    const loaded = load(file);
    if (!loaded) return [];
    const registrations = [];
    const visitFile = (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && METHODS.has(node.expression.name.text) && node.arguments.length >= 2) {
        const path = literalPath(node.arguments[0]);
        if (path && path.path.startsWith('/')) {
          let handler = node.arguments[node.arguments.length - 1];
          if (ts.isIdentifier(handler) && loaded.functions.has(handler.text)) handler = loaded.functions.get(handler.text);
          let facts = emptyFacts();
          if (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler) || ts.isFunctionDeclaration(handler)) {
            const first = handler.parameters[0];
            const taint = { request: new Set(first && ts.isIdentifier(first.name) ? [first.name.text] : []), body: new Set(), query: new Set(), params: new Set() };
            facts = inspect(file, handler, taint, 0, new Set());
          }
          const unique = (list) => [...new Map(list.map((item) => [`${item.file}:${item.name}`, item])).values()];
          registrations.push({
            method: node.expression.name.text.toUpperCase(),
            path: path.path,
            pattern: path.pattern,
            body: unique(facts.body),
            query: unique(facts.query),
            params: unique(facts.params),
            statuses: facts.statuses,
          });
        }
      }
      ts.forEachChild(node, visitFile);
    };
    visitFile(loaded.source);
    return registrations;
  };

  const cache = new Map();
  return {
    registrationsOf: (file) => {
      if (!cache.has(file)) cache.set(file, registrationsOf(file));
      return cache.get(file);
    },
  };
}

/** The registration of a route in its file's analysis: the longest path the route's URL ends with. */
export function registrationOf(route, registrations) {
  let best = null;
  for (const registration of registrations) {
    if (registration.method !== route.method) continue;
    const matches = registration.pattern
      ? registration.pattern.test(route.url)
      : route.url === registration.path || route.url.endsWith(registration.path);
    if (matches && (!best || registration.path.length > best.path.length)) best = registration;
  }
  return best;
}

// ─── The error envelope and the codes ───────────────────────────────

/**
 * Every error code the engine's source raises, with the HTTP statuses it raises it with. Read from the source (the
 * hosted layer's folders are skipped, so the public repository and the private one read the same files): a code in a
 * `StackError` call or in a class that extends it (`'CODE', 403`), in the table of a class that maps a reason to a code
 * and a status (`['CODE', 400]`), and in an error envelope written out by a handler (`error: { code: 'CODE' }`, with the
 * status of the `.status(NNN)` call that sends it, or none).
 */
export function errorCodes(root, { includeHosted = false } = {}) {
  const roots = ['apps/api/src', 'packages/shared/src', 'packages/vault/src', 'packages/dropoff/src'];
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (name === 'node_modules' || name === 'dist' || (name === 'hosted' && !includeHosted)) continue;
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (path.endsWith('.ts') && !/\.(test|checks|d)\.ts$|test-support/.test(path)) files.push(path);
    }
  };
  for (const r of roots) if (existsSync(join(root, r))) walk(join(root, r));
  const found = new Map();
  const add = (code, status, file) => {
    const entry = found.get(code) ?? { code, statuses: new Set(), files: new Set() };
    if (status) entry.statuses.add(status);
    entry.files.add(file.slice(root.length + 1).replaceAll('\\', '/'));
    found.set(code, entry);
  };
  const CODE = /^[A-Z][A-Z0-9_]{3,}$/;
  for (const file of files.sort()) {
    const text = readFileSync(file, 'utf8');
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
    const statusOf = (node) => (node && ts.isNumericLiteral(node) && Number(node.text) >= 100 && Number(node.text) < 600 ? Number(node.text) : null);
    // A table of codes a class picks from by a reason (`const SSO_CODES = { reason: 'CODE' }`).
    const tables = new Map();
    const findTables = (node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && /_CODES$/.test(node.name.text) && node.initializer) {
        const literal = ts.isAsExpression(node.initializer) ? node.initializer.expression : node.initializer;
        if (ts.isObjectLiteralExpression(literal)) {
          const values = literal.properties.flatMap((property) => (ts.isPropertyAssignment(property) && ts.isStringLiteral(property.initializer) && CODE.test(property.initializer.text) ? [property.initializer.text] : []));
          tables.set(node.name.text, values);
          for (const value of values) add(value, null, file);
        }
      }
      ts.forEachChild(node, findTables);
    };
    findTables(sf);
    const visit = (node) => {
      // new StackError(message, 'CODE', 400) and super(message, 'CODE', 400)
      if ((ts.isNewExpression(node) && ts.isIdentifier(node.expression) && /Error$/.test(node.expression.text))
        || (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.SuperKeyword)) {
        const args = node.arguments ?? [];
        for (let i = 0; i + 1 < args.length; i += 1) {
          if (ts.isStringLiteral(args[i]) && CODE.test(args[i].text) && statusOf(args[i + 1]) !== null) add(args[i].text, statusOf(args[i + 1]), file);
          // super(message, TABLE_CODES[kind], 409)
          if (ts.isElementAccessExpression(args[i]) && ts.isIdentifier(args[i].expression) && tables.has(args[i].expression.text) && statusOf(args[i + 1]) !== null) {
            for (const code of tables.get(args[i].expression.text)) add(code, statusOf(args[i + 1]), file);
          }
        }
      }
      // ['CODE', 400] in a table
      if (ts.isArrayLiteralExpression(node) && node.elements.length === 2 && ts.isStringLiteral(node.elements[0]) && CODE.test(node.elements[0].text) && statusOf(node.elements[1]) !== null) {
        add(node.elements[0].text, statusOf(node.elements[1]), file);
      }
      // { error: { code: 'CODE' } } written by a handler, with the status of the call that sends it
      if (ts.isPropertyAssignment(node) && ts.isIdentifier(node.name) && node.name.text === 'error' && ts.isObjectLiteralExpression(node.initializer)) {
        for (const property of node.initializer.properties) {
          if (ts.isPropertyAssignment(property) && ts.isIdentifier(property.name) && property.name.text === 'code' && ts.isStringLiteral(property.initializer) && CODE.test(property.initializer.text)) {
            let status = null;
            for (let up = node.parent; up && status === null; up = up.parent) {
              if (ts.isCallExpression(up) && ts.isPropertyAccessExpression(up.expression) && up.expression.name.text === 'send') {
                const sender = up.expression.expression;
                if (ts.isCallExpression(sender) && ts.isPropertyAccessExpression(sender.expression) && ['status', 'code'].includes(sender.expression.name.text)) status = statusOf(sender.arguments[0]);
              }
            }
            add(property.initializer.text, status, file);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return [...found.values()]
    .map((entry) => ({ code: entry.code, statuses: [...entry.statuses].sort((a, b) => a - b), files: [...entry.files].sort() }))
    .sort((a, b) => a.code.localeCompare(b.code));
}

// ─── The document ───────────────────────────────────────────────────

const pascal = (text) => text.replace(/[^A-Za-z0-9]+/g, ' ').trim().split(' ').filter(Boolean).map((word) => word[0].toUpperCase() + word.slice(1)).join('');

export const ERROR_ENVELOPE_SCHEMA = {
  type: 'object',
  description: 'The body of every error answer: one object with one property, `error`.',
  required: ['error'],
  additionalProperties: false,
  properties: {
    error: {
      type: 'object',
      required: ['code', 'message'],
      properties: {
        code: { type: 'string', pattern: '^[A-Z][A-Z0-9_]*$', description: 'A stable code in upper case with underscores. A client decides what to do by the code, never by the message.' },
        message: { type: 'string', description: 'A sentence for a person. It can change between versions.' },
        details: { type: 'object', description: 'Fields that depend on the code. Absent when a code has none. Never a secret, a credential or text a caller sent.' },
      },
    },
  },
};

const sha = (text) => createHash('sha256').update(text).digest('hex');
const canonical = (value) => JSON.stringify(value, (_key, v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]])) : v));

const pathTemplate = (url) => url.replace(/:([A-Za-z0-9_]+)/g, '{$1}');

function operationId(method, url) {
  const words = url.split('/').filter(Boolean).map((segment) => (segment.startsWith(':') ? `By${pascal(segment.slice(1))}` : pascal(segment)));
  return `${method.toLowerCase()}${words.join('')}`;
}

function tagOf(url) {
  const segments = url.split('/').filter(Boolean);
  if (segments[0] === 'v1') return segments[1]?.startsWith(':') ? 'v1' : (segments[1] ?? 'v1');
  return segments[0]?.startsWith('.') ? 'well-known' : (segments[0] ?? 'root');
}

/**
 * One OpenAPI 3.1 document.
 *
 * @param {object} input
 * @param {Array<{method:string,url:string,file:string|null,authenticated:boolean,gates:string[]}>} input.routes the routes to document
 * @param {Record<string, string|null>} input.scopes the OAuth ceiling of each `METHOD url`
 * @param {(route) => object|null} input.registrationOf what the source says of a route
 * @param {(file: string) => Promise<Record<string, unknown>|null>} input.scopeOf the names of a source file's built module
 * @param {(schema: unknown) => object} input.toJsonSchema Zod to JSON Schema
 * @param {{ title: string, description: string, version: string }} input.info
 * @param {Record<string, { name: string, zod: unknown }>} input.responseSchemas the success answer of the routes whose answer is a named schema, by `METHOD url`
 */
export async function buildOpenApi({ routes, scopes, registrationOf: registrationFor, scopeOf, toJsonSchema, info, tagsDescription = {}, responseSchemas = {} }) {
  /** Every named schema a route used, to give each one component and a `$ref` where the same definition repeats. */
  const named = [];
  const operations = [];

  for (const route of routes) {
    const registration = registrationFor(route);
    const resolve = async ({ name, file }) => {
      const scope = await scopeOf(file);
      if (!scope) return null;
      let value = scope;
      for (const part of name.split('.')) {
        try { value = value?.[part]; } catch { return null; }
      }
      return isZod(value) ? value : null;
    };
    const roles = {};
    for (const role of ['body', 'query', 'params']) {
      const candidates = [];
      for (const reference of registration?.[role] ?? []) {
        const zod = await resolve(reference);
        if (zod) candidates.push({ name: reference.name, file: reference.file, zod });
      }
      if (candidates.length > 0) roles[role] = candidates;
    }
    operations.push({ route, registration, roles });
  }

  const schemaOf = (candidate) => {
    const converted = toJsonSchema(candidate.zod);
    const { $schema: _dropped, ...body } = converted;
    return body;
  };

  const paths = {};
  const usedIds = new Set();
  const tags = new Set();
  for (const { route, registration, roles } of operations) {
    const template = pathTemplate(route.url);
    const id = operationId(route.method, route.url);
    if (usedIds.has(id)) throw new Error(`two routes have the operation id ${id}`);
    usedIds.add(id);
    const tag = tagOf(route.url);
    tags.add(tag);

    const operation = { operationId: id, tags: [tag], summary: `${route.method} ${route.url}` };
    const key = `${route.method} ${route.url}`;
    const scope = Object.hasOwn(scopes, key) ? scopes[key] : undefined;
    if (scope === null) operation['x-stack-oauth-scope'] = 'none';
    else if (typeof scope === 'string') operation['x-stack-oauth-scope'] = scope;
    if (route.gates.length > 0) operation['x-stack-gates'] = [...route.gates].sort();
    operation.security = route.authenticated ? [{ bearerAuth: [] }] : [];

    const parameters = [];
    const params = roles.params?.[0] ? schemaOf(roles.params[0]) : null;
    for (const [, name] of route.url.matchAll(/:([A-Za-z0-9_]+)/g)) {
      const described = params?.properties?.[name];
      parameters.push({ name, in: 'path', required: true, schema: described ?? { type: 'string' } });
    }
    const query = roles.query?.[0] ? schemaOf(roles.query[0]) : null;
    if (query?.type === 'object' && query.properties) {
      const required = new Set(query.required ?? []);
      for (const [name, schema] of Object.entries(query.properties)) parameters.push({ name, in: 'query', required: required.has(name), schema });
    }
    if (parameters.length > 0) operation.parameters = parameters;

    const successStatus = registration?.statuses.find((status) => status >= 200 && status < 300) ?? 200;
    if (roles.body) {
      // A handler that reads the body with more than one schema (a probe first, then the full shape) accepts what any of them accepts.
      const references = roles.body.map((candidate) => ({
        $stackSchema: named.push({ identifier: candidate.name.split('.').pop(), file: candidate.file, schema: schemaOf(candidate) }) - 1,
      }));
      operation.requestBody = {
        required: true,
        content: { 'application/json': { schema: references.length === 1 ? references[0] : { anyOf: references } } },
      };
    } else if (['POST', 'PUT', 'PATCH'].includes(route.method)) {
      // Either the operation takes no body or its handler reads it where this generator does not look.
      operation['x-stack-body'] = 'not described';
    }

    const responses = {
      [String(successStatus)]: { description: 'Success. The body is not described by this document.' },
    };
    const answer = responseSchemas[key];
    if (answer) {
      const { $schema: _dropped, ...schema } = toJsonSchema(answer.zod);
      const index = named.push({ identifier: answer.name, file: null, schema }) - 1;
      responses[String(successStatus)] = { description: 'Success.', content: { 'application/json': { schema: { $stackSchema: index } } } };
    }
    if (roles.body || roles.query || roles.params) responses['400'] = { $ref: '#/components/responses/ValidationError' };
    if (route.authenticated) responses['401'] = { $ref: '#/components/responses/Unauthorized' };
    responses.default = { $ref: '#/components/responses/Error' };
    operation.responses = responses;

    paths[template] ??= {};
    paths[template][route.method.toLowerCase()] = operation;
  }

  // Name each schema that more than one operation shares or that has a name of its own; a name two files give to
  // different definitions is kept apart by the file it comes from.
  const byIdentifier = new Map();
  for (const [index, entry] of named.entries()) {
    const list = byIdentifier.get(entry.identifier) ?? [];
    list.push({ index, entry, hash: sha(canonical(entry.schema)) });
    byIdentifier.set(entry.identifier, list);
  }
  const components = {};
  const refOf = new Map();
  for (const [identifier, list] of [...byIdentifier].sort((a, b) => a[0].localeCompare(b[0]))) {
    const hashes = new Set(list.map((item) => item.hash));
    for (const item of list) {
      const stem = (item.entry.file ?? '').split('/').pop()?.replace(/\.ts$/, '') ?? '';
      const name = hashes.size === 1 ? identifier : `${pascal(stem)}${identifier}`;
      components[name] ??= item.entry.schema;
      if (sha(canonical(components[name])) !== item.hash) throw new Error(`two different schemas are both named ${name}`);
      refOf.set(item.index, `#/components/schemas/${name}`);
    }
  }
  const unref = (node) => {
    if (Array.isArray(node)) return node.map(unref);
    if (node && typeof node === 'object') {
      if ('$stackSchema' in node) return { $ref: refOf.get(node.$stackSchema) };
      return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, unref(v)]));
    }
    return node;
  };

  const errorResponse = (description) => ({ description, content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorEnvelope' } } } });
  const sortedPaths = Object.fromEntries(Object.keys(paths).sort().map((p) => [p, Object.fromEntries(Object.keys(paths[p]).sort().map((m) => [m, paths[p][m]]))]));
  const document = {
    openapi: OPENAPI_VERSION,
    jsonSchemaDialect: SCHEMA_DIALECT,
    info,
    servers: [{ url: 'https://{host}', variables: { host: { default: 'localhost:3000', description: 'The host of the deployment.' } } }],
    tags: [...tags].sort().map((name) => ({ name, ...(tagsDescription[name] ? { description: tagsDescription[name] } : {}) })),
    paths: unref(sortedPaths),
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', description: 'An API key (`sk_live_...`), an OAuth access token, a dashboard session or an agent credential, sent as `Authorization: Bearer <token>`.' },
      },
      responses: {
        Error: errorResponse('Any other error. The body is the error envelope.'),
        ValidationError: errorResponse('The request failed validation: `error.code` is `VALIDATION_ERROR` (or `INVALID_JSON`, `EMPTY_BODY`, `INVALID_REQUEST`, `UNSUPPORTED_MEDIA_TYPE`).'),
        Unauthorized: errorResponse('No credential, or one the server does not accept: `error.code` is `INVALID_API_KEY`.'),
      },
      schemas: { ErrorEnvelope: ERROR_ENVELOPE_SCHEMA, ...Object.fromEntries(Object.keys(components).sort().map((name) => [name, unref(components[name])])) },
    },
  };
  return document;
}

/** A list of the routes of a table that a document leaves out, or a document's operations that no route has. */
export function operationKeys(document) {
  const keys = [];
  for (const [path, item] of Object.entries(document.paths)) {
    for (const method of Object.keys(item)) keys.push(`${method.toUpperCase()} ${path.replace(/\{([^}]+)\}/g, ':$1')}`);
  }
  return keys.sort();
}

export function zodToJsonSchemaOf(root) {
  const sharedRequire = createRequire(join(root, 'packages', 'shared', 'package.json'));
  const { zodToJsonSchema } = sharedRequire('zod-to-json-schema');
  return (schema) => zodToJsonSchema(schema, { $refStrategy: 'none', target: 'jsonSchema7' });
}

// ─── What the generator writes ──────────────────────────────────────

function quietly(work) {
  const levels = ['log', 'info', 'warn', 'error', 'debug'];
  const saved = Object.fromEntries(levels.map((level) => [level, console[level]]));
  for (const level of levels) console[level] = () => {};
  const restore = () => { for (const level of levels) console[level] = saved[level]; };
  return work().finally(restore);
}

/**
 * The OpenAPI document of the engine's routes and, when the hosted layer is built, a second one of the routes only STACK's own
 * deployment serves. The engine's document is the same whether it is generated in the private repository or in the public one.
 *
 * @param {{ root: string, hostedLayer: boolean, specVersion: string, shared: Record<string, any>, zod: any }} input
 */
export async function generateRestApi({ root, hostedLayer, specVersion, shared, zod }) {
  const tables = await quietly(() => routeTables(root, { hostedLayer }));
  const analyser = createSourceAnalyser(root);
  const registrationFor = (route) => (route.file ? registrationOf(route, analyser.registrationsOf(route.file)) : null);
  const toJsonSchema = zodToJsonSchemaOf(root);
  const responseSchemas = {
    'GET /v1/governance/approvals': { name: 'GovernanceApprovalList', zod: zod.object({ approvals: zod.array(shared.GovernanceApprovalView) }) },
    'GET /v1/services/connect-links': { name: 'ConnectLinkList', zod: shared.ConnectLinkList },
    'GET /v1/governance/approvals/:id': { name: 'GovernanceApprovalDetail', zod: shared.GovernanceApprovalDetail },
  };
  const build = (routes, info) => quietly(() => buildOpenApi({
    routes,
    scopes: tables.scopes,
    registrationOf: registrationFor,
    scopeOf: (file) => moduleScope(tables.dist, file),
    toJsonSchema,
    info,
    responseSchemas,
  }));

  const engine = await build(tables.engine, {
    title: 'STACK REST API',
    version: specVersion,
    summary: 'The HTTP routes of the STACK engine.',
    description: 'Every route a STACK engine serves, generated from the routes and the schemas the engine runs. The text that says what the routes have in common (the error envelope, authentication, the step-up for governance actions, refusals) is in SPEC.md beside this file.',
    license: { name: 'Apache-2.0', identifier: 'Apache-2.0' },
  });
  let hosted = null;
  if (tables.hosted) {
    const engineKeys = new Set(tables.engine.map((route) => `${route.method} ${route.url}`));
    const only = tables.hosted.filter((route) => !engineKeys.has(`${route.method} ${route.url}`));
    hosted = await build(only, {
      title: "STACK's own REST API (routes beyond the engine's)",
      version: specVersion,
      description: "The routes only STACK's own deployment serves, generated the same way as the engine's document. This file is private: it is never part of the public repository.",
    });
  }
  return { engine, hosted, tables };
}

/** The OAuth scopes of a document's operations, each with the number of operations it is the ceiling of. */
export function scopeCounts(document) {
  const counts = new Map();
  for (const item of Object.values(document.paths)) {
    for (const operation of Object.values(item)) {
      const scope = operation['x-stack-oauth-scope'];
      if (scope && scope !== 'none') counts.set(scope, (counts.get(scope) ?? 0) + 1);
    }
  }
  return counts;
}

// ─── The specification text must say what the code does ─────────────

/**
 * The checks that tie the hand-written text of spec/rest-api/SPEC.md to the code. A row of a table that names a code and a
 * status (`| `CODE` | 403 | ...`) must be a code the engine raises with that status; a row marked as hosted (`| `CODE` | 402, hosted | ...`)
 * must be one STACK's own deployment raises, which the private build checks. Every operation the text names by method and path
 * (`POST /v1/agents/register`) must be in the engine's document. Returns the problems found.
 */
export function restCoverage({ prose, engineCodes, hostedCodes, document }) {
  const problems = [];
  const engine = new Map(engineCodes.map((entry) => [entry.code, entry.statuses]));
  for (const match of prose.matchAll(/^\| `([A-Z][A-Z0-9_]{3,})` \| (\d{3})(, hosted)? \|/gm)) {
    const [, code, status, hosted] = match;
    if (hosted) {
      if (hostedCodes === null) continue;
      const known = hostedCodes.find((entry) => entry.code === code);
      if (!known) problems.push(`spec/rest-api/SPEC.md says STACK's own deployment raises ${code}, which its source does not`);
      else if (known.statuses.length > 0 && !known.statuses.includes(Number(status))) problems.push(`spec/rest-api/SPEC.md gives ${code} the status ${status}; the source raises it with ${known.statuses.join(', ')}`);
      continue;
    }
    if (!engine.has(code)) problems.push(`spec/rest-api/SPEC.md has a row for ${code}, which the engine's source does not raise`);
    else if (engine.get(code).length > 0 && !engine.get(code).includes(Number(status))) problems.push(`spec/rest-api/SPEC.md gives ${code} the status ${status}; the source raises it with ${engine.get(code).join(', ')}`);
  }
  const operations = new Set(operationKeys(document));
  for (const match of prose.matchAll(/`(GET|POST|PUT|PATCH|DELETE) (\/[A-Za-z0-9_\-./:{}]*)`/g)) {
    const key = `${match[1]} ${match[2].replace(/\{([^}]+)\}/g, ':$1')}`;
    if (!operations.has(key)) problems.push(`spec/rest-api/SPEC.md names the operation ${match[1]} ${match[2]}, which the engine does not serve`);
  }
  return problems;
}
