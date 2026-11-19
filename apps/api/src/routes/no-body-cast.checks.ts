import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import ts from 'typescript';

/**
 * Route handlers parse what a client sends; they never cast it. A cast tells
 * the compiler to trust an `unknown` body, query or params object, so a
 * request the type does not describe fails later and further from the cause.
 * `apps/api/eslint.rules.mjs` forbids the same syntax for the repository
 * lint; the tests that use this enforce it without ESLint, one over the
 * engine's routes and one over the deployment's own.
 */

const REQUEST_NAMES = new Set(['request', 'req']);
const INPUT_PROPERTIES = new Set(['body', 'query', 'params']);

/** `request.body`, `(request.query)` or `request['params']`. */
function isRequestInput(node: ts.Expression): boolean {
  let expression = node;
  while (ts.isParenthesizedExpression(expression)) expression = expression.expression;
  if (ts.isPropertyAccessExpression(expression)) {
    return ts.isIdentifier(expression.expression)
      && REQUEST_NAMES.has(expression.expression.text)
      && INPUT_PROPERTIES.has(expression.name.text);
  }
  if (ts.isElementAccessExpression(expression)) {
    return ts.isIdentifier(expression.expression)
      && REQUEST_NAMES.has(expression.expression.text)
      && ts.isStringLiteralLike(expression.argumentExpression)
      && INPUT_PROPERTIES.has(expression.argumentExpression.text);
  }
  return false;
}

/** 1-based line numbers of every `request.body as X`, `<X>request.query` and the like. */
export function findRequestInputCasts(fileName: string, source: string): number[] {
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const lines: number[] = [];
  const visit = (node: ts.Node): void => {
    if ((ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) && isRequestInput(node.expression)) {
      lines.push(file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return lines;
}

export function routeSources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return routeSources(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [path] : [];
  });
}

/** Every cast of request input in the route modules under `routesDir`, as `file:line` from it. */
export function requestInputCasts(routesDir: string): string[] {
  return routeSources(routesDir).flatMap((path) =>
    findRequestInputCasts(path, readFileSync(path, 'utf8'))
      .map((line) => `${relative(routesDir, path).replaceAll('\\', '/')}:${line}`));
}
