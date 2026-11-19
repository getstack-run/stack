// Flat-config entries for apps/api. The repository's root ESLint config spreads
// this array into its own (`...apiRules`); it carries no parser or plugin
// settings, so it relies on the root config for the TypeScript parser.
//
// Route handlers must parse what a client sends, never cast it: a cast makes
// the compiler trust an `unknown` body, query or params object, and a request
// the type does not describe fails later and further from the cause. Parse
// with a Zod schema (`Schema.parse(request.body)`), which sends a malformed
// request to the central error handler as a 400.
// `src/routes/no-body-cast.test.ts` enforces the same rule without ESLint.

const REQUEST_INPUT_CAST = {
  asExpression:
    "TSAsExpression[expression.type='MemberExpression'][expression.object.name=/^(request|req)$/][expression.property.name=/^(body|query|params)$/]",
  typeAssertion:
    "TSTypeAssertion[expression.type='MemberExpression'][expression.object.name=/^(request|req)$/][expression.property.name=/^(body|query|params)$/]",
};

const MESSAGE =
  'Parse request.body, request.query and request.params with a Zod schema instead of casting them.';

/** The rule: no cast of request input, for the route files under `files` (minus `ignores`). */
export function requestInputRule(name, files, ignores) {
  return {
    name,
    files,
    ignores,
    rules: {
      'no-restricted-syntax': [
        'error',
        { selector: REQUEST_INPUT_CAST.asExpression, message: MESSAGE },
        { selector: REQUEST_INPUT_CAST.typeAssertion, message: MESSAGE },
      ],
    },
  };
}

export default [requestInputRule('api/routes-parse-request-input', ['apps/api/src/routes/**/*.ts'], ['apps/api/src/routes/**/*.test.ts'])];
