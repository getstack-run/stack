// ESLint configuration for every package in this repository. Each package runs
// `eslint . --max-warnings=0` from its own folder; ESLint finds this file by
// walking up. TypeScript uses typescript-eslint's `recommended` set (not the
// type-checked variants: `tsc --noEmit` already enforces those checks).

import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// The packages are pure ESM, so a relative import names the runtime file with
// its extension (`./file.js`).
const RELATIVE_IMPORT_WITHOUT_EXTENSION = '^\\.\\.?(?:/.*)?/[^/.]+$';

export default [
  {
    name: 'repo/ignores',
    ignores: ['**/node_modules/**', '**/dist/**', '**/.turbo/**', '**/drizzle/**', 'sdk-python/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    name: 'repo/language',
    languageOptions: { ecmaVersion: 2023, sourceType: 'module', globals: globals.node },
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              regex: RELATIVE_IMPORT_WITHOUT_EXTENSION,
              message: 'Relative imports name the runtime file, extension included (./file.js), because the packages are ESM.',
            },
          ],
        },
      ],
    },
  },
  {
    name: 'repo/unused-names',
    rules: {
      // A leading underscore marks a binding that a signature forces on the author and the body does not read.
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          args: 'after-used',
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
          caughtErrors: 'all',
          caughtErrorsIgnorePattern: '^_',
          ignoreRestSiblings: true,
        },
      ],
    },
  },
  {
    name: 'repo/late-bound-consts',
    rules: { 'prefer-const': ['error', { ignoreReadBeforeAssign: true }] },
  },
  {
    name: 'repo/commonjs',
    files: ['**/*.cjs'],
    languageOptions: { sourceType: 'commonjs' },
    rules: { '@typescript-eslint/no-require-imports': 'off' },
  },
  {
    name: 'repo/tests',
    files: ['**/*.test.{ts,tsx}'],
    rules: { '@typescript-eslint/no-explicit-any': 'off' },
  },
];
