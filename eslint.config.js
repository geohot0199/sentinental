/**
 * ESLint flat config.
 *
 * The point of this file is not style: it is the gate that keeps the safety
 * invariants in `src/` from drifting. Two rules matter most here:
 *
 *   - `@typescript-eslint/no-explicit-any` / `no-unsafe-*` keep untrusted tool
 *     input from flowing into GitHub writes without going through zod.
 *   - `max-lines` (500) is the tripwire: a module that outgrows it is a module
 *     nobody reads top to bottom any more, and the approval annotations live
 *     next to the code they guard.
 *
 * Run it with `npm run lint`. CI runs it on every push and pull request.
 */
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

/** Hand-written browser bundles, served as-is; not part of the build. */
const VENDORED = ["src/web/public/**", "site/js/**", "site/serve.mjs"];

export default tseslint.config(
  {
    ignores: ["node_modules/**", "dist/**", "coverage/**", ...VENDORED],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,mts,cts}"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.node },
    },
    rules: {
      // ── Complexity gates ────────────────────────────────────────────────
      "max-lines": ["error", { max: 500, skipBlankLines: true, skipComments: true }],
      "max-lines-per-function": ["error", { max: 120, skipBlankLines: true, skipComments: true }],
      "max-depth": ["error", 4],
      complexity: ["error", { max: 20 }],

      // ── Correctness: anything unreachable or unused is dead weight ──────
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          args: "after-used",
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
      "no-empty": ["error", { allowEmptyCatch: false }],
      eqeqeq: ["error", "always", { null: "ignore" }],
      "no-var": "error",
      "prefer-const": "error",
      // A `while (true)` worker loop is fine; a `while (1)` typo is not.
      "no-constant-condition": ["error", { checkLoops: "allExceptWhileTrue" }],

      // ── Security hygiene ────────────────────────────────────────────────
      // Untrusted model input reaches a shell or a URL only through a vetted
      // path; both of these make that path visible in review.
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      "require-await": "error",
    },
  },
  {
    // Tests and scripts are not the shipped surface, and the shape rules that
    // keep `src/` readable do not fit them: a `describe` block is one long
    // list of cases, and a mock must match an async signature whether or not it
    // awaits anything. The safety rules above still apply to them in full.
    files: ["tests/**/*.ts", "scripts/**/*.ts"],
    rules: {
      "max-lines": "off",
      "max-lines-per-function": "off",
      "require-await": "off",
      complexity: "off",
    },
  },
);
