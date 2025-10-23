// Central flat config for the auditor (ESLint v9)
import js from "@eslint/js";
import tseslint from "typescript-eslint";

import importPlugin from "eslint-plugin-import";
import n from "eslint-plugin-n";
import promise from "eslint-plugin-promise";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y";
import security from "eslint-plugin-security";
import noSecrets from "eslint-plugin-no-secrets";

/** @type {import("eslint").Linter.FlatConfig[]} */
export default [
  { ignores: ["**/node_modules/**","**/dist/**","**/build/**","**/.next/**","**/coverage/**","**/.cache/**"] },

  // JS + TS (no type-aware lint for speed; works across arbitrary repos)
  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    plugins: {
      import: importPlugin,
      n,
      promise,
      react,
      "react-hooks": reactHooks,
      "jsx-a11y": jsxA11y,
      security,
      "no-secrets": noSecrets,
    },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    settings: {
      "import/resolver": {
        typescript: { alwaysTryTypes: true },
        node: { extensions: [".js",".jsx",".mjs",".cjs",".ts",".tsx"] },
      },
      react: { version: "detect" },
    },
    rules: {
      // ---- Core
      "no-undef": "error",
      "no-unreachable": "error",
      "no-unsafe-finally": "error",
      "no-constant-binary-expression": "error",
      "no-duplicate-imports": "error",
      eqeqeq: "error",
      "no-unused-vars": ["warn", { args: "none", ignoreRestSiblings: true }],
      complexity: ["warn", 12],
      "max-depth": ["warn", 4],
      "max-params": ["warn", 4],
      "max-nested-callbacks": ["warn", 3],
      "max-lines-per-function": ["warn", 120],

      // ---- import
      "import/no-unresolved": "error",
      "import/no-extraneous-dependencies": "error",
      "import/no-self-import": "error",
      "import/no-cycle": "warn",
      "import/no-duplicates": "error",
      "import/no-unused-modules": "off",

      // ---- node (n)
      "n/no-missing-import": "error",
      "n/no-missing-require": "error",
      "n/no-deprecated-api": "warn",
      "n/no-path-concat": "warn",
      "n/handle-callback-err": "warn",

      // ---- promises
      "promise/no-return-wrap": "error",
      "promise/always-return": "warn",
      "promise/no-nesting": "warn",
      "promise/no-promise-in-callback": "warn",
      "promise/catch-or-return": "warn",

      // ---- react & hooks
      "react/jsx-no-undef": "error",
      "react/jsx-no-duplicate-props": "error",
      "react/no-unstable-nested-components": "warn",
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",

      // ---- a11y
      "jsx-a11y/alt-text": "error",
      "jsx-a11y/anchor-is-valid": "error",

      // ---- security/secrets
      "security/detect-unsafe-regex": "warn",
      "security/detect-object-injection": "warn",
      "security/detect-eval-with-expression": "error",
      "no-secrets/no-secrets": "warn",
    },
  },
];
