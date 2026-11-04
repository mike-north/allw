import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";
import { relayPrivateStateRestrictions } from "./eslint/relay-private-state.js";

/** Runtime objects relay tests stub with a partial literal, and the Worker env. */
const RELAY_TEST_CAST_TARGETS = ["WebSocket", "Env", "DurableObjectState", "DurableObjectStorage"];

export default tseslint.config(
  { ignores: ["**/dist/**", "**/target/**", "**/.wrangler/**"] },
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "no-plusplus": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // Relay test sources are type-checked by tsconfig.test.json (src + test), which the project
    // service does not discover on its own (it reads each directory's tsconfig.json). The block
    // matches `.ts` only; packages/relay/test/lint-coverage.test.ts fails if test/ gains a source in
    // another language.
    files: [
      "packages/relay/test/**/*.ts",
      "packages/relay/vitest.config.ts",
      "packages/relay/vitest-environment-d.ts",
    ],
    // An unused disable directive is an error here, so the planted violations in
    // test/private-state-plants.ts fail lint if a rule they prove stops firing.
    linterOptions: { reportUnusedDisableDirectives: "error" },
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: "./packages/relay/tsconfig.test.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Tests reach AccountRelay's private state through element access (`relay["sql"]`), which
      // TypeScript checks against the class (#367); dot access to a private member does not compile.
      "@typescript-eslint/dot-notation": [
        "error",
        { allowPrivateClassPropertyAccess: true, allowProtectedClassPropertyAccess: true },
      ],
    },
  },
  {
    // Hygiene rules that keep test code on checked element access to AccountRelay's private state
    // (#367). eslint/relay-private-state.js lists what they check and their known limits.
    files: ["packages/relay/test/**/*.ts"],
    rules: {
      "no-restricted-syntax": relayPrivateStateRestrictions(RELAY_TEST_CAST_TARGETS),
    },
  },
  {
    // The WASM glue test reads the module's exports by name. `Record` accepts any key, so it is
    // allowed here only, never where a relay could be cast to it.
    files: ["packages/relay/test/core.test.ts"],
    rules: {
      "no-restricted-syntax": relayPrivateStateRestrictions([...RELAY_TEST_CAST_TARGETS, "Record"]),
    },
  },
  prettier,
);
