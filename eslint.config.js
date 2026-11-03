import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

/**
 * AST rules that keep relay tests on checked access to `AccountRelay`'s private state (#367).
 *
 * Tests read and inject private members with element access (`relay["sql"]`), which TypeScript
 * checks against the class. A cast through `unknown`, `never` or `any` compiles whatever shape it
 * names, so a renamed member would leave a test reading or assigning a field nothing uses. These
 * selectors match the AST, so line wrapping and parentheses don't hide a cast:
 *
 * - a double cast (`x as unknown as T`, `<T><unknown>x`) is allowed only to a runtime type tests
 *   stub, listed in `allowedTargets`, none of which can name a private member;
 * - a cast to `unknown` or `never` that isn't the first half of such a double cast is forbidden,
 *   so the two halves can't be split across a variable;
 * - prototype access is forbidden: any `.prototype` member (so a class alias doesn't help),
 *   `Object.create`, and the `Object`/`Reflect` prototype getters and setters, each matched where
 *   it is named, so aliasing the function doesn't help either. A prototype-built instance skips the
 *   constructor and field initializers. Tests that need an instance without a runtime construct a
 *   real `AccountRelay` over a stub state.
 *
 * `as any` is caught by `@typescript-eslint/no-explicit-any`, and reads through `any` by the
 * `no-unsafe-*` rules, both on in `strictTypeChecked`.
 */
function relayPrivateStateRestrictions(allowedTargets) {
  const cast = ":matches(TSAsExpression, TSTypeAssertion)";
  const throughTopType =
    "[expression.type=/^(TSAsExpression|TSTypeAssertion)$/]" +
    "[expression.typeAnnotation.type=/^(TSUnknownKeyword|TSNeverKeyword|TSAnyKeyword)$/]";
  const allowedTarget =
    '[typeAnnotation.type="TSTypeReference"]' +
    `[typeAnnotation.typeName.name=/^(${allowedTargets.join("|")})$/]`;
  return [
    "error",
    {
      selector: `${cast}${throughTopType}:not(${allowedTarget})`,
      message: `Reach AccountRelay's private state with element access (relay["name"]), which TypeScript checks. A double cast is allowed only to ${allowedTargets.join(", ")} (#367).`,
    },
    {
      selector: `${cast}[typeAnnotation.type=/^(TSUnknownKeyword|TSNeverKeyword)$/]:not(${cast} > .expression)`,
      message:
        "A cast to unknown or never is allowed only as the first half of an allowed double cast, so it can't launder a shape of AccountRelay (#367).",
    },
    {
      selector:
        'MemberExpression[property.name="prototype"], MemberExpression[object.name=/^(Object|Reflect)$/][property.name=/^(create|getPrototypeOf|setPrototypeOf)$/]',
      message:
        "Construct a real AccountRelay (over a stub state if needed); a prototype-built instance skips its constructor and field initializers (#367).",
    },
  ];
}

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
    // service does not discover on its own (it reads each directory's tsconfig.json).
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
      "@typescript-eslint/dot-notation": ["error", { allowPrivateClassPropertyAccess: true }],
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
