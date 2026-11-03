/**
 * Lint rules that keep relay tests on checked access to `AccountRelay`'s private state (#367).
 *
 * Tests read and inject private members with element access (`relay["sql"]`), which TypeScript
 * checks against the class: a renamed or retyped member fails `typecheck`. A cast compiles whatever
 * shape it names, so a test that casts the relay to a hand-written shape keeps compiling after a
 * rename, and goes on reading or assigning a field nothing uses. These `no-restricted-syntax`
 * selectors forbid the common ways of writing such a cast or of building a relay without its
 * constructor. They are test hygiene, not a sandbox: they make the mistake hard to write by accident,
 * and a determined author can still get around them (see "Not covered" below).
 *
 * The selectors match the AST, so line wrapping and parentheses don't change what matches.
 *
 * Casts:
 * - A double cast through `unknown`, `never` or `any` (`x as unknown as T`, `<T><unknown>x`) is
 *   allowed only when `T` is a bare reference to one of `allowedTargets`. A shape, a union, an
 *   intersection or a generic type there fails.
 * - A lone cast to `unknown` or `never` fails, so a double cast can't be split across a variable.
 * - A single cast to an object-literal type, or to `Partial`, `Pick`, `Omit`, `Record`, `Required`
 *   or `Readonly`, fails. A target with only optional members is comparable to almost anything, so
 *   such a cast launders a shape in one step. Two exceptions: the cast of a `JSON.parse(…)` call,
 *   which is fresh data and never the relay, and `Record` where `allowedTargets` lists it.
 *
 * Allowed target names keep their meaning:
 * - Test code can't declare a type, interface, class, enum, namespace, import-equals alias or type
 *   parameter with an allowed target's name, so `Env` can't be redefined locally as a shape.
 * - It can't import or re-export a binding under one of those names unless that is the binding's
 *   own name (`import { X as Env }` fails). Default and namespace imports under those names fail.
 *
 * Reflection:
 * - `prototype` and `__proto__` fail as a member name, as a key, and as a string literal anywhere,
 *   which covers computed keys (`x["prototype"]`) and quoted property names.
 * - `Object.create`, `assign`, `defineProperty`, `defineProperties`, `setPrototypeOf` and
 *   `getPrototypeOf` fail. `Reflect` fails wherever it appears.
 * - Any computed member access on `Object` or `globalThis` (`Object["create"]`, `Object[name]`)
 *   fails, as do `globalThis.Object` and `globalThis.Reflect`.
 * - Binding `Object` or `globalThis` to a variable, an assignment or a default value fails,
 *   destructuring included (`const { create } = Object`). So does destructuring a `prototype`,
 *   `create` or `__proto__` property from anything.
 *
 * `as any` is caught by `@typescript-eslint/no-explicit-any`, and reads through `any` by the
 * `no-unsafe-*` rules, both on in `strictTypeChecked`.
 *
 * Not covered (known limits):
 * - A single cast to a named interface or type alias declared with optional members
 *   (`relay as LooseShape`), including an alias of a utility type (`type P = Partial<AccountRelay>`,
 *   then `relay as P`). Syntax alone can't tell that from a legitimate cast. The declaration has to
 *   live in a test file, where review sees it.
 * - A single cast to an intersection (`relay as AccountRelay & { extra?: 1 }`), which TypeScript
 *   accepts because the target is a subtype.
 * - Laundering through a generic (`function launder<T>(x: unknown): T { return x as T }`). The
 *   cast inside is a cast to a type parameter, which syntax can't tell from a legitimate generic
 *   helper.
 * - Reaching `Object` or the global object through a value the rules can't see by name: one passed
 *   in as a function argument, `({}).constructor`, `Function("return this")()`, or a reflection
 *   name computed at runtime on anything but `Object` or `globalThis`.
 * - Other ways to get an object that isn't a constructed relay, or to intercept one: `new Proxy`,
 *   `structuredClone`, or a test subclass of `AccountRelay` that overrides members.
 * - Ambient declarations outside `test/`. `vitest-environment-d.ts` augments `Cloudflare.Env`,
 *   which is what types `env`.
 */

/** Utility types whose single-cast target launders a shape (see "Casts" above). */
const SHAPE_UTILITY_TYPES = ["Partial", "Pick", "Omit", "Record", "Required", "Readonly"];

/** The reflection functions on `Object` that build or rewire an instance. */
const OBJECT_REFLECTION = [
  "create",
  "assign",
  "defineProperty",
  "defineProperties",
  "setPrototypeOf",
  "getPrototypeOf",
];

const alternation = (names) => names.join("|");

/**
 * The `no-restricted-syntax` entry for relay test sources. `allowedTargets` lists the type names a
 * double cast may target: runtime objects tests stub with a partial literal, and the Worker env.
 */
export function relayPrivateStateRestrictions(allowedTargets) {
  const names = alternation(allowedTargets);
  const cast = ":matches(TSAsExpression, TSTypeAssertion)";
  const throughTopType =
    "[expression.type=/^(TSAsExpression|TSTypeAssertion)$/]" +
    "[expression.typeAnnotation.type=/^(TSUnknownKeyword|TSNeverKeyword|TSAnyKeyword)$/]";
  const allowedTarget =
    '[typeAnnotation.type="TSTypeReference"]' + `[typeAnnotation.typeName.name=/^(${names})$/]`;
  // Parsed JSON is fresh data, never the relay, so typing it with a cast is fine.
  const notParsedJson =
    ':not([expression.callee.object.name="JSON"][expression.callee.property.name="parse"])';
  const shapeUtilities = SHAPE_UTILITY_TYPES.filter((name) => !allowedTargets.includes(name));

  const cite = " (#367)";
  const elementAccess = `Reach AccountRelay's private state with element access (relay["name"]), which TypeScript checks.`;
  const constructIt =
    "Construct a real AccountRelay (over a stub state if needed); reflection can build or rewire one without its constructor and field initializers.";

  return [
    "error",
    // Casts.
    {
      selector: `${cast}${throughTopType}:not(${allowedTarget})`,
      message: `${elementAccess} A double cast is allowed only to a bare ${allowedTargets.join(", ")}${cite}.`,
    },
    {
      selector: `${cast}[typeAnnotation.type=/^(TSUnknownKeyword|TSNeverKeyword)$/]:not(${cast} > .expression)`,
      message: `${elementAccess} A cast to unknown or never is allowed only as the first half of an allowed double cast${cite}.`,
    },
    {
      selector: [
        `${cast}[typeAnnotation.type="TSTypeLiteral"]${notParsedJson}`,
        `${cast}[typeAnnotation.typeName.name=/^(${alternation(shapeUtilities)})$/]${notParsedJson}`,
      ].join(", "),
      message: `${elementAccess} A cast to an object-literal or utility type launders a shape${cite}.`,
    },
    // Allowed target names keep their meaning.
    {
      selector: [
        `:matches(TSInterfaceDeclaration, TSTypeAliasDeclaration, ClassDeclaration, ClassExpression, TSEnumDeclaration, TSModuleDeclaration, TSImportEqualsDeclaration)[id.name=/^(${names})$/]`,
        `TSTypeParameter[name.name=/^(${names})$/]`,
      ].join(", "),
      message: `Don't declare ${allowedTargets.join(", ")} in test code: a double cast may target those names, so they must keep their real meaning${cite}.`,
    },
    {
      selector: [
        ...allowedTargets.map(
          (name) => `ImportSpecifier[local.name="${name}"]:not([imported.name="${name}"])`,
        ),
        ...allowedTargets.map(
          (name) => `ExportSpecifier[exported.name="${name}"]:not([local.name="${name}"])`,
        ),
        `:matches(ImportDefaultSpecifier, ImportNamespaceSpecifier)[local.name=/^(${names})$/]`,
      ].join(", "),
      message: `Don't bind another type to ${allowedTargets.join(", ")}: a double cast may target those names, so they must keep their real meaning${cite}.`,
    },
    // Reflection.
    {
      selector: [
        "MemberExpression[property.name=/^(prototype|__proto__)$/]",
        'Identifier[name="__proto__"]',
        "Literal[value=/^(prototype|__proto__)$/]",
        `MemberExpression[object.name="Object"][property.name=/^(${alternation(OBJECT_REFLECTION)})$/]`,
        'Identifier[name="Reflect"]',
        "MemberExpression[computed=true][object.name=/^(Object|globalThis)$/]",
        "ObjectPattern > Property[key.name=/^(prototype|create|__proto__)$/]",
        "VariableDeclarator[init.name=/^(Object|globalThis)$/]",
        ":matches(AssignmentExpression, AssignmentPattern)[right.name=/^(Object|globalThis)$/]",
        'MemberExpression[object.name="globalThis"][property.name=/^(Object|Reflect)$/]',
      ].join(", "),
      message: `${constructIt}${cite}`,
    },
  ];
}
