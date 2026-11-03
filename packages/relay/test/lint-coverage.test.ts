/**
 * Guard: every relay test source stays under the private-state lint rules (#367, #290).
 *
 * The rules in `eslint/relay-private-state.js` only help if lint actually applies them. Two things
 * would quietly opt code out, so this suite fails on both:
 *
 * - A disable directive that switches `no-restricted-syntax` off. `reportUnusedDisableDirectives`
 *   catches an unused one, but a used one passes lint. Only `private-state-plants.ts`, whose
 *   plants exist to be disabled, may name the rule. A blanket disable (no rule list) and an inline
 *   `eslint` config comment naming the rule are refused everywhere.
 * - A test source in a language lint doesn't type-check here. The typed relay test block in
 *   `eslint.config.js` matches `test/**\/*.ts` only, so `test/` must hold no `.js`, `.mjs`, `.cjs`,
 *   `.jsx`, `.mts`, `.cts` or `.tsx` file.
 *
 * @see https://eslint.org/docs/latest/use/configure/rules#disabling-rules (directive comment forms)
 */

import { describe, expect, it } from "vitest";

/** Every `.ts` source under `test/`, by path, with its text. */
const SOURCES = import.meta.glob("./**/*.ts", { query: "?raw", import: "default", eager: true });

/** Paths under `test/` in a language the typed lint block doesn't cover. */
const UNCOVERED = Object.keys(import.meta.glob("./**/*.{js,mjs,cjs,jsx,mts,cts,tsx}"));

/** The one file allowed a disable directive for the guarded rule. */
const PLANTS_PATH = "./private-state-plants.ts";

const GUARDED_RULE = "no-restricted-syntax";
const ESLINT = "eslint";

/**
 * A directive comment: `//` or `/*`, optional whitespace, then `eslint`, `eslint-disable`,
 * `eslint-disable-line`, `eslint-disable-next-line` or `eslint-enable`, then the rest of the line.
 */
const DIRECTIVE = new RegExp(
  String.raw`(?:\/\/|\/\*)\s*(${ESLINT}(?:-disable(?:-next-line|-line)?|-enable)?)(?![\w-])([^\n]*)`,
  "g",
);

/** `path:line: reason` for each directive in `source` that would take code out of the guard. */
function guardOptOuts(path: string, source: string): string[] {
  const found: string[] = [];
  source.split("\n").forEach((line, index) => {
    for (const [, kind = "", rest = ""] of line.matchAll(DIRECTIVE)) {
      const where = `${path}:${String(index + 1)}`;
      const rules = (rest.split("--")[0] ?? "")
        .replace(/\*\/.*$/, "")
        .split(",")
        .map((rule) => rule.trim())
        .filter((rule) => rule !== "");
      if (kind === ESLINT) {
        if (rest.includes(GUARDED_RULE)) found.push(`${where}: inline config for ${GUARDED_RULE}`);
      } else if (kind.startsWith(`${ESLINT}-disable`)) {
        if (rules.length === 0) found.push(`${where}: blanket disable`);
        else if (rules.includes(GUARDED_RULE) && path !== PLANTS_PATH) {
          found.push(`${where}: disables ${GUARDED_RULE}`);
        }
      }
    }
  });
  return found;
}

/** Builds a directive comment's text, so this file holds none itself. */
const directive = (kind: string, body: string): string => `// ${ESLINT}${kind} ${body}`;

describe("relay test sources stay under the private-state lint rules", () => {
  it("scans the test sources, the plants included", () => {
    expect(Object.keys(SOURCES)).toContain("./relay-routing.test.ts");
    expect(Object.keys(SOURCES)).toContain("./support/relay-state.ts");
    expect(Object.keys(SOURCES)).toContain(PLANTS_PATH);
  });

  it("disables no-restricted-syntax only in the plants file, and never with a blanket disable", () => {
    expect(Object.entries(SOURCES).flatMap(([path, source]) => guardOptOuts(path, source))).toEqual(
      [],
    );
  });

  it("holds no test source that the typed lint block skips", () => {
    expect(UNCOVERED).toEqual([]);
  });

  it("flags planted opt-outs, and allows the plants file and other rules", () => {
    const disableGuarded = directive("-disable-next-line", `${GUARDED_RULE} -- planted`);
    const disableOther = directive(
      "-disable-next-line",
      "@typescript-eslint/no-unnecessary-type-parameters -- fine",
    );
    const listedSecond = directive(
      "-disable-line",
      `@typescript-eslint/dot-notation, ${GUARDED_RULE}`,
    );
    const blanket = `/* ${ESLINT}-disable */`;
    const inlineConfig = `/* ${ESLINT} ${GUARDED_RULE}: "off" */`;

    expect(guardOptOuts("./planted.test.ts", disableGuarded)).toEqual([
      `./planted.test.ts:1: disables ${GUARDED_RULE}`,
    ]);
    expect(guardOptOuts("./planted.test.ts", `x;\n${listedSecond}`)).toEqual([
      `./planted.test.ts:2: disables ${GUARDED_RULE}`,
    ]);
    expect(guardOptOuts("./planted.test.ts", blanket)).toEqual([
      "./planted.test.ts:1: blanket disable",
    ]);
    expect(guardOptOuts(PLANTS_PATH, blanket)).toEqual([`${PLANTS_PATH}:1: blanket disable`]);
    expect(guardOptOuts("./planted.test.ts", inlineConfig)).toEqual([
      `./planted.test.ts:1: inline config for ${GUARDED_RULE}`,
    ]);
    expect(guardOptOuts(PLANTS_PATH, disableGuarded)).toEqual([]);
    expect(guardOptOuts("./planted.test.ts", disableOther)).toEqual([]);
  });
});
