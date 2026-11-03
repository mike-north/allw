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
 * Known limit: comments are found by a regex over the source text, not by a tokenizer. The
 * TypeScript scanner would be exact, but loading `typescript` crashes the workerd test runtime.
 * The regex doesn't skip string, template or regex literals, so a `//` or `/*` inside one is read
 * as the start of a comment. That can hide a real directive after it: a string such as
 * `"src/*.ts"` opens a fake block comment that runs to the next `*\/`, and `"http://…"` opens
 * a fake line comment that eats the rest of its line. The "known limits" cases below pin this.
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
 * Every comment in a source, whole: a `/* … *\/` block (which may span lines) or a `//` line
 * comment. Not string-aware: a `//` or `/*` inside a string, template or regex literal starts a
 * match, which can hide a directive after it on the same line or up to the next `*\/` (see the
 * module comment).
 */
const COMMENT = /\/\*([\s\S]*?)\*\/|\/\/([^\n]*)/g;

/**
 * A directive at the start of a comment's text: `eslint`, `eslint-disable`, `eslint-disable-line`,
 * `eslint-disable-next-line` or `eslint-enable`, then the rest of the comment, newlines included.
 */
const DIRECTIVE = new RegExp(
  String.raw`^\s*(${ESLINT}(?:-disable(?:-next-line|-line)?|-enable)?)(?![\w-])([\s\S]*)$`,
);

/**
 * `path:line: reason` for each directive in `source` that would take code out of the guard. A
 * directive is read across its whole comment, so one that names the rule on a later line of a
 * block comment still counts. Any mention of the rule in a directive's rule list counts, which errs
 * toward flagging.
 */
function guardOptOuts(path: string, source: string): string[] {
  const found: string[] = [];
  for (const comment of source.matchAll(COMMENT)) {
    const [, kind = "", rest = ""] = DIRECTIVE.exec(comment[1] ?? comment[2] ?? "") ?? [];
    if (kind === "") continue;
    const line = source.slice(0, comment.index).split("\n").length;
    const where = `${path}:${String(line)}`;
    // ESLint reads a directive's description after `--`; the rule list comes before it.
    const ruleList = rest.split(/\s--\s/)[0] ?? "";
    if (kind === ESLINT) {
      if (rest.includes(GUARDED_RULE)) found.push(`${where}: inline config for ${GUARDED_RULE}`);
    } else if (kind.startsWith(`${ESLINT}-disable`)) {
      if (ruleList.replace(/[\s*]/g, "") === "") found.push(`${where}: blanket disable`);
      else if (ruleList.includes(GUARDED_RULE) && path !== PLANTS_PATH) {
        found.push(`${where}: disables ${GUARDED_RULE}`);
      }
    }
  }
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

  it("flags planted opt-outs, multi-line ones included, and allows the plants file and other rules", () => {
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
    const multiLineDisable = `/* ${ESLINT}-disable-next-line semi,\n  ${GUARDED_RULE} */`;
    expect(guardOptOuts("./planted.test.ts", `x;\n${multiLineDisable}`)).toEqual([
      `./planted.test.ts:2: disables ${GUARDED_RULE}`,
    ]);
    const multiLineConfig = `/* ${ESLINT}\n  ${GUARDED_RULE}: "off" */`;
    expect(guardOptOuts("./planted.test.ts", multiLineConfig)).toEqual([
      `./planted.test.ts:1: inline config for ${GUARDED_RULE}`,
    ]);
    expect(guardOptOuts(PLANTS_PATH, disableGuarded)).toEqual([]);
    expect(guardOptOuts("./planted.test.ts", disableOther)).toEqual([]);
  });

  describe("known limits: a comment opener inside a string hides a directive after it", () => {
    const disableGuarded = directive("-disable-next-line", `${GUARDED_RULE} -- hidden`);

    it("a glob string's /* swallows a later directive, up to the next */", () => {
      const source = `const glob = "src/*.ts";\n${disableGuarded}\nconst x = 1; /* end */`;
      expect(guardOptOuts("./planted.test.ts", source)).toEqual([]);
    });

    it("a URL string's // swallows a directive later on the same line", () => {
      const source = `const u = "http://x"; /* ${ESLINT}-disable-next-line ${GUARDED_RULE} */`;
      expect(guardOptOuts("./planted.test.ts", source)).toEqual([]);
    });
  });
});
