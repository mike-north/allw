/**
 * Guard: relay tests reach `AccountRelay`'s private state only through checked element access
 * (#367).
 *
 * TypeScript checks `relay["sql"]` against the real class, so renaming a private member, or
 * changing its type, fails `typecheck` in every test that touches it. A double cast through
 * `unknown` to a hand-written shape, such as `instance as unknown as { sql: SqlStorage }`,
 * compiles whatever the class says. That is how a renamed coalescer once left a test assigning a
 * field nothing read. So this guard allows a double cast only to the runtime types that tests
 * stub, never to a shape or to anything standing in for the relay, and it forbids building an
 * instance with `Object.create(AccountRelay.prototype)`, which skips its constructor and field
 * initializers.
 *
 * @see https://www.typescriptlang.org/docs/handbook/2/classes.html#caveats (bracket access to
 *   private members is checked)
 */

import { describe, expect, it } from "vitest";

/** Every relay test source's text, by path. New files are covered too. */
const SOURCES = import.meta.glob("./**/*.ts", { query: "?raw", import: "default", eager: true });

/** This file names the patterns it forbids, so it is not scanned for them. */
const SELF_PATH = "./private-state-access.test.ts";

/**
 * The types any test may double-cast to: runtime objects tests stub with a partial literal, and the
 * Worker env. None of them can name `AccountRelay`'s private members.
 */
const ALLOWED_DOUBLE_CAST_TARGETS = new Set([
  "WebSocket",
  "Env",
  "DurableObjectState",
  "DurableObjectStorage",
]);

/**
 * Double-cast targets allowed only in one file. `Record<string, unknown>` accepts any key, so a
 * global allowance would let `relay as unknown as Record<string, unknown>` assign a stale name
 * unchecked. Only the WASM glue module needs it, to read its exports by name.
 */
const ALLOWED_DOUBLE_CAST_TARGETS_BY_FILE: Readonly<Record<string, readonly string[]>> = {
  "./core.test.ts": ["Record<string, unknown>"],
};

const DOUBLE_CAST = ["as", "unknown", "as"].join(" ");
/** `<expr> as unknown as <target>`, capturing the target up to the end of its type expression. */
const DOUBLE_CAST_TARGET = new RegExp(`${DOUBLE_CAST}\\s+([A-Za-z_][\\w.]*(?:<[^>]*>)?|\\{)`, "g");
const PROTOTYPE_INSTANCE = ["Object.create(", "AccountRelay", ".prototype)"].join("");

/** `path:line: target` for each double cast in `source` whose target is not allowed. */
function forbiddenDoubleCasts(path: string, source: string): string[] {
  const found: string[] = [];
  source.split("\n").forEach((line, index) => {
    for (const match of line.matchAll(DOUBLE_CAST_TARGET)) {
      const target = match[1] ?? "";
      const allowedHere = ALLOWED_DOUBLE_CAST_TARGETS_BY_FILE[path] ?? [];
      if (!ALLOWED_DOUBLE_CAST_TARGETS.has(target) && !allowedHere.includes(target)) {
        found.push(`${path}:${String(index + 1)}: ${target}`);
      }
    }
  });
  return found;
}

describe("private-state access in relay tests", () => {
  const scanned = Object.entries(SOURCES).filter(([path]) => path !== SELF_PATH);

  it("scans the test sources", () => {
    expect(scanned.map(([path]) => path)).toContain("./relay-routing.test.ts");
    expect(scanned.map(([path]) => path)).toContain("./support/relay-state.ts");
  });

  it("double-casts only to stubbed runtime types, never to a shape of AccountRelay", () => {
    expect(scanned.flatMap(([path, source]) => forbiddenDoubleCasts(path, source))).toEqual([]);
  });

  it("never builds an AccountRelay from its prototype", () => {
    expect(
      scanned.filter(([, source]) => source.includes(PROTOTYPE_INSTANCE)).map(([path]) => path),
    ).toEqual([]);
  });

  it("flags a planted double cast to a stale private-state shape", () => {
    const planted = `const relay = instance ${DOUBLE_CAST} { webPushCoalescer: WakeupCoalescer };`;
    expect(forbiddenDoubleCasts("./planted.test.ts", planted)).toEqual(["./planted.test.ts:1: {"]);
  });

  it("allows a Record<string, unknown> double cast only in the file that needs it", () => {
    const planted = `const r = relay ${DOUBLE_CAST} Record<string, unknown>; r["webPushCoalescer"] = 1;`;
    expect(forbiddenDoubleCasts("./planted.test.ts", planted)).toEqual([
      "./planted.test.ts:1: Record<string, unknown>",
    ]);
    expect(forbiddenDoubleCasts("./core.test.ts", planted)).toEqual([]);
  });
});
