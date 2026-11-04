/**
 * Pins `AccountRelay`'s RPC surface (#373).
 *
 * `AccountRelay` extends `DurableObject` from `cloudflare:workers`, so every method on its
 * prototype is callable on a stub over Workers RPC, and TypeScript's `private` does not change
 * that (it is erased at compile time; only `#private` and instance properties are out of reach).
 * The Worker only needs `fetch`. So the class keeps these rules:
 *
 * - The public members are exactly `fetch` and the runtime handlers `alarm`, `webSocketMessage`
 *   and `webSocketClose`. The base class declares the handlers, so they stay public, and workerd
 *   rejects RPC calls to them as reserved names.
 * - Every other method is `#private`, or an instance property (an arrow function), which RPC
 *   cannot reach. Fields are never on the prototype.
 *
 * Lint keeps test code away from reflection on `AccountRelay` (`eslint/relay-private-state.js`), so
 * the member list comes from the class's source text, as `request-deadline.test.ts` does for its
 * guards, and each non-public member is then probed over a real stub.
 */

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import source from "../src/index.ts?raw";

/** The only public members of `AccountRelay`: `fetch` plus the runtime handlers. */
const EXPECTED_PUBLIC_MEMBERS = ["alarm", "fetch", "webSocketClose", "webSocketMessage"];

interface Member {
  readonly name: string;
  readonly modifiers: readonly string[];
}

/** The members declared directly in the `AccountRelay` class body (two-space indent), by source scan. */
function classMembers(): Member[] {
  const start = source.indexOf("export class AccountRelay");
  const end = source.indexOf("\n}\n", start);
  expect(start).toBeGreaterThan(-1);
  const body = source.slice(start, end).split("\n").slice(1);
  const members: Member[] = [];
  for (const line of body) {
    const match =
      /^ {2}((?:(?:override|private|protected|public|static|readonly|async|get|set) )*)(#?[A-Za-z_$][\w$]*)\s*[(<:=;]/.exec(
        line,
      );
    if (!match) continue;
    members.push({
      name: match[2] ?? "",
      modifiers: (match[1] ?? "").trim().split(/\s+/).filter(Boolean),
    });
  }
  return members;
}

/**
 * Call `name` on a stub for a fresh account. `RPC` resolves a property on the stub, so a name the
 * Durable Object doesn't expose fails there; the cast only names a property of the typed stub for
 * the compiler.
 */
async function callOverRpc(accountId: string, name: string): Promise<unknown> {
  const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
  return await stub[name as "fetch"](new Request("https://relay.allw.test/"));
}

const NOT_EXPOSED = /does not implement|reserved method/;

describe("AccountRelay RPC surface (#373)", () => {
  const members = classMembers().filter((member) => member.name !== "constructor");

  it("finds the class members", () => {
    expect(members.length).toBeGreaterThan(10);
    expect(members.map((member) => member.name)).toContain("sql");
  });

  it("declares only fetch and the runtime handlers as public members", () => {
    const publicNames = members
      .filter((member) => !member.name.startsWith("#"))
      .filter((member) => !member.modifiers.includes("private"))
      .filter((member) => !member.modifiers.includes("protected"))
      .map((member) => member.name)
      .sort();
    expect(publicNames).toEqual(EXPECTED_PUBLIC_MEMBERS);
  });

  it("calls fetch over RPC", async () => {
    const response = await callOverRpc("acct-rpc-fetch", "fetch");
    expect(response).toBeInstanceOf(Response);
    expect((response as Response).status).toBe(404);
  });

  it.each(["alarm", "webSocketMessage", "webSocketClose"])(
    "rejects an RPC call to the reserved handler %s",
    async (name) => {
      await expect(callOverRpc(`acct-rpc-${name}`, name)).rejects.toThrow(/reserved method/);
    },
  );

  it("rejects an RPC call to every private or protected member, and to names it never had", async () => {
    const hidden = members
      .filter(
        (member) => member.modifiers.includes("private") || member.modifiers.includes("protected"),
      )
      .map((member) => member.name);
    expect(hidden).toContain("initSchema");
    // `ctx` and `env` come from the base class.
    for (const name of [...hidden, "ctx", "env", "nonexistent"]) {
      await expect(callOverRpc(`acct-rpc-hidden-${name}`, name), name).rejects.toThrow(NOT_EXPOSED);
    }
  });
});
