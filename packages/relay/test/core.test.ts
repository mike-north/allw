/**
 * The relay's core binding loads the real `allw-wasm` build under the Workers runtime, and every
 * function `src/allw-wasm.d.ts` declares exists in the generated glue (so a renamed or removed
 * core export cannot drift silently behind the hand-written declarations).
 *
 * @see ../src/allw-wasm.d.ts
 * @see ../src/core.ts
 * @see ../../../docs/enrollment.md §Model (account id derivation)
 */

import { describe, it, expect } from "vitest";
import * as glue from "@allw/sdk/vendor/allw-wasm/allw_wasm.js";
import { checkAccountIdForRoot } from "../src/core.js";
import { testRoot } from "./support/accounts.js";

/** Every function declared for the glue module in `src/allw-wasm.d.ts`. */
const DECLARED_GLUE_FUNCTIONS = [
  "initSync",
  "account_id_for_root",
  "check_account_id_for_root",
  "verify_pairing_start_authorization",
  "sign_pairing_start_authorization",
  "ed25519_public_key",
] as const;

describe("core binding", () => {
  it("every declared glue function exists in the built wasm glue", () => {
    const exports = glue as unknown as Record<string, unknown>;
    for (const name of DECLARED_GLUE_FUNCTIONS) {
      expect(typeof exports[name], name).toBe("function");
    }
  });

  it("derives and checks a self-certifying account id under workerd", () => {
    const root = testRoot("core-binding");
    // Spec: base64url-unpadded SHA-256 → 43 URL-safe characters.
    expect(root.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(() => {
      checkAccountIdForRoot(root.id, root.rootPubkey);
    }).not.toThrow();
    expect(() => {
      checkAccountIdForRoot(testRoot("core-binding-other").id, root.rootPubkey);
    }).toThrow();
  });
});
