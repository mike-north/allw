/**
 * The constant-time token-hash compare runs on every path, including when there is no stored hash
 * (#357, `docs/relay-api.md` §1: the work must not depend on whether the row exists).
 */
import { describe, it, expect, vi } from "vitest";
import { matchesStoredHash, timingSafeEqual } from "../src/auth-token.js";

/** A base64url SHA-256 digest is 43 characters. */
const STORED = "q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9z0x1c";
const OTHER = "z9x8c7v6b5n4m3l2k1j0h9g8f7d6s5a4p3o2i1u0y9t";

describe("matchesStoredHash", () => {
  it("compares once against the stored hash when there is one", () => {
    const compare = vi.fn(timingSafeEqual);
    expect(matchesStoredHash(STORED, STORED, compare)).toBe(true);
    expect(matchesStoredHash(STORED, OTHER, compare)).toBe(false);
    expect(compare.mock.calls).toEqual([
      [STORED, STORED],
      [STORED, OTHER],
    ]);
  });

  it("still compares, against a same-length stand-in, when there is no stored hash", () => {
    const compare = vi.fn(timingSafeEqual);
    expect(matchesStoredHash(null, OTHER, compare)).toBe(false);
    expect(compare).toHaveBeenCalledTimes(1);
    const [standIn, presented] = compare.mock.calls[0] ?? [];
    expect(presented).toBe(OTHER);
    expect(standIn).toHaveLength(OTHER.length);
  });

  it("never matches a missing stored hash, whatever the compare says", () => {
    expect(matchesStoredHash(null, OTHER, () => true)).toBe(false);
  });
});

describe("timingSafeEqual", () => {
  it("is equality on strings", () => {
    expect(timingSafeEqual(STORED, STORED)).toBe(true);
    expect(timingSafeEqual(STORED, OTHER)).toBe(false);
    expect(timingSafeEqual(STORED, STORED.slice(0, -1))).toBe(false);
    expect(timingSafeEqual("", "")).toBe(true);
  });
});
