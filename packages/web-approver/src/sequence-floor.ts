/**
 * Device-side account-state rollback floor for the browser web approver (#171 — the web analogue of
 * `packages/approver`'s keyfile-persisted floor, #115).
 *
 * # Why a floor is needed (`docs/enrollment.md` §Account State, step 5)
 * The relay's `GET /{account_id}/account-states` response carries a self-reported `max_sequence`
 * metadata field alongside the opaque, root-signed account-state documents it distributes. The relay
 * cannot forge a root signature, but it CAN simply keep re-serving an OLDER — still validly
 * root-signed — account-state document (and lie about `max_sequence` to match) to suppress a newer
 * revocation. Nothing about that older document is individually invalid, so root-signature
 * verification alone cannot catch the rollback; only remembering the highest sequence this device
 * has ever accepted, across page reloads, closes the gap.
 *
 * # Two independent signals; the effective floor is the higher of the two
 * `runtime.ts` gates a verified origin on BOTH of the following independently:
 *
 * 1. the relay's own `max_sequence` metadata for the CURRENT fetch (an honesty check on the relay's
 *    bookkeeping for this one response), and
 * 2. the floor persisted by THIS store (the highest root-verified sequence ever accepted, surviving
 *    reloads).
 *
 * A verified-highest-sequence below EITHER signal fails closed to `unverified` — i.e. the effective
 * threshold a fetch must reach is `max(persisted floor, this fetch's relay max_sequence)`. This means
 * a corrupt or absent persisted floor (first-ever fetch, or local storage tampering/clearing) does
 * not by itself disable protection: the per-fetch relay metadata check still applies, and vice versa.
 *
 * # Storage-tamper / absence posture
 * `load()` never throws. A missing key (never paired / first run) or a value that fails to parse as
 * a non-negative safe integer (corrupted/tampered storage) both return `0` — "no floor recorded
 * yet" — rather than crashing approval rendering. This is safe *given* the dual-signal design above:
 * a `0` floor from this store never suppresses the still-independent relay-metadata check.
 *
 * @see ./runtime.ts (the consumer — `resolveAttestation`'s sequence-floor gate)
 * @see ./account-state.ts (surfaces the relay's per-fetch `max_sequence` this floor is compared to)
 * @see ../../approver/src/lib/keyfile.ts (`account_state_highest_sequence`, the Node/CLI analogue)
 * @see ../../../docs/enrollment.md §Account State
 */

/** The `localStorage` key under which the persisted floor is stored (plain decimal string). */
export const ACCOUNT_STATE_FLOOR_STORAGE_KEY = "allw:account-state-floor:v1";

/**
 * Injectable persistence seam for the device-side account-state sequence floor.
 *
 * The default implementation ({@link createLocalAccountStateFloorStore}) persists to
 * `localStorage`, mirroring {@link PairingStore}'s storage tradeoff (`docs/enrollment.md` §Device
 * Enrollment): survives reloads, accessible to any script on the origin. A custom implementation may
 * back this with `sessionStorage`, IndexedDB, or an in-memory store (tests / SSR).
 */
export interface AccountStateFloorStore {
  /** The highest root-verified account-state sequence persisted so far. `0` means none yet. */
  load(): number;
  /**
   * Persist a newly observed root-verified sequence. **Monotonic by construction**: a call with a
   * `sequence` at or below the currently stored value is a no-op — the floor can only ever go up,
   * regardless of what the caller passes.
   */
  save(sequence: number): void;
  /** Remove the persisted floor. Test/reset-only; production code never needs to lower the floor. */
  clear(): void;
}

/** Parse a raw stored value into a safe non-negative floor, defaulting to `0` on any failure. */
function parseStoredFloor(raw: string | null): number {
  if (raw === null) return 0;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return 0;
  return parsed;
}

/**
 * Build an {@link AccountStateFloorStore} backed by `localStorage` (or an injected
 * `Storage`-compatible object — a plain `Map`-backed fake in tests).
 */
export function createLocalAccountStateFloorStore(storage?: Storage): AccountStateFloorStore {
  const store: Storage = storage ?? localStorage;

  function load(): number {
    try {
      return parseStoredFloor(store.getItem(ACCOUNT_STATE_FLOOR_STORAGE_KEY));
    } catch {
      // A storage read can throw (private-browsing quota lockouts, security errors); treat like
      // "no floor recorded yet" — the independent relay-metadata check in runtime.ts still applies.
      return 0;
    }
  }

  return {
    load,
    save(sequence: number) {
      if (!Number.isSafeInteger(sequence) || sequence <= 0) return;
      if (sequence <= load()) return; // monotonic: never move the floor down or hold it steady
      try {
        store.setItem(ACCOUNT_STATE_FLOOR_STORAGE_KEY, String(sequence));
      } catch {
        // A full/blocked storage quota must not crash approval rendering — the floor simply will
        // not survive to the next reload; this call's in-memory comparison already happened.
      }
    },
    clear() {
      store.removeItem(ACCOUNT_STATE_FLOOR_STORAGE_KEY);
    },
  };
}

/**
 * Build an in-memory {@link AccountStateFloorStore} with no cross-reload persistence. This is the
 * default the runtime falls back to when no store is supplied (matching `resolveAccountStates`'s
 * "no resolution" default) — it still enforces monotonicity and the sequence-floor gate WITHIN one
 * runtime instance's lifetime, but a fresh page load starts a fresh instance with `load() === 0`.
 * Production boot (`app.ts`) always supplies {@link createLocalAccountStateFloorStore} explicitly so
 * the floor survives reloads.
 */
export function createInMemoryAccountStateFloorStore(): AccountStateFloorStore {
  let floor = 0;
  return {
    load: () => floor,
    save(sequence: number) {
      if (Number.isSafeInteger(sequence) && sequence > floor) floor = sequence;
    },
    clear() {
      floor = 0;
    },
  };
}
