/**
 * Preload (`node --import`) for the backstop UATs that need the hook **parked mid-wait** and then
 * interrupted (#265): signals, an uncaught async throw, and a stray `process.exit(1)`.
 *
 * `fetch` returns a promise that never settles and `WebSocket` is removed, so the gate's SDK waits
 * forever. On the first `fetch` (which happens only after `main()` has installed the backstop) it
 * writes {@link FETCH_PENDING_MARKER} to stderr, then does what `ALLW_TEST_AFTER_FETCH` says:
 *
 * - `wait` (default): hold the event loop open, so the test can send a signal at a known point.
 * - `throw`: throw from a timer shortly after, an uncaught exception outside `main()`'s try/catch.
 * - `exit1`: call `process.exit(1)` shortly after, as a misbehaving dependency might.
 *
 * The hook bin itself is the real, unmodified `dist/cli.js`.
 */

/** Written to stderr once the hook is waiting on the relay. */
export const FETCH_PENDING_MARKER = "allw-test: fetch pending";

/** Delay before the `throw` / `exit1` interruption, so it lands while the wait is pending. */
const INTERRUPT_AFTER_MS = 50;

let announced = false;

globalThis.fetch = () => {
  if (!announced) {
    announced = true;
    process.stderr.write(`${FETCH_PENDING_MARKER}\n`);
    const mode = process.env.ALLW_TEST_AFTER_FETCH ?? "wait";
    if (mode === "wait") {
      setInterval(() => {}, 60_000);
    } else if (mode === "throw") {
      setTimeout(() => {
        throw new Error("allw-test: async throw while waiting");
      }, INTERRUPT_AFTER_MS);
    } else if (mode === "exit1") {
      setTimeout(() => process.exit(1), INTERRUPT_AFTER_MS);
    } else {
      throw new Error(`allw-test: unknown ALLW_TEST_AFTER_FETCH=${mode}`);
    }
  }
  return new Promise(() => {});
};
globalThis.WebSocket = undefined;
