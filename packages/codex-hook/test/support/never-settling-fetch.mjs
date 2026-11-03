/**
 * Preload (`node --import`) for the exit-backstop UATs (#265): makes the gate's SDK wait a promise
 * that never settles and holds no event-loop refs.
 *
 * `fetch` returns a promise nothing will ever resolve, and `WebSocket` is removed so the SDK cannot
 * open a socket either. With nothing left to keep Node alive, the event loop drains while `main()` is
 * still awaiting the approval: the shape of the #254 bug, where the hook exited 0 with empty stdout.
 * The hook bin itself is the real, unmodified `dist/cli.js`.
 */

globalThis.fetch = () => new Promise(() => {});
globalThis.WebSocket = undefined;
