/**
 * An in-process double for the narrow `ApprovalGateway` surface the decision core depends on.
 *
 * It speaks the real RPC method names and the real response shapes (`approval.get`,
 * `approval.resolve`, `exec.approval.list`), and records every call so tests can assert on what was
 * — and, more importantly, was **not** — submitted.
 *
 * The over-the-wire frame contract is exercised separately, against a real WebSocket server, in
 * `../gateway.test.mjs`.
 *
 * @see ../../../../docs/openclaw-integration.md §7.4 Submitting the resolve
 */

export class FakeGateway {
  /** Every `{ method, params }` the bridge issued, in order. */
  calls = [];
  /** Every `approval.resolve` params object, in order. */
  resolves = [];
  #listeners = new Set();
  #handlers;

  /**
   * @param handlers per-method handlers. A handler may return a value or throw to simulate a
   *   gateway error / lost connection.
   */
  constructor(handlers = {}) {
    this.#handlers = handlers;
  }

  get connected() {
    return true;
  }

  async request(method, params) {
    this.calls.push({ method, params });
    if (method === "approval.resolve") this.resolves.push(params);
    const handler = this.#handlers[method];
    if (handler === undefined) throw new Error(`fake gateway: unhandled method '${method}'`);
    return await handler(params, this);
  }

  addEventListener(listener) {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  /** Deliver a broadcast frame to every registered listener. */
  emit(event, payload) {
    for (const listener of [...this.#listeners]) listener({ event, payload });
  }
}

/** A verdict double with the two members the bridge reads. */
export function verdict(
  decision,
  { verifies = decision === "approved", verifyThrows = false } = {},
) {
  return {
    decision,
    verify: async () => {
      if (verifyThrows) throw new Error("verification exploded");
      return verifies;
    },
  };
}

/** Collect log records so tests can assert on what the operator sees (and what they do not). */
export function recordingLogger() {
  const records = [];
  const push =
    (level) =>
    (event, fields = {}) =>
      records.push({ level, event, fields });
  return {
    records,
    logger: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") },
  };
}
