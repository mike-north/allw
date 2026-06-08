/**
 * `@allw/sdk` — the call site for agents, hooks, and CI to request a human approval.
 *
 * See `../../docs/contract.md`. Security-critical logic lives in `allw-core` (Rust), reached
 * here via WASM; this package is the ergonomic TypeScript surface. **Status: skeleton.**
 */

export type Decision = "approved" | "denied" | "expired" | "aborted";
export type Risk = "low" | "medium" | "high" | "critical";

/** The interception paradigm an action arrived through. */
export type Surface = "command" | "mcp_tool_call";

/**
 * A reduced, matchable record of an approvable action. v1 carries the syntactic substrate;
 * semantic `capabilities`/`scope` are reserved for the policy layer. See `../../docs/policy-seam.md`.
 */
export interface ActionRecord {
  readonly recordSchemaVersion: number;
  readonly surface: Surface;
  /** Raw, structured syntactic form (tokenized command / MCP call). */
  readonly syntactic: unknown;
  readonly risk: Risk;
}

export interface ApprovalRequest {
  readonly action: ActionRecord;
  /** One-line, human-readable summary shown in the notification. */
  readonly summary: string;
  /** Routing target — the approver's inbox. */
  readonly approver: string;
  /** Fail-closed deadline; on expiry the verdict resolves to `expired`. */
  readonly timeoutMs?: number;
}

export interface Verdict {
  readonly requestId: string;
  readonly decision: Decision;
  /** Verify the signature + request binding against the approver's root key. */
  verify(approverRootKey: Uint8Array): boolean;
}

/**
 * Request a one-shot human decision over an E2EE channel.
 *
 * Fail-closed: on timeout or an unverifiable response, resolves to a `denied`/`expired`
 * verdict. Never returns "allow" — the caller composes
 * `allow = approved ∧ verified ∧ policy ∧ other gates`.
 *
 * @throws not yet implemented — skeleton.
 */
export function requestApproval(_req: ApprovalRequest): Promise<Verdict> {
  return Promise.reject(new Error("allw: requestApproval not yet implemented"));
}
