export type ApprovalDecision = "approved" | "denied";

export type ApprovalStatus = "pending" | "deciding" | "expired" | "unverified" | ApprovalDecision;

export interface ApprovalEnvelope {
  readonly v: number;
  readonly id: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly approver: string;
  readonly context_ciphertext: string;
  readonly resolved_at?: number;
}

export interface ApprovalActor {
  readonly id: string;
  readonly display: string;
  readonly attestation: "verified" | "unverified" | "pending";
}

export interface ApprovalRisk {
  readonly level: "low" | "medium" | "high" | "critical";
  readonly reversible: boolean;
  readonly summary: string;
}

export interface CommandAction {
  readonly cwd?: string;
  readonly argv: readonly string[];
  readonly raw?: string;
}

export interface McpCallAction {
  readonly server: string;
  readonly tool: string;
  readonly params: unknown;
}

export interface NumberMatchChallenge {
  readonly kind: "number-match";
  readonly code: string;
  readonly prompt: string;
}

export interface ApprovalContext {
  readonly kind: "command" | "mcp";
  readonly command?: CommandAction;
  readonly mcp?: McpCallAction;
  readonly actor: ApprovalActor;
  readonly risk: ApprovalRisk;
  readonly allowed_decisions: readonly ApprovalDecision[];
  readonly challenge?: NumberMatchChallenge;
}

export interface PreparedApproval {
  readonly requestHash: string;
  readonly context: ApprovalContext;
  /** MUST be set only from a core-verified terminal Verdict. */
  readonly resolvedDecision?: ApprovalDecision;
}

export interface SignDecisionInput {
  readonly envelope: ApprovalEnvelope;
  readonly prepared: PreparedApproval;
  readonly decision: ApprovalDecision;
  readonly challengeResponse?: string;
}

export interface SignedVerdict {
  readonly requestId: string;
  readonly decision: ApprovalDecision;
  readonly signedVerdictJson: string;
}

export interface WebApproverRuntime {
  /**
   * Decrypts the relay envelope, recomputes the WYSIWYS request hash, and returns the
   * exact plaintext model to render. Implementations must call the WASM/core-backed
   * allw surfaces; the web shell treats failures as deny-by-default.
   */
  prepare(envelope: ApprovalEnvelope): Promise<PreparedApproval>;

  /**
   * Signs a human decision with the device/account key material held by the runtime.
   * The controller validates UI state first, but signing remains delegated to core.
   */
  signDecision(input: SignDecisionInput): Promise<SignedVerdict>;
}

export interface WebApproverControllerOptions {
  readonly runtime: WebApproverRuntime;
  readonly nowMs?: () => number;
}

export interface ApprovalListItem {
  readonly id: string;
  readonly status: ApprovalStatus;
  readonly actor: string;
  readonly riskLevel: ApprovalRisk["level"] | "unknown";
  readonly summary: string;
  readonly expiresAt: number;
  readonly countdownMs: number;
  readonly denyOnly: boolean;
}

export interface ApprovalDetail extends ApprovalListItem {
  readonly requestHash?: string;
  readonly exactPlaintext: string;
  readonly actorId?: string;
  readonly attestation?: ApprovalActor["attestation"];
  readonly reversible?: boolean;
  readonly verificationError?: string;
  readonly challenge?: NumberMatchChallenge;
}

interface ApprovalRecord {
  readonly envelope: ApprovalEnvelope;
  readonly prepared?: PreparedApproval;
  readonly verificationError?: string;
  status: ApprovalStatus;
  decidedAt?: number;
}

export class WebApproverController {
  readonly #runtime: WebApproverRuntime;
  readonly #nowMs: () => number;
  readonly #records = new Map<string, ApprovalRecord>();

  constructor(options: WebApproverControllerOptions) {
    this.#runtime = options.runtime;
    this.#nowMs = options.nowMs ?? Date.now;
  }

  /**
   * Refreshes the controller from relay-visible envelopes. Each envelope is prepared
   * independently so one tampered/undecryptable request cannot hide the rest of the inbox.
   */
  async sync(envelopes: readonly ApprovalEnvelope[]): Promise<void> {
    const preparedRecords = await Promise.all(envelopes.map((envelope) => this.#prepare(envelope)));
    this.#records.clear();

    for (const record of preparedRecords) {
      this.#records.set(record.envelope.id, record);
    }
  }

  inbox(): readonly ApprovalListItem[] {
    return this.#list(["pending", "deciding", "expired", "unverified"]).filter(
      (item) => item.status === "pending" || item.status === "deciding",
    );
  }

  history(): readonly ApprovalListItem[] {
    return this.#list(["approved", "denied"]);
  }

  detail(id: string): ApprovalDetail | undefined {
    const record = this.#records.get(id);
    if (!record) {
      return undefined;
    }
    return this.#toDetail(record);
  }

  canApprove(id: string, options: { readonly challengeResponse?: string } = {}): boolean {
    const record = this.#records.get(id);
    if (!record?.prepared || record.status !== "pending") {
      return false;
    }
    if (!record.prepared.context.allowed_decisions.includes("approved")) {
      return false;
    }
    return this.#challengeSatisfied(record.prepared.context, options.challengeResponse);
  }

  async decide(
    id: string,
    decision: ApprovalDecision,
    options: { readonly challengeResponse?: string } = {},
  ): Promise<SignedVerdict> {
    const record = this.#records.get(id);
    if (!record) {
      throw new Error(`unknown request '${id}'`);
    }
    if (record.status === "expired") {
      throw new Error(`request '${id}' is expired`);
    }
    if (record.status === "deciding") {
      throw new Error(`request '${id}' is already being decided`);
    }
    if (!record.prepared || record.status === "unverified") {
      throw new Error(`request '${id}' is not approvable`);
    }
    if (!record.prepared.context.allowed_decisions.includes(decision)) {
      throw new Error(`decision '${decision}' is not allowed for request '${id}'`);
    }
    if (decision === "approved" && !this.canApprove(id, options)) {
      if (record.prepared.context.challenge?.kind === "number-match") {
        throw new Error(`number-match challenge failed for request '${id}'`);
      }
      throw new Error(`request '${id}' is not approvable`);
    }

    const signInput = this.#signInput(record, decision, options.challengeResponse);
    // Claim the request before signing so duplicate submits cannot produce two verdicts.
    record.status = "deciding";
    try {
      const verdict = await this.#runtime.signDecision(signInput);
      record.status = decision;
      record.decidedAt = this.#nowMs();
      return verdict;
    } catch (error) {
      record.status = "pending";
      throw error;
    }
  }

  async #prepare(envelope: ApprovalEnvelope): Promise<ApprovalRecord> {
    try {
      const prepared = await this.#runtime.prepare(envelope);
      const resolvedDecision = prepared.resolvedDecision;
      if (resolvedDecision) {
        return { envelope, prepared, status: resolvedDecision };
      }
      return {
        envelope,
        prepared,
        status: envelope.expires_at <= this.#nowMs() ? "expired" : "pending",
      };
    } catch (error) {
      return {
        envelope,
        status: "unverified",
        verificationError: error instanceof Error ? error.message : String(error),
      };
    }
  }

  #list(statuses: readonly ApprovalStatus[]): readonly ApprovalListItem[] {
    return Array.from(this.#records.values())
      .filter((record) => statuses.includes(record.status))
      .map((record) => this.#toListItem(record))
      .sort((left, right) => {
        if (left.status === "pending" && right.status === "pending") {
          return left.expiresAt - right.expiresAt;
        }
        return right.expiresAt - left.expiresAt;
      });
  }

  #toListItem(record: ApprovalRecord): ApprovalListItem {
    const context = record.prepared?.context;
    return {
      id: record.envelope.id,
      status: record.status,
      actor: context?.actor.display ?? "Unverified request",
      riskLevel: context?.risk.level ?? "unknown",
      summary: context ? actionSummary(context) : "Unable to verify or decrypt this request",
      expiresAt: record.envelope.expires_at,
      countdownMs: Math.max(0, record.envelope.expires_at - this.#nowMs()),
      denyOnly: record.status === "unverified" || record.status === "expired",
    };
  }

  #toDetail(record: ApprovalRecord): ApprovalDetail {
    const item = this.#toListItem(record);
    const prepared = record.prepared;
    const context = prepared?.context;
    const base = {
      ...item,
      exactPlaintext: context ? exactPlaintext(context) : "Context could not be verified.",
    };

    if (!prepared) {
      return {
        ...base,
        verificationError: record.verificationError ?? "unverified request",
      };
    }

    const detail: ApprovalDetail = {
      ...base,
      requestHash: prepared.requestHash,
      actorId: prepared.context.actor.id,
      attestation: prepared.context.actor.attestation,
      reversible: prepared.context.risk.reversible,
    };
    if (prepared.context.challenge) {
      return { ...detail, challenge: prepared.context.challenge };
    }
    return detail;
  }

  #challengeSatisfied(context: ApprovalContext, challengeResponse: string | undefined): boolean {
    const challenge = context.challenge;
    if (!challenge) {
      return true;
    }
    return challengeResponse === challenge.code;
  }

  #signInput(
    record: ApprovalRecord,
    decision: ApprovalDecision,
    challengeResponse: string | undefined,
  ): SignDecisionInput {
    if (!record.prepared) {
      throw new Error(`request '${record.envelope.id}' has no prepared plaintext`);
    }
    const input: SignDecisionInput = {
      envelope: record.envelope,
      prepared: record.prepared,
      decision,
    };
    if (challengeResponse !== undefined) {
      return { ...input, challengeResponse };
    }
    return input;
  }
}

export function actionSummary(context: ApprovalContext): string {
  if (context.kind === "command" && context.command) {
    return context.command.raw ?? shellQuote(context.command.argv);
  }
  if (context.kind === "mcp" && context.mcp) {
    return `${context.mcp.server}.${context.mcp.tool}`;
  }
  return "Unknown action";
}

export function exactPlaintext(context: ApprovalContext): string {
  if (context.kind === "command" && context.command) {
    const cwd = context.command.cwd ? `cwd: ${context.command.cwd}\n` : "";
    return `${cwd}argv: ${JSON.stringify(context.command.argv)}\nraw: ${
      context.command.raw ?? shellQuote(context.command.argv)
    }`;
  }
  if (context.kind === "mcp" && context.mcp) {
    return `mcp: ${context.mcp.server}.${context.mcp.tool}\nparams: ${JSON.stringify(
      context.mcp.params,
      null,
      2,
    )}`;
  }
  return "Unknown action";
}

function shellQuote(argv: readonly string[]): string {
  return argv
    .map((part) => {
      if (/^[A-Za-z0-9_./:=@+-]+$/.test(part)) {
        return part;
      }
      return `'${part.replaceAll("'", "'\\''")}'`;
    })
    .join(" ");
}
