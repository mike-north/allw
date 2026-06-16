/**
 * Audit-history DOM renderer: a read-only timeline of resolved decisions.
 *
 * Thin-shell over the `WebApproverController`: this module only renders the view model produced by
 * `controller.auditHistory()`; no crypto, hashing, or verification is implemented here
 * (`docs/architecture.md` §Thin surfaces, `docs/contract.md` §Invariants #6).
 *
 * # Fail-closed display (`docs/contract.md` §Invariants #6)
 * Records with `chainStatus: "broken"` must be visually prominent and must never look
 * approved-looking. This module uses `data-chain-status` and `data-decision` attributes so CSS
 * can apply the correct visual treatment without any conditional string injection. The decision
 * controls area is intentionally omitted — audit history is read-only by design (flow-notes.md).
 *
 * # WYSIWYS receipt
 * The exact plaintext from `detail.exactPlaintext` is rendered verbatim in a `<pre>` with
 * `textContent` only — no innerHTML, no interpolation — matching the inbox detail view.
 *
 * @see design/web-approver/audit-history/app.jsx (visual source of truth, design #125)
 * @see design/web-approver/inbox/tokens.css (verbatim token source)
 * @see docs/contract.md §Audit chain, §Invariants #6 (fail-closed)
 * @see packages/web-approver/src/index.ts (AuditHistoryItem, WebApproverController)
 */

import type { AuditHistoryItem, WebApproverController } from "./index.js";

/**
 * Mount the audit-history view into `root`. Returns a disposer that tears down all DOM children
 * added by this function (suitable for SPA route cleanup).
 *
 * The caller is responsible for calling `controller.sync(envelopes)` before mounting; this
 * function only renders `controller.auditHistory()` — it does not fetch or sync.
 */
export function mountAuditHistory(
  root: HTMLElement,
  controller: WebApproverController,
): () => void {
  const items = controller.auditHistory();
  root.replaceChildren();

  const section = document.createElement("section");
  section.className = "audit-history";
  section.setAttribute("aria-label", "Audit history");

  // Chain integrity cue — shown even when the list is empty so the header is always present.
  const brokenCount = items.filter((item) => item.chainStatus === "broken").length;
  const chainHealthy = brokenCount === 0;
  section.append(chainCue(chainHealthy));

  const heading = textElement("h2", "Resolved decisions");
  heading.className = "audit-history__heading";
  section.append(heading);

  if (items.length === 0) {
    const empty = textElement("p", "No resolved decisions.");
    empty.className = "audit-history__empty";
    section.append(empty);
    root.append(section);
    return () => {
      root.replaceChildren();
    };
  }

  // Timeline list
  const list = document.createElement("ol");
  list.className = "audit-history__list";
  for (const item of items) {
    list.append(timelineRow(item, controller));
  }
  section.append(list);
  root.append(section);

  return () => {
    root.replaceChildren();
  };
}

/** The chain-integrity status cue displayed in the audit-history header. */
function chainCue(healthy: boolean): HTMLElement {
  const cue = document.createElement("div");
  cue.className = "audit-chain-cue";
  cue.dataset.chainStatus = healthy ? "verified" : "broken";
  cue.setAttribute("role", "status");

  const icon = document.createElement("span");
  icon.className = "audit-chain-cue__icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = healthy ? "✓" : "⚠";

  const label = textElement(
    "span",
    healthy
      ? "Audit chain verified for all resolved decisions in this view."
      : "Chain integrity warning: one or more records could not be verified.",
  );
  label.className = "audit-chain-cue__label";

  cue.append(icon, label);
  return cue;
}

/** A single timeline row for one resolved `AuditHistoryItem`. */
function timelineRow(item: AuditHistoryItem, controller: WebApproverController): HTMLElement {
  const detail = controller.detail(item.id);

  const li = document.createElement("li");
  li.className = "audit-row";
  li.dataset.decision = item.status;
  li.dataset.chainStatus = item.chainStatus;

  // Rail dot — color comes from CSS via data-chain-status
  const dot = document.createElement("span");
  dot.className = "audit-row__dot";
  dot.setAttribute("aria-hidden", "true");

  // Time column
  const time = document.createElement("time");
  time.className = "audit-row__time";
  if (item.decidedAt !== undefined) {
    time.dateTime = new Date(item.decidedAt).toISOString();
    time.textContent = formatTime(item.decidedAt);
  } else {
    time.textContent = "—";
  }

  // Summary + meta column
  const main = document.createElement("div");
  main.className = "audit-row__main";

  const summary = textElement("span", item.summary);
  summary.className = "audit-row__summary";

  const meta = textElement("span", `${item.actor} · risk: ${item.riskLevel}`);
  meta.className = "audit-row__meta";

  main.append(summary, meta);

  // Decision chip
  const chip = textElement("span", item.status);
  chip.className = "audit-decision-chip";

  li.append(dot, time, main, chip);

  // Expand to detail pane inline if detail is available
  const pane = detailPane(item, detail);
  if (pane) {
    li.append(pane);
  }

  return li;
}

/**
 * The decision-detail pane rendered under each row. Mirrors the design's "Decision detail" section
 * (`design/web-approver/audit-history/app.jsx` `Detail` component).
 *
 * Fail-closed: broken records display the fail-closed banner and never show
 * verification-passing evidence.
 */
function detailPane(
  item: AuditHistoryItem,
  detail: ReturnType<WebApproverController["detail"]>,
): HTMLElement | null {
  if (!detail) return null;

  const pane = document.createElement("div");
  pane.className = "audit-detail";

  // Status grid: verdict signature (chainStatus proxy), actor origin (attestation)
  const statusGrid = document.createElement("div");
  statusGrid.className = "audit-status-grid";

  statusGrid.append(
    evidenceCard(
      "Verdict signature",
      item.chainStatus === "verified" ? "verified" : "unverifiable",
      item.chainStatus !== "verified",
    ),
    evidenceCard(
      "Actor origin",
      detail.attestation ?? "unverified",
      detail.attestation !== "verified",
    ),
    evidenceCard(
      "Request hash",
      detail.requestHash ?? "unavailable",
      detail.requestHash === undefined,
    ),
  );

  pane.append(statusGrid);

  // WYSIWYS receipt — plain text, no innerHTML
  const wysiwys = document.createElement("div");
  wysiwys.className = "audit-wysiwys";

  const codeLabel = textElement("span", "WYSIWYS render");
  codeLabel.className = "audit-wysiwys__label";

  const pre = document.createElement("pre");
  pre.className = "audit-wysiwys__pre";
  pre.textContent = detail.exactPlaintext;

  wysiwys.append(codeLabel, pre);
  pane.append(wysiwys);

  // Fail-closed banner for broken records
  if (item.chainStatus === "broken") {
    const banner = document.createElement("div");
    banner.className = "audit-fail-closed";
    banner.setAttribute("role", "alert");

    const icon = document.createElement("span");
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = "⚠";

    const msg = textElement(
      "span",
      "This record is fail-closed and unapprovable until local chain continuity is restored.",
    );

    banner.append(icon, msg);
    pane.append(banner);
  }

  // Verification error (if any)
  if (detail.verificationError) {
    const err = textElement("p", `Verification failed: ${detail.verificationError}`);
    err.className = "audit-verification-error";
    pane.append(err);
  }

  return pane;
}

/** An evidence card for the status grid (verdict signature, actor origin, request hash). */
function evidenceCard(label: string, value: string, bad: boolean): HTMLElement {
  const card = document.createElement("div");
  card.className = bad ? "audit-evidence audit-evidence--bad" : "audit-evidence";

  const iconEl = document.createElement("span");
  iconEl.className = "audit-evidence__icon";
  iconEl.setAttribute("aria-hidden", "true");
  iconEl.textContent = bad ? "⚠" : "✓";

  const body = document.createElement("span");
  body.className = "audit-evidence__body";

  const labelEl = textElement("span", label);
  labelEl.className = "audit-evidence__label";

  const valueEl = textElement("span", value);
  valueEl.className = "audit-evidence__value";

  body.append(labelEl, valueEl);
  card.append(iconEl, body);
  return card;
}

/** Format a Unix-ms timestamp as a short human-readable string (no locale dependency). */
function formatTime(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${String(d.getUTCFullYear())}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

/** Create an element of the given tag containing only the given text (no innerHTML). */
function textElement<Tag extends keyof HTMLElementTagNameMap>(
  tag: Tag,
  text: string,
): HTMLElementTagNameMap[Tag] {
  const el = document.createElement(tag);
  el.textContent = text;
  return el;
}
