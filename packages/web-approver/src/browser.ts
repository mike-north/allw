import {
  WebApproverController,
  type ApprovalDecision,
  type ApprovalEnvelope,
  type ApprovalStatus,
  type WebApproverRuntime,
} from "./index.js";

interface BrowserConfig {
  readonly root: HTMLElement;
  readonly runtime: WebApproverRuntime;
  readonly fetchInbox: () => Promise<readonly ApprovalEnvelope[]>;
  readonly nowMs?: () => number;
}

declare global {
  interface Window {
    allwWebApprover?: BrowserConfig;
  }
}

export async function mountWebApprover(config: BrowserConfig): Promise<WebApproverController> {
  const controllerOptions = {
    runtime: config.runtime,
    ...(config.nowMs ? { nowMs: config.nowMs } : {}),
  };
  const controller = new WebApproverController(controllerOptions);

  async function refresh(): Promise<void> {
    const envelopes = await config.fetchInbox();
    await controller.sync(envelopes);
    render(config.root, controller, refresh);
  }

  await refresh();
  return controller;
}

function render(
  root: HTMLElement,
  controller: WebApproverController,
  refresh: () => Promise<void>,
): void {
  root.replaceChildren();
  const shell = document.createElement("main");
  shell.className = "approver-shell";

  const header = document.createElement("header");
  header.className = "approver-header";
  header.append(textElement("h1", "allw approvals"));

  const refreshButton = document.createElement("button");
  refreshButton.type = "button";
  refreshButton.className = "icon-button";
  refreshButton.title = "Refresh approvals";
  refreshButton.textContent = "↻";
  refreshButton.addEventListener("click", () => {
    void refresh();
  });
  header.append(refreshButton);
  shell.append(header);

  const inbox = section("Pending", controller.inbox(), controller, true, refresh);
  const history = section("History", controller.history(), controller, false, refresh);
  shell.append(inbox, history);
  root.append(shell);
}

function section(
  title: string,
  items: readonly ReturnType<WebApproverController["inbox"]>[number][],
  controller: WebApproverController,
  interactive: boolean,
  refresh: () => Promise<void>,
): HTMLElement {
  const sectionEl = document.createElement("section");
  sectionEl.className = "approver-section";
  sectionEl.append(textElement("h2", title));

  if (items.length === 0) {
    const empty = textElement(
      "p",
      title === "Pending" ? "No pending approvals." : "No resolved approvals.",
    );
    empty.className = "empty-state";
    sectionEl.append(empty);
    return sectionEl;
  }

  const list = document.createElement("div");
  list.className = "approval-list";
  for (const item of items) {
    list.append(card(item.id, controller, interactive, refresh));
  }
  sectionEl.append(list);
  return sectionEl;
}

function card(
  id: string,
  controller: WebApproverController,
  interactive: boolean,
  refresh: () => Promise<void>,
): HTMLElement {
  const detail = controller.detail(id);
  if (!detail) {
    return document.createElement("article");
  }

  const article = document.createElement("article");
  article.className = `approval-card approval-card--${statusClass(detail.status)}`;
  article.append(textElement("h3", detail.summary));
  article.append(metaLine("Actor", detail.actor));
  article.append(
    metaLine("Risk", `${detail.riskLevel}${detail.reversible === false ? " · irreversible" : ""}`),
  );
  article.append(metaLine("Expires", `${String(Math.ceil(detail.countdownMs / 1000))}s`));
  article.append(metaLine("Request hash", detail.requestHash ?? "unverified"));

  const plaintext = document.createElement("pre");
  plaintext.className = "approval-plaintext";
  plaintext.textContent = detail.exactPlaintext;
  article.append(plaintext);

  if (detail.verificationError) {
    const warning = textElement("p", `Verification failed: ${detail.verificationError}`);
    warning.className = "verification-warning";
    article.append(warning);
  }

  if (interactive) {
    article.append(decisionControls(id, controller, refresh));
  }
  return article;
}

function decisionControls(
  id: string,
  controller: WebApproverController,
  refresh: () => Promise<void>,
): HTMLElement {
  const form = document.createElement("form");
  form.className = "decision-controls";
  const detail = controller.detail(id);
  const challenge = detail?.challenge;

  const challengeInput = document.createElement("input");
  challengeInput.name = "challenge";
  challengeInput.inputMode = "numeric";
  challengeInput.autocomplete = "one-time-code";
  challengeInput.placeholder = challenge?.prompt ?? "Number match";
  challengeInput.hidden = !challenge;

  const deny = button("Deny", "denied");
  const approve = button("Approve", "approved");
  approve.disabled = !controller.canApprove(id);

  challengeInput.addEventListener("input", () => {
    approve.disabled = !controller.canApprove(id, { challengeResponse: challengeInput.value });
  });

  form.append(challengeInput, deny, approve);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const submitter = event.submitter;
    const decision =
      submitter instanceof HTMLButtonElement && isDecision(submitter.value)
        ? submitter.value
        : "denied";
    const challengeResponse = challengeInput.value || undefined;
    deny.disabled = true;
    approve.disabled = true;
    challengeInput.disabled = true;
    void controller
      .decide(id, decision, {
        ...(challengeResponse ? { challengeResponse } : {}),
      })
      .then(refresh, refresh);
  });
  return form;
}

function button(label: string, value: ApprovalDecision): HTMLButtonElement {
  const buttonEl = document.createElement("button");
  buttonEl.type = "submit";
  buttonEl.name = "decision";
  buttonEl.value = value;
  buttonEl.textContent = label;
  return buttonEl;
}

function isDecision(value: string): value is ApprovalDecision {
  return value === "approved" || value === "denied";
}

function metaLine(label: string, value: string): HTMLElement {
  const line = document.createElement("p");
  line.className = "approval-meta";
  line.append(textElement("strong", `${label}: `), document.createTextNode(value));
  return line;
}

function textElement<Tag extends keyof HTMLElementTagNameMap>(
  tag: Tag,
  text: string,
): HTMLElementTagNameMap[Tag] {
  const element = document.createElement(tag);
  element.textContent = text;
  return element;
}

function statusClass(status: ApprovalStatus): string {
  return status.replaceAll(" ", "-");
}

if (typeof window !== "undefined" && window.allwWebApprover) {
  void mountWebApprover(window.allwWebApprover);
}
