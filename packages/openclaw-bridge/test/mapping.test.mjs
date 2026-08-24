/**
 * Mapping tests: an OpenClaw exec approval → the allw `ApprovalContext` the human decides.
 *
 * Every expected value below is written by hand from the spec's tables (§5.1, §6.2, §6.4), not
 * captured from the implementation. The module under test is pure, so these are real unit
 * assertions against the real WASM core — no `ActionRecord` construction is faked.
 *
 * @see ../../../docs/openclaw-integration.md §5.1 exec → command, §6.1 two-source reconcile,
 *   §6.2 the ApprovalContext, §6.3 what is not bound, §6.4 risk/challenge/reversibility, §7.1 actor
 * @see ../../../docs/contract.md §request_hash (why `summary` and `chain` are hashed fields)
 */

import assert from "node:assert/strict";
import test from "node:test";

import { loadWasm } from "@allw/hook";

import {
  buildExecApprovalRequest,
  buildPluginApprovalRequest,
  execSummary,
  floorRisk,
  pluginSummary,
  reversibleForRisk,
  slugifyTitle,
} from "../dist/index.js";
import {
  AGENT_ID,
  APPROVAL_ID,
  GATEWAY_ID,
  PLUGIN_APPROVAL_ID,
  PLUGIN_ID,
  SESSION_KEY,
  TOOL_CALL_ID,
  TOOL_NAME,
  execEvent,
  execSnapshot,
  pluginEvent,
  pluginSnapshot,
} from "./support/fixtures.mjs";

const wasm = await loadWasm();
const TIMEOUT_MS = 420_000;

function build(overrides = {}) {
  return buildExecApprovalRequest(wasm, {
    event: overrides.event ?? execEvent(),
    snapshot: overrides.snapshot ?? execSnapshot(),
    gatewayId: overrides.gatewayId ?? GATEWAY_ID,
    timeoutMs: overrides.timeoutMs ?? TIMEOUT_MS,
  });
}

function buildPlugin(overrides = {}) {
  return buildPluginApprovalRequest(wasm, {
    event: overrides.event ?? pluginEvent(),
    snapshot: overrides.snapshot ?? pluginSnapshot(),
    gatewayId: overrides.gatewayId ?? GATEWAY_ID,
    timeoutMs: overrides.timeoutMs ?? TIMEOUT_MS,
  });
}

// ── §5.1 the ActionRecord ───────────────────────────────────────────────────────

test("exec approvals map to surface 'command' (§5.1)", () => {
  const result = build();
  assert.equal(result.kind, "request");
  assert.equal(result.request.action.surface, "command");
  assert.equal(result.request.action.recordSchemaVersion, 1);
});

test("syntactic.argv is systemRunPlan.argv verbatim — never a re-tokenization (§5.1)", () => {
  // `commandText` is a *rendering* for reviewers, not shell-safe quoting. Re-parsing it here would
  // split the script argument into four extra tokens and bind a vector that is NOT what the gateway
  // will execute — the exact failure the never-re-tokenize rule exists to prevent.
  const event = execEvent({
    systemRunPlan: {
      argv: ["bash", "-lc", "echo one two three"],
      commandText: "bash -lc echo one two three",
      cwd: "/srv/app",
    },
  });
  const snapshot = execSnapshot({ presentation: { commandText: "bash -lc echo one two three" } });
  const result = build({ event, snapshot });

  assert.equal(result.kind, "request");
  assert.deepEqual(result.request.action.syntactic.argv, ["bash", "-lc", "echo one two three"]);
  assert.equal(result.request.action.syntactic.bin, "bash");
  assert.equal(
    result.request.action.syntactic.raw,
    "bash -lc echo one two three",
    "raw is the exact string OpenClaw shows its other reviewers (§5.1)",
  );
  assert.equal(
    result.request.action.syntactic.argv.length,
    3,
    "a re-parse of commandText would have produced 6 tokens — the rule exists for exactly this",
  );
});

test("syntactic.cwd comes from systemRunPlan.cwd, then request.cwd (§5.1)", () => {
  assert.equal(build().request.action.syntactic.cwd, "/srv/app");

  const noPlanCwd = execEvent({
    request: { cwd: "/fallback" },
    systemRunPlan: { argv: ["ls"], commandText: "ls", cwd: undefined },
  });
  const result = build({
    event: noPlanCwd,
    snapshot: execSnapshot({ presentation: { commandText: "ls" } }),
  });
  assert.equal(result.request.action.syntactic.cwd, "/fallback");
});

test("request.commandArgv is used when there is no systemRunPlan (§5.1 fallback order)", () => {
  const event = execEvent({
    request: { commandArgv: ["kubectl", "delete", "ns", "prod"], systemRunPlan: undefined },
  });
  event.request.command = "kubectl delete ns prod";
  const result = build({
    event,
    snapshot: execSnapshot({ presentation: { commandText: "kubectl delete ns prod" } }),
  });
  assert.equal(result.kind, "request");
  assert.deepEqual(result.request.action.syntactic.argv, ["kubectl", "delete", "ns", "prod"]);
});

test("with neither plan nor commandArgv the core tokenizes the command text (§5.1 last resort)", () => {
  const event = execEvent({
    request: { command: "rm -rf /tmp/scratch", systemRunPlan: undefined },
  });
  const result = build({
    event,
    snapshot: execSnapshot({ presentation: { commandText: "rm -rf /tmp/scratch" } }),
  });
  assert.equal(result.kind, "request");
  assert.deepEqual(result.request.action.syntactic.argv, ["rm", "-rf", "/tmp/scratch"]);
});

test("OpenClaw's execution locus never leaks into allw's syntactic.host (§5.1 name collision)", () => {
  // `host: "node"` on an OpenClaw approval is the execution locus, not an ssh/scp destination.
  const result = build();
  assert.equal(
    result.request.action.syntactic.host,
    undefined,
    "syntactic.host is core-derived from the command, not OpenClaw's `host` field",
  );
  assert.match(result.request.summary, /node\/node-7/, "the locus belongs in the hashed summary");
});

// ── §6.2 the ApprovalContext ────────────────────────────────────────────────────

test("actor is openclaw:<gateway-id> with kind 'openclaw' (§6.2, §7.1)", () => {
  const result = build();
  assert.deepEqual(result.request.actor, { id: `openclaw:${GATEWAY_ID}`, kind: "openclaw" });
});

test("summary follows the §6.2 exec template", () => {
  assert.equal(
    build().request.summary,
    `OpenClaw ${GATEWAY_ID} · node/node-7 · agent ${AGENT_ID} · git push --force`,
  );
});

test("summary renders unknown components as the literal 'unknown', never dropping them (§6.2)", () => {
  const event = execEvent({
    request: { host: undefined, nodeId: undefined, agentId: undefined },
    systemRunPlan: { argv: ["ls"], commandText: "ls", cwd: "/srv", agentId: undefined },
  });
  const result = build({ event, snapshot: execSnapshot({ presentation: { commandText: "ls" } }) });
  assert.equal(result.request.summary, `OpenClaw ${GATEWAY_ID} · unknown · agent unknown · ls`);
});

test("a bound mutable file operand is surfaced in the summary (§6.3)", () => {
  const event = execEvent({
    systemRunPlan: {
      argv: ["sed", "-i", "s/a/b/", "/srv/app/config.yml"],
      commandText: "sed -i s/a/b/ /srv/app/config.yml",
      cwd: "/srv/app",
      mutableFileOperand: { path: "/srv/app/config.yml" },
    },
  });
  const result = build({
    event,
    snapshot: execSnapshot({ presentation: { commandText: "sed -i s/a/b/ /srv/app/config.yml" } }),
  });
  assert.match(result.request.summary, /· bound file \/srv\/app\/config\.yml$/);
});

test("an absent cwd renders an explicit 'working directory not bound' line (§6.3)", () => {
  const event = execEvent({
    request: { cwd: undefined },
    systemRunPlan: { argv: ["ls"], commandText: "ls", cwd: undefined },
  });
  const result = build({ event, snapshot: execSnapshot({ presentation: { commandText: "ls" } }) });
  assert.match(
    result.request.summary,
    /· working directory not bound$/,
    "a weaker binding must be visible, not look like a normal request",
  );
});

test("chain carries the approval id and session key for audit correlation (§6.2)", () => {
  assert.deepEqual(build().request.chain, [
    `openclaw:${GATEWAY_ID}:approval:${APPROVAL_ID}`,
    `openclaw:session:${SESSION_KEY}`,
  ]);
});

test("chain omits the session component when OpenClaw supplied none (§6.2)", () => {
  const event = execEvent({
    request: { sessionKey: undefined },
    systemRunPlan: { argv: ["ls"], commandText: "ls", cwd: "/srv", sessionKey: undefined },
  });
  const result = build({ event, snapshot: execSnapshot({ presentation: { commandText: "ls" } }) });
  assert.deepEqual(result.request.chain, [`openclaw:${GATEWAY_ID}:approval:${APPROVAL_ID}`]);
});

test("allowed_decisions is always ['approved','denied'] regardless of OpenClaw's set (§6.2)", () => {
  for (const allowedDecisions of [["deny"], ["allow-once", "deny"], ["allow-always", "deny"]]) {
    const result = build({ snapshot: execSnapshot({ presentation: { allowedDecisions } }) });
    assert.deepEqual(result.request.constraints.allowedDecisions, ["approved", "denied"]);
  }
});

// ── §6.4 risk, challenge, reversibility ─────────────────────────────────────────

test("risk comes from the core's classify_risk over the bound argv (§6.4)", () => {
  // `git push --force` is High in the core's documented v1 heuristic.
  assert.equal(build().request.risk, "high");
  assert.equal(build().request.action.risk, "high");
});

test("a non-empty warningText floors the risk at high (§5.1, §6.4)", () => {
  const event = execEvent({
    request: { warningText: "this command was flagged by the gateway" },
    systemRunPlan: { argv: ["ls"], commandText: "ls", cwd: "/srv" },
  });
  const result = build({ event, snapshot: execSnapshot({ presentation: { commandText: "ls" } }) });
  assert.equal(result.request.risk, "high", "`ls` classifies Low; the warning floors it at high");
});

test("a blank warningText does not floor the risk", () => {
  const event = execEvent({
    request: { warningText: "   " },
    systemRunPlan: { argv: ["ls"], commandText: "ls", cwd: "/srv" },
  });
  const result = build({ event, snapshot: execSnapshot({ presentation: { commandText: "ls" } }) });
  assert.equal(result.request.risk, "low");
});

test("challenge_required is exactly risk === 'critical' (§6.4)", () => {
  assert.equal(build().request.constraints.challengeRequired, false);

  const event = execEvent({
    systemRunPlan: {
      argv: ["dd", "if=/dev/zero", "of=/dev/disk2"],
      commandText: "dd if=/dev/zero of=/dev/disk2",
      cwd: "/",
    },
  });
  const critical = build({
    event,
    snapshot: execSnapshot({ presentation: { commandText: "dd if=/dev/zero of=/dev/disk2" } }),
  });
  assert.equal(critical.request.risk, "critical");
  assert.equal(critical.request.constraints.challengeRequired, true);
});

test("reversible is risk ∈ {low, medium} (§6.4)", () => {
  assert.equal(reversibleForRisk("low"), true);
  assert.equal(reversibleForRisk("medium"), true);
  assert.equal(reversibleForRisk("high"), false);
  assert.equal(reversibleForRisk("critical"), false);
  assert.equal(build().request.reversible, false, "git push --force is High ⇒ not reversible");
});

test("floorRisk never lowers a risk", () => {
  assert.equal(floorRisk("critical", "high"), "critical");
  assert.equal(floorRisk("low", "high"), "high");
  assert.equal(floorRisk("high", "high"), "high");
});

test("the derived timeout is carried onto the request (§8)", () => {
  assert.equal(build({ timeoutMs: 31_337 }).request.timeoutMs, 31_337);
});

// ── negatives: every fail-closed row this module owns (§9) ──────────────────────

test("a snapshot id that differs from the event id is presentation-divergence (§6.1, §9)", () => {
  const result = build({ snapshot: execSnapshot({ id: "apr_SOMETHING_ELSE" }) });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "presentation-divergence");
});

test("a snapshot kind that differs from the event family is presentation-divergence (§5.3, §9)", () => {
  const result = build({ snapshot: execSnapshot({ presentation: { kind: "plugin" } }) });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "presentation-divergence");
});

test("a snapshot commandText that differs from the event's is presentation-divergence (§6.1, §9)", () => {
  const result = build({
    snapshot: execSnapshot({ presentation: { commandText: "git push" } }),
  });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "presentation-divergence");
});

test("a sanitized snapshot that omits commandText is NOT a divergence (§6.1)", () => {
  // The reviewer projection is allowed to withhold fields; only a *different* value is divergence.
  const result = build({ snapshot: execSnapshot({ presentation: { commandText: undefined } }) });
  assert.equal(result.kind, "request");
});

test("an empty command text is build-error (§9)", () => {
  const event = execEvent({
    request: { command: undefined, systemRunPlan: undefined },
  });
  const result = build({
    event,
    snapshot: execSnapshot({ presentation: { commandText: undefined } }),
  });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "build-error");
});

test("a whitespace-only command text is build-error (§9)", () => {
  const event = execEvent({ request: { command: "   ", systemRunPlan: undefined } });
  const result = build({
    event,
    snapshot: execSnapshot({ presentation: { commandText: undefined } }),
  });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "build-error");
});

test("a malformed gateway id denies config-error per request (§7.1, §9)", () => {
  for (const bad of ["", "  ", "Has Space", "x".repeat(64)]) {
    const result = build({ gatewayId: bad });
    assert.equal(result.kind, "deny", `expected '${bad}' to deny`);
    assert.equal(result.reason, "config-error");
  }
});

test("a non-pending snapshot raises no allw request at all (§6.1 rule 4)", () => {
  for (const status of ["resolved", "expired", "cancelled"]) {
    const result = build({ snapshot: execSnapshot({ status }) });
    assert.equal(result.kind, "not-pending");
    assert.equal(result.status, status);
  }
});

test("the reconcile runs before any record is built (§6.1)", () => {
  // A divergent pair whose command text would ALSO fail to build must report the divergence: the
  // human must never be shown a context assembled from two sources that disagree.
  const event = execEvent({ request: { command: "", systemRunPlan: undefined } });
  const result = build({
    event,
    snapshot: execSnapshot({ presentation: { kind: "system-agent" } }),
  });
  assert.equal(result.reason, "presentation-divergence");
});

// ── the summary helper in isolation ─────────────────────────────────────────────

test("execSummary composes host/nodeId into a single locus component (§6.2)", () => {
  assert.equal(
    execSummary({ gatewayId: "gw", host: "gateway", agentId: "a", commandText: "ls", cwd: "/" }),
    "OpenClaw gw · gateway · agent a · ls",
  );
  assert.equal(
    execSummary({
      gatewayId: "gw",
      host: "node",
      nodeId: "n1",
      agentId: "a",
      commandText: "ls",
      cwd: "/",
    }),
    "OpenClaw gw · node/n1 · agent a · ls",
  );
});

// ── §5.2 plugin permission requests ─────────────────────────────────────────────

test("plugin approvals map to surface 'agent_tool_call' (§5.2)", () => {
  const result = buildPlugin();
  assert.equal(result.kind, "request");
  assert.equal(result.request.action.surface, "agent_tool_call");
  assert.equal(result.request.action.recordSchemaVersion, 1);
});

test("syntactic.server is pluginId, syntactic.tool is toolName (§5.2)", () => {
  const result = buildPlugin();
  assert.equal(result.request.action.syntactic.server, PLUGIN_ID);
  assert.equal(result.request.action.syntactic.tool, TOOL_NAME);
});

test("syntactic.server falls back to 'openclaw' when pluginId is absent (§5.2)", () => {
  const result = buildPlugin({ event: pluginEvent({ request: { pluginId: undefined } }) });
  assert.equal(result.kind, "request");
  assert.equal(result.request.action.syntactic.server, "openclaw");
});

test("syntactic.tool falls back to a normalized slug of title when toolName is absent (§5.2)", () => {
  const result = buildPlugin({
    event: pluginEvent({ request: { toolName: undefined, title: "Deploy Service Now!" } }),
  });
  assert.equal(result.kind, "request");
  assert.equal(result.request.action.syntactic.tool, "deploy-service-now");
});

test("syntactic.params is absent — OpenClaw exposes no structured parameters (§5.2)", () => {
  const result = buildPlugin();
  assert.ok(
    !("params" in result.request.action.syntactic),
    "params must be absent, not synthesized",
  );
});

test("syntactic.raw is description, plus detail when present (§5.2)", () => {
  const withoutDetail = buildPlugin();
  assert.equal(
    withoutDetail.request.action.syntactic.raw,
    "This plugin wants to deploy to production.",
  );

  const withDetail = buildPlugin({
    event: pluginEvent({ request: { detail: "It will restart 3 pods." } }),
  });
  assert.equal(
    withDetail.request.action.syntactic.raw,
    "This plugin wants to deploy to production.\n\nIt will restart 3 pods.",
  );
});

test("risk comes from severity: info→low, warning→medium, critical→critical (§5.2, §6.4)", () => {
  const info = buildPlugin({ event: pluginEvent({ request: { severity: "info" } }) });
  assert.equal(info.request.risk, "low");

  const warning = buildPlugin({ event: pluginEvent({ request: { severity: "warning" } }) });
  assert.equal(warning.request.risk, "medium");

  const critical = buildPlugin({ event: pluginEvent({ request: { severity: "critical" } }) });
  assert.equal(critical.request.risk, "critical");
});

test("absent severity defaults to the upstream 'warning' default (medium risk) (§5.2)", () => {
  const result = buildPlugin({ event: pluginEvent({ request: { severity: undefined } }) });
  assert.equal(result.request.risk, "medium");
});

test("summary follows the §6.2 plugin template", () => {
  assert.equal(
    buildPlugin().request.summary,
    `OpenClaw ${GATEWAY_ID} · agent ${AGENT_ID} · ${PLUGIN_ID}/${TOOL_NAME}: Deploy service — ` +
      "This plugin wants to deploy to production.",
  );
});

test("summary renders unknown components as the literal 'unknown' (§6.2)", () => {
  const result = buildPlugin({
    event: pluginEvent({
      request: { agentId: undefined, title: undefined, description: undefined },
    }),
  });
  assert.equal(
    result.request.summary,
    `OpenClaw ${GATEWAY_ID} · agent unknown · ${PLUGIN_ID}/${TOOL_NAME}: unknown — unknown`,
  );
});

test("actor is openclaw:<gateway-id> with kind 'openclaw' (§6.2, §7.1)", () => {
  assert.deepEqual(buildPlugin().request.actor, { id: `openclaw:${GATEWAY_ID}`, kind: "openclaw" });
});

test("chain carries the approval id, session key, and tool call id (§6.2)", () => {
  assert.deepEqual(buildPlugin().request.chain, [
    `openclaw:${GATEWAY_ID}:approval:${PLUGIN_APPROVAL_ID}`,
    `openclaw:session:${SESSION_KEY}`,
    `openclaw:tool_call:${TOOL_CALL_ID}`,
  ]);
});

test("chain omits session/tool-call components OpenClaw did not supply (§6.2)", () => {
  const result = buildPlugin({
    event: pluginEvent({ request: { sessionKey: undefined, toolCallId: undefined } }),
  });
  assert.deepEqual(result.request.chain, [`openclaw:${GATEWAY_ID}:approval:${PLUGIN_APPROVAL_ID}`]);
});

test("allowed_decisions is always ['approved','denied'] for plugin approvals too (§6.2)", () => {
  for (const allowedDecisions of [["deny"], ["allow-once", "deny"], ["allow-always", "deny"]]) {
    const result = buildPlugin({
      snapshot: pluginSnapshot({ presentation: { allowedDecisions } }),
    });
    assert.deepEqual(result.request.constraints.allowedDecisions, ["approved", "denied"]);
  }
});

test("challenge_required/reversible follow the shared risk rule for plugin approvals (§6.4)", () => {
  const critical = buildPlugin({ event: pluginEvent({ request: { severity: "critical" } }) });
  assert.equal(critical.request.constraints.challengeRequired, true);
  assert.equal(critical.request.reversible, false);

  const info = buildPlugin({ event: pluginEvent({ request: { severity: "info" } }) });
  assert.equal(info.request.constraints.challengeRequired, false);
  assert.equal(info.request.reversible, true);
});

test("the derived timeout is carried onto the plugin request (§8)", () => {
  assert.equal(buildPlugin({ timeoutMs: 31_337 }).request.timeoutMs, 31_337);
});

// ── negatives: the four rejection paths at the boundary (§9) ───────────────────

test("neither toolName nor a usable title slug is build-error (§5.2, §9)", () => {
  const result = buildPlugin({
    event: pluginEvent({ request: { toolName: undefined, title: "!!!" } }),
  });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "build-error");
});

test("a divergent presentation.kind is presentation-divergence (§5.3, §9)", () => {
  const result = buildPlugin({ snapshot: pluginSnapshot({ presentation: { kind: "exec" } }) });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "presentation-divergence");
});

test("a severity value outside the known set is build-error (§5.2, §9)", () => {
  const result = buildPlugin({ event: pluginEvent({ request: { severity: "urgent" } }) });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "build-error");
});

test("a plugin snapshot id that differs from the event id is presentation-divergence (§6.1, §9)", () => {
  const result = buildPlugin({ snapshot: pluginSnapshot({ id: "apr_SOMETHING_ELSE" }) });
  assert.equal(result.kind, "deny");
  assert.equal(result.reason, "presentation-divergence");
});

test("a malformed gateway id denies config-error for plugin approvals too (§7.1, §9)", () => {
  for (const bad of ["", "  ", "Has Space", "x".repeat(64)]) {
    const result = buildPlugin({ gatewayId: bad });
    assert.equal(result.kind, "deny", `expected '${bad}' to deny`);
    assert.equal(result.reason, "config-error");
  }
});

test("a non-pending plugin snapshot raises no allw request at all (§6.1 rule 4)", () => {
  for (const status of ["resolved", "expired", "cancelled"]) {
    const result = buildPlugin({ snapshot: pluginSnapshot({ status }) });
    assert.equal(result.kind, "not-pending");
    assert.equal(result.status, status);
  }
});

// ── slugifyTitle / pluginSummary in isolation ───────────────────────────────────

test("slugifyTitle normalizes to a lowercase, hyphenated token", () => {
  assert.equal(slugifyTitle("Deploy Service Now!"), "deploy-service-now");
  assert.equal(slugifyTitle("  leading/trailing  "), "leading-trailing");
});

test("slugifyTitle returns undefined for an absent or unusable title", () => {
  assert.equal(slugifyTitle(undefined), undefined);
  assert.equal(slugifyTitle("!!!"), undefined, "no alphanumeric characters ⇒ no usable slug");
  assert.equal(slugifyTitle(""), undefined);
});

test("pluginSummary renders the §6.2 template with the resolved server/tool identity", () => {
  assert.equal(
    pluginSummary({
      gatewayId: "gw",
      agentId: "a",
      server: "openclaw",
      tool: "deploy_service",
      title: "Deploy",
      description: "deploy now",
    }),
    "OpenClaw gw · agent a · openclaw/deploy_service: Deploy — deploy now",
  );
});
