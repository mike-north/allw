/* data.jsx — sample requests per the brief. Durations in ms; expiry computed at session start. */

function makeRequests() {
  return [
    {
      id: "r1",
      actor: "Claude Code",
      sub: "mike's-macbook-pro",
      kind: "Agent",
      action: { type: "command", argv: ["git", "push", "--force", "origin", "main"], cwd: "~/dev/allw" },
      summaryParts: ["Force-push to ", { code: "main" }, " — overwrites remote history"],
      summaryPlain: "Force-push to main — overwrites remote history",
      risk: "critical",
      reversible: false,
      durationMs: 90 * 1000,
      fingerprint: "a1f3…9e2c",
      challenge: "042",
    },
    {
      id: "r2",
      actor: "ChatGPT (web)",
      sub: "via OmniFocus MCP",
      kind: "Agent",
      action: { type: "mcp_tool_call", tool: "omnifocus.delete_project", params: { project: "Q3 Planning" }, via: "OmniFocus MCP" },
      summaryParts: ["Delete the ", { code: "Q3 Planning" }, " project (42 tasks)"],
      summaryPlain: "Delete the 'Q3 Planning' project (42 tasks)",
      risk: "high",
      reversible: false,
      durationMs: 4 * 60 * 1000,
      fingerprint: "7b20…c4d1",
      challenge: "317",
    },
    {
      id: "r3",
      actor: "Claude Code",
      sub: "mike's-macbook-pro",
      kind: "Agent",
      action: { type: "command", argv: ["rm", "-rf", "./node_modules"], cwd: "~/dev/allw/packages/sdk" },
      summaryParts: ["Remove ", { code: "node_modules" }, " to force a clean install"],
      summaryPlain: "Remove node_modules to force a clean install",
      risk: "low",
      reversible: true,
      durationMs: 10 * 60 * 1000,
      fingerprint: "e5c8…1a07",
      challenge: null,
    },
  ];
}

function Summary({ parts }) {
  return (
    <React.Fragment>
      {parts.map((p, i) =>
        typeof p === "string"
          ? <React.Fragment key={i}>{p}</React.Fragment>
          : <code key={i}>{p.code}</code>
      )}
    </React.Fragment>
  );
}

Object.assign(window, { makeRequests, Summary });
