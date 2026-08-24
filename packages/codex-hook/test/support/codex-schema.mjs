/**
 * A structural conformance check for Codex's `PreToolUse` output contract, written directly from
 * the spec — never from this package's own serializer — so it can catch the class of bug filed as
 * #191: an undocumented `hookSpecificOutput` field silently made Codex discard the entire deny
 * payload and continue the tool call.
 *
 * Documented fields on `hookSpecificOutput` for `PreToolUse`: `hookEventName`,
 * `permissionDecision`, `permissionDecisionReason`, `updatedInput`, `additionalContext`. The
 * schema declares `additionalProperties: false` on that object, and the open-source
 * implementation deserializes it with `#[serde(deny_unknown_fields)]`
 * (`codex-rs/hooks/src/schema.rs`, `PreToolUseHookSpecificOutputWire`) — any other key makes the
 * whole stdout payload fail to parse, which Codex reports as a hook error and then **continues
 * the tool call**.
 *
 * A bare `permissionDecision: "allow"` (without `updatedInput`) is parsed but not a decision
 * Codex implements yet — it is reported as a hook failure (the tool call proceeds regardless, so
 * this is noise rather than a security gap, but every approval would surface a spurious error).
 * "allw does not block this call" must instead be empty stdout + exit 0, which the docs state is
 * "treated as success and Codex continues" — never a wire `permissionDecision` value at all.
 *
 * @see https://learn.chatgpt.com/docs/hooks
 */

const DOCUMENTED_HOOK_SPECIFIC_OUTPUT_FIELDS = new Set([
  "hookEventName",
  "permissionDecision",
  "permissionDecisionReason",
  "updatedInput",
  "additionalContext",
]);

/**
 * Assert that `payload` — the exact value the hook would `JSON.stringify` to stdout, or `null` for
 * "no output" — conforms to Codex's documented `PreToolUse` output contract as this package uses
 * it (an explicit `deny`, or silence). Throws a descriptive `Error` on the first violation found.
 */
export function assertConformsToPreToolUseOutputContract(payload) {
  if (payload === null) {
    // Empty stdout + exit 0: Codex's documented clean-success path. Always schema-valid.
    return;
  }
  if (typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error(`expected an object or null, got ${JSON.stringify(payload)}`);
  }

  const topLevelKeys = Object.keys(payload);
  if (topLevelKeys.length !== 1 || topLevelKeys[0] !== "hookSpecificOutput") {
    throw new Error(
      `expected the payload's only key to be 'hookSpecificOutput', got [${topLevelKeys.join(", ")}]`,
    );
  }

  const hso = payload.hookSpecificOutput;
  if (typeof hso !== "object" || hso === null || Array.isArray(hso)) {
    throw new Error(`hookSpecificOutput must be an object, got ${JSON.stringify(hso)}`);
  }

  for (const key of Object.keys(hso)) {
    if (!DOCUMENTED_HOOK_SPECIFIC_OUTPUT_FIELDS.has(key)) {
      throw new Error(
        `hookSpecificOutput has undocumented field '${key}' — Codex's schema declares ` +
          "additionalProperties: false on this object and will reject the whole payload",
      );
    }
  }

  if (hso.hookEventName !== "PreToolUse") {
    throw new Error(`hookEventName must be 'PreToolUse', got ${JSON.stringify(hso.hookEventName)}`);
  }

  // This package only ever emits an explicit `deny` to stdout; "allw does not block" is `null`
  // (empty stdout), never a bare wire `allow` (see module doc comment).
  if (hso.permissionDecision !== "deny") {
    throw new Error(
      `permissionDecision must be 'deny' for a non-null payload, got ${JSON.stringify(
        hso.permissionDecision,
      )}`,
    );
  }

  if (
    typeof hso.permissionDecisionReason !== "string" ||
    hso.permissionDecisionReason.length === 0
  ) {
    throw new Error(
      "a 'deny' permissionDecision requires a non-empty string permissionDecisionReason " +
        "(an empty one degrades to a hook failure and Codex continues the tool call)",
    );
  }
}
