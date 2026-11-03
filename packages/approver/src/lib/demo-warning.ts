/**
 * The same-machine demo warning for the CLI approver (#241).
 *
 * `allw-approver` keeps the account-root seed and the device signing seed in a keyfile on the machine
 * it runs on (`./keyfile.ts`). When that is the machine the gated agent runs on, any process running
 * as the same OS user — including the agent — can read the keyfile and sign an "approved" verdict
 * for its own request. The cryptography still verifies; the human is simply no longer in the loop.
 * `docs/threat-model.md` R8 treats this as the walking-skeleton exception, and it must be presented
 * as one. So every `pair` and `watch` run prints this warning to stderr, before doing any work, so it
 * appears even when the command then fails.
 *
 * This module only defines the text and where it goes. Moving the root off the agent's machine
 * (#244) and self-certifying accounts (#242) are the real fixes; this warning is the stop-gap label.
 *
 * @see ../../../../docs/threat-model.md (R8)
 * @see ../../../../docs/enrollment.md (§The gap this closes)
 */

/** The hosted web approver, the setup the warning points users to instead of this CLI. */
export const HOSTED_WEB_APPROVER_URL = "https://allw-web-approver.pages.dev";

/**
 * The warning text (multi-line, no trailing newline). It states the three facts users need: the keys
 * live on this machine, any same-user process (the agent included) can read them and approve its own
 * requests, and the setup is for demos only.
 */
export const SAME_MACHINE_DEMO_WARNING = [
  "⚠ DEMO ONLY: this approver keeps the account root key and the device signing key in its keyfile",
  "  on this machine. Any process running as this user, including the AI agent you are gating, can",
  "  read them and approve its own requests. Use this setup for demos only.",
  `  For real use, approve from another device with the hosted web approver (${HOSTED_WEB_APPROVER_URL})`,
  "  and keep the keyfile off the machine the agent runs on. See docs/quickstart.md §2.",
].join("\n");

/** Write the demo warning to the given sink (stderr by default). */
export function printSameMachineDemoWarning(
  write: (line: string) => void = (line) => {
    console.error(line);
  },
): void {
  write(SAME_MACHINE_DEMO_WARNING);
}
