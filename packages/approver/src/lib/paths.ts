/**
 * Default on-disk locations for the approver. The keyfile holds **secret seeds** (v0 stand-in),
 * so it lives under the user's home in a dot-directory, not the cwd.
 */

import { homedir } from "node:os";
import { join } from "node:path";

/** Default keyfile path: `~/.allw/approver-keyfile.json`. Overridable via `--keyfile`. */
export function defaultKeyfilePath(): string {
  return join(homedir(), ".allw", "approver-keyfile.json");
}
