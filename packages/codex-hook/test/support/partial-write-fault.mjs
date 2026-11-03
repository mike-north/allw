/**
 * Preload (`node --import`) that makes the hook's first decision write fail **part-way**: the first
 * write to stdout writes only {@link PARTIAL_BYTES} bytes, the next one throws `EIO`, and later writes
 * go through normally.
 *
 * That is the case where a failed `finalize` has already put part of a decision on stdout. The
 * backstop must not then append a second, full deny (the whole of stdout would be invalid JSON, read
 * as "no objection" on exit 0); the process must exit non-zero instead. `fs.writeSync` is replaced
 * and `syncBuiltinESMExports` pushes the replacement into the `node:fs` named exports the hook
 * imports. The hook bin itself is the real, unmodified `dist/cli.js`.
 */

import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";

/** How many bytes the first, short stdout write lets through. */
export const PARTIAL_BYTES = 10;

const STDOUT_FD = 1;
const realWriteSync = fs.writeSync;
let stdoutWrites = 0;

fs.writeSync = (fd, buffer, offset, length, ...rest) => {
  if (fd === STDOUT_FD) {
    stdoutWrites += 1;
    if (stdoutWrites === 1) return realWriteSync(fd, buffer, offset, PARTIAL_BYTES, ...rest);
    if (stdoutWrites === 2) {
      throw Object.assign(new Error("allw-test: injected stdout EIO"), { code: "EIO" });
    }
  }
  return realWriteSync(fd, buffer, offset, length, ...rest);
};
syncBuiltinESMExports();
