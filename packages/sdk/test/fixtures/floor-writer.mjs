/**
 * Child process for the racing-writers test (`account-state-source.test.mjs`): raise one account's
 * file-backed sequence floor through each sequence in argv, in order, as fast as possible.
 *
 * Usage: node floor-writer.mjs <state-dir> <account-id> <seq> [<seq> …]
 */

import { fileSequenceFloorStore } from "../../dist/index.js";

const [dir, accountId, ...sequences] = process.argv.slice(2);
const store = fileSequenceFloorStore({ accountId, dir });
for (const sequence of sequences) {
  await store.raise(Number(sequence));
}
