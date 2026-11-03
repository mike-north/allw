/**
 * The shipped {@link AccountStateSource}: fetch root-signed account state from the relay and keep a
 * per-account **sequence floor** on disk, so a rollback to an older state is refused across runs.
 *
 * Integrators (the Claude Code and Codex hooks, the OpenClaw bridge) pass
 * `relayAccountStateSource({ relayUrl, accountId, floorStore: fileSequenceFloorStore({ accountId }) })`
 * as `createClient({ accountStates })`. Nothing here is trusted: the relay's documents are verified in
 * the core against the client's root key, and the floor only ever makes selection stricter.
 *
 * # The floor file
 * `~/.allw/state/<account_id>.floor.json` (the directory is overridable), holding
 * `{ "v": 1, "account_id": "…", "sequence": n }`.
 *
 * - **Fail-closed reads.** A missing file means "first use" (no floor). Anything else that is not a
 *   well-formed floor for this account — unreadable, corrupt, wrong owner or mode, not a regular
 *   file, oversized — throws, which denies the request. It is never read as `0`.
 * - **Monotonic, race-free writes.** Several hook processes can record a floor at once. A writer
 *   takes an exclusive lockfile, re-reads the floor, writes `max(stored, sequence)` to a temp file
 *   and renames it into place, then releases the lock. A plain read-max-write without the lock can
 *   lose a higher value to a slower writer holding a lower one.
 * - **No path tricks.** The account id must have the self-certifying id's syntax (43 base64url
 *   characters) before it becomes part of a path.
 *
 * @see ../../../docs/enrollment.md §Model (recipient selection rule; sequence floor)
 * @see ./user-file.ts (the shared ownership/mode checks)
 */

import { randomUUID } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import type { AccountStateSet, AccountStateSource } from "./index.js";
import { MAX_ESCAPED_DIAGNOSTIC_CHARS, escapeToPrintableAscii } from "./printable-ascii.js";
import { RelayClient, type FetchImpl, type ScheduleImpl } from "./relay.js";
import {
  errorCode,
  readUserOwnedFile,
  UserFileError,
  type UserFileCheckDeps,
} from "./user-file.js";

/**
 * The syntax of a self-certifying account id: `base64url-unpadded(SHA-256(…))`, always 43
 * characters (`docs/enrollment.md` §Model). Checked before the id becomes part of a file name.
 */
const ACCOUNT_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The only floor-file `v` this module reads or writes. */
const FLOOR_FILE_VERSION = 1;

/** The largest floor file read (bytes). A real one is under 100. */
const MAX_FLOOR_FILE_BYTES = 1024;

/** How long a writer waits for the floor lock before failing closed. */
const FLOOR_LOCK_TIMEOUT_MS = 5_000;

/** A lockfile older than this is from a crashed writer and may be broken. Writes take milliseconds. */
const FLOOR_LOCK_STALE_MS = 30_000;

/** Pause between attempts to take the floor lock. */
const FLOOR_LOCK_RETRY_MS = 10;

/** The persisted account-state sequence floor for one account. */
export interface SequenceFloorStore {
  /** The stored floor, or `undefined` on first use. Throws when the store can't be trusted. */
  read(): Promise<number | undefined>;
  /** Persist `max(stored, sequence)`. Idempotent; never lowers the floor. Throws on failure. */
  raise(sequence: number): Promise<void>;
}

/**
 * A floor store that cannot be read or written safely. Fail-closed: the request is denied. `path`
 * keeps the raw path; the message shows it escaped to printable ASCII (#358), since it is built from
 * `HOME` or the caller's `dir` and the message can reach the agent through a hook's deny reason.
 */
export class SequenceFloorError extends Error {
  constructor(
    readonly path: string,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(
      `allw: sequence floor ${escapeToPrintableAscii(path, MAX_ESCAPED_DIAGNOSTIC_CHARS)} ` +
        `${message} (fail-closed)`,
      options,
    );
    this.name = "SequenceFloorError";
  }
}

/** Options for {@link fileSequenceFloorStore}. */
export interface FileSequenceFloorStoreOptions {
  /** The account whose floor this is; must have the self-certifying id syntax. */
  readonly accountId: string;
  /** The state directory. Defaults to `~/.allw/state`. Created `0700` when missing. */
  readonly dir?: string;
}

/**
 * Test seams for {@link fileSequenceFloorStoreWith}.
 *
 * @internal
 */
export interface FileSequenceFloorStoreDeps extends UserFileCheckDeps {
  /** Override the clock used for lock staleness. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/** The default state directory, `~/.allw/state`. */
export function defaultStateDir(): string {
  return join(homedir(), ".allw", "state");
}

/** A file-backed {@link SequenceFloorStore} (see the module docs for the guarantees). */
export function fileSequenceFloorStore(options: FileSequenceFloorStoreOptions): SequenceFloorStore {
  return fileSequenceFloorStoreWith(options, {});
}

/**
 * {@link fileSequenceFloorStore} with test seams.
 *
 * @internal
 */
export function fileSequenceFloorStoreWith(
  options: FileSequenceFloorStoreOptions,
  deps: FileSequenceFloorStoreDeps,
): SequenceFloorStore {
  if (!ACCOUNT_ID_PATTERN.test(options.accountId)) {
    throw new TypeError(
      "allw: sequence floor account id must be a self-certifying account id " +
        "(43 base64url characters)",
    );
  }
  const dir = options.dir ?? defaultStateDir();
  const path = join(dir, `${options.accountId}.floor.json`);
  const lockPath = `${path}.lock`;
  const now = deps.now ?? Date.now;

  const read = (): number | undefined => readFloor(path, options.accountId, deps);

  return {
    read: () => Promise.resolve().then(read),
    async raise(sequence: number): Promise<void> {
      if (!Number.isSafeInteger(sequence) || sequence < 0) {
        throw new SequenceFloorError(path, `cannot record sequence ${String(sequence)}`);
      }
      // Cheap exit without the lock: the floor only rises, so a stored value >= sequence is final.
      const before = read();
      if (before !== undefined && before >= sequence) return;
      ensureStateDir(dir, path, deps);
      const release = await acquireLock(lockPath, path, now);
      try {
        const stored = read();
        if (stored !== undefined && stored >= sequence) return;
        writeFloorAtomically(path, options.accountId, sequence);
      } finally {
        release();
      }
    },
  };
}

/** Read and validate the floor file; `undefined` only when it does not exist. */
function readFloor(path: string, accountId: string, deps: UserFileCheckDeps): number | undefined {
  let text: string | null;
  try {
    text = readUserOwnedFile(path, MAX_FLOOR_FILE_BYTES, deps);
  } catch (cause) {
    const problem = cause instanceof UserFileError ? cause.problem.kind : "unreadable";
    throw new SequenceFloorError(path, `cannot be trusted (${problem})`, { cause });
  }
  if (text === null) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw new SequenceFloorError(path, "is not valid JSON", { cause });
  }
  const floor = parsed as { v?: unknown; account_id?: unknown; sequence?: unknown } | null;
  if (
    typeof parsed !== "object" ||
    floor === null ||
    Array.isArray(parsed) ||
    floor.v !== FLOOR_FILE_VERSION ||
    floor.account_id !== accountId ||
    !Number.isSafeInteger(floor.sequence) ||
    (floor.sequence as number) < 0
  ) {
    throw new SequenceFloorError(
      path,
      `is malformed (expected { v: 1, account_id: <this account>, sequence: <non-negative integer> })`,
    );
  }
  return floor.sequence as number;
}

/**
 * Create the state directory `0700` if missing, and refuse one this user does not own or that
 * others can write (they could replace the floor file between our reads).
 */
function ensureStateDir(dir: string, path: string, deps: UserFileCheckDeps): void {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (cause) {
    throw new SequenceFloorError(path, "state directory could not be created", { cause });
  }
  const stat = lstatSync(dir);
  if (!stat.isDirectory()) {
    throw new SequenceFloorError(path, "state directory is not a directory");
  }
  if ((deps.platform ?? process.platform) !== "win32") {
    const euid = (deps.geteuid ?? process.geteuid)?.();
    if (euid !== undefined && stat.uid !== euid) {
      throw new SequenceFloorError(path, "state directory is owned by another user");
    }
    if ((stat.mode & 0o022) !== 0) {
      throw new SequenceFloorError(path, "state directory is group- or world-writable");
    }
  }
}

/** Write the floor to a fresh temp file in the same directory and rename it over the floor file. */
function writeFloorAtomically(path: string, accountId: string, sequence: number): void {
  const tmp = `${path}.${String(process.pid)}.${randomUUID()}.tmp`;
  const body = `${JSON.stringify({ v: FLOOR_FILE_VERSION, account_id: accountId, sequence })}\n`;
  try {
    const fd = openSync(tmp, "wx", 0o600);
    try {
      writeSync(fd, body);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  } catch (cause) {
    try {
      unlinkSync(tmp);
    } catch {
      // The temp file may never have been created; nothing to clean up.
    }
    throw new SequenceFloorError(path, "could not be written", { cause });
  }
}

/**
 * Take the exclusive floor lock (`O_CREAT | O_EXCL`), waiting up to {@link FLOOR_LOCK_TIMEOUT_MS}.
 * A lock older than {@link FLOOR_LOCK_STALE_MS} is a crashed writer's and is broken — by renaming
 * it aside and checking it is still the same file, so a writer never breaks a fresh lock that
 * replaced the stale one. Returns the release function.
 */
async function acquireLock(lockPath: string, path: string, now: () => number): Promise<() => void> {
  const deadline = now() + FLOOR_LOCK_TIMEOUT_MS;
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      writeSync(fd, `${String(process.pid)}\n`);
      closeSync(fd);
      return () => {
        try {
          unlinkSync(lockPath);
        } catch {
          // Already broken as stale by another writer; nothing to release.
        }
      };
    } catch (cause) {
      if (errorCode(cause) !== "EEXIST") {
        throw new SequenceFloorError(path, "lock could not be taken", { cause });
      }
    }
    breakLockIfStale(lockPath, now);
    if (now() >= deadline) {
      throw new SequenceFloorError(path, `lock is held by another writer (${lockPath})`);
    }
    await new Promise((resolve) => setTimeout(resolve, FLOOR_LOCK_RETRY_MS));
  }
}

/** Remove `lockPath` only if it is stale and is still the same file we judged stale. */
function breakLockIfStale(lockPath: string, now: () => number): void {
  let stale;
  try {
    stale = statSync(lockPath);
  } catch {
    return; // Released meanwhile.
  }
  if (now() - stale.mtimeMs < FLOOR_LOCK_STALE_MS) return;
  const aside = `${lockPath}.${randomUUID()}.stale`;
  try {
    renameSync(lockPath, aside);
  } catch {
    return; // Someone else broke or released it.
  }
  try {
    const moved = statSync(aside);
    if (moved.ino !== stale.ino || moved.mtimeMs !== stale.mtimeMs) {
      // We moved a fresh lock that replaced the stale one: put it back for its owner.
      renameSync(aside, lockPath);
      return;
    }
    unlinkSync(aside);
  } catch {
    // Best effort: a leftover `.stale` file is harmless.
  }
}

/** Options for {@link relayAccountStateSource}. */
export interface RelayAccountStateSourceOptions {
  /** The relay base URL (same transport rules as `createClient`). */
  readonly relayUrl: string;
  /** The approver's account id. */
  readonly accountId: string;
  /** Where the sequence floor is kept; usually {@link fileSequenceFloorStore}. */
  readonly floorStore: SequenceFloorStore;
  /** Override `fetch` (tests). */
  readonly fetchImpl?: FetchImpl;
  /** Per-fetch timeout in ms; defaults to the SDK's relay default. */
  readonly fetchTimeoutMs?: number;
  /** Override the timer that bounds the fetch (tests; mirrors `ClientConfig.scheduleImpl`). */
  readonly scheduleImpl?: ScheduleImpl;
}

/**
 * An {@link AccountStateSource} that fetches `GET /{account}/account-states` (unauthenticated) on
 * every request and pairs it with the persisted floor; `accepted` raises the floor.
 *
 * `load` throws — denying the request — when the relay call fails, the relay holds no account state
 * yet (the root holder has not published one: run `allw-approver pair`), or the floor cannot be
 * trusted.
 */
export function relayAccountStateSource(
  options: RelayAccountStateSourceOptions,
): AccountStateSource {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const relay = new RelayClient(options.relayUrl, options.accountId, fetchImpl, {
    ...(options.fetchTimeoutMs !== undefined ? { fetchTimeoutMs: options.fetchTimeoutMs } : {}),
    ...(options.scheduleImpl ? { schedule: options.scheduleImpl } : {}),
  });
  return {
    async load(): Promise<AccountStateSet> {
      const [fetched, minSequence] = await Promise.all([
        relay.fetchAccountStates(),
        options.floorStore.read(),
      ]);
      if (fetched.account_states.length === 0) {
        throw new Error(
          `allw: the relay has no account state for account '${options.accountId}'; the root ` +
            `holder must publish one (run allw-approver pair)`,
        );
      }
      return minSequence === undefined
        ? { accountStates: fetched.account_states }
        : { accountStates: fetched.account_states, minSequence };
    },
    accepted: (sequence: number) => options.floorStore.raise(sequence),
  };
}
