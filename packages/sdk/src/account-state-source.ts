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
 *   file, a symlink, oversized, or in a state directory that is not a directory this user owns and
 *   only this user can write — throws, which denies the request. It is never read as `0`.
 * - **Monotonic, race-free writes.** Several hook processes can record a floor at once. A writer
 *   takes an exclusive lockfile, re-reads the floor, writes `max(stored, sequence)` to a temp file
 *   and renames it into place, then releases the lock. A plain read-max-write without the lock can
 *   lose a higher value to a slower writer holding a lower one.
 * - **Stale locks.** A lock older than 30 s is a crashed writer's and is broken: renamed aside, and
 *   deleted only if it is still the file judged stale. A fresh lock moved by mistake is linked back,
 *   never renamed over a newer one. A holder confirms the lock file is still its own just before it
 *   commits the floor and before it releases, so a lock lost to a breaker fails that write closed
 *   rather than letting two writers commit.
 * - **No path tricks.** The account id must have the self-certifying id's syntax (43 base64url
 *   characters) before it becomes part of a path, and the floor file is opened without following a
 *   symlink.
 *
 * @see ../../../docs/enrollment.md §Model (recipient selection rule; sequence floor)
 * @see ./user-file.ts (the shared ownership/mode checks)
 */

import { randomUUID } from "node:crypto";
import {
  closeSync,
  fstatSync,
  fsyncSync,
  linkSync,
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
  /** Runs after a writer takes the lock, before it re-reads and commits (race tests). */
  readonly afterLockAcquired?: () => void;
  /** Interleaving points inside {@link breakLockIfStale} (race tests). */
  readonly lockBreak?: LockBreakHooks;
}

/**
 * Interleaving points inside {@link breakLockIfStale}, for tests that replay a race step by step.
 *
 * @internal
 */
export interface LockBreakHooks {
  /** After the lock was judged stale, before it is moved aside. */
  readonly afterJudgedStale?: () => void;
  /** After the lock was moved aside, before the moved file is checked. */
  readonly afterMovedAside?: () => void;
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

  const read = (): number | undefined => {
    checkStateDir(dir, path, deps);
    return readFloor(path, options.accountId, deps);
  };

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
      const lock = await acquireLock(lockPath, path, now, deps.lockBreak);
      try {
        deps.afterLockAcquired?.();
        const stored = read();
        if (stored !== undefined && stored >= sequence) return;
        writeFloorAtomically(path, options.accountId, sequence, () => {
          if (!lock.stillHeld()) {
            throw new SequenceFloorError(
              path,
              "lock was taken over by another writer before this write committed",
            );
          }
        });
      } finally {
        lock.release();
      }
    },
  };
}

/** Read and validate the floor file; `undefined` only when it does not exist. */
function readFloor(path: string, accountId: string, deps: UserFileCheckDeps): number | undefined {
  let text: string | null;
  try {
    text = readUserOwnedFile(path, MAX_FLOOR_FILE_BYTES, deps, { noFollow: true });
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
 * Create the state directory `0700` if missing, then apply {@link checkStateDir}.
 */
function ensureStateDir(dir: string, path: string, deps: UserFileCheckDeps): void {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (cause) {
    throw new SequenceFloorError(path, "state directory could not be created", { cause });
  }
  checkStateDir(dir, path, deps);
}

/**
 * Refuse a state directory that is not a real directory (a symlink included), that this user does
 * not own, or that others can write: they could replace the floor file between our reads. A
 * missing directory passes, since it holds no floor yet (first use).
 */
function checkStateDir(dir: string, path: string, deps: UserFileCheckDeps): void {
  let stat;
  try {
    stat = lstatSync(dir);
  } catch (cause) {
    if (errorCode(cause) === "ENOENT") return;
    throw new SequenceFloorError(path, "state directory cannot be inspected", { cause });
  }
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

/**
 * Write the floor to a fresh temp file in the same directory and rename it over the floor file.
 * `beforeCommit` runs just before the rename and may throw to abandon the write.
 */
function writeFloorAtomically(
  path: string,
  accountId: string,
  sequence: number,
  beforeCommit: () => void,
): void {
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
    beforeCommit();
    renameSync(tmp, path);
  } catch (cause) {
    try {
      unlinkSync(tmp);
    } catch {
      // The temp file may never have been created; nothing to clean up.
    }
    if (cause instanceof SequenceFloorError) throw cause;
    throw new SequenceFloorError(path, "could not be written", { cause });
  }
}

/** A floor lock this writer holds, identified by the lock file's device and inode. */
interface HeldLock {
  /** Whether the file at the lock path is still this writer's lock (not broken and replaced). */
  stillHeld(): boolean;
  /** Remove the lock, but only while it is still this writer's: never delete a newer lock. */
  release(): void;
}

/**
 * Take the exclusive floor lock (`O_CREAT | O_EXCL`), waiting up to {@link FLOOR_LOCK_TIMEOUT_MS}.
 * A lock older than {@link FLOOR_LOCK_STALE_MS} is a crashed writer's and is broken — by renaming
 * it aside and checking it is still the same file, so a writer never breaks a fresh lock that
 * replaced the stale one. Returns the release function.
 */
async function acquireLock(
  lockPath: string,
  path: string,
  now: () => number,
  hooks: LockBreakHooks = {},
): Promise<HeldLock> {
  const deadline = now() + FLOOR_LOCK_TIMEOUT_MS;
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      let ino: number;
      let dev: number;
      try {
        writeSync(fd, `${String(process.pid)}\n`);
        ({ ino, dev } = fstatSync(fd));
      } finally {
        closeSync(fd);
      }
      const stillHeld = (): boolean => {
        try {
          const current = lstatSync(lockPath);
          return current.ino === ino && current.dev === dev;
        } catch {
          return false;
        }
      };
      return {
        stillHeld,
        release() {
          if (!stillHeld()) return; // Broken as stale meanwhile; a newer lock is not ours to remove.
          try {
            unlinkSync(lockPath);
          } catch {
            // Already gone; nothing to release.
          }
        },
      };
    } catch (cause) {
      if (errorCode(cause) !== "EEXIST") {
        throw new SequenceFloorError(path, "lock could not be taken", { cause });
      }
    }
    breakLockIfStale(lockPath, now, hooks);
    if (now() >= deadline) {
      throw new SequenceFloorError(
        path,
        `lock is held by another writer (${escapeToPrintableAscii(lockPath, MAX_ESCAPED_DIAGNOSTIC_CHARS)})`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, FLOOR_LOCK_RETRY_MS));
  }
}

/**
 * Remove `lockPath` only if it is stale and is still the same file we judged stale.
 *
 * Breaking is rename-aside-then-check, because nothing removes a path only if it is a given file.
 * When the moved file turns out to be a fresh lock that replaced the stale one, it goes back with
 * `link`, which fails with `EEXIST` rather than overwrite a lock taken meanwhile (a rename back
 * would replace it, and two writers would both hold "the" lock). If the link fails, the moved
 * lock's owner no longer holds the lock; its {@link HeldLock.stillHeld} check sees that and it
 * fails its write closed.
 *
 * @internal
 */
export function breakLockIfStale(
  lockPath: string,
  now: () => number,
  hooks: LockBreakHooks = {},
): void {
  let stale;
  try {
    stale = statSync(lockPath);
  } catch {
    return; // Released meanwhile.
  }
  if (now() - stale.mtimeMs < FLOOR_LOCK_STALE_MS) return;
  hooks.afterJudgedStale?.();
  const aside = `${lockPath}.${randomUUID()}.stale`;
  try {
    renameSync(lockPath, aside);
  } catch {
    return; // Someone else broke or released it.
  }
  hooks.afterMovedAside?.();
  try {
    const moved = statSync(aside);
    if (moved.ino !== stale.ino || moved.dev !== stale.dev || moved.mtimeMs !== stale.mtimeMs) {
      // We moved a fresh lock that replaced the stale one: give it back to its owner, but never
      // over a newer lock (EEXIST leaves the newer one in place).
      try {
        linkSync(aside, lockPath);
      } catch {
        // A newer lock exists; the moved lock's owner will find it lost and fail closed.
      }
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
