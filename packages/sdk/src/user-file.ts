/**
 * Reading a small file the integrator's trust depends on — the config file (`./config.ts`) and the
 * account-state sequence floor (`./account-state-source.ts`) — with the same fail-closed checks
 * everywhere.
 *
 * # Checks
 * The file is opened, checked and read through ONE descriptor, so nothing can be swapped between a
 * check and the read:
 *
 * - opened `O_NONBLOCK`, so a FIFO at the path cannot block the open (a synchronous read of a FIFO
 *   or `/dev/zero` would otherwise hang a hook before any deadline is armed);
 * - `fstat` must report a regular file (a FIFO, device, socket or directory is rejected);
 * - on POSIX, the file must be owned by the effective uid and not group- or world-writable —
 *   whoever can write it controls what the integrator trusts;
 * - at most `maxBytes` are read.
 *
 * Only a missing file (`ENOENT`) is a non-error result (`null`); what that means is the caller's
 * call. Every other problem throws a {@link UserFileError} whose {@link UserFileProblem} lets each
 * caller word its own message. Neither this module nor its errors ever echo the file's contents.
 *
 * @see ../../../docs/threat-model.md (trust anchor at rest)
 */

import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from "node:fs";

/** Why a user-owned file could not be read. */
export type UserFileProblem =
  /** Opening failed with `EACCES` / `EPERM`. */
  | { readonly kind: "unreadable"; readonly code: string }
  /** Opening failed for another reason (e.g. `ELOOP`, `EISDIR`). */
  | { readonly kind: "open_failed"; readonly code: string | undefined }
  /** The path is a directory, FIFO, device or socket. */
  | { readonly kind: "not_regular" }
  /** On POSIX, the file is owned by another uid. */
  | { readonly kind: "wrong_owner"; readonly uid: number; readonly euid: number }
  /** On POSIX, the file is group- or world-writable. `mode` is the permission bits. */
  | { readonly kind: "group_or_world_writable"; readonly mode: number }
  /** The file exceeds the cap: per `fstat` (`size`), or it grew past it while being read. */
  | { readonly kind: "too_large"; readonly size: number | undefined }
  /** Reading the open descriptor failed. */
  | { readonly kind: "read_failed"; readonly code: string | undefined };

/** A fail-closed read failure for a user-owned file. */
export class UserFileError extends Error {
  constructor(
    readonly path: string,
    readonly problem: UserFileProblem,
    options?: { cause?: unknown },
  ) {
    super(`allw: ${path} cannot be trusted (${problem.kind})`, options);
    this.name = "UserFileError";
  }
}

/**
 * Test seams for the ownership check.
 *
 * @internal
 */
export interface UserFileCheckDeps {
  /** Override the effective uid used for the ownership check (POSIX). */
  readonly geteuid?: () => number;
  /** Override the platform (the ownership/mode check is skipped on `win32`). */
  readonly platform?: NodeJS.Platform;
}

/** The `code` of a Node system error, if any. */
export function errorCode(err: unknown): string | undefined {
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = err.code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

/**
 * Read `path` as UTF-8 after the checks in the module docs. Returns `null` only when the file does
 * not exist (`ENOENT`).
 *
 * @throws {UserFileError} on any other failure.
 */
export function readUserOwnedFile(
  path: string,
  maxBytes: number,
  deps: UserFileCheckDeps = {},
): string | null {
  const platform = deps.platform ?? process.platform;
  // O_NONBLOCK is POSIX-only (undefined on Windows, where FIFOs at a path do not exist).
  const optional: Partial<typeof fsConstants> = fsConstants;
  const flags = fsConstants.O_RDONLY | (optional.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = openSync(path, flags);
  } catch (cause) {
    const code = errorCode(cause);
    if (code === "ENOENT") return null;
    if (code === "EACCES" || code === "EPERM") {
      throw new UserFileError(path, { kind: "unreadable", code }, { cause });
    }
    throw new UserFileError(path, { kind: "open_failed", code }, { cause });
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new UserFileError(path, { kind: "not_regular" });
    if (platform !== "win32") {
      const euid = (deps.geteuid ?? process.geteuid)?.();
      if (euid !== undefined && stat.uid !== euid) {
        throw new UserFileError(path, { kind: "wrong_owner", uid: stat.uid, euid });
      }
      if ((stat.mode & 0o022) !== 0) {
        throw new UserFileError(path, { kind: "group_or_world_writable", mode: stat.mode & 0o777 });
      }
    }
    if (stat.size > maxBytes) {
      throw new UserFileError(path, { kind: "too_large", size: stat.size });
    }
    // Read from the same descriptor, never more than the cap (+1 to detect growth since fstat).
    const buf = Buffer.alloc(maxBytes + 1);
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, total, buf.length - total, null);
      if (n === 0) break;
      total += n;
      if (total > maxBytes) throw new UserFileError(path, { kind: "too_large", size: undefined });
    }
    return buf.subarray(0, total).toString("utf8");
  } catch (cause) {
    if (cause instanceof UserFileError) throw cause;
    throw new UserFileError(path, { kind: "read_failed", code: errorCode(cause) }, { cause });
  } finally {
    closeSync(fd);
  }
}
