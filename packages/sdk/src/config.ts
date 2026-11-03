/**
 * The integrator config loader (issue #230): one non-secret file, read by the SDK, the hooks, and
 * any other integrator surface, so first run does not depend on hand-exported env vars.
 *
 * # The file
 * `~/.allw/config.json` by default; `ALLW_CONFIG` (or the `path` option) overrides the location.
 *
 * ```json
 * { "version": 1, "relay_url": "https://…", "account_id": "…", "approver_root_key": "…" }
 * ```
 *
 * It is **not** the approver keyfile (`~/.allw/approver-keyfile.json`, which holds secret seeds and
 * the device auth token); this file holds only public coordinates. It is, however, the integrator's
 * **trust anchor at rest**: whoever can rewrite `approver_root_key` can redirect approvals to a
 * root they control (`docs/threat-model.md`). Keep it user-only (`0600`, directory `0700`).
 *
 * # Precedence
 * Per field: the env var wins over the file (`ALLW_RELAY_URL` > `relay_url`, `ALLW_ACCOUNT_ID` >
 * `account_id`, `ALLW_APPROVER_ROOT_KEY` > `approver_root_key`).
 *
 * # Fail-closed (`docs/contract.md` §Invariants #6)
 * The loader never returns a partial config. It throws a {@link ClientConfigError} — whose message
 * names the file path and the env var(s) to fix, and never echoes the file's contents — when:
 *
 * - there is no file and the env does not supply every field;
 * - `ALLW_CONFIG` / `path` is not absolute (after expanding a leading `~/`) — a relative path would
 *   resolve against the agent's working directory, letting a cloned repo supply the trust anchor;
 * - an explicitly named file (`ALLW_CONFIG` / `path`) does not exist;
 * - the path is not a readable regular file (a FIFO, device, socket or directory is rejected via
 *   `fstat` on the opened descriptor, so it can never block the read), or exceeds
 *   {@link MAX_CLIENT_CONFIG_BYTES};
 * - on POSIX, the file is not owned by the effective uid, or is group- or world-writable;
 * - the file exists but is malformed JSON, is not an object, has an unknown `version`, is missing a
 *   key, has an unknown key, or has a non-string / empty value — even when the env would override
 *   every field (a corrupted trust-anchor file is never silently skipped);
 * - the resolved `relay_url` fails the SDK's transport check (`https:`, or `http:` on loopback);
 * - the resolved `approver_root_key` is not a base64url-unpadded 32-byte Ed25519 public key;
 * - the resolved `account_id` does not derive from `approver_root_key` (accounts are
 *   self-certifying, `docs/enrollment.md` §Model).
 *
 * The last two checks are the audited core's (`account_id_for_root` / `check_account_id_for_root`,
 * reached through WASM) — this module does not reimplement key decoding or id derivation.
 *
 * The loader is **synchronous** so surfaces with a synchronous config step (the hooks) can call it;
 * it reaches the core through {@link loadWasmSync}.
 *
 * @see ../../../docs/quickstart.md §4
 * @see ../../../docs/threat-model.md (trust anchor at rest)
 * @see ../../../docs/enrollment.md §Model (self-certifying account ids)
 */

import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

import { assertRelayUrlTransport } from "./relay.js";
import { readUserOwnedFile, UserFileError } from "./user-file.js";
import { loadWasmSync, type AllwWasm } from "./wasm.js";

/** The only config-file `version` this loader understands. */
export const CLIENT_CONFIG_VERSION = 1;

/** The env var that overrides the config-file location. */
export const CLIENT_CONFIG_PATH_ENV = "ALLW_CONFIG";

/** The resolved, validated integrator coordinates. Spread it into `createClient`. */
export interface IntegratorConfig {
  /** Base URL of the zero-knowledge relay. */
  readonly relayUrl: string;
  /** The approver's self-certifying account id (derives from {@link approverRootKey}). */
  readonly accountId: string;
  /** The approver account-root Ed25519 public key (base64url-unpadded) — the trust anchor. */
  readonly approverRootKey: string;
}

/** An environment map (injectable for tests; defaults to `process.env`). */
export type ConfigEnv = Readonly<Record<string, string | undefined>>;

/** Options for {@link loadClientConfig}. */
export interface LoadClientConfigOptions {
  /** The environment to read overrides from. Defaults to `process.env`. */
  readonly env?: ConfigEnv;
  /**
   * The config-file path. Takes precedence over `ALLW_CONFIG`; when either is given the file must
   * exist. Defaults to `~/.allw/config.json`, which may be absent if the env supplies every field.
   * Must be absolute after a leading `~/` is expanded — a relative path would resolve against the
   * agent's working directory (e.g. a cloned repo), letting it supply the trust anchor.
   */
  readonly path?: string;
}

/**
 * Test seams for {@link loadClientConfigWith}. Not re-exported from the package entry point.
 *
 * @internal
 */
export interface LoadClientConfigDeps {
  /** Override the WASM core. Defaults to {@link loadWasmSync}. */
  readonly wasm?: Pick<AllwWasm, "account_id_for_root" | "check_account_id_for_root">;
  /** Override the effective uid used for the ownership check (POSIX). */
  readonly geteuid?: () => number;
  /** Override the platform (the ownership/mode check is skipped on `win32`). */
  readonly platform?: NodeJS.Platform;
}

/** The largest config file the loader reads (bytes). The real file is a few hundred bytes. */
export const MAX_CLIENT_CONFIG_BYTES = 64 * 1024;

/** A fail-closed config error. `path` is the config-file location the loader consulted. */
export class ClientConfigError extends Error {
  readonly path: string;
  constructor(message: string, path: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ClientConfigError";
    this.path = path;
  }
}

/** One config field: its file key and its env override. */
interface FieldSpec {
  readonly key: "relay_url" | "account_id" | "approver_root_key";
  readonly envVar: "ALLW_RELAY_URL" | "ALLW_ACCOUNT_ID" | "ALLW_APPROVER_ROOT_KEY";
}

const RELAY_FIELD: FieldSpec = { key: "relay_url", envVar: "ALLW_RELAY_URL" };
const ACCOUNT_FIELD: FieldSpec = { key: "account_id", envVar: "ALLW_ACCOUNT_ID" };
const ROOT_FIELD: FieldSpec = { key: "approver_root_key", envVar: "ALLW_APPROVER_ROOT_KEY" };
const FIELDS: readonly FieldSpec[] = [RELAY_FIELD, ACCOUNT_FIELD, ROOT_FIELD];

const FILE_KEYS = new Set<string>(["version", ...FIELDS.map((f) => f.key)]);

/** The default config-file location, `~/.allw/config.json`. */
export function defaultClientConfigPath(): string {
  return join(homedir(), ".allw", "config.json");
}

/** A non-blank env value, or `null`. */
function envValue(env: ConfigEnv, key: string): string | null {
  const value = env[key];
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

/** Where a resolved field came from, for error messages. */
function describeSource(field: FieldSpec, fromEnv: boolean, path: string): string {
  return fromEnv ? `env var ${field.envVar}` : `'${field.key}' in ${path}`;
}

/**
 * Expand a leading `~/` and require an absolute path. A relative `ALLW_CONFIG` would resolve against
 * the agent's cwd — a cloned repo could then supply the trust anchor.
 */
function resolveConfigPath(raw: string, source: string): string {
  const expanded = raw === "~" || raw.startsWith("~/") ? join(homedir(), raw.slice(1)) : raw;
  if (!isAbsolute(expanded)) {
    throw new ClientConfigError(
      `allw: ${source} '${raw}' must be an absolute path (a leading ~/ is expanded); a relative ` +
        `path would resolve against the agent's working directory (fail-closed)`,
      expanded,
    );
  }
  return expanded;
}

/** A JSON parse error's position only — never Node's quoted snippet of the file's contents. */
function jsonErrorPosition(err: unknown): string {
  const match = err instanceof Error ? /position (\d+)/.exec(err.message) : null;
  return match?.[1] !== undefined ? `at position ${match[1]}` : "at an unknown position";
}

/** The JSON type name of a value (never the value itself — it might be something secret). */
function jsonType(value: unknown): string {
  if (value === undefined) return "missing";
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

/**
 * Open, check, and read the config file through ONE descriptor (no check/read TOCTOU), via the
 * shared {@link readUserOwnedFile} checks: it is the trust anchor at rest (`docs/threat-model.md`).
 * Returns `null` only when the file is absent and was not explicitly requested.
 */
function readConfigText(
  path: string,
  explicit: boolean,
  deps: LoadClientConfigDeps,
): string | null {
  let text: string | null;
  try {
    text = readUserOwnedFile(path, MAX_CLIENT_CONFIG_BYTES, {
      ...(deps.geteuid ? { geteuid: deps.geteuid } : {}),
      ...(deps.platform ? { platform: deps.platform } : {}),
    });
  } catch (cause) {
    if (cause instanceof UserFileError) throw configFileError(path, cause);
    throw cause;
  }
  if (text === null && explicit) {
    throw new ClientConfigError(
      `allw: config file ${path} does not exist (named by ${CLIENT_CONFIG_PATH_ENV} or the path ` +
        `option). Create it, or unset ${CLIENT_CONFIG_PATH_ENV} and set ALLW_RELAY_URL, ` +
        `ALLW_ACCOUNT_ID and ALLW_APPROVER_ROOT_KEY (fail-closed)`,
      path,
    );
  }
  return text;
}

/** Word a {@link UserFileError} as the config loader's actionable message. */
function configFileError(path: string, err: UserFileError): ClientConfigError {
  const problem = err.problem;
  const options = { cause: err.cause ?? err };
  switch (problem.kind) {
    case "unreadable":
      return new ClientConfigError(
        `allw: config file ${path} is not readable by this user (${problem.code}). Fix its ` +
          `permissions (chmod 600 ${path}, owned by you) or point ${CLIENT_CONFIG_PATH_ENV} at a ` +
          `readable file (fail-closed)`,
        path,
        options,
      );
    case "open_failed":
      return new ClientConfigError(
        `allw: config file ${path} is not a readable regular file${
          problem.code !== undefined ? ` (${problem.code})` : ""
        }. Point ${CLIENT_CONFIG_PATH_ENV} at a regular file (fail-closed)`,
        path,
        options,
      );
    case "not_regular":
      return new ClientConfigError(
        `allw: config file ${path} is not a readable regular file (a directory, FIFO, device or ` +
          `socket). Point ${CLIENT_CONFIG_PATH_ENV} at a regular file (fail-closed)`,
        path,
        options,
      );
    case "wrong_owner":
      return new ClientConfigError(
        `allw: config file ${path} is owned by uid ${String(problem.uid)}, not by the current ` +
          `user (uid ${String(problem.euid)}); whoever owns it controls your approval trust ` +
          `anchor. chown it to yourself (chown $(id -u) ${path}) or write your own (fail-closed)`,
        path,
        options,
      );
    case "group_or_world_writable":
      return new ClientConfigError(
        `allw: config file ${path} is group- or world-writable (mode ${problem.mode
          .toString(8)
          .padStart(3, "0")}); anyone who can write it can redirect approvals. ` +
          `Run: chmod 600 ${path} (fail-closed)`,
        path,
        options,
      );
    case "too_large":
      return new ClientConfigError(
        problem.size !== undefined
          ? `allw: config file ${path} is ${String(problem.size)} bytes, over the ` +
              `${String(MAX_CLIENT_CONFIG_BYTES)}-byte limit; it should hold only version, ` +
              `relay_url, account_id and approver_root_key (fail-closed)`
          : `allw: config file ${path} exceeds the ${String(MAX_CLIENT_CONFIG_BYTES)}-byte limit ` +
              `(fail-closed)`,
        path,
        options,
      );
    case "read_failed":
      return new ClientConfigError(
        `allw: config file ${path} is not a readable regular file (${
          problem.code ?? "read failed"
        }). Point ${CLIENT_CONFIG_PATH_ENV} at a regular file (fail-closed)`,
        path,
        options,
      );
  }
}

/**
 * Read and validate the config file at `path`. Returns `null` only when the file is absent and was
 * not explicitly requested.
 */
function readConfigFile(
  path: string,
  explicit: boolean,
  deps: LoadClientConfigDeps,
): Record<string, string> | null {
  const text = readConfigText(path, explicit, deps);
  if (text === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw new ClientConfigError(
      `allw: config file ${path} is not valid JSON (${jsonErrorPosition(cause)}). Fix or delete it; ` +
        `the env vars ALLW_RELAY_URL, ALLW_ACCOUNT_ID and ALLW_APPROVER_ROOT_KEY override its ` +
        `fields but never a corrupt file (fail-closed)`,
      path,
      { cause },
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ClientConfigError(
      `allw: config file ${path} must be a JSON object { "version": 1, "relay_url", ` +
        `"account_id", "approver_root_key" } (fail-closed)`,
      path,
    );
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.version !== CLIENT_CONFIG_VERSION) {
    throw new ClientConfigError(
      `allw: config file ${path} has an unsupported version (got ${jsonType(obj.version)}); ` +
        `this @allw/sdk understands only version ${String(CLIENT_CONFIG_VERSION)}. Upgrade @allw/sdk ` +
        `or rewrite the file (fail-closed)`,
      path,
    );
  }
  for (const key of Object.keys(obj)) {
    if (!FILE_KEYS.has(key)) {
      throw new ClientConfigError(
        `allw: config file ${path} has unknown key '${key}'; version 1 allows only version, ` +
          `relay_url, account_id and approver_root_key — and never secrets (fail-closed)`,
        path,
      );
    }
  }
  const out: Record<string, string> = {};
  for (const field of FIELDS) {
    const value = obj[field.key];
    if (value === undefined) {
      throw new ClientConfigError(
        `allw: config file ${path} is missing '${field.key}'. Add it to the file ` +
          `(${field.envVar} can override it, but the file must be complete) (fail-closed)`,
        path,
      );
    }
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new ClientConfigError(
        `allw: config file ${path} has a non-string or empty '${field.key}'; set it to a ` +
          `non-empty string, or override it with ${field.envVar} after fixing the file (fail-closed)`,
        path,
      );
    }
    out[field.key] = value;
  }
  return out;
}

/**
 * Load the integrator config: per-field env overrides over the config file, validated fail-closed.
 *
 * @throws {ClientConfigError} on any missing, malformed, unsafe, or inconsistent input — never a
 *   partial config — and when the WASM core needed for validation cannot be loaded. This is the
 *   only error type it throws. The message names the file path and the env var(s) involved and
 *   never echoes the file's contents.
 */
export function loadClientConfig(options: LoadClientConfigOptions = {}): IntegratorConfig {
  return loadClientConfigWith(options, {});
}

/**
 * {@link loadClientConfig} with test seams. Not re-exported from the package entry point.
 *
 * @internal
 */
export function loadClientConfigWith(
  options: LoadClientConfigOptions,
  deps: LoadClientConfigDeps,
): IntegratorConfig {
  const env = options.env ?? process.env;
  const envPath = envValue(env, CLIENT_CONFIG_PATH_ENV);
  const explicit = options.path !== undefined || envPath !== null;
  const path =
    options.path !== undefined
      ? resolveConfigPath(options.path, "the path option")
      : envPath !== null
        ? resolveConfigPath(envPath, CLIENT_CONFIG_PATH_ENV)
        : defaultClientConfigPath();

  const file = readConfigFile(path, explicit, deps);

  const resolved: Record<string, { value: string; fromEnv: boolean }> = {};
  for (const field of FIELDS) {
    const fromEnv = envValue(env, field.envVar);
    if (fromEnv !== null) {
      resolved[field.key] = { value: fromEnv, fromEnv: true };
      continue;
    }
    const fromFile = file?.[field.key];
    if (fromFile === undefined) {
      // Only reachable when there is no file at all (a present file is complete or rejected).
      throw new ClientConfigError(
        `allw: no allw config found — ${path} does not exist and ${field.envVar} is not set. ` +
          `Configure allw either by writing ${path} ({ "version": 1, "relay_url", "account_id", ` +
          `"approver_root_key" }; ${CLIENT_CONFIG_PATH_ENV} moves it) or by setting ` +
          `ALLW_RELAY_URL, ALLW_ACCOUNT_ID and ALLW_APPROVER_ROOT_KEY (fail-closed)`,
        path,
      );
    }
    resolved[field.key] = { value: fromFile, fromEnv: false };
  }

  const relay = resolved.relay_url;
  const account = resolved.account_id;
  const root = resolved.approver_root_key;
  if (relay === undefined || account === undefined || root === undefined) {
    throw new ClientConfigError("allw: config resolution is incomplete (fail-closed)", path);
  }

  try {
    assertRelayUrlTransport(relay.value);
  } catch (cause) {
    throw new ClientConfigError(
      `${cause instanceof Error ? cause.message : String(cause)} (from ${describeSource(
        RELAY_FIELD,
        relay.fromEnv,
        path,
      )}; fail-closed)`,
      path,
      { cause },
    );
  }

  let wasm: NonNullable<LoadClientConfigDeps["wasm"]>;
  try {
    wasm = deps.wasm ?? loadWasmSync();
  } catch (cause) {
    throw new ClientConfigError(
      `allw: cannot validate ${path} — ${cause instanceof Error ? cause.message : String(cause)} ` +
        `(fail-closed)`,
      path,
      { cause },
    );
  }

  // The core decodes and validates the root key (base64url-unpadded, exactly 32 bytes, a valid
  // Ed25519 point). Deriving the id doubles as that validation.
  try {
    wasm.account_id_for_root(root.value);
  } catch (cause) {
    throw new ClientConfigError(
      `allw: approver_root_key from ${describeSource(
        ROOT_FIELD,
        root.fromEnv,
        path,
      )} is not a base64url-unpadded 32-byte Ed25519 public key (${
        cause instanceof Error ? cause.message : String(cause)
      }). Copy the account-root public key printed by \`allw-approver pair\` into ${path} ` +
        `or ALLW_APPROVER_ROOT_KEY (fail-closed)`,
      path,
      { cause },
    );
  }

  try {
    wasm.check_account_id_for_root(account.value, root.value);
  } catch (cause) {
    throw new ClientConfigError(
      `allw: account_id from ${describeSource(
        ACCOUNT_FIELD,
        account.fromEnv,
        path,
      )} does not derive from approver_root_key from ${describeSource(
        ROOT_FIELD,
        root.fromEnv,
        path,
      )}. Account ids are self-certifying; use the account id and root key that ` +
        `\`allw-approver pair\` printed together, in ${path} or in ALLW_ACCOUNT_ID / ` +
        `ALLW_APPROVER_ROOT_KEY (fail-closed)`,
      path,
      { cause },
    );
  }

  return { relayUrl: relay.value, accountId: account.value, approverRootKey: root.value };
}
