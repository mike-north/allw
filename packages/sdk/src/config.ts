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
 * names the file path and the env var(s) to fix — when:
 *
 * - there is no file and the env does not supply every field;
 * - an explicitly named file (`ALLW_CONFIG` / `path`) does not exist or cannot be read;
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

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { assertRelayUrlTransport } from "./relay.js";
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
   */
  readonly path?: string;
  /** Override the WASM core (tests). Defaults to {@link loadWasmSync}. */
  readonly wasm?: Pick<AllwWasm, "account_id_for_root" | "check_account_id_for_root">;
}

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

const FIELDS: readonly FieldSpec[] = [
  { key: "relay_url", envVar: "ALLW_RELAY_URL" },
  { key: "account_id", envVar: "ALLW_ACCOUNT_ID" },
  { key: "approver_root_key", envVar: "ALLW_APPROVER_ROOT_KEY" },
];

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
 * Read and validate the config file at `path`. Returns `null` only when the file is absent and was
 * not explicitly requested.
 */
function readConfigFile(path: string, explicit: boolean): Record<string, string> | null {
  if (!existsSync(path)) {
    if (!explicit) return null;
    throw new ClientConfigError(
      `allw: config file ${path} does not exist (named by ${CLIENT_CONFIG_PATH_ENV} or the path ` +
        `option). Create it, or unset ${CLIENT_CONFIG_PATH_ENV} and set ALLW_RELAY_URL, ALLW_ACCOUNT_ID ` +
        `and ALLW_APPROVER_ROOT_KEY (fail-closed)`,
      path,
    );
  }
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (cause) {
    throw new ClientConfigError(
      `allw: config file ${path} could not be read: ${String(cause)}. Fix its permissions, or point ` +
        `${CLIENT_CONFIG_PATH_ENV} at a readable file (fail-closed)`,
      path,
      { cause },
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw new ClientConfigError(
      `allw: config file ${path} is not valid JSON (${String(cause)}). Fix or delete it; ` +
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
      `allw: config file ${path} has unsupported version ${JSON.stringify(obj.version) ?? "(missing)"}; ` +
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
 * @throws {ClientConfigError} on any missing, malformed, or inconsistent input — never a partial
 *   config. The message names the file path and the env var(s) involved.
 */
export function loadClientConfig(options: LoadClientConfigOptions = {}): IntegratorConfig {
  const env = options.env ?? process.env;
  const envPath = envValue(env, CLIENT_CONFIG_PATH_ENV);
  const explicit = options.path !== undefined || envPath !== null;
  const path = options.path ?? envPath ?? defaultClientConfigPath();

  const file = readConfigFile(path, explicit);

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

  const spec = (key: FieldSpec["key"]): FieldSpec =>
    FIELDS.find((f) => f.key === key) ?? { key, envVar: "ALLW_RELAY_URL" };
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
        spec("relay_url"),
        relay.fromEnv,
        path,
      )}; fail-closed)`,
      path,
      { cause },
    );
  }

  const wasm = options.wasm ?? loadWasmSync();

  // The core decodes and validates the root key (base64url-unpadded, exactly 32 bytes, a valid
  // Ed25519 point). Deriving the id doubles as that validation.
  try {
    wasm.account_id_for_root(root.value);
  } catch (cause) {
    throw new ClientConfigError(
      `allw: approver_root_key from ${describeSource(
        spec("approver_root_key"),
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
        spec("account_id"),
        account.fromEnv,
        path,
      )} does not derive from approver_root_key from ${describeSource(
        spec("approver_root_key"),
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
