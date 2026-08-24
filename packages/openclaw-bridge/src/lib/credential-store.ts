/**
 * Custody for the bridge's two gateway secrets: the **Ed25519 device private key** and the paired
 * **device token** (`docs/openclaw-integration.md` §4.2).
 *
 * Both are secrets at rest. They are written to a `0600` file under the bridge's state directory —
 * the same custody backend `packages/approver/src/lib/keyfile.ts` uses for the v0 approver identity
 * — and are **never** placed in an environment variable (visible in a process list), a checked-in
 * config file, or a log line. `docs/policy-seam.md` §Network egress classes them as credential-vault
 * material; a real OS keystore backend is a follow-up that swaps this module out without touching
 * the gateway client.
 *
 * The shared bootstrap credential is deliberately *not* stored here: it is a bootstrap step only
 * (§4.2), supplied per-run by the operator, and the long-lived credential is the paired device
 * token this module persists.
 *
 * @see ../../../../docs/openclaw-integration.md §4.2 Pairing and credential handling
 * @see ../../../../packages/approver/src/lib/keyfile.ts (the same 0600 custody pattern)
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { join } from "node:path";

/** Current on-disk schema version for the bridge credential file. */
export const CREDENTIAL_FILE_VERSION = 1 as const;

/** The gateway device identity, in the PEM shape `@openclaw/gateway-client` consumes. */
export interface DeviceIdentity {
  readonly deviceId: string;
  /** ⚠️ secret — Ed25519 private key (PKCS#8 PEM). */
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
}

/** A device token issued by the gateway after pairing, scoped to one role. */
export interface DeviceTokenRecord {
  readonly token: string;
  readonly scopes: readonly string[];
}

/** The persisted file. **Contains a secret key** — never log, transmit, or commit it. */
interface CredentialFile {
  readonly version: typeof CREDENTIAL_FILE_VERSION;
  readonly device_id: string;
  readonly device_private_key_pem: string;
  readonly device_public_key_pem: string;
  /** Device tokens keyed by the role they were issued for (the bridge only ever uses `operator`). */
  readonly device_tokens?: Record<string, { token: string; scopes: string[] }>;
}

/** Persistent custody for the bridge's gateway credentials. */
export interface CredentialStore {
  loadOrCreateDeviceIdentity(): DeviceIdentity;
  loadDeviceToken(role: string): DeviceTokenRecord | null;
  storeDeviceToken(role: string, record: DeviceTokenRecord): void;
  clearDeviceToken(role: string): void;
}

function credentialPath(stateDir: string, gatewayId: string): string {
  return join(stateDir, `openclaw-bridge-${gatewayId}.json`);
}

function readFile(path: string): CredentialFile | null {
  if (!existsSync(path)) return null;
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (typeof parsed !== "object" || parsed === null) return null;
    const file = parsed as Partial<CredentialFile>;
    if (
      file.version !== CREDENTIAL_FILE_VERSION ||
      typeof file.device_id !== "string" ||
      typeof file.device_private_key_pem !== "string" ||
      typeof file.device_public_key_pem !== "string"
    ) {
      return null;
    }
    return file as CredentialFile;
  } catch {
    // A corrupt credential file is treated as absent: the bridge mints a fresh identity and the
    // operator re-pairs. Reusing a half-parsed key would be worse than re-pairing.
    return null;
  }
}

function writeFileSecurely(path: string, file: CredentialFile): void {
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
  // `mode` only applies at creation; chmod covers the rewrite-an-existing-file case.
  chmodSync(path, 0o600);
}

/**
 * Open (or lazily create) the credential store for one gateway. The state directory is created with
 * `0700` so the credential file is never world-readable even transiently.
 */
export function openCredentialStore(stateDir: string, gatewayId: string): CredentialStore {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const path = credentialPath(stateDir, gatewayId);

  function read(): CredentialFile | null {
    return readFile(path);
  }

  return {
    loadOrCreateDeviceIdentity(): DeviceIdentity {
      const existing = read();
      if (existing !== null) {
        return {
          deviceId: existing.device_id,
          privateKeyPem: existing.device_private_key_pem,
          publicKeyPem: existing.device_public_key_pem,
        };
      }
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const identity: DeviceIdentity = {
        deviceId: `allw-openclaw-bridge-${randomUUID()}`,
        privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      };
      writeFileSecurely(path, {
        version: CREDENTIAL_FILE_VERSION,
        device_id: identity.deviceId,
        device_private_key_pem: identity.privateKeyPem,
        device_public_key_pem: identity.publicKeyPem,
      });
      return identity;
    },

    loadDeviceToken(role: string): DeviceTokenRecord | null {
      const file = read();
      const entry = file?.device_tokens?.[role];
      if (entry === undefined || typeof entry.token !== "string" || entry.token.length === 0) {
        return null;
      }
      return { token: entry.token, scopes: Array.isArray(entry.scopes) ? entry.scopes : [] };
    },

    storeDeviceToken(role: string, record: DeviceTokenRecord): void {
      const file = read();
      if (file === null) return;
      writeFileSecurely(path, {
        ...file,
        device_tokens: {
          ...file.device_tokens,
          [role]: { token: record.token, scopes: [...record.scopes] },
        },
      });
    },

    clearDeviceToken(role: string): void {
      const file = read();
      if (file?.device_tokens?.[role] === undefined) return;
      const remaining = Object.fromEntries(
        Object.entries(file.device_tokens).filter(([key]) => key !== role),
      );
      writeFileSecurely(path, { ...file, device_tokens: remaining });
    },
  };
}
