/**
 * Persisted per-install "surface" identity (issue #150; `docs/relay-api.md` §3, §7.4).
 *
 * `surface_id` is a stable per-browser-install identifier passed to the relay's
 * `GET /{acct}/devices/{deviceId}/connect?surface_id=…` WebSocket so co-located transports on one
 * physical screen (e.g. this web approver tab and a Mirrored iPhone) receive at most one push per
 * surface (`docs/relay-api.md` §7.4). It is **not** the `device_id` — a single device can host
 * multiple installs/tabs, each with its own surface id — and it must stay stable across reloads:
 * a value that changes every connection defeats the relay's per-surface dedupe and would let the
 * same visible screen receive duplicate pushes.
 *
 * @see ../../../docs/relay-api.md §3 (`connect?surface_id=…`), §7.4 (surface_id client FAQ)
 * @see ./retract-listener.ts (the consumer)
 */

/** The `localStorage` key under which the persisted surface id is stored. */
export const SURFACE_ID_STORAGE_KEY = "allw:surface-id:v1";

/** The relay's `surface_id` shape contract (`docs/relay-api.md` §3): 1-128 URL-safe chars. */
const SURFACE_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Injectable persistence seam for the surface id, mirroring {@link AccountStateFloorStore} /
 * {@link PairingStore}'s storage tradeoff. The default implementation persists to `localStorage`.
 */
export interface SurfaceIdStore {
  /** The persisted surface id, or `null` if none has been minted yet (or storage is unavailable). */
  load(): string | null;
  /** Persist a newly minted surface id. */
  save(surfaceId: string): void;
}

/**
 * Build a {@link SurfaceIdStore} backed by `localStorage` (or an injected `Storage`-compatible
 * object — a plain `Map`-backed fake in tests). A storage read/write failure (private-browsing
 * quota lockouts, security errors) is treated as "no store available" rather than crashing the
 * caller — {@link resolveSurfaceId} mints a fresh in-memory id for that call in that case.
 */
export function createLocalSurfaceIdStore(storage?: Storage): SurfaceIdStore {
  const store: Storage = storage ?? localStorage;
  return {
    load() {
      try {
        return store.getItem(SURFACE_ID_STORAGE_KEY);
      } catch {
        return null;
      }
    },
    save(surfaceId: string) {
      try {
        store.setItem(SURFACE_ID_STORAGE_KEY, surfaceId);
      } catch {
        // A full/blocked storage quota must not crash boot — the id simply will not survive to
        // the next reload, and the relay's dedupe just treats the next reload as a new surface.
      }
    },
  };
}

/**
 * Resolve this install's surface id, minting and persisting a fresh one on first use (or when the
 * stored value fails the relay's `surface_id` shape contract — a corrupt/foreign value must never
 * be sent to the relay, which rejects a malformed `surface_id` with `400` on the WS upgrade).
 */
export function resolveSurfaceId(
  store: SurfaceIdStore,
  generateId: () => string = () => crypto.randomUUID(),
): string {
  const stored = store.load();
  if (stored !== null && SURFACE_ID_PATTERN.test(stored)) {
    return stored;
  }
  const fresh = generateId();
  store.save(fresh);
  return fresh;
}
