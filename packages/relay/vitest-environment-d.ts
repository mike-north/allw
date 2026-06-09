/**
 * Ambient type declarations for `@cloudflare/vitest-pool-workers` test environment.
 *
 * Provides type-safe access to the `cloudflare:test` module which exposes:
 * - `SELF` — a fetch-compatible stub bound to the Worker's default export
 * - `env` — the Worker's Env bindings (including the `ACCOUNT` DO namespace)
 * - `runInDurableObject` — run code directly inside a DO instance (for seeding state in tests)
 *
 * `ProvidedEnv` is the mechanism by which the pool knows the Worker's binding types.
 * It must match the `Env` interface exported from `src/index.ts`.
 */
import type { Env } from "./src/index.ts";

// @ts-expect-error: ambient module — resolved by the vitest-pool-workers runtime
declare module "cloudflare:test" {
  interface ProvidedEnv extends Env {}
}
