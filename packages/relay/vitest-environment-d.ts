/**
 * Ambient type wiring for the `@cloudflare/vitest-pool-workers` test environment.
 *
 * The `cloudflare:test` module itself (`SELF`, `env`, `runInDurableObject`, …) is typed by
 * `@cloudflare/vitest-pool-workers/types`, listed in `tsconfig.test.json`'s `types`. Its `env`
 * export is typed as `Cloudflare.Env`; augmenting that global interface here gives tests the
 * Worker's real binding types (including the `ACCOUNT` DO namespace). It must stay in step with
 * the `Env` interface exported from `src/index.ts`, which is why it extends it directly.
 */
import type { Env } from "./src/index.js";

declare global {
  namespace Cloudflare {
    interface Env extends RelayEnv {}
  }
}

type RelayEnv = Env;
