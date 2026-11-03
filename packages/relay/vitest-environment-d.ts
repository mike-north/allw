/**
 * Ambient type wiring for the `@cloudflare/vitest-pool-workers` test environment.
 *
 * Tests take `env` and `exports` from `cloudflare:workers` (typed by `@cloudflare/workers-types`)
 * and `runInDurableObject` from `cloudflare:test` (typed by `@cloudflare/vitest-pool-workers/types`;
 * both are listed in `tsconfig.test.json`'s `types`).
 *
 * - `env` is typed as `Cloudflare.Env`. Augmenting that global interface gives tests the Worker's
 *   real binding types (including the `ACCOUNT` DO namespace). It must stay in step with the `Env`
 *   interface exported from `src/index.ts`, which is why it extends it directly.
 * - `exports` is typed from `Cloudflare.GlobalProps.mainModule`. Declaring the Worker's entry module
 *   there types `exports.default.fetch()`, the loopback into the Worker's own fetch handler.
 *
 * The global-namespace augmentation and the empty extending interface are what TypeScript requires
 * to merge into `Cloudflare.Env`, so the lint rules against both are disabled for this file.
 */
/* eslint-disable @typescript-eslint/no-namespace, @typescript-eslint/no-empty-object-type */
import type { Env } from "./src/index.js";

declare global {
  namespace Cloudflare {
    interface Env extends RelayEnv {}
    interface GlobalProps {
      mainModule: typeof import("./src/index.js");
    }
  }
}

// Aliased: inside `namespace Cloudflare`, `Env` names `Cloudflare.Env` itself, so `extends Env` would add nothing.
type RelayEnv = Env;
