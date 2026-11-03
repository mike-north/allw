/**
 * Vitest configuration for `@allw/relay`.
 *
 * Uses `@cloudflare/vitest-pool-workers` (v0.16+) so tests run inside a real `workerd`
 * instance with the Durable Object SQLite migration applied (from `wrangler.jsonc`).
 *
 * The `cloudflareTest` plugin (v0.16+ API) replaces the old `defineWorkersConfig` helper
 * (which was removed in v0.16 when the package dropped its `/config` export path).
 */
import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // Test requests carry no `CF-Connecting-IP`, so every test in a run would share the one
        // `ip|unknown` bucket of the per-client limiter. Raise only that binding's limit here; the
        // per-account bindings keep their `wrangler.jsonc` limits (see test/support/README.md).
        ratelimits: {
          RATE_LIMIT_CLIENT: { simple: { limit: 1_000_000, period: 60 } },
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
