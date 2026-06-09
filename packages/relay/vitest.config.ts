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
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
