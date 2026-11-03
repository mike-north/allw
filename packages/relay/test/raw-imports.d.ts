/**
 * Vite `?raw` imports resolve to the file's text. Tests use them to check committed config
 * (e.g. `wrangler.jsonc`) without filesystem access inside the Workers runtime.
 */
declare module "*?raw" {
  const content: string;
  export default content;
}

/**
 * Vite's `import.meta.glob`, in the two forms relay tests use: eager `?raw` default import, so each
 * matched source file maps to its text (`request-deadline.test.ts`, `lint-coverage.test.ts`), and
 * lazy, for listing matched paths. Declared here because the test tsconfig does not load
 * `vite/client` types.
 */
interface ImportMeta {
  glob(
    pattern: string,
    options: { readonly query: "?raw"; readonly import: "default"; readonly eager: true },
  ): Record<string, string>;
  /** Lazy form: each matched path maps to a loader that is never called here (#290). */
  glob(pattern: string): Record<string, () => Promise<unknown>>;
}
