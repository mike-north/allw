/**
 * Vite `?raw` imports resolve to the file's text. Tests use them to check committed config
 * (e.g. `wrangler.jsonc`) without filesystem access inside the Workers runtime.
 */
declare module "*?raw" {
  const content: string;
  export default content;
}

/**
 * Vite's `import.meta.glob`, as the source guard in `request-deadline.test.ts` uses it: eager,
 * `?raw`, default import, so each matched source file maps to its text. Declared here because the
 * test tsconfig does not load `vite/client` types.
 */
interface ImportMeta {
  glob(
    pattern: string,
    options: { readonly query: "?raw"; readonly import: "default"; readonly eager: true },
  ): Record<string, string>;
}
