/**
 * Vite `?raw` imports resolve to the file's text. Tests use them to check committed config
 * (e.g. `wrangler.jsonc`) without filesystem access inside the Workers runtime.
 */
declare module "*?raw" {
  const content: string;
  export default content;
}
