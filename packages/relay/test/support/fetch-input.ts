/**
 * Reading back what a stubbed `fetch` was called with.
 *
 * `fetch` takes a string, a `URL` or a `Request`. `String()` on a `Request` gives
 * `"[object Request]"`, not its URL, so tests read the URL through {@link urlOf} rather than
 * stringifying the input.
 */

/** The URL of one `fetch` input. Throws if there was no such call, so a missing call fails loudly. */
export function urlOf(input: RequestInfo | URL | undefined): string {
  if (input === undefined) throw new Error("fetch was not called with an input at that index");
  return input instanceof Request ? input.url : input.toString();
}
