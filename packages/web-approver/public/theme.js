/**
 * Theme selection (issue #162), loaded as an external classic script so the page needs no inline
 * script under its Content-Security-Policy (`script-src 'self'`, issue #249 — see `public/_headers`).
 *
 * `.theme-light` on `<html>` is the no-JS/pre-paint default so the page never renders unstyled.
 * This script is referenced from `<head>` without `async`/`defer`, so it runs before the
 * stylesheets are requested: it upgrades to `.theme-dark` when the OS/browser reports a dark
 * preference, and keeps following live changes to that preference. It is pure presentation
 * wiring — it does not touch `#app` or any approver runtime state.
 */
(function () {
  var media =
    typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-color-scheme: dark)")
      : null;
  function applyTheme(prefersDark) {
    var root = document.documentElement;
    root.classList.toggle("theme-dark", prefersDark);
    root.classList.toggle("theme-light", !prefersDark);
  }
  if (media) {
    applyTheme(media.matches);
    if (typeof media.addEventListener === "function") {
      media.addEventListener("change", function (event) {
        applyTheme(event.matches);
      });
    }
  }
})();
