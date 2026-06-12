# @allw/web-approver

Browser approver surface for issue #93. It renders the approval inbox, WYSIWYS detail view, and
number-match decision flow.

This is slice 1 of #93: controller state, safe rendering, and a static shell for runtime integration.

The package deliberately keeps cryptographic work behind an injected `WebApproverRuntime`:

- `prepare(envelope)` decrypts the relay envelope, recomputes the WYSIWYS `request_hash`, and returns the exact
  plaintext model to render.
- `signDecision(input)` signs the human's approve/deny decision.

Both methods must be backed by the allw WASM/core surfaces. The UI/controller code treats preparation failures as
fail-closed unverified requests and never reimplements hashing, verification, decryption, or signing.

`public/index.html` is a static browser shell for wiring a runtime at `window.allwWebApprover`.
