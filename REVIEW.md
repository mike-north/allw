VERDICT: OK-WITH-NITS

Adversarial review of PR #277 (head `74ad1af`, "web-approver, sdk: drop [::1] as a loopback relay host; note pin
migration"). Gate run on the PR head: `pnpm install`, WASM build, `pnpm -r build`, `pnpm -r typecheck`,
`pnpm -r lint`, `prettier --check` all green; `@allw/sdk` tests 137/137 and `@allw/web-approver` tests 279/279
pass. The WASM was built with `wasm-pack --no-opt` because the sandbox could not download binaryen for
`wasm-opt`; that does not affect these tests. Cargo was not run because the PR has no Rust changes.

## Findings (most severe first)

### 1. should-fix: the PR causes the problem its new comment warns about. A browser paired to `http://[::1]` silently loses its device identity.

- **Where:** `packages/web-approver/src/relay-config.ts:45` (narrowed `LOOPBACK_HOSTNAMES`), together with
  `packages/web-approver/src/pairing.ts:101-104` (`parseIdentity` requires `checkRelayUrl(pin).ok`) and
  `pairing.ts:494` (`goToPairing` → `store.clear()`).
- **Scenario:** On `main`, a developer pairs the web approver against `http://[::1]:8787` with no CSP, for example
  when serving `dist-site` locally or testing in jsdom. The pinned identity is stored. Then they upgrade to this PR:
  - `pairingStore.load()` returns `null` because the pin no longer passes `checkRelayUrl`.
  - `boot` treats the browser as unpaired.
  - If a pre-pairing candidate (`allw:relay-url:v1`) is persisted, or as soon as the human types one into the
    "Connect a relay" prompt, `mountPairingGate` → `goToPairing` → `store.clear()` erases
    `allw:pairing:v1`, including the seeds and `deviceAuthToken`.
  - Nothing tells the human why. The page looks like a first visit.

  The new doc comments added in `pairing.ts:89-91` and `relay-config.ts:93-96` describe exactly this failure, but
  only for "changing the canonical form". Narrowing the *accepted set* has the same effect, and this PR does that
  without a migration and without a note in the docs.
- **REPRODUCED:** I added a temporary test to `packages/web-approver/test/` that reused `app-boot.test.mjs`'s
  harness (jsdom, `memoryStorage`, real `boot()`), then deleted it. I seeded `allw:pairing:v1` with
  `{...PINNED_IDENTITY, relayUrl: "http://[::1]:8787"}` and `allw:relay-url:v1 = "http://127.0.0.1:8787"`, then
  awaited `boot({search: ""})`. Afterwards `allw:pairing:v1` was `null`. Without a candidate, the relay-config
  prompt renders (pairing form not shown) and the identity is still present but will be cleared on the next step.
- **Impact:** The security direction is fail-closed (deny), so this is not a security hole. Only dev/loopback
  users are affected, and a hosted build's CSP would already have blocked a `[::1]` relay. But it destroys key
  material without telling anyone, which is the outcome the PR claims to document against.
- **Suggested fix (pick one):**
  - (a) Do a one-shot migration in `createLocalPairingStore().load()` or in `boot`: if the stored pin's hostname
    is `[::1]` and the protocol is `http:`, rewrite it to the same URL on `127.0.0.1` (same port and path) and
    re-save. Both are the same machine's loopback, so moving the pin does not widen trust.
  - (b) Stop calling `store.clear()` on a *structurally valid identity whose pin is no longer accepted*. Instead,
    show a "your pinned relay `http://[::1]:…` is no longer supported; use `127.0.0.1` and re-pair" notice.
  - At minimum, add a sentence to `docs/web-approver-deploy.md` §2 *Relay pinning* and to the PR body saying that
    browsers pinned to `[::1]` must re-pair, plus one boot test pinning the chosen behaviour.

### 2. nit: the migration note is only in code comments and frames the rule too narrowly.

- **Where:** `packages/web-approver/src/pairing.ts:89-91`, `packages/web-approver/src/relay-config.ts:93-96`,
  `docs/web-approver-deploy.md` §2 *Relay pinning* (lines ~91-110, unchanged).
- **Scenario:** The title says "note pin migration", but the operator/developer runbook still says nothing about
  what happens to a stored pin that later fails validation. It also does not say that the "clear site data to
  change relays" advice can happen *implicitly*. The comment says "changing that canonical form requires
  migrating". It should say "changing the canonical form **or narrowing what `checkRelayUrl` accepts**". This
  PR is the first instance of the second case.
- **Fix:** Reword both comments. Add a bullet under *Relay pinning*: "A pin that a later build no longer accepts
  makes the stored identity load as corrupt; the browser must re-pair. Builds that narrow the relay rule ship a
  migration."
- **Reasoned only** (doc text vs. code read above).

### 3. nit (pre-existing, outside this PR's diff): the `@allw/approver` CLI enforces no relay transport rule at all.

- **Where:** `packages/approver/src/cli.ts:124,143` pass `--relay` straight through. There is no
  `assertRelayUrlTransport` or equivalent anywhere in `packages/approver/src`.
- **Scenario:** `allw-approver pair --relay http://relay.example.com` (or `http://[::1]`) is accepted, and the
  device bearer token travels over plaintext HTTP. The new deploy-doc sentence ("rejected by the web approver, the
  SDK, and the site build alike") is accurate as written, but a reader could take it to mean every surface
  enforces the rule.
- **Fix:** Follow up by validating `--relay` / `relay_url` with the SDK's `assertRelayUrlTransport`, which the
  approver can import. That would also put the shared vectors on a fourth consumer.
- **Reasoned only** (grep over `packages/approver/src`; not executed).

### 4. nit (pre-existing): the SDK builds request and WebSocket URLs from the caller's raw string, not the parsed URL.

- **Where:** `packages/sdk/src/relay.ts` `accountBase` / `toWsUrl` (≈lines 160-170).
- **Scenario:** `" http://127.0.0.1:8787 "` and `"HTTP://127.0.0.1:8787"` pass `assertRelayUrlTransport`, which
  parses a trimmed/normalized form. But `toWsUrl` does a case-sensitive `^http` replace, and `accountBase` does
  not trim, so the derived URLs can be malformed. This fails closed: fetch/WS throws, which means deny. It is not
  a bypass. The web approver avoids this by storing the canonical form.
- **Fix:** Have `createClient` store `new URL(relayUrl)`'s canonical origin+path, as `checkRelayUrl` does.
- **Reasoned only**; outside #277's scope.

## Design decisions for Mike

1. **Migrate or re-pair?** Rewriting `[::1]` pins to `127.0.0.1` is safe, since both are loopback on the same
   machine, and it keeps dev devices. Requiring a re-pair is simpler, but then the gate should say why instead of
   silently clearing. More generally: should `goToPairing` ever `clear()` an identity whose only defect is a
   no-longer-accepted pin, or should that be a distinct, visible "re-pair required" state?
2. **Single source of truth for the loopback set.** There are now three hand-mirrored copies: the SDK, the web
   approver runtime and `build-site.mjs`. The shared vectors catch drift, but exporting the set from the SDK, or
   having the web approver import `assertRelayUrlTransport`, would remove the duplication. The approver CLI
   (finding 3) is the surface the mirrors missed.
3. **Should `localhost` stay?** It is accepted everywhere. In Node, `localhost` may resolve to `::1` first, which
   is harmless for the SDK. In the browser it is CSP-expressible. Keeping it is fine; noting it only because the
   PR's rationale for dropping `[::1]` is CSP expressibility, not resolution.

## What I tried that held up

I ran every form below through all three validators: SDK `assertRelayUrlTransport`, web approver
`checkRelayUrl`, and build `relayConnectSources`. **All three agreed on every input.**

- **IPv6 / IPv4-mapped forms, rejected everywhere:** `http://[::1]`, `http://[::1]:8787`,
  `http://[0:0:0:0:0:0:0:1]`, `http://[::ffff:127.0.0.1]`, `http://[::ffff:7f00:1]`.
- **Other non-loopback or near-miss hosts, rejected everywhere:** `127.0.0.2`, `0.0.0.0`, `0`,
  `foo.localhost`, `localhost.`, `localhost%2e`, `xn--localhost`, `ws://127.0.0.1`.
- **Accepted everywhere, all normalizing to a genuine loopback canonical form:** `127.1`, `2130706433`,
  `0x7f000001`, `0177.0.0.1`, `127.0.0.1.`, `LOCALHOST`, `lo%63alhost`, `local<TAB>host`, `http:localhost:8787`,
  `http:/127.0.0.1`, `http:\\127.0.0.1`, `HTTP://`, surrounding whitespace, trailing `/`, `:80`. The WHATWG
  parser normalizes these, so no off-machine host gets through. The build emits only the normalized origin into
  `connect-src`, so no CSP injection is possible.
- **Tests:**
  - The new `[::1]` rejection tests in `packages/sdk/test/relay-url-transport.test.mjs` and
    `packages/web-approver/test/relay-config.test.mjs` are direct negative tests and would fail on `main`, which
    accepted `[::1]`.
  - The shared vector `http://[::1]:8787` was changed to `runtime: reject` with no `canonical`. That is consistent
    with how the three consumers load it, and all pass.
  - The assertions match the reason text and the `INSECURE_RELAY_URL_REASON` constant, not captured output.
- **Pre-pairing candidate:** a persisted `allw:relay-url:v1 = http://[::1]:8787` is re-validated on read by
  `readStoredRelayUrl` and dropped. It is not destructive: the prompt is shown.
- **Docs:** `docs/web-approver-deploy.md` §2 and §3.1 match the code. `docs/quickstart.md` and
  `docs/relay-api.md` already use `127.0.0.1`. No other `[::1]` references remain in the source.
- **Contract invariants:** this PR does not affect them. There is no new allow path, and every changed branch
  only tightens.
