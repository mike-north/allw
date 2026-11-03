# DX report: blind run of the README quickstart

**Status: IN PROGRESS (partial).** Base: `origin/main` @ `2e3d0f2`. Run date 2026-11-03 (UTC).

The run follows README.md → docs/quickstart.md only. Packages are not on npm, so the workspace build stands in.

## Timeline (UTC)

| Time     | Step                                                     | Result                                                                                                           |
| -------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| 06:26:21 | Start: read README + quickstart                          |                                                                                                                  |
| 06:26:45 | `npm install @allw/hook @allw/approver` (per README §1)  | "succeeds", but installs 930-byte name-reservation stubs with no bin                                             |
| 06:26:45 | `npx allw-hook --version`                                | npx fetches the _unscoped_ `allw-hook` stub, which throws "use @allw/hook instead", which was just installed      |
| 06:26:58 | Fallback: `pnpm install` (workspace)                     | OK, 9s. Bin-link warnings (dist not built yet), engine warnings (Node 22 here, Node ≥24 required)                |
| 06:27:22 | `pnpm run build:wasm`                                    | `sh: wasm-pack: not found`: the source path needs Rust + wasm-pack, and the docs never say so                    |
| 06:27:47 | Installed wasm-pack (npm -g); rustup auto-installed 1.99.1 + wasm32 |                                                                                                       |
| 06:29:43 | `build:wasm` retry                                       | Failed downloading binaryen (sandbox proxy issue, not a doc defect). Installed `wasm-opt` manually               |
| 06:30:06 | `build:wasm`                                             | OK                                                                                                               |
| 06:30:35 | `pnpm -r build`                                          | OK (26s)                                                                                                         |
| 06:30:47 | `pnpm --filter @allw/relay dev`                          | Ready on :8787 in ~5s                                                                                            |
| 06:30:52 | `allw-approver pair --relay http://127.0.0.1:8787`       | OK, 1s. Prints account id + root key                                                                             |
| 06:31    | `allw-approver watch`                                    | Connected                                                                                                        |
| …        | hook wiring + first approval                             | _in progress_                                                                                                    |
