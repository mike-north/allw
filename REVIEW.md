VERDICT: PENDING (interim — SSRF/JWT/cap/prune analysis done, gate + repros running)

Interim notes on PR #255 at head f693d74:
- SSRF allowlist held against host-parsing probes (case, fullwidth, %2E, backslash, userinfo, :443, trailing dot, lookalike suffix, fragment-@).
- Candidate findings: fragment not stripped on normalization (two rows for one subscription); push_wakeups counts webpush tokens under Noop transport; path/query unconstrained on allowlisted hosts; arbitrary-depth *.notify.windows.com.
