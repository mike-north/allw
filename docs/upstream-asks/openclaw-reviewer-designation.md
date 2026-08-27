# Upstream ask — OpenClaw: least-privilege reviewer designation for external approval clients

**Status:** draft, not filed. This is the text to post as a feature request on
`openclaw/openclaw`. It is written to be posted by a human, in their own voice, as an ordinary
upstream feature request — there is no allw branding in the body below, and it should stay that
way.

**Pinned against:** commit
[`1d526c5c`](https://github.com/openclaw/openclaw/commit/1d526c5c0ef635b4b7fda952c2b26da0c0290652).
Re-check the line ranges before posting; adjust or drop any that have moved.

---

## Title

Least-privilege reviewer designation for external approval clients

## Body

### Summary

Building a third-party approval surface against the gateway today works, but only if the client
requests `operator.admin`. The `operator.approvals` scope is documented as the approval capability,
and the client-capability registry has a public `approvals` handshake cap for exactly this kind of
non-UI bridge — but a newly paired generic client still does not see the approvals it exists to
review, because per-record visibility filtering excludes it.

The gateway already has the mechanism to fix this (`approvalReviewerDeviceIds`); it just has no
supported way for an operator to designate a device. I'd like to ask for that designation surface,
so an external approval client can run on `operator.approvals` alone.

### Why the current path forces admin

`docs/cli/approvals.md` already states the constraint directly for the built-in CLI:

> Complete enumeration and the matching operator-wide `resolve` flow use `operator.admin` because
> approval records otherwise retain requester/reviewer filtering. […] a restricted third-party
> client should not request admin merely to emulate this command.

That last sentence is the ask. I agree with it, and today there is no alternative — so a
third-party approval client either requests admin (against your own advice) or cannot function.

Delivery is two-stage at the pinned commit:

1. **Recipient set** —
   [`canDeliverApprovals`](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-request-context.ts#L135-L161)
   admits a client holding `operator.admin` or `operator.approvals` that is an internal approval
   runtime, a known first-party client id, **or** declares the public
   [`approvals` capability](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/packages/gateway-protocol/src/client-info.ts#L82-L95).
   This stage already works for a third-party client — nothing to change here.
2. **Per-record visibility** —
   [`isApprovalRecordVisibleToClient`](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/approval-record-lookup.ts#L72-L120)
   returns true unconditionally for `operator.admin`; otherwise it admits only the internal approval
   runtime, a device listed in the record's `approvalReviewerDeviceIds`, or the recording requester
   connection/device. A record with no binding at all stays visible to any `operator.approvals`
   client, but the records a reviewer actually cares about are bound at creation.

`approvalReviewerDeviceIds` is exactly the right hook, and it is already wired end to end —
[`bindApprovalReviewerDeviceIds`](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/approval-shared.ts#L103-L111)
feeds both the visibility check above (L104-L106) and
[`operator-approval-authorization.ts` L69-L71](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/operator-approval-authorization.ts#L69-L79).
The only gap is that it can be bound solely by the server-trusted internal approval runtime
([exec bind guard](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/exec-approval.ts#L416-L423),
[plugin bind guard](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/gateway/server-methods/plugin-approval.ts#L237-L241)),
and there is no config, CLI, or pairing surface that sets it. So it can only ever _narrow_ access —
never grant it.

### Proposed change

A supported way for the operator to designate reviewer devices, applied at record creation:

**Option A (preferred) — gateway config.** A config-settable list, e.g.
`gateway.approvals.reviewerDeviceIds`, read when an approval record is created and merged into the
existing `bindApprovalReviewerDeviceIds` call alongside the internal-runtime path. Nothing else
changes: a designated device then passes `approval-record-lookup.ts` L104-L106 and
`operator-approval-authorization.ts` L69-L71 on `operator.approvals` alone.

**Option B — a pairing/device flag.** Mark a paired device as an approval reviewer (e.g. an
`approvalReviewer` flag on the device record, or a `--reviewer` flag on
`openclaw devices approve`), and have record creation union the flagged device ids into the same
binding. This may fit the existing device-management UX better; either shape solves the problem.

In both cases the behavior on an existing deployment is unchanged unless an operator explicitly
designates a device, so this is additive.

**Note on semantics.** Today `approvalReviewerDeviceIds` is a pure narrowing mechanism, and this
proposal makes it also a granting one for a designated device. That is a real semantic change worth
being deliberate about — an alternative shape that keeps the field purely restrictive would be a
separate operator-designated reviewer set that record creation unions in, leaving
`approvalReviewerDeviceIds` meaning what it means now. I don't have a strong preference; I'd rather
follow whatever reads correctly to you.

### Optional follow-on: enrich `ApprovalPresentation`

Separately, and lower priority: the sanitized presentation built by
[`approval-presentation.ts` L46-L72](https://github.com/openclaw/openclaw/blob/1d526c5c0ef635b4b7fda952c2b26da0c0290652/src/infra/approval-presentation.ts#L46-L72)
omits fields a reviewer usually wants to see before deciding — notably `cwd` and `envKeys`, and some
digest or fingerprint of the `systemRunPlan` so a reviewer surface can show _that_ the exact plan is
pinned without carrying the plan itself.

This is not blocking: the `*.approval.requested` events and `exec.approval.list` /
`plugin.approval.list` return the raw stored request, so a reviewer client that consumes those has
everything it needs. But a client that renders from `approval.get` currently has less context than
the CLI does, and a plan digest in particular would let a reviewer surface display an integrity
indicator without widening what the sanitized projection exposes.

### Why this is worth doing

This is least-privilege hardening of a capability the gateway already documents and ships. The
`operator.approvals` scope, the `approvals` client capability, the kind-agnostic approval RPCs, and
the documented backfill/reconcile pattern in `docs/gateway/clients.md` all describe a first-class
external-approver seam. Right now that seam is reachable in practice only by handing a reviewer
client full admin — which means config mutation and native hooks, i.e. the ability to rewrite the
very exec policy the reviewer exists to enforce. A designated-reviewer path lets an external
approval surface do its job with an authority that can only ever answer approval requests.

Happy to send a PR for either option if you'd tell me which shape you'd prefer.

---

## Notes for the poster (not part of the issue body)

- Do **not** let an agent file this. `openclaw/openclaw` is not on the GitHub write allowlist; this
  file is the deliverable, and Mike posts it personally.
- Before posting, re-verify each cited line range at `1d526c5c` (or re-pin to whatever
  `openclaw/openclaw` `main` is at the time) — line numbers drift.
- Keep allw out of the body. If asked what the client is, answering plainly is fine; leading with it
  is not.
