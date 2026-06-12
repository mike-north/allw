/* screens-detail.jsx — Detail (D), Number-match challenge (E), Confirmation (F), Expired (G) */

const { useState: useStateD, useEffect: useEffectD, useRef: useRefD } = React;

// countdown ring
function Ring({ pct, label, danger }) {
  const r = 25, c = 2 * Math.PI * r;
  return (
    <div className="ring">
      <svg width="56" height="56" viewBox="0 0 56 56">
        <circle cx="28" cy="28" r={r} fill="none" stroke="var(--border)" strokeWidth="4" />
        <circle cx="28" cy="28" r={r} fill="none" stroke={danger ? "var(--risk-crit-fg)" : "var(--accent)"} strokeWidth="4"
          strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - pct)}
          style={{ transition: "stroke-dashoffset .5s linear, stroke .3s" }} />
      </svg>
      <span className="rt" style={danger ? { color: "var(--risk-crit-fg)" } : null}>{label}</span>
    </div>
  );
}

// ---------------- D. REQUEST DETAIL ----------------
function DetailScreen({ req, now, onApprove, onDeny, back }) {
  const [expanded, setExpanded] = useStateD(false);
  const remaining = req.expiresAt - now;
  const low = remaining <= 60 * 1000;
  const pct = Math.max(0, Math.min(1, remaining / req.durationMs));

  return (
    <div className="screen s-enter">
      <div className="nav">
        <button className="nav-back" onClick={back}><I.chevL />Inbox</button>
        <span className="nav-title">Approval</span>
        <span className="nav-spacer" />
      </div>

      <div className="detail" data-risk={req.risk}>
        <div className="slip">
          <div className="slip-head">
            <div className="slip-actor-row">
              <Actor actor={req.actor} sub={req.sub} kind={req.kind} />
              <span className="actor-verify-text"><I.shieldLock />Verified</span>
            </div>
            <div className="ring-row">
              <Ring pct={pct} label={fmt(remaining)} danger={low} />
              <div className="ring-meta">
                <span className="big" style={low ? { color: "var(--risk-crit-fg)" } : { color: "var(--ink)" }}>
                  Expires in {fmt(remaining)}
                </span>
                <span className="small">No response auto-denies · the agent stays blocked</span>
              </div>
            </div>
          </div>

          <div className="perf"><span className="notch l" /><span className="notch r" /></div>

          <div className="slip-body">
            <div>
              <div className="summary-lead">Approve this action</div>
              <div className="summary-text"><Summary parts={req.summaryParts} /></div>
            </div>

            <ActionCode req={req} expandable expanded={expanded} onToggle={() => setExpanded((e) => !e)} />

            <div className="meta-row">
              <RiskChip risk={req.risk} />
              <Reversibility reversible={req.reversible} />
            </div>

            <div className="seal">
              <span className="seal-icon"><I.shield /></span>
              <div className="seal-text">
                <span className="seal-title">Verified origin · end-to-end encrypted</span>
                <Fingerprint fp={req.fingerprint} />
              </div>
            </div>

            {req.challenge && (
              <div className="challenge-hint" data-risk={req.risk}>
                <I.hash />
                <span className="ch-text">This action needs number-match confirmation. You'll enter a code shown in the terminal where it was launched.</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="actionbar">
        <div className="actions-2">
          <button className="btn btn-deny" onClick={onDeny}><I.x />Deny</button>
          <button className="btn btn-approve" onClick={onApprove}>
            {req.challenge ? <React.Fragment><I.hash />Confirm to approve</React.Fragment> : <React.Fragment><I.check />Approve</React.Fragment>}
          </button>
        </div>
        <div className="deny-note">Denying is instant. Approving signs locally on this device.</div>
      </div>
    </div>
  );
}

// ---------------- E. NUMBER-MATCH CHALLENGE ----------------
function ChallengeScreen({ req, now, onVerified, back }) {
  const [digits, setDigits] = useStateD(["", "", ""]);
  const [state, setState] = useStateD("idle"); // idle | error | ok
  const target = (req.challenge || "").split("");
  const remaining = req.expiresAt - now;
  const low = remaining <= 60 * 1000;
  const filled = digits.filter((d) => d !== "").length;

  const press = (n) => {
    if (state === "ok") return;
    if (state === "error") setState("idle");
    setDigits((prev) => {
      const f = prev.filter((d) => d !== "").length;
      if (f >= 3) return prev;
      const next = [...prev];
      next[f] = String(n);
      if (next.every((d) => d !== "")) check(next);
      return next;
    });
  };
  const del = () => {
    if (state === "ok") return;
    if (state === "error") setState("idle");
    setDigits((prev) => {
      const f = prev.filter((d) => d !== "").length;
      const next = [...prev];
      if (f - 1 >= 0) next[f - 1] = "";
      return next;
    });
  };
  const check = (entered) => {
    if (entered.join("") === target.join("")) {
      setState("ok");
      setTimeout(() => onVerified(), 650);
    } else {
      setState("error");
      setTimeout(() => { setDigits(["", "", ""]); setState("idle"); }, 800);
    }
  };

  return (
    <div className="screen s-enter">
      <div className="nav">
        <button className="nav-back" onClick={back}><I.chevL />Back</button>
        <span className="nav-title">Confirm number</span>
        <span className="countdown" data-low={low}><span className="t">{fmt(remaining)}</span></span>
      </div>

      <div className="challenge">
        <div className="ch-head">
          <h1 className="ch-h">Match the number to approve</h1>
          <p className="ch-sub">This confirms you and the agent mean the same action. Type the 3-digit number shown in the terminal where it was launched.</p>
        </div>

        {/* mock origin terminal */}
        <div className="term">
          <div className="term-bar">
            <span className="term-dot r" /><span className="term-dot y" /><span className="term-dot g" />
            <span className="term-title">{req.sub} — claude-code</span>
          </div>
          <div className="term-body">
            <div className="line"><span className="pr">$</span> <span className="dim">{req.action.type === "command" ? req.action.argv.join(" ") : req.action.tool}</span></div>
            <div className="line dim">⏳ waiting for approval on your phone…</div>
            <div className="term-callout">
              <div>
                <div className="lbl">Match this number</div>
                <div className="term-num">{req.challenge}</div>
              </div>
              <div className="term-arrow" style={{ marginLeft: "auto" }}>
                <I.arrowDown />type below
              </div>
            </div>
          </div>
        </div>

        {/* digit display */}
        <div>
          <div className="digit-row">
            {[0, 1, 2].map((i) => {
              let cls = "digit";
              if (state === "error") cls += " error";
              else if (state === "ok") cls += " ok";
              else if (i === filled) cls += " active";
              else if (digits[i]) cls += " filled";
              return <div key={i} className={cls}>{digits[i]}</div>;
            })}
          </div>
          <div className="ch-error">{state === "error" ? "That doesn't match — check the terminal and try again." : ""}</div>
        </div>

        {/* keypad */}
        <div className="keypad">
          {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => (
            <button key={n} className="key" onClick={() => press(n)}>{n}</button>
          ))}
          <span className="key blank" />
          <button className="key" onClick={() => press(0)}>0</button>
          <button className="key del" onClick={del} aria-label="Delete"><I.delete style={{ width: 22, height: 22 }} /></button>
        </div>
      </div>

      <div className="actionbar">
        <button className="btn btn-approve" disabled={state !== "ok"} onClick={onVerified}>
          {state === "ok" ? <React.Fragment><I.check />Matched — approve</React.Fragment> : "Enter the number to approve"}
        </button>
      </div>
    </div>
  );
}

// ---------------- F. CONFIRMATION ----------------
function ConfirmScreen({ req, verdict, time, onDone }) {
  const approved = verdict === "approved";
  return (
    <div className="screen s-enter">
      <div className={"confirm " + (approved ? "approved" : "denied")}>
        <div className="confirm-seal">
          {approved && <span className="halo" />}
          <div className="confirm-badge">{approved ? <I.check /> : <I.x />}</div>
        </div>
        <div>
          <h1 className="confirm-h">{approved ? "Approved" : "Denied"}</h1>
          <p className="confirm-sub">
            {approved
              ? "Signed on this device. The agent can now proceed with exactly this action."
              : "The agent has been blocked. Nothing was signed and no action was taken."}
          </p>
        </div>

        <div className="signed-card">
          <div className="signed-row">
            <span className="signed-k"><I.shieldLock />{approved ? "Signed locally" : "Decision"}</span>
            <span className={"signed-v" + (approved ? " ok" : "")}>{approved ? "✓ on this device" : "Blocked"}</span>
          </div>
          <div className="signed-row">
            <span className="signed-k"><I.clock />Time</span>
            <span className="signed-v">{time}</span>
          </div>
          <div className="signed-row">
            <span className="signed-k"><I.lock />Fingerprint</span>
            <span className="signed-v">{req.fingerprint}</span>
          </div>
        </div>
      </div>

      <div className="actionbar">
        <button className="btn btn-approve" onClick={onDone}><I.chevL style={{ transform: "none" }} />Back to inbox</button>
      </div>
    </div>
  );
}

// ---------------- G. EXPIRED / FAIL-CLOSED ----------------
function ExpiredScreen({ req, onDone }) {
  return (
    <div className="screen s-enter">
      <div className="expired">
        <div className="expired-badge"><I.clock /></div>
        <div>
          <h1 className="expired-h">Expired — denied automatically</h1>
          <p className="expired-sub">This request reached its time limit with no response, so allw denied it for you. The agent was blocked.</p>
        </div>
        <div className="failclosed-note">
          <I.shield />
          <div>
            <div className="fc-t">This was the safe outcome</div>
            <div className="fc-s">Silence always means no. Nothing is ever approved without your explicit decision on this device.</div>
          </div>
        </div>
        <div className="signed-card">
          <div className="signed-row">
            <span className="signed-k"><I.agent style={{ width: 13, height: 13 }} />{req.actor}</span>
            <span className="blocked-tag">Blocked</span>
          </div>
          <div className="signed-row">
            <span className="signed-k">Action</span>
            <span className="signed-v" style={{ maxWidth: "60%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {req.action.type === "command" ? req.action.argv.join(" ") : req.action.tool}
            </span>
          </div>
        </div>
      </div>
      <div className="actionbar">
        <button className="btn btn-deny" onClick={onDone}><I.chevL />Back to inbox</button>
      </div>
    </div>
  );
}

Object.assign(window, { DetailScreen, ChallengeScreen, ConfirmScreen, ExpiredScreen, Ring });
