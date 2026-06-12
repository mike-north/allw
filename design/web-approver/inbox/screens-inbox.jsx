/* screens-inbox.jsx — Pairing (A), Inbox empty (B) + list (C), request card */

const { useState, useEffect, useRef } = React;

// ---------------- A. PAIRING ----------------
function PairingScreen({ onPaired }) {
  const TARGET = ["K", "4", "P", "9", "Q", "X"]; // K4P-9QX
  const [vals, setVals] = useState(["", "", "", "", "", ""]);
  const [shake, setShake] = useState(false);
  const refs = useRef([]);

  const setAt = (i, v) => {
    v = v.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 1);
    const next = [...vals];
    next[i] = v;
    setVals(next);
    if (v && i < 5) refs.current[i + 1]?.focus();
    if (next.every((x) => x)) verify(next);
  };
  const verify = (entered) => {
    if (entered.join("") === TARGET.join("")) {
      setTimeout(() => onPaired(), 420);
    } else {
      setShake(true);
      setTimeout(() => { setShake(false); setVals(["", "", "", "", "", ""]); refs.current[0]?.focus(); }, 500);
    }
  };
  const onKey = (i, e) => {
    if (e.key === "Backspace" && !vals[i] && i > 0) refs.current[i - 1]?.focus();
  };
  const fillDemo = () => { setVals(TARGET); setTimeout(() => verify(TARGET), 250); };

  useEffect(() => { refs.current[0]?.focus(); }, []);

  return (
    <div className="screen s-enter">
      <div className="screen-pad">
        <div className="pair">
          <div>
            <div className="pair-logo"><I.shieldLock /></div>
            <h1 className="pair-h" style={{ marginTop: "20px" }}>Pair this device</h1>
            <p className="pair-sub">Enter the code shown where you set up allw. This links your device so it can hold the signing key — privately, on-device.</p>
          </div>

          <div>
            <div className={"code-input" + (shake ? " shake-row" : "")} style={shake ? { animation: "shake .45s" } : null}>
              {[0, 1, 2].map((i) => (
                <input key={i} ref={(el) => (refs.current[i] = el)} className={"code-cell" + (vals[i] ? " filled" : "")}
                  value={vals[i]} inputMode="text" maxLength={1} aria-label={"Code character " + (i + 1)}
                  onChange={(e) => setAt(i, e.target.value)} onKeyDown={(e) => onKey(i, e)} />
              ))}
              <span className="code-sep">–</span>
              {[3, 4, 5].map((i) => (
                <input key={i} ref={(el) => (refs.current[i] = el)} className={"code-cell" + (vals[i] ? " filled" : "")}
                  value={vals[i]} inputMode="text" maxLength={1} aria-label={"Code character " + (i + 1)}
                  onChange={(e) => setAt(i, e.target.value)} onKeyDown={(e) => onKey(i, e)} />
              ))}
            </div>
            <button className="btn btn-ghost" style={{ marginTop: "14px", fontSize: "13px" }} onClick={fillDemo}>
              Demo — autofill K4P-9QX
            </button>
          </div>

          <div className="pair-or">or</div>
          <button className="scan-btn" onClick={fillDemo}><I.qr />Scan pairing QR code</button>

          <div className="pair-foot"><I.lock />End-to-end encrypted · the key never leaves this device</div>
        </div>
      </div>
    </div>
  );
}

// ---------------- request card ----------------
function RequestCard({ req, now, onOpen }) {
  const remaining = req.expiresAt - now;
  const low = remaining <= 60 * 1000;
  const pct = Math.max(0, Math.min(1, remaining / req.durationMs));
  const cmdLine = req.action.type === "command"
    ? "$ " + req.action.argv.join(" ")
    : req.action.tool + " { … }";
  return (
    <button className="req-card" data-risk={req.risk} onClick={() => onOpen(req.id)}>
      <div className="req-card-top">
        <Actor actor={req.actor} sub={req.sub} kind={req.kind} />
        <RiskChip risk={req.risk} sm />
      </div>
      <div className="req-summary"><Summary parts={req.summaryParts} /></div>
      <div className="req-cmd">{cmdLine}</div>
      <div className="req-bar"><i style={{ width: (pct * 100) + "%" }} /></div>
      <div className="req-card-foot">
        <span className="req-expiry" data-low={low}>
          <I.clock />{fmt(remaining)}<span style={{ fontWeight: 500, color: "var(--ink-3)" }}>&nbsp;left</span>
        </span>
        <span className="req-chev"><I.chevR /></span>
      </div>
    </button>
  );
}

// ---------------- B/C. INBOX ----------------
function InboxScreen({ requests, now, onOpen, back }) {
  const pending = requests.filter((r) => r.status === "pending" && r.expiresAt > now);
  return (
    <div className="screen s-enter">
      <div className="inbox-head">
        <div className="inbox-top">
          <div className="inbox-brand">
            <div className="inbox-logo"><I.shield /></div>
            <span className="inbox-wordmark">allw</span>
          </div>
          <div className="avatar-chip" title="mike">M</div>
        </div>
        <h1 className="inbox-h1">
          Approvals {pending.length > 0 && <span className="inbox-count">· {pending.length}</span>}
        </h1>
        <div className="status-strip">
          <span className="status-pulse"><i /></span>
          2 devices online
          <span className="sep">·</span>
          <span className="lock"><I.lock />end-to-end encrypted</span>
        </div>
      </div>

      {pending.length === 0 ? (
        <div className="empty">
          <div className="empty-orb">
            <span className="ring r1" /><span className="ring r2" />
            <span className="empty-core"><I.shield /></span>
          </div>
          <div>
            <div className="empty-h">No pending approvals</div>
            <p className="empty-sub">You're connected. Anything an agent asks to do will show up here for your decision.</p>
          </div>
          <span className="empty-status"><I.check style={{ width: 14, height: 14, color: "var(--risk-low-fg)" }} />You're all clear</span>
        </div>
      ) : (
        <div className="req-list">
          {pending.map((r) => <RequestCard key={r.id} req={r} now={now} onOpen={onOpen} />)}
        </div>
      )}
    </div>
  );
}

Object.assign(window, { PairingScreen, InboxScreen, RequestCard });
