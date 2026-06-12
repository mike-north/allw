/* hero-variants.jsx — three exploration directions for the Request Detail (hero) screen.
   All render Request 1: CRITICAL force-push to main. */

// ---- shared little pieces ----
const IconAgent = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 7V4"/><circle cx="12" cy="3" r="1"/>
    <circle cx="9" cy="13" r="1.2" fill="currentColor" stroke="none"/><circle cx="15" cy="13" r="1.2" fill="currentColor" stroke="none"/>
  </svg>
);
const IconCheck = () => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12l4.5 4.5L19 7"/></svg>);
const IconClock = () => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>);
const IconWarn = () => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 9v4M12 17h.01M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>);
const IconShield = () => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3Z"/><path d="M9 12l2 2 4-4"/></svg>);
const IconX = () => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>);
const IconLock = () => (<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>);

function Actor() {
  return (
    <div className="actor">
      <div className="actor-avatar">
        <IconAgent />
        <span className="actor-verify"><IconCheck /></span>
      </div>
      <div className="actor-meta">
        <div className="actor-name">Claude Code</div>
        <div className="actor-sub"><span>mike's-macbook-pro</span><span className="actor-kind">Agent</span></div>
      </div>
    </div>
  );
}

function Argv() {
  return (
    <div className="argv">
      <span className="prompt">$</span>
      <span className="tok-cmd">git</span>{" "}
      <span className="tok-arg">push</span>{" "}
      <span className="tok-flag">--force</span>{" "}
      <span className="tok-arg">origin</span>{" "}
      <span className="tok-arg">main</span>
    </div>
  );
}

function Fingerprint() {
  return (
    <span className="fingerprint" title="This fingerprint binds your verdict to exactly what you see.">
      <IconLock />
      <span>fp&nbsp;<b>a1f3…9e2c</b></span>
    </span>
  );
}

function StatusBar() {
  return (
    <div className="phone-statusbar">
      <span>9:41</span>
      <span className="dots">
        <svg width="17" height="11" viewBox="0 0 17 11" fill="currentColor"><rect x="0" y="7" width="3" height="4" rx="1"/><rect x="4.5" y="5" width="3" height="6" rx="1"/><rect x="9" y="2.5" width="3" height="8.5" rx="1"/><rect x="13.5" y="0" width="3" height="11" rx="1"/></svg>
        <svg width="22" height="11" viewBox="0 0 22 11" fill="none" stroke="currentColor" strokeWidth="1"><rect x=".5" y=".5" width="18" height="10" rx="2.5"/><rect x="2" y="2" width="13" height="7" rx="1" fill="currentColor"/><path d="M20.5 4v3" strokeWidth="1.5" strokeLinecap="round"/></svg>
      </span>
    </div>
  );
}

// =================== DIRECTION A — Signed Receipt ===================
function HeroA() {
  return (
    <div className="phone theme-tag">
      <StatusBar />
      <div className="phone-body">
        <div className="hero-a" data-risk="critical">
          <div className="card">
            <div className="topbar">
              <Actor />
              <span className="pill-clock">
                <IconClock />
                <span className="countdown" data-low="true"><span className="t">1:28</span></span>
              </span>
            </div>
            <div>
              <div className="summary-lead" style={{marginBottom:"7px"}}>Approve this action</div>
              <div className="summary-text">Force-push to <code style={{fontFamily:"var(--font-mono)",fontSize:".82em"}}>main</code> — overwrites remote history</div>
            </div>
            <div className="code">
              <div className="code-label">Exact action — what you'll sign</div>
              <Argv />
              <div className="code-cwd"><span className="k">cwd</span><span>~/dev/allw</span></div>
            </div>
            <div className="divider" />
            <div className="meta-list">
              <div className="meta-line"><span className="meta-k">Risk</span><span className="risk-chip"><span className="risk-dot" />Critical</span></div>
              <div className="meta-line"><span className="meta-k">Reversible</span><span className="irrev"><IconWarn />Irreversible</span></div>
            </div>
            <div className="footnote">
              <Fingerprint />
            </div>
          </div>
          <div className="actions">
            <button className="btn btn-deny"><IconX />Deny</button>
            <button className="btn btn-approve"><IconCheck />Approve</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// =================== DIRECTION B — Confirmation slip (tactile) ===================
function Ring({ pct = 0.6, label = "1:28" }) {
  const r = 23, c = 2 * Math.PI * r;
  return (
    <div className="ring">
      <svg width="52" height="52" viewBox="0 0 52 52">
        <circle cx="26" cy="26" r={r} fill="none" stroke="var(--border)" strokeWidth="4" />
        <circle cx="26" cy="26" r={r} fill="none" stroke="var(--risk-crit-fg)" strokeWidth="4" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - pct)} />
      </svg>
      <span className="t">{label}</span>
    </div>
  );
}
function HeroB() {
  return (
    <div className="phone theme-tag">
      <StatusBar />
      <div className="phone-body">
        <div className="hero-b" data-risk="critical">
          <div className="slip">
            <div className="slip-head">
              <Actor />
              <div className="ring-wrap">
                <Ring pct={0.58} label="1:28" />
                <div className="ring-meta">
                  <span className="big" style={{color:"var(--risk-crit-fg)"}}>Expires in 1:28</span>
                  <span className="small">No response auto-denies · agent stays blocked</span>
                </div>
              </div>
            </div>
            <div className="perf"><span className="notch l" /><span className="notch r" /></div>
            <div className="slip-body">
              <div>
                <div className="summary-lead" style={{marginBottom:"6px"}}>Approve this action</div>
                <div className="summary-text">Force-push to <code style={{fontFamily:"var(--font-mono)",fontSize:".82em"}}>main</code> — overwrites remote history</div>
              </div>
              <div className="code">
                <div className="code-label">Exact action</div>
                <Argv />
                <div className="code-cwd"><span className="k">cwd</span><span>~/dev/allw</span></div>
              </div>
              <div className="meta-row">
                <span className="risk-chip"><span className="risk-dot" />Critical</span>
                <span className="irrev"><IconWarn />Irreversible</span>
              </div>
              <div className="seal">
                <div className="seal-left">
                  <span className="seal-icon"><IconShield /></span>
                  <div style={{display:"flex",flexDirection:"column",gap:"1px"}}>
                    <span style={{fontSize:"12px",fontWeight:600,color:"var(--ink)"}}>Verified &amp; encrypted</span>
                    <Fingerprint />
                  </div>
                </div>
              </div>
              <div className="actions">
                <button className="btn btn-deny"><IconX />Deny</button>
                <button className="btn btn-approve"><IconCheck />Approve</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// =================== DIRECTION C — Instrument panel ===================
function HeroC() {
  return (
    <div className="phone theme-tag">
      <StatusBar />
      <div className="phone-body">
        <div className="hero-c" data-risk="critical">
          <div className="panel">
            <div className="panel-head">
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:"12px"}}>
                <Actor />
                <span className="countdown" data-low="true"><span className="t">1:28</span><span className="lbl">left</span></span>
              </div>
              <div className="progress"><i style={{width:"58%"}} /></div>
            </div>
            <div className="code code-block">
              <div className="code-label">Exact action — what you'll sign</div>
              <Argv />
              <div className="code-cwd"><span className="k">cwd</span><span>~/dev/allw</span></div>
            </div>
            <div className="grid">
              <div className="cell full">
                <span className="cell-k">Summary</span>
                <span className="cell-v" style={{fontWeight:500,lineHeight:1.35}}>Force-push to main — overwrites remote history</span>
              </div>
              <div className="cell">
                <span className="cell-k">Risk</span>
                <span className="cell-v"><span className="risk-chip"><span className="risk-dot" />Critical</span></span>
              </div>
              <div className="cell">
                <span className="cell-k">Reversible</span>
                <span className="cell-v"><span className="tag-irrev">Irreversible</span></span>
              </div>
            </div>
            <div className="panel-foot">
              <Fingerprint />
              <span style={{display:"inline-flex",alignItems:"center",gap:"6px",fontSize:"11px",fontWeight:600,color:"var(--risk-low-fg)"}}>
                <span style={{width:"6px",height:"6px",borderRadius:"50%",background:"var(--risk-low-fg)"}} />E2E encrypted
              </span>
            </div>
          </div>
          <div className="actions">
            <button className="btn btn-deny"><IconX />Deny</button>
            <button className="btn btn-approve"><IconCheck />Approve</button>
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { HeroA, HeroB, HeroC });
