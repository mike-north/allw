/* icons.jsx — icon set + shared display atoms used across screens */

const I = {
  agent: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 7V4"/><circle cx="12" cy="3.2" r="1.1"/><circle cx="9" cy="13" r="1.2" fill="currentColor" stroke="none"/><circle cx="15" cy="13" r="1.2" fill="currentColor" stroke="none"/><path d="M9.5 16.2h5"/></svg>),
  check: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12l4.5 4.5L19 7"/></svg>),
  checkThin: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12l4.5 4.5L19 7"/></svg>),
  clock: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>),
  warn: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 9v4M12 17h.01M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>),
  shield: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3Z"/><path d="M9 12l2 2 4-4"/></svg>),
  shieldLock: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3Z"/></svg>),
  x: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>),
  lock: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>),
  chevL: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 5l-7 7 7 7"/></svg>),
  chevR: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 5l7 7-7 7"/></svg>),
  arrowDown: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 5v14M6 13l6 6 6-6"/></svg>),
  qr: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 14h3v3M21 14v.01M21 21v-4M14 21h3"/></svg>),
  delete: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 5 6M9.5 6V4.5a1.5 1.5 0 0 1 1.5-1.5h2a1.5 1.5 0 0 1 1.5 1.5V6M6.5 6l.7 12a2 2 0 0 0 2 1.9h5.6a2 2 0 0 0 2-1.9l.7-12"/></svg>),
  trash: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 5 6M9.5 6V4.5a1.5 1.5 0 0 1 1.5-1.5h2a1.5 1.5 0 0 1 1.5 1.5V6M6.5 6l.7 12a2 2 0 0 0 2 1.9h5.6a2 2 0 0 0 2-1.9l.7-12"/></svg>),
  terminal: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M7 9l3 2.5L7 14M13 15h4"/></svg>),
  hash: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 4 7 20M17 4l-2 16M5 9h14M4 15h14"/></svg>),
  fp: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a8 8 0 0 1 8 8c0 1.5-.2 2.8-.5 4M5 18c-.6-1.3-1-2.9-1-4.5a8 8 0 0 1 .8-3.5"/><path d="M8 19.5C7 17.5 6.5 15 6.5 13a5.5 5.5 0 0 1 11 0c0 1-.1 2-.3 3"/><path d="M12 13c0 3 .5 5 1.5 7"/><path d="M9.5 21c-.5-1.5-1-3.5-1-5.5a3.5 3.5 0 0 1 7 0"/></svg>),
  device: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>),
  eye: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>),
  expand: (p) => (<svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M8 3H4v4M16 3h4v4M8 21H4v-4M16 21h4v-4"/></svg>),
};

// verified actor badge
function Actor({ actor, sub, kind = "Agent" }) {
  return (
    <div className="actor">
      <div className="actor-avatar">
        <I.agent />
        <span className="actor-verify"><I.check /></span>
      </div>
      <div className="actor-meta">
        <div className="actor-name">{actor}</div>
        <div className="actor-sub">
          <span>{sub}</span>
          <span className="actor-kind">{kind}</span>
        </div>
      </div>
    </div>
  );
}

// argv / tool-call renderer with syntax tokens
function ActionCode({ req, label = "Exact action — what you'll sign", expandable, expanded, onToggle }) {
  let body;
  if (req.action.type === "command") {
    const [cmd, ...rest] = req.action.argv;
    body = (
      <React.Fragment>
        <div className="argv">
          <span className="prompt">$</span>
          <span className="tok-cmd">{cmd}</span>{" "}
          {rest.map((a, i) => (
            <React.Fragment key={i}>
              <span className={a.startsWith("-") ? "tok-flag" : "tok-arg"}>{a}</span>
              {i < rest.length - 1 ? " " : ""}
            </React.Fragment>
          ))}
        </div>
        {req.action.cwd && (
          <div className="code-cwd"><span className="k">cwd</span><span>{req.action.cwd}</span></div>
        )}
      </React.Fragment>
    );
  } else {
    const params = req.action.params || {};
    const keys = Object.keys(params);
    body = (
      <React.Fragment>
        <div className="argv">
          <span className="tok-cmd">{req.action.tool}</span>
          <span className="tok-punct"> {"{"}</span>
          {keys.map((k, i) => (
            <div key={k} style={{ paddingLeft: "18px" }}>
              <span className="tok-key">{k}</span>
              <span className="tok-punct">: </span>
              <span className="tok-str">"{String(params[k])}"</span>
              {i < keys.length - 1 ? <span className="tok-punct">,</span> : ""}
            </div>
          ))}
          <span className="tok-punct">{"}"}</span>
        </div>
        {req.action.via && (
          <div className="code-cwd"><span className="k">via</span><span>{req.action.via}</span></div>
        )}
      </React.Fragment>
    );
  }
  return (
    <div className="code">
      <div className="code-label">
        {label}
        {expandable && (
          <button className="exp" onClick={onToggle}>
            <I.eye />{expanded ? "collapse" : "verify full"}
          </button>
        )}
      </div>
      {body}
    </div>
  );
}

function RiskChip({ risk, sm }) {
  const labels = { low: "Low", medium: "Medium", high: "High", critical: "Critical" };
  return (
    <span className={"risk-chip" + (sm ? " sm" : "")}>
      <span className="risk-dot" />{labels[risk]}
    </span>
  );
}

function Reversibility({ reversible }) {
  return reversible ? (
    <span className="reversible"><I.check />Reversible</span>
  ) : (
    <span className="irrev"><I.warn />Irreversible</span>
  );
}

function Fingerprint({ fp }) {
  return (
    <span className="fingerprint">
      <I.lock />
      <span>fp&nbsp;<b>{fp}</b></span>
      <span className="tip">This fingerprint binds your verdict to exactly what you see — nothing else can be signed in its place.</span>
    </span>
  );
}

// mm:ss formatter
function fmt(ms) {
  if (ms <= 0) return "0:00";
  const s = Math.ceil(ms / 1000);
  const m = Math.floor(s / 60);
  const r = s % 60;
  return m + ":" + String(r).padStart(2, "0");
}

Object.assign(window, { I, Actor, ActionCode, RiskChip, Reversibility, Fingerprint, fmt });
