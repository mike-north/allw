/* app.jsx — root state machine, countdown ticker, transitions, tweaks */

const { useState: useStateA, useEffect: useEffectA, useRef: useRefA, useCallback } = React;

const ACCENT_OPTS = ["#4E6BFF", "#6E86FF", "#7C5CFF", "#12A594"];

function hexToRgb(h) {
  h = h.replace("#", "");
  return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
}
function rgba(h, a) { const [r, g, b] = hexToRgb(h); return `rgba(${r},${g},${b},${a})`; }
function shift(h, amt) {
  const [r, g, b] = hexToRgb(h).map((c) => Math.max(0, Math.min(255, c + amt)));
  return `rgb(${r},${g},${b})`;
}
function luminance(h) { const [r, g, b] = hexToRgb(h); return (0.299 * r + 0.587 * g + 0.114 * b) / 255; }

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "theme": "dark",
  "accent": "#4E6BFF",
  "density": "regular",
  "verdict": "rg"
}/*EDITMODE-END*/;

function nowTime() {
  const d = new Date();
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [paired, setPaired] = useStateA(() => localStorage.getItem("allw_paired") === "1");
  const [requests, setRequests] = useStateA(() => {
    const base = makeRequests();
    const start = Date.now();
    return base.map((r) => ({ ...r, status: "pending", expiresAt: start + r.durationMs }));
  });
  const [route, setRoute] = useStateA({ screen: paired ? "inbox" : "pairing", reqId: null });
  const [now, setNow] = useStateA(Date.now());
  const [confirmData, setConfirmData] = useStateA(null);

  // ticker
  useEffectA(() => {
    const id = setInterval(() => setNow(Date.now()), 400);
    return () => clearInterval(id);
  }, []);

  const routeRef = useRefA(route);
  routeRef.current = route;

  // auto-expire pending requests (fail-closed)
  useEffectA(() => {
    setRequests((prev) => {
      let changed = false;
      const next = prev.map((r) => {
        if (r.status === "pending" && r.expiresAt <= now) {
          changed = true;
          return { ...r, status: "expired" };
        }
        return r;
      });
      if (!changed) return prev;
      // if the user is viewing an expired request, surface fail-closed
      const cur = routeRef.current;
      if ((cur.screen === "detail" || cur.screen === "challenge") && cur.reqId) {
        const exp = next.find((r) => r.id === cur.reqId && r.status === "expired");
        if (exp) setRoute({ screen: "expired", reqId: exp.id });
      }
      return next;
    });
  }, [now]);

  const getReq = (id) => requests.find((r) => r.id === id);

  const open = (id) => setRoute({ screen: "detail", reqId: id });
  const back = () => setRoute({ screen: "inbox", reqId: null });

  const decide = (id, verdict) => {
    setRequests((prev) => prev.map((r) => (r.id === id ? { ...r, status: verdict } : r)));
    setConfirmData({ reqId: id, verdict, time: nowTime() });
    setRoute({ screen: "confirm", reqId: id });
  };

  const onApprove = (id) => {
    const r = getReq(id);
    if (r.challenge) setRoute({ screen: "challenge", reqId: id });
    else decide(id, "approved");
  };

  const finishConfirm = () => { setConfirmData(null); back(); };

  const pairingDone = () => {
    localStorage.setItem("allw_paired", "1");
    setPaired(true);
    setRoute({ screen: "inbox", reqId: null });
  };

  // demo helpers via tweak buttons
  const resetDemo = () => {
    localStorage.removeItem("allw_paired");
    setPaired(false);
    const start = Date.now();
    setRequests(makeRequests().map((r) => ({ ...r, status: "pending", expiresAt: start + r.durationMs })));
    setConfirmData(null);
    setRoute({ screen: "pairing", reqId: null });
  };
  const expireOpen = () => {
    const cur = routeRef.current;
    const id = cur.reqId;
    if (!id) return;
    setRequests((prev) => prev.map((r) => (r.id === id ? { ...r, expiresAt: Date.now() - 1 } : r)));
  };

  // accent vars
  const acc = t.accent || "#4E6BFF";
  const isLight = t.theme === "light";
  const accentInk = luminance(acc) > 0.62 ? "#0A0A0A" : "#FFFFFF";
  const appStyle = {
    "--accent": acc,
    "--accent-press": isLight ? shift(acc, -22) : shift(acc, 26),
    "--accent-soft": rgba(acc, isLight ? 0.10 : 0.20),
    "--accent-ink": accentInk,
  };

  const cur = route;
  const req = getReq(cur.reqId);

  return (
    <div className={"stage theme-" + t.theme}>
      <aside className="aside">
        <div className="brand">
          <span className="aside-logo"><I.shield /></span>
          <span className="wordmark">allw</span>
        </div>
        <p className="tagline">Human-in-the-loop approval for AI agents. When an agent needs to do something sensitive, it pauses and asks you — here.</p>
        <div className="principles">
          <div className="principle"><span className="pi"><I.eye /></span><div><div className="pt">What you see is what you sign</div><div className="ps">The exact action is the security boundary.</div></div></div>
          <div className="principle"><span className="pi"><I.clock /></span><div><div className="pt">Fail-closed</div><div className="ps">No response auto-denies. Silence means no.</div></div></div>
          <div className="principle"><span className="pi"><I.lock /></span><div><div className="pt">End-to-end encrypted</div><div className="ps">Even allw can't read these requests.</div></div></div>
        </div>
      </aside>

      <div className={"app density-" + t.density} style={appStyle} data-verdict={t.verdict}>
        <div className="statusbar">
          <span>{nowTime()}</span>
          <span className="right">
            <svg width="18" height="12" viewBox="0 0 18 12" fill="currentColor"><rect x="0" y="8" width="3" height="4" rx="1"/><rect x="5" y="5.5" width="3" height="6.5" rx="1"/><rect x="10" y="3" width="3" height="9" rx="1"/><rect x="15" y="0" width="3" height="12" rx="1"/></svg>
            <svg width="24" height="12" viewBox="0 0 24 12" fill="none" stroke="currentColor" strokeWidth="1"><rect x=".5" y=".5" width="20" height="11" rx="3"/><rect x="2" y="2" width="15" height="8" rx="1.5" fill="currentColor"/><path d="M22.5 4.5v3" strokeWidth="1.6" strokeLinecap="round"/></svg>
          </span>
        </div>

        <div className="screen-wrap">
          {cur.screen === "pairing" && <PairingScreen key="pair" onPaired={pairingDone} />}
          {cur.screen === "inbox" && <InboxScreen key="inbox" requests={requests} now={now} onOpen={open} />}
          {cur.screen === "detail" && req && (
            <DetailScreen key={"d" + req.id} req={req} now={now}
              onApprove={() => onApprove(req.id)} onDeny={() => decide(req.id, "denied")} back={back} />
          )}
          {cur.screen === "challenge" && req && (
            <ChallengeScreen key={"c" + req.id} req={req} now={now}
              onVerified={() => decide(req.id, "approved")} back={() => setRoute({ screen: "detail", reqId: req.id })} />
          )}
          {cur.screen === "confirm" && req && confirmData && (
            <ConfirmScreen key="confirm" req={req} verdict={confirmData.verdict} time={confirmData.time} onDone={finishConfirm} />
          )}
          {cur.screen === "expired" && req && <ExpiredScreen key="exp" req={req} onDone={back} />}
        </div>
      </div>

      <TweaksPanel>
        <TweakSection label="Appearance" />
        <TweakRadio label="Theme" value={t.theme} options={["dark", "light"]} onChange={(v) => setTweak("theme", v)} />
        <TweakColor label="Accent" value={t.accent} options={ACCENT_OPTS} onChange={(v) => setTweak("accent", v)} />
        <TweakRadio label="Density" value={t.density} options={["compact", "regular", "comfy"]} onChange={(v) => setTweak("density", v)} />
        <TweakSelect label="Verdict colors" value={t.verdict} options={[{value:"brand",label:"Brand blue"},{value:"rgdeny",label:"Red deny"},{value:"rg",label:"Red / green"}]} onChange={(v) => setTweak("verdict", v)} />
        <TweakSection label="Demo" />
        <TweakButton label="Force-expire open request" onClick={expireOpen} />
        <TweakButton label="Restart demo (re-pair)" onClick={resetDemo} />
      </TweaksPanel>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
