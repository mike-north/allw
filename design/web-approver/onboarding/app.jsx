/* app.jsx - allw web approver onboarding prototype for issue #94.
   This is a design artifact: state is local, but the copy and visual hierarchy are implementation
   guidance for packages/web-approver. */

const { useMemo, useState } = React;

const FLOW = [
  {
    id: "create",
    label: "Create account",
    caption: "Generate the user-owned account root.",
  },
  {
    id: "pair",
    label: "Pair device",
    caption: "Enter the CLI pairing code.",
  },
  {
    id: "returning",
    label: "Already paired",
    caption: "Recognize this browser and re-auth.",
  },
  {
    id: "empty",
    label: "First inbox",
    caption: "Land ready, with hook config.",
  },
];

function Icon({ name }) {
  const paths = {
    shield: <path d="M12 3l7 3v5c0 5-3 8.5-7 10-4-1.5-7-5-7-10V6l7-3z" />,
    key: <path d="M8.5 14.5a4 4 0 113-3L20 20h-3v-3h-3v-3l-2.5-2.5" />,
    link: (
      <path d="M10 13a5 5 0 007 0l2-2a5 5 0 00-7-7l-1 1M14 11a5 5 0 00-7 0l-2 2a5 5 0 007 7l1-1" />
    ),
    lock: <path d="M7 11V8a5 5 0 0110 0v3M6 11h12v9H6z" />,
    copy: <path d="M9 9h10v10H9zM5 15H4a1 1 0 01-1-1V5a1 1 0 011-1h9a1 1 0 011 1v1" />,
    arrow: <path d="M5 12h14M13 6l6 6-6 6" />,
    user: <path d="M20 21a8 8 0 10-16 0M12 11a4 4 0 100-8 4 4 0 000 8z" />,
  };
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name] || paths.shield}
    </svg>
  );
}

function Shell({ current, onSelect, children }) {
  return (
    <div className="stage theme-light">
      <div className="workspace">
        <aside className="rail">
          <div className="brand">
            <span className="brand-mark">
              <Icon name="shield" />
            </span>
            <span className="wordmark">allw</span>
          </div>
          <p className="rail-copy">
            A security-first setup journey from npm quickstart to the first pending approval.
          </p>
          <div className="steps" role="tablist" aria-label="Onboarding screens">
            {FLOW.map((step) => (
              <button
                key={step.id}
                className="step"
                type="button"
                role="tab"
                aria-current={current === step.id}
                onClick={() => onSelect(step.id)}
              >
                <span className="step-icon">
                  <Icon
                    name={
                      step.id === "create"
                        ? "key"
                        : step.id === "pair"
                          ? "link"
                          : step.id === "returning"
                            ? "lock"
                            : "shield"
                    }
                  />
                </span>
                <span>
                  <span className="step-label">{step.label}</span>
                  <span className="step-caption">{step.caption}</span>
                </span>
              </button>
            ))}
          </div>
          <p className="rail-note">
            Pairing is treated as a trust ceremony, not a signup funnel. Password language is
            avoided; the browser is trusted because it holds local keys.
          </p>
        </aside>
        <main className="canvas">{children}</main>
      </div>
    </div>
  );
}

function CreateAccount({ onNext }) {
  return (
    <section className="screen" aria-labelledby="create-title">
      <div className="main">
        <div>
          <span className="hero-kicker">
            <Icon name="key" />
            First-run account creation
          </span>
          <h1 id="create-title" className="headline">
            Your keys. Your approvals.
          </h1>
          <p className="subcopy">
            allw creates a user-owned account root on this device. There is no password-based
            account in the classic sense: recovery depends on the Recovery kit you save now.
          </p>
        </div>
        <div className="actions">
          <button className="btn btn-primary" type="button" onClick={onNext}>
            Generate account root <Icon name="arrow" />
          </button>
          <button className="btn btn-secondary" type="button">
            Import recovery kit
          </button>
        </div>
      </div>
      <aside className="panel">
        <img
          className="visual"
          src="trust-map.svg"
          alt="Diagram of local keys, pairing code, and encrypted approval requests"
        />
        <div className="recovery" aria-label="Recovery kit preview">
          <div className="recovery-item">
            <div className="item-label">Recovery kit</div>
            <div className="item-value">root-key.txt</div>
          </div>
          <div className="recovery-item">
            <div className="item-label">Identity</div>
            <div className="item-value">acct_7K9...</div>
          </div>
          <div className="recovery-item">
            <div className="item-label">Storage</div>
            <div className="item-value">browser only</div>
          </div>
        </div>
      </aside>
    </section>
  );
}

function PairDevice({ onNext }) {
  const code = ["K", "4", "P", "9", "Q", "X"];
  return (
    <section className="screen" aria-labelledby="pair-title">
      <div className="main">
        <div>
          <span className="hero-kicker">
            <Icon name="link" />
            Device pairing ceremony
          </span>
          <h1 id="pair-title" className="headline">
            Trust this browser.
          </h1>
          <p className="subcopy">
            Enter the Pairing code from the CLI quickstart. This grants the browser permission to
            decrypt pending requests and sign verdicts for this account.
          </p>
        </div>
        <div className="actions">
          <button className="btn btn-primary" type="button" onClick={onNext}>
            Pair browser <Icon name="arrow" />
          </button>
          <button className="btn btn-secondary" type="button">
            Scan QR code
          </button>
        </div>
      </div>
      <aside className="panel">
        <div className="code-grid" aria-label="Pairing code K4P-9QX">
          {code.slice(0, 3).map((char) => (
            <span className="code-cell" key={char}>
              {char}
            </span>
          ))}
          <span className="dash">-</span>
          {code.slice(3).map((char) => (
            <span className="code-cell" key={char}>
              {char}
            </span>
          ))}
        </div>
        <ul className="trust-list">
          <li>
            <span className="check">✓</span>
            <span>Device key is created locally before pairing.</span>
          </li>
          <li>
            <span className="check">✓</span>
            <span>Relay receives public key material and routing metadata only.</span>
          </li>
          <li>
            <span className="check">✓</span>
            <span>Approval context remains end-to-end encrypted.</span>
          </li>
        </ul>
      </aside>
    </section>
  );
}

function ReturningDevice({ onNext }) {
  return (
    <section className="screen" aria-labelledby="returning-title">
      <div className="main">
        <div>
          <span className="hero-kicker">
            <Icon name="lock" />
            Returning device login
          </span>
          <h1 id="returning-title" className="headline">
            Already paired.
          </h1>
          <p className="subcopy">
            The browser recognizes its local device key. Re-auth confirms a human is present before
            this device can decrypt a pending request or sign a verdict.
          </p>
        </div>
        <div className="actions">
          <button className="btn btn-primary" type="button" onClick={onNext}>
            Unlock inbox <Icon name="arrow" />
          </button>
          <button className="btn btn-secondary" type="button">
            Use another device
          </button>
        </div>
      </div>
      <aside className="panel">
        <div className="device-ticket">
          <div>
            <div className="device-title">Mike's MacBook Browser</div>
            <div className="device-meta">dev_web_8D4A · last seen 2m ago</div>
          </div>
          <span className="status-pill">verified</span>
        </div>
        <div className="evidence">
          <div className="evidence-row">
            <span className="check">✓</span>
            <span>
              <b>Local key found.</b> No password reset loop.
            </span>
          </div>
          <div className="evidence-row">
            <span className="check">✓</span>
            <span>
              <b>Account root anchored.</b> Origin checks use root-signed state.
            </span>
          </div>
          <div className="evidence-row">
            <span className="check">✓</span>
            <span>
              <b>Human re-auth required.</b> Signing still needs local confirmation.
            </span>
          </div>
        </div>
      </aside>
    </section>
  );
}

function EmptyState() {
  const [copyStatus, setCopyStatus] = useState("idle");
  const config = useMemo(
    () =>
      `{\n  "hooks": {\n    "PreToolUse": [{\n      "matcher": "Bash|apply_patch|mcp__.*",\n      "hooks": [{\n        "type": "command",\n        "command": "node ./node_modules/.bin/allw-codex-hook"\n      }]\n    }]\n  }\n}`,
    [],
  );
  async function copyConfig() {
    try {
      await navigator.clipboard?.writeText(config);
    } catch {
      // Design reviews often run from local files or preview servers where clipboard permission is denied.
    }
    setCopyStatus("copied");
    window.setTimeout(() => setCopyStatus("idle"), 1600);
  }
  return (
    <section className="screen" aria-labelledby="empty-title">
      <div className="main">
        <div>
          <span className="hero-kicker">
            <Icon name="shield" />
            Paired empty state
          </span>
          <h1 id="empty-title" className="headline">
            Ready for the first approval.
          </h1>
          <p className="subcopy">
            No requests yet. The copy hook config moment keeps the user in flow from setup to the
            first agent action without making the inbox feel empty or broken.
          </p>
        </div>
        <div className="actions">
          <button className="btn btn-primary" type="button" onClick={copyConfig}>
            {copyStatus === "copied" ? "copied" : "copy hook config"} <Icon name="copy" />
          </button>
          <button className="btn btn-secondary" type="button">
            Open setup docs
          </button>
        </div>
      </div>
      <aside className="panel">
        <div className="mini-inbox">
          <div>
            <span className="mini-shield">
              <Icon name="shield" />
            </span>
            <div className="empty-title">No pending approvals</div>
            <p className="empty-sub">
              Point your agent at this approver. Sensitive actions will pause here.
            </p>
          </div>
        </div>
        <div className="config">
          <div className="config-head">
            <span>Codex hook config</span>
            <button
              className="copy-icon"
              type="button"
              aria-label="Copy hook config snippet"
              onClick={copyConfig}
            >
              <Icon name="copy" />
            </button>
          </div>
          <pre>{config}</pre>
        </div>
      </aside>
    </section>
  );
}

function App() {
  const [screen, setScreen] = useState("create");
  const next = () => {
    const index = FLOW.findIndex((step) => step.id === screen);
    setScreen(FLOW[Math.min(FLOW.length - 1, index + 1)].id);
  };

  return (
    <Shell current={screen} onSelect={setScreen}>
      {screen === "create" && <CreateAccount onNext={next} />}
      {screen === "pair" && <PairDevice onNext={next} />}
      {screen === "returning" && <ReturningDevice onNext={next} />}
      {screen === "empty" && <EmptyState />}
    </Shell>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
