import { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000/api";

const fmtTime = (ts) => (ts ? new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "-");
const fmtDate = (ts) => (ts ? new Date(ts).toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" }) : "-");
const cls = (value) => String(value || "").toLowerCase().replaceAll("_", "-");

/* ---------------------------------------------------------------
   Inline icon set — outline style, currentColor, no icon library
   --------------------------------------------------------------- */

const IconAlert = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);
const IconPulse = () => (
  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="2 12 8 12 10 6 14 18 16 12 22 12" />
  </svg>
);
const IconLock = () => (
  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="4" y="10" width="16" height="10" rx="2" />
    <path d="M8 10V7a4 4 0 0 1 8 0v3" />
  </svg>
);
const IconHash = () => (
  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <line x1="4" y1="9" x2="20" y2="9" /><line x1="4" y1="15" x2="20" y2="15" />
    <line x1="10" y1="3" x2="8" y2="21" /><line x1="16" y1="3" x2="14" y2="21" />
  </svg>
);
const IconEye = () => (
  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z" /><circle cx="12" cy="12" r="3" />
  </svg>
);
const IconClock = () => (
  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="9" /><polyline points="12 7 12 12 16 14" />
  </svg>
);
const IconTag = () => (
  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20.59 13.41 12 22l-9-9 8.59-8.59A2 2 0 0 1 13 4h6a1 1 0 0 1 1 1v6a2 2 0 0 1-.41 1.41Z" />
    <circle cx="16.5" cy="7.5" r="1" />
  </svg>
);

const SPEC_ICONS = { Hashing: IconHash, "Watch mode": IconEye, "Correlation window": IconClock, Classification: IconTag };

const SPECS = [
  ["Hashing", "SHA-256"],
  ["Watch mode", "Watchdog (real-time)"],
  ["Correlation window", "30s temporal"],
  ["Classification", "Rule-based severity"],
];

/* ---------------------------------------------------------------
   Small data-driven visuals
   --------------------------------------------------------------- */

function Sparkline({ values, tone }) {
  const w = 220, h = 40, pad = 4;
  if (!values.length) {
    return <svg className={`sparkline ${tone ? `tone-${tone}` : ""}`} viewBox={`0 0 ${w} ${h}`} />;
  }
  const step = values.length > 1 ? (w - 2 * pad) / (values.length - 1) : 0;
  const points = values.map((v, i) => `${pad + i * step},${h - pad - (Math.min(100, v) / 100) * (h - 2 * pad)}`);
  const last = points[points.length - 1].split(",");
  return (
    <svg className={`sparkline ${tone ? `tone-${tone}` : ""}`} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polyline points={points.join(" ")} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={last[0]} cy={last[1]} r="3" fill="currentColor" />
    </svg>
  );
}

function ScanDial() {
  return (
    <div className="scan-dial">
      <svg viewBox="0 0 120 120" className="scan-dial-ring">
        <circle cx="60" cy="60" r="52" className="scan-dial-track" />
        <circle cx="60" cy="60" r="52" className="scan-dial-ticks" />
        <g className="scan-sweep">
          <line x1="60" y1="60" x2="60" y2="12" />
        </g>
      </svg>
      <div className="scan-dial-label">
        <strong>READY</strong>
        <span>Awaiting baseline</span>
      </div>
    </div>
  );
}

function App() {
  const [page, setPage] = useState("landing");
  const [status, setStatus] = useState(null);
  const [activity, setActivity] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [autoEnabled, setAutoEnabled] = useState(false);
  const [autoBusy, setAutoBusy] = useState(false);
  const [alertMessage, setAlertMessage] = useState("");
  const [clock, setClock] = useState(() => new Date());
  const audioContextRef = useRef(null);
  const lastAutoCheckRef = useRef(null);

  const loadDashboard = async () => {
    try {
      const [a, h, s] = await Promise.all([fetch(`${API}/activity`), fetch(`${API}/history`), fetch(`${API}/status`)]);
      if (!a.ok || !h.ok || !s.ok) throw new Error("Backend request failed");
      const ad = await a.json();
      const hd = await h.json();
      const sd = await s.json();
      setActivity(ad);
      setEvents(hd.events || []);
      setStatus(sd);
      setError("");
    } catch (e) {
      setError("Backend is not reachable. Start FastAPI and try again.");
    }
  };

  const playAlertSound = () => {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = audioContextRef.current || new AudioCtx();
      audioContextRef.current = ctx;
      if (ctx.state === "suspended") ctx.resume();
      const now = ctx.currentTime;
      [0, 0.18, 0.36].forEach((offset, index) => {
        const oscillator = ctx.createOscillator();
        const gain = ctx.createGain();
        oscillator.type = "square";
        oscillator.frequency.value = index % 2 ? 880 : 660;
        gain.gain.setValueAtTime(0.0001, now + offset);
        gain.gain.exponentialRampToValueAtTime(0.18, now + offset + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + offset + 0.14);
        oscillator.connect(gain);
        gain.connect(ctx.destination);
        oscillator.start(now + offset);
        oscillator.stop(now + offset + 0.15);
      });
    } catch (_) {}
  };

  useEffect(() => {
    if (page !== "dashboard") return;
    loadDashboard();
    const id = setInterval(loadDashboard, 2000);
    return () => clearInterval(id);
  }, [page]);

  useEffect(() => {
    if (page !== "dashboard") return;
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, [page]);

  useEffect(() => {
    if (!status) return;
    setAutoEnabled(Boolean(status.automatic_monitoring));
    const checkAt = status.last_auto_check_at;
    const newChanges = Number(status.last_auto_new_changes || 0);
    const risk = Number(status.last_auto_risk_score || 0);
    if (autoEnabled && checkAt && checkAt !== lastAutoCheckRef.current) {
      lastAutoCheckRef.current = checkAt;
      if (newChanges > 0 && risk > 50) {
        playAlertSound();
        setAlertMessage(`HIGH RISK: automatic integrity check found ${newChanges} new change${newChanges === 1 ? "" : "s"} (risk ${risk}/100).`);
        setTimeout(() => setAlertMessage(""), 7000);
      }
    } else if (checkAt) {
      lastAutoCheckRef.current = checkAt;
    }
  }, [status, autoEnabled]);

  const toggleAutomaticMonitoring = async () => {
    setAutoBusy(true);
    setError("");
    try {
      const endpoint = autoEnabled ? "/automatic/stop" : "/automatic/start";
      if (!autoEnabled) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) {
          audioContextRef.current = audioContextRef.current || new AudioCtx();
          if (audioContextRef.current.state === "suspended") await audioContextRef.current.resume();
        }
      }
      const response = await fetch(`${API}${endpoint}`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Unable to change automatic monitoring mode");
      setStatus(data);
      setAutoEnabled(Boolean(data.automatic_monitoring));
      setAlertMessage(data.automatic_monitoring ? "Automatic integrity monitoring enabled. Full SHA-256 verification runs every 5 minutes." : "Automatic integrity monitoring disabled.");
      setTimeout(() => setAlertMessage(""), 5000);
    } catch (e) {
      setError(e.message || "Unable to change automatic monitoring mode");
    } finally {
      setAutoBusy(false);
    }
  };

  const startTool = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`${API}/start`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Unable to start monitor");
      setStatus(data);
      setPage("dashboard");
    } catch (e) {
      setError(e.message || "Unable to start the tool");
    } finally {
      setLoading(false);
    }
  };

  const stopTool = async () => {
    await fetch(`${API}/stop`, { method: "POST" });
    await loadDashboard();
  };

  const correlation = activity?.correlation || { risk_score: 0, classification: "NORMAL", activity: "NO_ACTIVITY", reason: "No file activity detected.", event_count: 0, distinct_files: 0, types: [] };
  const latest = activity?.latest_event || events[0];

  const counts = useMemo(
    () => ({
      total: events.length,
      critical: events.filter((e) => e.severity === "CRITICAL").length,
      high: events.filter((e) => Number(e.risk_score) >= 50).length,
      modified: events.filter((e) => e.type === "MODIFIED").length,
    }),
    [events]
  );

  const trend = useMemo(() => events.slice(0, 20).map((e) => Number(e.risk_score) || 0).reverse(), [events]);

  if (page === "landing") {
    return (
      <main className="landing">
        <div className="grid-glow" />
        <div className="landing-shell">
          <div className="landing-main">
            <div className="brand-mark">3301</div>
            <div className="eyebrow"><span className="dot" /> Cybersecurity / File Integrity</div>
            <h1>File Integrity Detection Console</h1>
            <p>
              Baseline every trusted file with SHA-256, watch the filesystem in real time, and let the correlation
              engine turn raw events into a single defensible risk score.
            </p>
            <button className="start-button" onClick={startTool} disabled={loading}>
              {loading ? "Initializing baseline..." : "Start tool"}
            </button>
            {error && <div className="landing-error">{error}</div>}
            <div className="landing-note">
              Starting the tool creates a fresh trusted baseline from the current contents of the monitored folder.
              Any file already inside it becomes the reference every future change is measured against.
            </div>
          </div>
          <div className="landing-specs">
            <ScanDial />
            <h2>System configuration</h2>
            {SPECS.map(([label, value]) => {
              const Icon = SPEC_ICONS[label];
              return (
                <div className="spec-row" key={label}>
                  <span>{Icon && <Icon />}{label}</span>
                  <span>{value}</span>
                </div>
              );
            })}
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span>3301</span>
          <div>
            <strong>File Integrity</strong>
            <small>Detection &amp; response console</small>
          </div>
        </div>
        <div className="top-actions">
          <div className="status-clock mono">{clock.toLocaleTimeString([], { hour12: false })}</div>
          <div className={`live-pill ${status?.running ? "on" : "off"}`}>
            <i /> {status?.running ? "Monitoring active" : "Monitor stopped"}
          </div>
          <button className={`auto-monitor-toggle ${autoEnabled ? "active" : ""}`} onClick={toggleAutomaticMonitoring} disabled={autoBusy || !status?.running}>
            <IconLock />
            {autoBusy ? "Starting..." : autoEnabled ? "Auto integrity: on" : "Start automatic integrity monitoring"}
          </button>
          <button className="outline-button" onClick={stopTool}>Stop</button>
          <button className="outline-button" onClick={() => setPage("landing")}>New baseline</button>
        </div>
      </header>

      {alertMessage && (
        <div className="security-alert">
          <span className="alert-icon"><IconAlert /></span>
          <div>
            <strong>Security alert</strong>
            <small>{alertMessage}</small>
          </div>
        </div>
      )}

      <section className="hero-row">
        <div>
          <div className="eyebrow"><span className="dot" /> Security operations dashboard</div>
          <h1>Integrity command center</h1>
          <p>Trusted baseline &rarr; real-time events &rarr; correlation &rarr; classification &rarr; risk score.</p>
        </div>
        <div className="baseline-card">
          <span>Baseline files</span>
          <strong>{status?.baseline_file_count ?? 0}</strong>
          <small>{status?.baseline_created_at ? `Created ${fmtDate(status.baseline_created_at)} ${fmtTime(status.baseline_created_at)}` : "Not initialized"}</small>
        </div>
      </section>

      <section className="metric-grid">
        <Metric label="Overall risk" value={correlation.risk_score} suffix="/100" tone={cls(correlation.classification)} />
        <Metric label="Classification" value={correlation.classification} tone={cls(correlation.classification)} compact />
        <Metric label="Correlated events" value={correlation.event_count} />
        <Metric label="Affected files" value={correlation.distinct_files} />
      </section>

      <section className="dashboard-grid">
        <div className="panel risk-panel">
          <div className="panel-head">
            <div>
              <span className="section-kicker">Correlation engine</span>
              <h2>Overall risk assessment</h2>
            </div>
            <span className={`classification ${cls(correlation.classification)}`}>{correlation.classification}</span>
          </div>
          <div className="risk-main">
            <div className={`risk-ring ${cls(correlation.classification)}`} style={{ "--score": `${correlation.risk_score}%` }}>
              <strong>{correlation.risk_score}</strong>
              <span>Risk</span>
            </div>
            <div className="risk-copy">
              <h3>{correlation.activity}</h3>
              <p>{correlation.reason}</p>
              <div className="signal-list">
                <Signal label="Temporal window" value={`${correlation.window_seconds}s`} />
                <Signal label="Event types" value={correlation.types?.join(", ") || "None"} />
                <Signal label="Correlation group" value={correlation.correlation_group || "\u2014"} />
              </div>
            </div>
          </div>
          <div className="risk-trend">
            <div className="risk-trend-head">
              <span>Risk trend &middot; last {trend.length || 0} events</span>
              <span className={`mono tone-${cls(correlation.classification)}`}>{trend.length ? `${trend[trend.length - 1]}/100` : "\u2014"}</span>
            </div>
            <Sparkline values={trend} tone={cls(correlation.classification)} />
          </div>
          <div className="method-box">
            <strong>Correlation technique</strong>
            <span>Temporal burst + event diversity + sensitive-path detection + destructive-event weighting + distinct-file count.</span>
          </div>
        </div>

        <div className="panel current-panel">
          <div className="panel-head">
            <div>
              <span className="section-kicker">Live event</span>
              <h2>Current activity</h2>
            </div>
            <span className="live-text"><IconPulse /> Live</span>
          </div>
          {latest ? (
            <div className="event-focus">
              <div className="badge-row">
                <span className={`event-badge ${cls(latest.type)}`}>{latest.type}</span>
                <span className={`classification ${cls(latest.classification || latest.severity)}`}>{latest.classification || latest.severity}</span>
              </div>
              <h3>{latest.file}</h3>
              <div className="event-facts">
                <Fact label="Detected" value={`${fmtDate(latest.timestamp)} ${fmtTime(latest.timestamp)}`} />
                <Fact label="Severity" value={latest.severity} />
                <Fact label="Risk" value={`${latest.risk_score}/100`} />
                <Fact label="Incident" value={latest.incident_id} />
              </div>
            </div>
          ) : (
            <Empty text="Waiting for a file event..." />
          )}
        </div>
      </section>

      <section className="summary-strip">
        <Stat label="Total events" value={counts.total} />
        <Stat label="Critical" value={counts.critical} tone="critical" />
        <Stat label="High risk" value={counts.high} tone="high-risk" />
        <Stat label="Modified files" value={counts.modified} />
      </section>

      <section className="panel history-panel">
        <div className="panel-head">
          <div>
            <span className="section-kicker">Forensic stream</span>
            <h2>Activity timeline</h2>
          </div>
          <span className="muted">Auto-refresh: 2s</span>
        </div>
        {events.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>File</th>
                  <th>Classification</th>
                  <th>Severity</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 20).map((e) => (
                  <tr key={e.id} className={e.severity === "CRITICAL" ? "row-critical" : ""}>
                    <td className="mono">{fmtTime(e.timestamp)}</td>
                    <td><span className={`event-badge ${cls(e.type)}`}>{e.type}</span></td>
                    <td className="file-cell">{e.file}</td>
                    <td><span className={`classification ${cls(e.classification || e.severity)}`}>{e.classification || e.severity}</span></td>
                    <td>{e.severity}</td>
                    <td className="risk-number">{e.risk_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty text="No changes detected since the baseline was created." />
        )}
      </section>

      <section className="panel automatic-panel">
        <div className="panel-head">
          <div>
            <span className="section-kicker">Automatic verification</span>
            <h2>Periodic integrity monitoring</h2>
          </div>
          <span className={`classification ${autoEnabled ? "normal" : "suspicious"}`}>{autoEnabled ? "Active" : "Off"}</span>
        </div>
        <div className="auto-grid">
          <div><span>Verification interval</span><strong>5 minutes</strong></div>
          <div><span>Last verification</span><strong>{status?.last_auto_check_at ? `${fmtDate(status.last_auto_check_at)} ${fmtTime(status.last_auto_check_at)}` : "Not run"}</strong></div>
          <div><span>Next verification</span><strong>{status?.next_auto_check_at ? `${fmtDate(status.next_auto_check_at)} ${fmtTime(status.next_auto_check_at)}` : "\u2014"}</strong></div>
          <div><span>Last verification risk</span><strong>{status?.last_auto_risk_score ?? 0}/100</strong></div>
          <div><span>New changes found</span><strong>{status?.last_auto_new_changes ?? 0}</strong></div>
          <div><span>Sound alert threshold</span><strong>&gt; 50 risk</strong></div>
        </div>
        <div className="auto-note">
          Automatic mode performs a complete SHA-256 comparison against the trusted baseline. New deviations above
          risk 50 trigger a visual alert and audible warning.
        </div>
      </section>

      <footer>
        <span>3301 FIM</span>
        <span>SHA-256 &middot; Watchdog &middot; Correlation &middot; Classification</span>
        <span>{status?.monitored_directory}</span>
      </footer>
    </main>
  );
}

function Metric({ label, value, suffix, tone, compact }) {
  return (
    <div className={`metric-card ${tone ? `metric-card--${tone}` : ""}`}>
      <span>{label}</span>
      <strong className={tone ? `tone-${tone}` : ""}>
        {value}
        {suffix && <em>{suffix}</em>}
      </strong>
      {compact && <small>Rule-based security classification</small>}
    </div>
  );
}
function Signal({ label, value }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
function Fact({ label, value }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
function Stat({ label, value, tone }) {
  return (
    <div className={tone ? `stat--${tone}` : ""}>
      <span>{label}</span>
      <strong className={tone ? `tone-${tone}` : ""}>{value}</strong>
    </div>
  );
}
function Empty({ text }) {
  return <div className="empty">{text}</div>;
}

export default App;
