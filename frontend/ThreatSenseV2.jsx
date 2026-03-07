import { useState, useRef, useCallback, useEffect } from "react";

const API_BASE = "http://localhost:8000";

const G = {
  bg: "#09090b",
  surface: "#0f0f11",
  card: "#141418",
  border: "#1f1f23",
  borderHover: "#2e2e35",
  muted: "#52525b",
  mutedFg: "#71717a",
  text: "#e4e4e7",
  textDim: "#a1a1aa",
  accent: "#e4e4e7",
  blue: "#3b82f6",
  red: "#ef4444",
  orange: "#f97316",
  amber: "#f59e0b",
  green: "#22c55e",
  purple: "#a855f7",
};

const SEV = {
  CRITICAL: { color: G.red, bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.2)" },
  HIGH: { color: G.orange, bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.2)" },
  MEDIUM: { color: G.amber, bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.2)" },
  LOW: { color: G.green, bg: "rgba(34,197,94,0.08)", border: "rgba(34,197,94,0.2)" },
  BENIGN: { color: G.blue, bg: "rgba(59,130,246,0.08)", border: "rgba(59,130,246,0.2)" },
  UNKNOWN: { color: G.mutedFg, bg: "rgba(113,113,122,0.08)", border: "rgba(113,113,122,0.2)" },
};

const css = `
@import url('https://fonts.googleapis.com/css2?family=Geist+Mono:wght@300;400;500&family=Instrument+Serif:ital@0;1&family=Geist:wght@300;400;500;600&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { -webkit-font-smoothing: antialiased; }
body { background: ${G.bg}; color: ${G.text}; font-family: 'Geist', sans-serif; font-size: 14px; line-height: 1.5; }
::-webkit-scrollbar { width: 3px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: ${G.border}; }
button { cursor: pointer; font-family: inherit; border: none; background: none; }
input { font-family: inherit; }

@keyframes fadeIn   { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }
@keyframes slideUp  { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
@keyframes spin     { to { transform:rotate(360deg); } }
@keyframes pulse2   { 0%,100% { opacity:1; } 50% { opacity:.4; } }
@keyframes shimmer  { from { background-position: -200% 0; } to { background-position: 200% 0; } }
@keyframes expand   { from { width:0; } to { width:var(--w); } }

.fade-in  { animation: fadeIn  .35s ease both; }
.slide-up { animation: slideUp .4s  ease both; }
.spin     { animation: spin 1.2s linear infinite; }
.pulse2   { animation: pulse2 2s ease-in-out infinite; }

.mono { font-family: 'Geist Mono', monospace; }
.serif { font-family: 'Instrument Serif', serif; }

/* Divider */
.divider { height: 1px; background: ${G.border}; }

/* Ghost button */
.btn-ghost {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 14px; border-radius: 6px;
  font-size: 13px; font-weight: 500; color: ${G.textDim};
  border: 1px solid ${G.border};
  transition: all .15s;
}
.btn-ghost:hover { color: ${G.text}; border-color: ${G.borderHover}; background: rgba(255,255,255,.03); }

/* Primary button */
.btn-primary {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 16px; border-radius: 6px;
  font-size: 13px; font-weight: 500;
  color: ${G.bg}; background: ${G.text};
  transition: all .15s;
}
.btn-primary:hover { background: ${G.textDim}; }

/* Outline button */
.btn-outline {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 14px; border-radius: 6px;
  font-size: 13px; font-weight: 500; color: ${G.text};
  border: 1px solid ${G.border};
  transition: all .15s;
}
.btn-outline:hover { border-color: ${G.borderHover}; background: rgba(255,255,255,.03); }

/* Card */
.card {
  background: ${G.card}; border: 1px solid ${G.border}; border-radius: 10px;
  transition: border-color .15s;
}
.card:hover { border-color: ${G.borderHover}; }

/* Badge */
.badge {
  display: inline-flex; align-items: center;
  padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 500; letter-spacing: .3px;
  font-family: 'Geist Mono', monospace;
  border: 1px solid;
}

/* Tag */
.tag {
  display: inline-flex; align-items: center;
  padding: 1px 7px; border-radius: 4px;
  font-size: 11px; color: ${G.mutedFg};
  border: 1px solid ${G.border};
  font-family: 'Geist Mono', monospace;
}

/* Step indicator */
.step-dot {
  width: 20px; height: 20px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 10px; font-weight: 600; flex-shrink: 0;
  font-family: 'Geist Mono', monospace;
  transition: all .3s;
}

/* Progress track */
.progress-track {
  height: 2px; background: ${G.border}; border-radius: 1px; overflow: hidden;
}
.progress-fill {
  height: 100%; border-radius: 1px;
  transition: width .6s cubic-bezier(.4,0,.2,1);
}

/* File drop area */
.dropzone {
  border: 1px dashed ${G.border}; border-radius: 10px;
  transition: all .2s; cursor: pointer; position: relative;
}
.dropzone.hovered {
  border-color: ${G.borderHover};
  background: rgba(255,255,255,.02);
}
.dropzone.dragging {
  border-color: rgba(255,255,255,.25);
  background: rgba(255,255,255,.03);
}

/* Separator dot */
.sep::before { content:'·'; margin: 0 6px; color: ${G.muted}; }

/* Modal */
.overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,.75);
  backdrop-filter: blur(12px); z-index: 200;
  display: flex; align-items: center; justify-content: center;
  padding: 24px;
  animation: fadeIn .2s ease;
}
.modal {
  width: 100%; max-width: 480px; max-height: 90vh;
  background: ${G.card}; border: 1px solid ${G.borderHover};
  border-radius: 14px; overflow: hidden;
  animation: slideUp .25s ease;
  box-shadow: 0 24px 60px rgba(0,0,0,.6), 0 0 0 1px rgba(255,255,255,.04);
}
.modal-lg { max-width: 680px; }

/* Nav */
.nav {
  height: 52px; border-bottom: 1px solid ${G.border};
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 24px; position: sticky; top: 0; z-index: 100;
  background: rgba(9,9,11,.85); backdrop-filter: blur(16px);
}

/* Feature pill */
.feature-pill {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 14px; border-radius: 8px;
  border: 1px solid ${G.border};
  background: ${G.card};
  font-size: 12px; color: ${G.textDim};
  transition: all .15s;
}
.feature-pill:hover { border-color: ${G.borderHover}; color: ${G.text}; }
.feature-pill .dot { width:6px; height:6px; border-radius:50%; flex-shrink:0; }

/* Kbd */
.kbd {
  display: inline-flex; align-items: center;
  padding: 1px 5px; border-radius: 3px;
  font-size: 10px; font-family: 'Geist Mono', monospace;
  color: ${G.mutedFg}; border: 1px solid ${G.border};
  background: rgba(255,255,255,.03);
}

/* Table row */
.table-row {
  display: grid; gap: 12px; padding: 10px 0;
  border-bottom: 1px solid ${G.border};
  align-items: center;
}
.table-row:last-child { border-bottom: none; }
`;

// ─────────────────────────────────────────────
// Tiny icon components
// ─────────────────────────────────────────────
const Icon = ({ d, size = 16, stroke = G.mutedFg }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);

const Icons = {
  Upload: () => <Icon d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" />,
  Shield: () => <Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
  X: () => <Icon d="M18 6L6 18M6 6l12 12" />,
  ChevR: () => <Icon d="M9 18l6-6-6-6" />,
  Check: (p) => <Icon d="M20 6L9 17l-5-5" stroke={p.c || G.green} />,
  Cpu: () => <Icon d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />,
  File: () => <Icon d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />,
  Zap: () => <Icon d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />,
  Link: () => <Icon d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" />,
  Eye: () => <Icon d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 9a3 3 0 100 6 3 3 0 000-6z" />,
  Download: () => <Icon d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3" />,
  Info: () => <Icon d="M12 16v-4M12 8h.01M22 12c0 5.523-4.477 10-10 10S2 17.523 2 12 6.477 2 12 2s10 4.477 10 10z" />,
  Globe: () => <Icon d="M12 2a10 10 0 100 20A10 10 0 0012 2zM2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20" />,
  Lock: () => <Icon d="M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zM7 11V7a5 5 0 0110 0v4" />,
  Clock: () => <Icon d="M12 2a10 10 0 100 20 10 10 0 000-20zM12 6v6l4 2" />,
  Spinner: () => (
    <svg className="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={G.mutedFg} strokeWidth="2" strokeLinecap="round">
      <path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke="rgba(255,255,255,.1)" />
      <path d="M21 12a9 9 0 00-9-9" />
    </svg>
  ),
};

// ─────────────────────────────────────────────
// About modal (unchanged)
// ─────────────────────────────────────────────
function AboutModal({ onClose }) {
  const pipeline = [
    { n: "01", title: "Upload", desc: "Drop any executable or script file into the analyzer." },
    { n: "02", title: "Hash & Detect", desc: "SHA256 fingerprint computed. File type identified (binary/script)." },
    { n: "03", title: "Static Analysis", desc: "Entropy, API imports, obfuscation, IOC extraction." },
    { n: "04", title: "VirusTotal", desc: "Hash cross-referenced across 70+ antivirus engines." },
    { n: "05", title: "Correlation", desc: "IOCs matched against the incident history database." },
    { n: "06", title: "AI Synthesis", desc: "Local Llama3 reasons over all signals. Report generated." },
  ];
  const team = [
    { label: "Backend", detail: "FastAPI · SQLite · Analysis Pipeline", color: G.green },
    { label: "AI Engine", detail: "Ollama · Llama3 · Prompt Engineering", color: G.purple },
    { label: "Frontend", detail: "React · Dashboard · PDF Export", color: G.orange },
    { label: "QA & Demo", detail: "Test Files · Presentation · Docs", color: G.blue },
  ];

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal modal-lg" onClick={e => e.stopPropagation()} style={{ maxHeight: "88vh", overflowY: "auto" }}>
        {/* Header */}
        <div style={{ padding: "20px 24px", borderBottom: `1px solid ${G.border}`, position: "sticky", top: 0, background: G.card, zIndex: 10 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(255,255,255,.06)", border: `1px solid ${G.border}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icons.Shield />
              </div>
              <div>
                <div style={{ fontSize: 15, fontWeight: 600, color: G.text }}>ThreatSense</div>
                <div style={{ fontSize: 11, color: G.muted }}>AI-Powered Malware Analysis</div>
              </div>
            </div>
            <button className="btn-ghost" style={{ padding: "4px 8px" }} onClick={onClose}><Icons.X /></button>
          </div>
        </div>

        <div style={{ padding: "24px" }}>
          {/* What it is */}
          <div style={{ marginBottom: 28 }}>
            <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 10, fontFamily: "Geist Mono, monospace" }}>Overview</div>
            <p style={{ fontSize: 14, color: G.textDim, lineHeight: 1.7 }}>
              ThreatSense is a <span style={{ color: G.text, fontWeight: 500 }}>local-first</span> malware analysis platform. Upload a suspicious file and get a professional incident report in under 30 seconds — powered by a locally-running LLM.{" "}
              <span style={{ color: G.text, fontWeight: 500 }}>Zero data leaves your network.</span>
            </p>
          </div>

          {/* Pipeline */}
          <div style={{ marginBottom: 28 }}>
            <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 14, fontFamily: "Geist Mono, monospace" }}>Analysis Pipeline</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              {pipeline.map((s, i) => (
                <div key={i} style={{ display: "flex", gap: 12, padding: "12px 14px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface }}>
                  <div style={{ fontFamily: "Geist Mono, monospace", fontSize: 10, color: G.muted, marginTop: 1, flexShrink: 0 }}>{s.n}</div>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 500, color: G.text, marginBottom: 2 }}>{s.title}</div>
                    <div style={{ fontSize: 12, color: G.mutedFg, lineHeight: 1.5 }}>{s.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Why local */}
          <div style={{ marginBottom: 28, padding: "14px 16px", borderRadius: 8, border: `1px solid rgba(34,197,94,.15)`, background: "rgba(34,197,94,.04)" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <Icons.Lock />
              <div>
                <div style={{ fontSize: 13, fontWeight: 500, color: G.text, marginBottom: 4 }}>Why local inference?</div>
                <div style={{ fontSize: 12, color: G.mutedFg, lineHeight: 1.6 }}>
                  Files may contain sensitive organizational data. Sending them to cloud APIs violates GDPR, HIPAA, and DPDP. Llama3 runs entirely on-premise via Ollama — no external API calls.
                </div>
              </div>
            </div>
          </div>

          {/* Team */}
          <div>
            <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 12, fontFamily: "Geist Mono, monospace" }}>Team</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              {team.map((m, i) => (
                <div key={i} style={{ display: "flex", gap: 10, padding: "10px 14px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface, alignItems: "center" }}>
                  <div style={{ width: 3, height: 30, borderRadius: 2, background: m.color, flexShrink: 0 }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 500, color: G.text }}>{m.label}</div>
                    <div style={{ fontSize: 11, color: G.muted, fontFamily: "Geist Mono, monospace" }}>{m.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// History modal (NEW)
// ─────────────────────────────────────────────
function HistoryModal({ incidents, onClose, onSelect }) {
  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal modal-lg" onClick={e => e.stopPropagation()} style={{ maxHeight: "88vh", overflowY: "auto" }}>
        <div style={{ padding: "20px 24px", borderBottom: `1px solid ${G.border}`, position: "sticky", top: 0, background: G.card, zIndex: 10 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(255,255,255,.06)", border: `1px solid ${G.border}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icons.Clock />
              </div>
              <div>
                <div style={{ fontSize: 15, fontWeight: 600, color: G.text }}>Incident History</div>
                <div style={{ fontSize: 11, color: G.muted }}>{incidents.length} incident{incidents.length !== 1 ? "s" : ""}</div>
              </div>
            </div>
            <button className="btn-ghost" style={{ padding: "4px 8px" }} onClick={onClose}><Icons.X /></button>
          </div>
        </div>
        <div style={{ padding: 20 }}>
          {incidents.length === 0 && (
            <div style={{ textAlign: "center", padding: 40, color: G.muted, fontSize: 13 }}>
              No incidents yet. Upload a file to begin analysis.
            </div>
          )}
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {incidents.map((inc, i) => {
              const sevKey = (inc.severity || "UNKNOWN").toUpperCase();
              const S = SEV[sevKey] || SEV.UNKNOWN;
              return (
                <button
                  key={inc.incident_id || i}
                  onClick={() => onSelect(inc.incident_id)}
                  style={{ textAlign: "left", display: "flex", alignItems: "center", gap: 12, padding: "12px 14px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface, cursor: "pointer", transition: "all .15s", width: "100%" }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = G.borderHover; e.currentTarget.style.background = G.card; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = G.border; e.currentTarget.style.background = G.surface; }}
                >
                  <span className="badge" style={{ color: S.color, background: S.bg, borderColor: S.border, minWidth: 60, justifyContent: "center" }}>{sevKey}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 500, color: G.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inc.filename}</div>
                    <div style={{ fontSize: 11, color: G.muted, fontFamily: "Geist Mono, monospace" }}>
                      #{inc.incident_id} · {inc.threat_class || "Unknown"}
                    </div>
                  </div>
                  <Icons.ChevR />
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Progress view — real API call
// ─────────────────────────────────────────────
function ProgressView({ file, onDone, onError }) {
  const [step, setStep] = useState(0);
  const [errMsg, setErrMsg] = useState(null);
  const steps = [
    "Hashing file",
    "Running static analysis",
    "Querying VirusTotal",
    "Correlating IOCs",
    "Generating AI report",
  ];

  useEffect(() => {
    let cancelled = false;
    const timers = [];
    const abortController = new AbortController();

    // Animate steps forward while waiting for API response
    let s = 0;
    const advance = () => {
      if (cancelled) return;
      s++;
      if (s < steps.length) {
        setStep(s);
        // Later steps take longer (LLM synthesis is slow)
        const delay = s < 3 ? 1200 + Math.random() * 800 : 3000 + Math.random() * 3000;
        timers.push(setTimeout(advance, delay));
      }
    };
    timers.push(setTimeout(advance, 900));

    // Actual API call — POST /analyze
    const formData = new FormData();
    formData.append("file", file);

    fetch(`${API_BASE}/analyze`, {
      method: "POST",
      body: formData,
      signal: abortController.signal,
    })
      .then(res => {
        if (!res.ok) throw new Error(`Analysis failed (HTTP ${res.status})`);
        return res.json();
      })
      .then(data => {
        if (cancelled) return;
        // Complete all steps
        setStep(steps.length);
        timers.push(setTimeout(() => onDone(data), 700));
      })
      .catch(err => {
        if (cancelled) return;
        if (err.name === "AbortError") return; // StrictMode cleanup, ignore
        setErrMsg(err.message);
        if (onError) onError(err.message);
      });

    return () => {
      cancelled = true;
      abortController.abort();
      timers.forEach(clearTimeout);
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const pct = Math.round((step / steps.length) * 100);

  return (
    <div className="fade-in" style={{ padding: "32px 0" }}>
      {/* File row */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 16px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface, marginBottom: 28 }}>
        <Icons.File />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, color: G.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{file?.name}</div>
          <div style={{ fontSize: 11, color: G.muted, fontFamily: "Geist Mono, monospace" }}>
            {file ? (file.size / 1024).toFixed(0) + " KB" : ""}
          </div>
        </div>
        <span className="badge" style={{ color: G.blue, background: "rgba(59,130,246,.08)", borderColor: "rgba(59,130,246,.2)" }}>
          analyzing
        </span>
      </div>

      {/* Progress bar */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
          <span style={{ fontSize: 12, color: errMsg ? G.red : G.muted }}>{errMsg ? "Error" : "Analyzing…"}</span>
          <span style={{ fontSize: 12, color: G.text, fontFamily: "Geist Mono, monospace" }}>{pct}%</span>
        </div>
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${pct}%`, background: errMsg ? G.red : G.blue }} />
        </div>
      </div>

      {/* Error banner */}
      {errMsg && (
        <div style={{ display: "flex", gap: 8, padding: "12px 14px", borderRadius: 8, background: "rgba(239,68,68,.06)", border: "1px solid rgba(239,68,68,.15)", marginBottom: 16 }}>
          <Icons.Info />
          <div style={{ fontSize: 12, color: G.red, lineHeight: 1.5 }}>
            {errMsg}. Make sure the backend is running at {API_BASE}.
          </div>
        </div>
      )}

      {/* Steps */}
      <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
        {steps.map((s, i) => {
          const done = i < step;
          const active = i === step && !errMsg && step < steps.length;
          const pend = i >= step;
          return (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "9px 0", borderBottom: i < steps.length - 1 ? `1px solid ${G.border}` : "none", opacity: pend && !active ? .35 : 1, transition: "opacity .3s" }}>
              <div className="step-dot" style={{
                background: done ? "rgba(34,197,94,.12)" : active ? "rgba(255,255,255,.08)" : "transparent",
                border: `1px solid ${done ? "rgba(34,197,94,.3)" : active ? G.borderHover : G.border}`,
                color: done ? G.green : active ? G.text : G.muted,
              }}>
                {done ? <Icons.Check c={G.green} /> : active ? <Icons.Spinner /> : <span style={{ fontSize: 9 }}>{String(i + 1).padStart(2, "0")}</span>}
              </div>
              <span style={{ fontSize: 13, color: done ? G.textDim : active ? G.text : G.muted, fontWeight: active ? 500 : 400 }}>{s}</span>
              {active && <span style={{ marginLeft: "auto", fontSize: 11, color: G.muted, fontFamily: "Geist Mono, monospace" }} className="pulse2">running</span>}
              {done && <span style={{ marginLeft: "auto", fontSize: 11, color: G.green, fontFamily: "Geist Mono, monospace" }}>done</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Report view — data-driven from backend API
// ─────────────────────────────────────────────
function ReportView({ data, onReset }) {
  const llm = data.llm_report || {};
  const sevKey = (llm.severity || "UNKNOWN").toUpperCase();
  const S = SEV[sevKey] || SEV.UNKNOWN;
  const conf = llm.confidence || 0;
  const cls = llm.threat_classification || "Unknown";
  const summary = llm.executive_summary || "No executive summary available.";
  const techniques = llm.attack_techniques || [];
  const remediation = llm.remediation || [];
  const analystNotes = llm.analyst_notes || "";

  const hashes = data.hashes || {};
  const entropy = data.entropy || 0;
  const entropyV = data.entropy_verdict || data.findings?.entropy_verdict || "";
  const fileType = data.file_type || data.findings?.file_type || data.input_type || "unknown";

  const iocs = data.iocs || {};
  const allIocs = [
    ...(iocs.ips || []).map(v => ({ value: v, type: "IP" })),
    ...(iocs.domains || []).map(v => ({ value: v, type: "Domain" })),
    ...(iocs.urls || []).map(v => ({ value: v, type: "URL" })),
    ...(iocs.registry_keys || []).map(v => ({ value: v, type: "Registry" })),
    ...(iocs.file_paths || []).map(v => ({ value: v, type: "Path" })),
  ];

  const vt = data.vt_result || {};
  const corr = data.correlation || {};

  const [checked, setChecked] = useState({});

  const handleExportPDF = () => {
    const id = data.incident_id;
    if (id && id > 0) {
      window.open(`${API_BASE}/incidents/${id}/pdf`, "_blank");
    }
  };

  return (
    <div className="fade-in">
      {/* Report header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 12 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
              <span className="badge" style={{ color: S.color, background: S.bg, borderColor: S.border }}>{sevKey}</span>
              <span className="tag">{cls}</span>
              <span className="tag">{fileType}</span>
            </div>
            <div style={{ fontSize: 16, fontWeight: 600, color: G.text }}>{data.filename}</div>
            <div style={{ fontSize: 12, color: G.muted, fontFamily: "Geist Mono, monospace", marginTop: 2 }}>
              Confidence {conf}%{data.incident_id > 0 ? ` · Incident #${data.incident_id}` : ""}{data.analysis_time_seconds ? ` · ${data.analysis_time_seconds}s` : ""}
            </div>
          </div>
          <button className="btn-ghost" onClick={onReset} style={{ fontSize: 12 }}>
            ← New file
          </button>
        </div>
        <div className="divider" />
      </div>

      {/* Correlation banner */}
      {corr.matches_found && (
        <div style={{ padding: "14px 16px", borderRadius: 8, border: `1px solid rgba(239,68,68,.25)`, background: "rgba(239,68,68,.06)", marginBottom: 12 }}>
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <Icons.Link />
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: G.red, marginBottom: 4 }}>
                {corr.campaign_flag ? "⚠ CAMPAIGN DETECTED" : "⚠ Correlation Match"}
              </div>
              <div style={{ fontSize: 12, color: G.textDim, lineHeight: 1.6 }}>
                {corr.campaign_message}
              </div>
              {corr.matched_iocs?.length > 0 && (
                <div style={{ display: "flex", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
                  {corr.matched_iocs.map((ioc, i) => (
                    <span key={i} className="tag" style={{ color: G.red, borderColor: "rgba(239,68,68,.2)" }}>{ioc}</span>
                  ))}
                </div>
              )}
              {corr.related_incidents?.length > 0 && (
                <div style={{ marginTop: 8, fontSize: 11, color: G.muted }}>
                  Related: {corr.related_incidents.map(r => `#${r.incident_id} (${r.filename})`).join(", ")}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Source Reputation banner */}
      {(() => {
        const src = data.source || {};
        const rep = data.source_reputation || {};
        const srcDomain = src.domain || data.source_domain || "";
        const srcIp = src.ip || data.source_ip || "";
        if (!srcDomain && !srcIp) return null;
        const score = rep.score || 0;
        const label = rep.label || "CLEAN";
        const malFiles = rep.malicious_files || 0;
        const totalFiles = rep.total_files || 0;
        const linkedIncs = rep.incidents || [];
        const ratio = totalFiles > 0 ? Math.round((malFiles / totalFiles) * 100) : 0;
        const RC = label === "BLACKLISTED" ? { color: G.red, bg: "rgba(239,68,68,.06)", border: "rgba(239,68,68,.25)" }
          : label === "MALICIOUS" ? { color: G.orange, bg: "rgba(249,115,22,.06)", border: "rgba(249,115,22,.25)" }
            : label === "SUSPICIOUS" ? { color: G.amber, bg: "rgba(245,158,11,.06)", border: "rgba(245,158,11,.25)" }
              : { color: G.green, bg: "rgba(34,197,94,.04)", border: "rgba(34,197,94,.15)" };
        return (
          <div style={{ padding: "14px 16px", borderRadius: 8, border: `1px solid ${RC.border}`, background: RC.bg, marginBottom: 12 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <Icons.Globe />
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: G.text }}>Source Reputation</span>
                  <span className="badge" style={{ color: RC.color, background: RC.bg, borderColor: RC.border, fontSize: 10 }}>{label}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <span style={{ fontSize: 12, color: G.textDim, fontFamily: "Geist Mono, monospace" }}>
                    {srcDomain}{srcIp && srcIp !== srcDomain ? ` (${srcIp})` : ""}
                  </span>
                </div>
                {/* Score bar */}
                <div style={{ marginBottom: 8 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: G.muted }}>Reputation Score</span>
                    <span style={{ fontSize: 11, fontWeight: 600, color: RC.color, fontFamily: "Geist Mono, monospace" }}>{score}/100</span>
                  </div>
                  <div className="progress-track" style={{ height: 4 }}>
                    <div className="progress-fill" style={{ width: `${score}%`, background: RC.color, transition: "width .6s ease" }} />
                  </div>
                </div>
                {/* Stats row */}
                <div style={{ display: "flex", gap: 16, fontSize: 11, color: G.textDim }}>
                  {totalFiles > 0 && <span><strong>{totalFiles}</strong> files observed</span>}
                  {malFiles > 0 && <span style={{ color: RC.color }}><strong>{malFiles}</strong> malicious ({ratio}%)</span>}
                  {linkedIncs.length > 0 && <span>Incidents: {linkedIncs.slice(0, 5).map(id => `#${id}`).join(", ")}</span>}
                </div>
                {score >= 31 && (
                  <div style={{ marginTop: 8, fontSize: 11, color: RC.color, fontStyle: "italic", lineHeight: 1.5 }}>
                    ⚠ This source has a history of distributing malicious files. Exercise extreme caution.
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Propagation Chain banner */}
      {data.propagation_chain?.chain_detected && (() => {
        const pc = data.propagation_chain;
        const chain = pc.chain || [];
        return (
          <div style={{ padding: "14px 16px", borderRadius: 8, border: "1px solid rgba(239,68,68,.25)", background: "rgba(239,68,68,.06)", marginBottom: 12 }}>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <Icons.Zap />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: G.red, marginBottom: 6 }}>
                  ⚠ ATTACK PROPAGATION CHAIN — {pc.chain_length} Sources
                </div>
                {/* Chain visualization */}
                <div style={{ display: "flex", alignItems: "center", gap: 0, flexWrap: "wrap", marginBottom: 10 }}>
                  {chain.map((node, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center" }}>
                      <div style={{
                        padding: "6px 12px", borderRadius: 6,
                        background: "rgba(239,68,68,.1)", border: "1px solid rgba(239,68,68,.2)",
                        fontSize: 11, fontFamily: "Geist Mono, monospace", color: G.text,
                      }}>
                        <div style={{ fontWeight: 600 }}>{node.source}</div>
                        <div style={{ fontSize: 9, color: G.muted }}>#{node.incident_id}</div>
                      </div>
                      {i < chain.length - 1 && (
                        <span style={{ margin: "0 6px", color: G.red, fontSize: 14, fontWeight: 700 }}>→</span>
                      )}
                    </div>
                  ))}
                </div>
                <div style={{ fontSize: 11, color: G.textDim, lineHeight: 1.5 }}>
                  This malware has spread across <strong>{pc.chain_length} distinct sources</strong>.
                  Each hop indicates the file was forwarded from one compromised host to another.
                  All sources should be investigated and isolated.
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
        {/* Executive summary */}
        <div style={{ gridColumn: "1/-1", padding: "16px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface }}>
          <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 8, fontFamily: "Geist Mono, monospace" }}>Executive Summary</div>
          <p style={{ fontSize: 13, color: G.textDim, lineHeight: 1.7 }}>{summary}</p>
        </div>

        {/* Hashes */}
        <div style={{ padding: "16px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface }}>
          <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 10, fontFamily: "Geist Mono, monospace" }}>File Hashes</div>
          {["md5", "sha1", "sha256"].map(h => hashes[h] ? (
            <div key={h} style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: G.muted, textTransform: "uppercase", fontFamily: "Geist Mono, monospace", marginBottom: 2 }}>{h}</div>
              <div style={{ fontSize: 11, color: G.textDim, fontFamily: "Geist Mono, monospace", wordBreak: "break-all", lineHeight: 1.4 }}>{hashes[h]}</div>
            </div>
          ) : null)}
          <div style={{ marginTop: 8, fontSize: 11, color: G.muted, fontFamily: "Geist Mono, monospace" }}>
            {data.size_bytes ? `${(data.size_bytes / 1024).toFixed(1)} KB` : ""}
          </div>
        </div>

        {/* Entropy + VirusTotal */}
        <div style={{ padding: "16px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface }}>
          <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 10, fontFamily: "Geist Mono, monospace" }}>Entropy</div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginBottom: 6 }}>
            <span style={{ fontSize: 24, fontWeight: 600, color: entropy >= 7.2 ? G.red : entropy >= 6.0 ? G.amber : G.green, fontFamily: "Geist Mono, monospace" }}>
              {entropy.toFixed(2)}
            </span>
            <span style={{ fontSize: 12, color: G.muted }}>/8.0</span>
          </div>
          <div className="progress-track" style={{ marginBottom: 8 }}>
            <div className="progress-fill" style={{ width: `${(entropy / 8) * 100}%`, background: entropy >= 7.2 ? G.red : entropy >= 6.0 ? G.amber : G.green, transition: "width .6s ease" }} />
          </div>
          <div style={{ fontSize: 11, color: G.textDim, lineHeight: 1.4 }}>{entropyV}</div>

          {/* VirusTotal inline */}
          <div style={{ marginTop: 14, paddingTop: 12, borderTop: `1px solid ${G.border}` }}>
            <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 8, fontFamily: "Geist Mono, monospace" }}>VirusTotal</div>
            {vt.known ? (
              <>
                <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginBottom: 4 }}>
                  <span style={{ fontSize: 20, fontWeight: 600, color: vt.malicious > 0 ? G.red : G.green, fontFamily: "Geist Mono, monospace" }}>{vt.malicious}</span>
                  <span style={{ fontSize: 12, color: G.muted }}>/{vt.total} engines</span>
                </div>
                <div style={{ fontSize: 11, color: G.textDim }}>{vt.message}</div>
                {vt.threat_names?.length > 0 && (
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 6 }}>
                    {vt.threat_names.slice(0, 5).map((n, i) => <span key={i} className="tag" style={{ fontSize: 10 }}>{n}</span>)}
                  </div>
                )}
              </>
            ) : (
              <div style={{ fontSize: 12, color: G.textDim }}>{vt.message || "Lookup unavailable"}</div>
            )}
          </div>
        </div>

        {/* Attack techniques */}
        {techniques.length > 0 && (
          <div style={{ padding: "16px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface }}>
            <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 10, fontFamily: "Geist Mono, monospace" }}>Attack Techniques</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {techniques.map((t, i) => (
                <div key={i} style={{ fontSize: 12, color: G.textDim, padding: "6px 10px", borderRadius: 6, background: G.card, border: `1px solid ${G.border}`, fontFamily: "Geist Mono, monospace" }}>{t}</div>
              ))}
            </div>
          </div>
        )}

        {/* IOC highlights */}
        {allIocs.length > 0 && (
          <div style={{ padding: "16px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface }}>
            <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 10, fontFamily: "Geist Mono, monospace" }}>Indicators of Compromise</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {allIocs.slice(0, 10).map((ioc, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 10px", borderRadius: 6, background: G.card, border: `1px solid ${G.border}` }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, flex: 1 }}>
                    <span className="tag" style={{ fontSize: 9, flexShrink: 0 }}>{ioc.type}</span>
                    <span style={{ fontSize: 12, color: G.text, fontFamily: "Geist Mono, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{ioc.value}</span>
                  </div>
                  <button style={{ fontSize: 10, color: G.muted, background: "none", border: "none", cursor: "pointer", flexShrink: 0, marginLeft: 8 }}
                    onClick={() => navigator.clipboard?.writeText(ioc.value)}>copy</button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Remediation */}
        {remediation.length > 0 && (
          <div style={{ gridColumn: "1/-1", padding: "16px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface }}>
            <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 10, fontFamily: "Geist Mono, monospace" }}>Remediation Steps</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
              {remediation.map((s, i) => (
                <label key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 0", borderBottom: i < remediation.length - 1 ? `1px solid ${G.border}` : "none", cursor: "pointer" }}>
                  <div
                    onClick={() => setChecked(c => ({ ...c, [i]: !c[i] }))}
                    style={{ width: 16, height: 16, borderRadius: 4, border: `1px solid ${checked[i] ? G.green : G.border}`, background: checked[i] ? "rgba(34,197,94,.12)" : "transparent", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, transition: "all .15s", cursor: "pointer" }}>
                    {checked[i] && <Icons.Check c={G.green} />}
                  </div>
                  <span style={{ fontSize: 13, color: checked[i] ? G.muted : G.textDim, textDecoration: checked[i] ? "line-through" : "none", transition: "all .2s" }}>{s}</span>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Analyst notes */}
        {analystNotes && (
          <div style={{ gridColumn: "1/-1", padding: "16px", borderRadius: 8, border: `1px solid ${G.border}`, background: G.surface }}>
            <div style={{ fontSize: 11, fontWeight: 500, letterSpacing: ".05em", textTransform: "uppercase", color: G.muted, marginBottom: 8, fontFamily: "Geist Mono, monospace" }}>Analyst Notes</div>
            <p style={{ fontSize: 13, color: G.textDim, lineHeight: 1.7 }}>{analystNotes}</p>
          </div>
        )}
      </div>

      {/* Export */}
      <button className="btn-primary" style={{ width: "100%", justifyContent: "center", padding: "10px" }} onClick={handleExportPDF}>
        <Icons.Download /> Export PDF Report
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
export default function ThreatSense() {
  const [mode, setMode] = useState("idle"); // idle | analyzing | done
  const [file, setFile] = useState(null);
  const [reportData, setReport] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [about, setAbout] = useState(false);
  const [showHistory, setShowHist] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState(null);
  const [backendUp, setBackendUp] = useState(null);
  const fileRef = useRef(null);

  // Fetch stats + incidents from backend
  const fetchMeta = useCallback(() => {
    fetch(`${API_BASE}/stats`).then(r => r.json()).then(d => { setStats(d); setBackendUp(true); }).catch(() => setBackendUp(false));
    fetch(`${API_BASE}/incidents`).then(r => r.json()).then(setIncidents).catch(() => { });
  }, []);

  useEffect(() => { fetchMeta(); }, [fetchMeta]);

  const handleFile = useCallback(f => {
    setFile(f);
    setReport(null);
    setMode("analyzing");
  }, []);

  const handleDrop = useCallback(e => {
    e.preventDefault(); setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, [handleFile]);

  const handleDone = useCallback(data => {
    setReport(data);
    setMode("done");
    fetchMeta(); // refresh history + stats
  }, [fetchMeta]);

  const handleReset = useCallback(() => {
    setMode("idle");
    setFile(null);
    setReport(null);
  }, []);

  const handleViewIncident = useCallback(id => {
    fetch(`${API_BASE}/incidents/${id}`)
      .then(r => r.json())
      .then(data => {
        setReport({ ...data, incident_id: data.incident_id || id });
        setMode("done");
        setShowHist(false);
      })
      .catch(() => { });
  }, []);

  const features = [
    { dot: G.blue, label: "Local inference", sub: "No data leaves network" },
    { dot: G.green, label: "< 30s analysis", sub: "Full pipeline" },
    { dot: G.purple, label: "VirusTotal", sub: "70+ AV engines" },
    { dot: G.amber, label: "IOC correlation", sub: "Cross-incident" },
  ];

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: css }} />

      {/* Nav */}
      <nav className="nav">
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 24, height: 24, borderRadius: 6, background: "rgba(255,255,255,.08)", border: `1px solid ${G.border}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Icons.Shield />
          </div>
          <span style={{ fontSize: 14, fontWeight: 600, letterSpacing: "-.01em" }}>ThreatSense</span>
          <span className="badge" style={{ color: G.muted, borderColor: G.border, marginLeft: 4, fontSize: 10 }}>beta</span>
          {stats && (
            <div style={{ display: "flex", gap: 6, marginLeft: 12, alignItems: "center" }}>
              <span style={{ fontSize: 11, color: G.muted, fontFamily: "Geist Mono, monospace" }}>
                Total: {stats.total}
              </span>
              {stats.by_severity && Object.entries(stats.by_severity).map(([k, v]) => v > 0 ? (
                <span key={k} className="badge" style={{ color: (SEV[k] || SEV.UNKNOWN).color, background: (SEV[k] || SEV.UNKNOWN).bg, borderColor: (SEV[k] || SEV.UNKNOWN).border, fontSize: 9, padding: "1px 5px" }}>
                  {v} {k}
                </span>
              ) : null)}
            </div>
          )}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {incidents.length > 0 && (
            <button className="btn-ghost" style={{ fontSize: 12 }} onClick={() => setShowHist(true)}>
              <Icons.Clock /> History
            </button>
          )}
          <button className="btn-ghost" style={{ fontSize: 12 }} onClick={() => setAbout(true)}>
            About
          </button>
          <button className="btn-outline" style={{ fontSize: 12 }} onClick={() => fileRef.current?.click()}>
            <Icons.Upload /> Upload file
          </button>
        </div>
      </nav>

      {/* Hidden file input (top level so it works in any mode) */}
      <input ref={fileRef} type="file" style={{ display: "none" }} onChange={e => { if (e.target.files[0]) handleFile(e.target.files[0]); e.target.value = ""; }} />

      {/* Page */}
      <div style={{ maxWidth: 640, margin: "0 auto", padding: "48px 24px 80px" }}>

        {mode === "idle" && (
          <>
            {/* Hero */}
            <div className="fade-in" style={{ marginBottom: 40, textAlign: "center" }}>
              <div style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 12px 4px 8px", borderRadius: 20, border: `1px solid ${G.border}`, background: G.card, marginBottom: 20 }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: backendUp === false ? G.red : G.green }} className="pulse2" />
                <span style={{ fontSize: 12, color: G.mutedFg }}>
                  {backendUp === false ? "Backend offline · Start on port 8000" : "System online · Local inference ready"}
                </span>
              </div>
              <h1 className="serif" style={{ fontSize: 48, lineHeight: 1.1, color: G.text, marginBottom: 14, letterSpacing: "-.02em" }}>
                Analyze any<br /><span style={{ fontStyle: "italic", color: G.mutedFg }}>suspicious file</span>
              </h1>
              <p style={{ fontSize: 15, color: G.mutedFg, lineHeight: 1.6, maxWidth: 420, margin: "0 auto" }}>
                Multi-signal malware analysis powered by a locally-running LLM. Professional incident reports in seconds.
              </p>
            </div>

            {/* Drop zone */}
            <div
              className={`dropzone ${dragging ? "dragging" : hovered ? "hovered" : ""}`}
              style={{ padding: "48px 32px", textAlign: "center", marginBottom: 16 }}
              onDragOver={e => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
              onMouseEnter={() => setHovered(true)}
              onMouseLeave={() => setHovered(false)}
              onClick={() => fileRef.current?.click()}
            >
              <div style={{ width: 40, height: 40, borderRadius: 10, border: `1px solid ${G.border}`, background: G.card, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 14px" }}>
                <Icons.Upload />
              </div>
              <div style={{ fontSize: 14, fontWeight: 500, color: G.text, marginBottom: 4 }}>
                {dragging ? "Release to analyze" : "Drop file here"}
              </div>
              <div style={{ fontSize: 13, color: G.muted, marginBottom: 16 }}>
                or <span style={{ color: G.textDim, textDecoration: "underline", textUnderlineOffset: 3 }}>browse your computer</span>
              </div>
              <div style={{ display: "flex", gap: 6, justifyContent: "center", flexWrap: "wrap" }}>
                {[".exe", ".dll", ".py", ".ps1", ".js", ".sh", ".bat", ".txt", ".eml"].map(ext => (
                  <span key={ext} className="kbd">{ext}</span>
                ))}
              </div>
            </div>

            {/* Features */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              {features.map((f, i) => (
                <div key={i} className="feature-pill">
                  <div className="dot" style={{ background: f.dot }} />
                  <span style={{ fontWeight: 500, color: G.textDim, fontSize: 12 }}>{f.label}</span>
                  <span style={{ color: G.muted, fontSize: 11 }}>{f.sub}</span>
                </div>
              ))}
            </div>
          </>
        )}

        {mode === "analyzing" && (
          <div className="card" style={{ padding: "24px" }}>
            <ProgressView file={file} onDone={handleDone} onError={() => { }} />
          </div>
        )}

        {mode === "done" && reportData && (
          <ReportView data={reportData} onReset={handleReset} />
        )}
      </div>

      {/* Modals */}
      {about && <AboutModal onClose={() => setAbout(false)} />}
      {showHistory && <HistoryModal incidents={incidents} onClose={() => setShowHist(false)} onSelect={handleViewIncident} />}
    </>
  );
}
