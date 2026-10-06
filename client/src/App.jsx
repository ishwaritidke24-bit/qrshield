import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import RiskBanner from "./components/RiskBanner.jsx";
import Timeline from "./components/Timeline.jsx";
import PayloadCard from "./components/PayloadCard.jsx";
import RedirectChain from "./components/RedirectChain.jsx";
import FactsPanel from "./components/FactsPanel.jsx";
import ReasoningPanel from "./components/ReasoningPanel.jsx";
import CrossCheck from "./components/CrossCheck.jsx";
import { Chip } from "./components/ui.jsx";
import sampleReport from "./sample/sampleReport.js";

const ACCEPTED = ["image/png", "image/jpeg", "image/webp"];
const MAX_UPLOAD = 8 * 1024 * 1024;

/** Stepper shown while the request is in flight. Timing is cosmetic: the server returns one report at the end. */
const WAIT_STEPS = [
  { key: "qr", label: "QR detected", after: 0 },
  { key: "url", label: "Destination inspected", after: 900 },
  { key: "gemma", label: "Gemma 4 analyzes poster + evidence", after: 3000 },
  { key: "evidence", label: "Evidence", after: 14000 },
  { key: "report", label: "Risk report", after: 18000 },
];

/** The six steps every investigation goes through, shown above the form. */
const FLOW = ["Upload / scan", "QR detected", "Destination inspected", "Gemma 4 analyzes", "Evidence", "Risk report"];

/** Demo posters bundled with the client (copies of tests/fixtures). Order = suggested demo order. */
const DEMO_POSTERS = [
  {
    file: "no-fee-upi.png",
    title: "No Application Fee + UPI payment",
    blurb: "Poster says free; the QR is a prefilled 499 INR UPI request. Needs no network. Start here.",
    tone: "critical",
  },
  {
    file: "scholarship-phish.png",
    title: "Scholarship phishing",
    blurb: "Redirect chain into a form asking for password, card, CVV and OTP. Needs the fixture server.",
    tone: "high",
  },
  {
    file: "legit-event.png",
    title: "Legitimate event",
    blurb: "University TechFest poster whose page matches the claims. Needs the fixture server.",
    tone: "low",
  },
];

/** Turn a fetch Response / error into a human message without leaking anything sensitive. */
async function describeError(res) {
  let detail = "";
  try {
    const body = await res.json();
    detail = body && (body.error || body.message) ? String(body.error || body.message) : "";
  } catch {
    /* non-JSON body */
  }
  detail = detail.replace(/AIza[0-9A-Za-z_-]+|AQ\.[0-9A-Za-z_-]{10,}/g, "[redacted]");
  if (res.status === 400) return `Bad input (400)${detail ? `: ${detail}` : "."}`;
  if (res.status === 413) return `Image too large (413)${detail ? `: ${detail}` : "."}`;
  if (res.status === 429) return `Rate limited (429): too many investigations from this address. Wait a minute and retry.`;
  return `Server returned ${res.status}${detail ? `: ${detail}` : "."}`;
}

export default function App() {
  const [mode, setMode] = useState("image"); // image | url
  const [file, setFile] = useState(null);
  const previewUrl = useMemo(() => {
    if (!file || typeof URL === "undefined" || typeof URL.createObjectURL !== "function") return null;
    try {
      return URL.createObjectURL(file);
    } catch {
      return null;
    }
  }, [file]);
  const [manualUrl, setManualUrl] = useState("");
  const [urlOnly, setUrlOnly] = useState("");
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [startedAt, setStartedAt] = useState(0);
  const [now, setNow] = useState(0);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [hoveredFactId, setHoveredFactId] = useState(null);
  const fileInput = useRef(null);

  // ?demo=sample loads the offline fixture.
  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get("demo") === "sample") setReport(sampleReport);
    } catch {
      /* ignore */
    }
  }, []);

  // Release the object URL when the file changes or the component unmounts.
  useEffect(() => {
    if (!previewUrl) return undefined;
    return () => {
      try {
        URL.revokeObjectURL(previewUrl);
      } catch {
        /* ignore */
      }
    };
  }, [previewUrl]);

  /** Remove the uploaded poster and return the scan area to its initial state. */
  const removeFile = useCallback(() => {
    setFile(null);
    setError(null);
    setReport(null);
    setHoveredFactId(null);
    if (fileInput.current) fileInput.current.value = "";
  }, []);

  // Tick while busy so the stepper advances.
  useEffect(() => {
    if (!busy) return undefined;
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, [busy]);

  const pickFile = useCallback((f) => {
    setError(null);
    if (!f) return;
    if (!ACCEPTED.includes(f.type)) {
      setError("Unsupported file type. Use PNG, JPEG or WebP.");
      return;
    }
    if (f.size > MAX_UPLOAD) {
      setError("Image is larger than 8 MiB.");
      return;
    }
    // A new poster starts a new case: never show a previous verdict under it.
    setReport(null);
    setHoveredFactId(null);
    setFile(f);
  }, []);

  const [demoLoading, setDemoLoading] = useState(null);
  async function loadDemo(d) {
    setError(null);
    setDemoLoading(d.file);
    try {
      const res = await fetch(`/demo/${d.file}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      pickFile(new File([blob], d.file, { type: "image/png" }));
    } catch (err) {
      setError(`Could not load the demo poster (${err && err.message ? err.message : "fetch failed"}).`);
    } finally {
      setDemoLoading(null);
    }
  }

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    pickFile(f);
  };

  async function submit(e) {
    e.preventDefault();
    setError(null);
    setReport(null);
    setHoveredFactId(null);

    let request;
    if (mode === "image") {
      if (!file) {
        setError("Choose a poster image first.");
        return;
      }
      const form = new FormData();
      form.append("image", file, file.name);
      if (manualUrl.trim()) form.append("url", manualUrl.trim());
      request = fetch("/api/investigate", { method: "POST", body: form });
    } else {
      const url = urlOnly.trim();
      if (!url) {
        setError("Enter a URL to investigate.");
        return;
      }
      request = fetch("/api/investigate-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
    }

    setBusy(true);
    setStartedAt(Date.now());
    setNow(Date.now());
    try {
      const res = await request;
      if (!res.ok) {
        setError(await describeError(res));
        return;
      }
      const data = await res.json();
      if (!data || typeof data !== "object" || !data.risk) {
        setError("The server returned an unexpected response shape.");
        return;
      }
      setReport(data);
    } catch (err) {
      setError(`Network error: ${err && err.message ? err.message : "request failed"}. Is the server running on /api?`);
    } finally {
      setBusy(false);
    }
  }

  const elapsed = busy ? now - startedAt : 0;
  const serverFactIds = report && report.facts && Array.isArray(report.facts.server_facts)
    ? report.facts.server_facts.map((f) => f.id)
    : [];

  return (
    <div className="app">
      <header className="masthead">
        <div className="brand">
          <span className="logo" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="28" height="28">
              <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" fill="none" stroke="currentColor" strokeWidth="1.6" />
              <rect x="8" y="8" width="3" height="3" fill="currentColor" />
              <rect x="13" y="8" width="3" height="3" fill="currentColor" />
              <rect x="8" y="13" width="3" height="3" fill="currentColor" />
              <rect x="13" y="13" width="1.4" height="1.4" fill="currentColor" />
              <rect x="14.6" y="14.6" width="1.4" height="1.4" fill="currentColor" />
            </svg>
          </span>
          <div>
            <h1>QRShield</h1>
            <p className="tagline">Security layer for QR codes</p>
          </div>
        </div>
        <p className="masthead-note">
          Compares <strong>what a poster claims</strong> with <strong>where its QR code really leads</strong>.
          Server-verified facts and Gemma 4 reasoning are kept apart and labelled.
        </p>
      </header>

      <main>
        <form className="card upload" onSubmit={submit}>
          <ol className="flow" aria-label="How an investigation works">
            {FLOW.map((step, i) => (
              <li key={step} className={`flow-step ${i === 3 ? "flow-gemma" : ""}`}>
                <span className="flow-num">{i + 1}</span>
                {step}
              </li>
            ))}
          </ol>
          <div className="tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={mode === "image"}
              className={`tab ${mode === "image" ? "tab-on" : ""}`}
              onClick={() => setMode("image")}
            >
              Upload / scan a poster
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === "url"}
              className={`tab ${mode === "url" ? "tab-on" : ""}`}
              onClick={() => setMode("url")}
            >
              Investigate a URL only
            </button>
          </div>

          {mode === "image" ? (
            <>
              <div className="intake-label mono small">
                <span>Evidence intake</span>
                <span>{file ? "exhibit loaded" : "awaiting poster"}</span>
              </div>
              <div
                className={`drop ${dragging ? "drop-on" : ""} ${file ? "drop-has" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                onClick={() => fileInput.current && fileInput.current.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    fileInput.current && fileInput.current.click();
                  }
                }}
              >
                <input
                  ref={fileInput}
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  hidden
                  onChange={(e) => pickFile(e.target.files && e.target.files[0])}
                />
                <span className="corner c-tl" aria-hidden="true" />
                <span className="corner c-tr" aria-hidden="true" />
                <span className="corner c-bl" aria-hidden="true" />
                <span className="corner c-br" aria-hidden="true" />
                {file && previewUrl ? (
                  <div className="preview">
                    <img src={previewUrl} alt="Poster preview" />
                    <div>
                      <div className="file-name">{file.name}</div>
                      <div className="muted small">
                        {file.type} / {(file.size / 1024).toFixed(0)} KiB
                      </div>
                      <button
                        type="button"
                        className="link-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          removeFile();
                        }}
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="drop-hint">
                    <strong>Place the physical evidence here</strong> drop a poster photo or click to choose a file
                    <div className="muted small">PNG, JPEG or WebP up to 8 MiB. The image is sent to Gemma; nothing is stored.</div>
                  </div>
                )}
              </div>
              <div className="demo-cards" aria-label="Demo posters">
                {DEMO_POSTERS.map((d) => (
                  <button
                    type="button"
                    key={d.file}
                    className={`demo-card demo-${d.tone} ${file && file.name === d.file ? "demo-on" : ""}`}
                    onClick={() => loadDemo(d)}
                    disabled={busy || demoLoading !== null}
                  >
                    <img src={`/demo/${d.file}`} alt="" loading="lazy" />
                    <span className="demo-text">
                      <strong>{d.title}</strong>
                      <span className="muted small">{demoLoading === d.file ? "Loading..." : d.blurb}</span>
                    </span>
                  </button>
                ))}
              </div>
              <label className="field">
                <span>Manual URL override (optional)</span>
                <input
                  type="text"
                  inputMode="url"
                  placeholder="https://... use when the QR is unreadable but the link is printed"
                  value={manualUrl}
                  onChange={(e) => setManualUrl(e.target.value)}
                />
              </label>
            </>
          ) : (
            <label className="field">
              <span>URL from the QR code</span>
              <input
                type="text"
                inputMode="url"
                placeholder="https://example.com/offer"
                value={urlOnly}
                onChange={(e) => setUrlOnly(e.target.value)}
                autoFocus
              />
              <span className="muted small">No poster image means Gemma cannot compare the physical claim; expect a lower confidence.</span>
            </label>
          )}

          <div className="actions">
            <button type="submit" className="primary" disabled={busy}>
              {busy ? "Investigating..." : "Investigate"}
            </button>
            <a className="link-btn" href="?demo=sample">
              Load demo report
            </a>
          </div>

          {busy && (
            <ol className="wait" aria-label="Progress">
              {WAIT_STEPS.map((s, i) => {
                const next = WAIT_STEPS[i + 1];
                const state = elapsed >= s.after ? (next && elapsed >= next.after ? "done" : "active") : "todo";
                return (
                  <li key={s.key} className={`wait-step wait-${state}`}>
                    <span className="wait-dot" />
                    {s.label}
                  </li>
                );
              })}
            </ol>
          )}

          {error && (
            <div className="error" role="alert">
              {error}
            </div>
          )}
        </form>

        {report && (
          <div className="report">
            <RiskBanner risk={report.risk} reasoningMeta={report.reasoning_meta} meta={report.meta} />

            <div className="report-meta mono small">
              <span>id {report.investigation_id}</span>
              <span>{report.created_at}</span>
              {report.input && <Chip tone="outline">mode: {report.input.mode}</Chip>}
              {report.input && report.input.manual_url && <Chip tone="outline">manual URL</Chip>}
              {report.meta && report.meta.timings && report.meta.timings.total_ms !== undefined && (
                <span>total {report.meta.timings.total_ms} ms</span>
              )}
            </div>

            <CrossCheck report={report} />

            <Timeline stages={report.stages} facts={report.facts} />

            <div className="legend small" aria-label="How to read this report">
              <span><Chip tone="verified">Verified fact</Chip> deterministic server checks (QR, URL, SSRF-guarded fetch)</span>
              <span><Chip tone="hybrid">Model inference</Chip> Gemma 4 reasoning over the poster image + evidence packet</span>
              <span><Chip tone="strong">Contradiction</Chip> poster claim vs destination observation</span>
              <span><Chip tone="insufficient">Uncertainty</Chip> what could not be verified</span>
            </div>

            <div className="grid-two">
              <div className="col">
                <PayloadCard qr={report.facts && report.facts.qr} payload={report.facts && report.facts.payload} />
                <RedirectChain
                  chain={report.facts && report.facts.redirect_chain}
                  destination={report.facts && report.facts.destination}
                />
                <FactsPanel facts={report.facts} hoveredFactId={hoveredFactId} />
              </div>
              <div className="col">
                <ReasoningPanel
                  reasoning={report.reasoning}
                  reasoningMeta={report.reasoning_meta}
                  serverAdjustments={report.server_adjustments}
                  serverFactIds={serverFactIds}
                  onHoverFact={setHoveredFactId}
                />
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="foot muted small">
        QRShield v{(report && report.meta && report.meta.version) || "0.1.0"}. Risk labels are evidence-based estimates, never
        certainties. Poster images are sent to Google&apos;s Gemini API for Gemma 4 reasoning; nothing is stored server-side.
      </footer>
    </div>
  );
}
