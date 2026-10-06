import React, { useState } from "react";
import { Card } from "./ui.jsx";
import { STAGE_ORDER, STAGE_ICONS, fmtMs } from "../lib/labels.js";

/** Map a stage key to the facts sub-object it produced. */
function factsFor(key, facts) {
  if (!facts) return null;
  switch (key) {
    case "qr":
      return facts.qr || null;
    case "payload":
      return facts.payload || null;
    case "url":
      return facts.url || null;
    case "fetch":
      return { redirect_chain: facts.redirect_chain, destination: facts.destination };
    default:
      return null;
  }
}

/**
 * Stepper of pipeline stages. Each step can be expanded to reveal the raw
 * deterministic facts that stage produced.
 */
export default function Timeline({ stages, facts }) {
  const [openStage, setOpenStage] = useState(null);
  if (!stages) return null;

  return (
    <Card
      title="Pipeline timeline"
      subtitle="Every stage reports its own status; a degraded stage never hides the rest."
    >
      <ol className="timeline">
        {STAGE_ORDER.map(([key, label]) => {
          const s = stages[key];
          if (!s) return null;
          const open = openStage === key;
          const data = factsFor(key, facts);
          return (
            <li key={key} className={`tl-step tl-${s.status}`}>
              <button
                type="button"
                className="tl-btn"
                onClick={() => setOpenStage(open ? null : key)}
                aria-expanded={open}
              >
                <span className={`tl-icon st-${s.status}`} aria-hidden="true">
                  {STAGE_ICONS[s.status] || "?"}
                </span>
                <span className="tl-body">
                  <span className="tl-name">{label}</span>
                  <span className="tl-meta">
                    <span className={`tl-status st-${s.status}`}>{s.status}</span>
                    {s.duration_ms !== undefined && s.duration_ms !== null && (
                      <span className="mono">{fmtMs(s.duration_ms)}</span>
                    )}
                  </span>
                  {s.note && <span className="tl-note">{s.note}</span>}
                </span>
              </button>
              {open && (
                <pre className="json">
                  {JSON.stringify(data === null ? { stage: s } : { stage: s, facts: data }, null, 2)}
                </pre>
              )}
            </li>
          );
        })}
      </ol>
    </Card>
  );
}
