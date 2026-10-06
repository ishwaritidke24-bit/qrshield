import React from "react";
import { Card, Chip, KvTable, Empty } from "./ui.jsx";
import { STRENGTH_TONE, strengthLabel, riskLabel, RISK_TONE } from "../lib/labels.js";

const SENSITIVE_LABELS = {
  password: "password",
  payment_card: "payment card",
  otp: "OTP",
  upi: "UPI / UPI PIN",
  aadhaar: "Aadhaar",
  pan: "PAN",
  bank: "bank account",
};

/** Index signals by id so facts can show their strength chip. */
function indexSignals(signals) {
  const map = new Map();
  for (const s of signals || []) map.set(s.id, s);
  return map;
}

function FactRow({ fact, signal, highlighted }) {
  const strength = signal ? signal.strength : "neutral";
  return (
    <li id={`fact-${fact.id}`} className={`fact ${highlighted ? "fact-hot" : ""}`}>
      <span className="fact-id mono">{fact.id}</span>
      <span className="fact-text">
        {fact.text}
        <span className="fact-chips">
          <Chip tone={STRENGTH_TONE[strength] || "info"}>{strengthLabel(strength)}</Chip>
          {signal && signal.hybrid && <Chip tone="hybrid">model-derived fact</Chip>}
        </span>
      </span>
    </li>
  );
}

/**
 * Left column: everything produced by code, not by the model.
 * `hoveredFactId` comes from App; a Gemma evidence item hovered on the right
 * highlights its cited fact here.
 */
export default function FactsPanel({ facts, hoveredFactId }) {
  if (!facts) return null;
  const signals = indexSignals(facts.signals);
  const serverFacts = Array.isArray(facts.server_facts) ? facts.server_facts : [];
  const hybrid = (facts.signals || []).filter((s) => s.hybrid);
  const d = facts.destination || null;
  const floor = facts.floor || null;

  const sensitive = d && d.sensitive_inputs
    ? Object.entries(d.sensitive_inputs).filter(([, v]) => v).map(([k]) => k)
    : [];

  return (
    <Card
      title="Verified facts (deterministic, no AI)"
      subtitle="Produced by QR decoding, URL parsing, DNS/IP checks, redirect following and HTML extraction."
      className="facts-panel"
    >
      {serverFacts.length === 0 ? (
        <Empty>No server facts were produced for this input.</Empty>
      ) : (
        <ol className="facts">
          {serverFacts.map((f) => (
            <FactRow key={f.id} fact={f} signal={signals.get(f.signal_id)} highlighted={hoveredFactId === f.id} />
          ))}
        </ol>
      )}

      {floor && floor.level && (
        <div className={`floor floor-${RISK_TONE[floor.level] || "insufficient"}`}>
          <strong>Deterministic floor:</strong> {riskLabel(floor.level)}
          {Array.isArray(floor.triggered_by) && floor.triggered_by.length > 0 && (
            <span className="muted"> (triggered by {floor.triggered_by.join(", ")})</span>
          )}
          <div className="muted small">A floor can only raise the model verdict, never lower it.</div>
        </div>
      )}

      {hybrid.length > 0 && (
        <div className="sub">
          <h3 className="h3">
            Hybrid signals <Chip tone="hybrid">model-derived fact</Chip>
          </h3>
          <p className="muted small">
            These compare the destination with what Gemma read off the poster, so they depend on the model reading.
          </p>
          <ul className="plain">
            {hybrid.map((s) => (
              <li key={s.id} className="hybrid-row">
                <Chip tone={STRENGTH_TONE[s.strength] || "info"}>{strengthLabel(s.strength)}</Chip> {s.fact}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="sub">
        <h3 className="h3">Destination summary</h3>
        {!d ? (
          <Empty>No destination data.</Empty>
        ) : !d.fetched ? (
          <Empty>
            Destination not fetched
            {d.error_code ? (
              <>
                {" "}
                (<span className="mono">{d.error_code}</span>
                {d.error_message ? `: ${d.error_message}` : ""})
              </>
            ) : (
              "."
            )}
          </Empty>
        ) : (
          <KvTable
            rows={[
              ["Title", d.title],
              ["HTTP status", d.http_status],
              ["Content type", d.content_type],
              ["Site name", d.site_name],
              ["Canonical host", d.canonical_host],
              ["Language", d.lang],
              ["Meta description", d.meta_description],
              [
                "Sensitive inputs",
                sensitive.length === 0 ? (
                  <span className="muted">none detected</span>
                ) : (
                  <span className="chips">
                    {sensitive.map((k) => (
                      <Chip key={k} tone={k === "otp" || k === "upi" || k === "password" ? "critical" : "strong"}>
                        {SENSITIVE_LABELS[k] || k}
                      </Chip>
                    ))}
                  </span>
                ),
              ],
              [
                "Forms",
                Array.isArray(d.forms) && d.forms.length > 0 ? (
                  <ul className="plain small">
                    {d.forms.map((f, i) => (
                      <li key={i}>
                        <span className="mono">{(f.method || "GET").toUpperCase()}</span> to{" "}
                        <span className="mono">{f.action_host || "same page"}</span>
                        {f.cross_origin && <Chip tone="medium">cross-origin</Chip>}
                        {f.action_is_http && <Chip tone="strong">plain HTTP</Chip>}
                        {Array.isArray(f.field_types) && f.field_types.length > 0 && (
                          <span className="muted"> fields: {f.field_types.join(", ")}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="muted">none</span>
                ),
              ],
              [
                "External hosts",
                Array.isArray(d.external_hosts) && d.external_hosts.length > 0 ? (
                  <span className="mono break">{d.external_hosts.join(", ")}</span>
                ) : (
                  <span className="muted">none</span>
                ),
              ],
              ["Script hosts", Array.isArray(d.external_script_hosts) && d.external_script_hosts.length ? d.external_script_hosts.join(", ") : null],
              ["Iframe hosts", Array.isArray(d.iframe_hosts) && d.iframe_hosts.length ? d.iframe_hosts.join(", ") : null],
              ["meta-refresh target", d.meta_refresh_target],
              ["Download links", d.has_download_links ? "yes" : null],
              ["Bot wall", d.bot_wall_detected ? "detected" : null],
              ["Body", d.truncated ? `${d.bytes_read} bytes (truncated)` : d.bytes_read ? `${d.bytes_read} bytes` : null],
            ]}
          />
        )}
        {d && d.visible_text_excerpt && (
          <details className="excerpt">
            <summary>Visible text excerpt</summary>
            <p className="small">{d.visible_text_excerpt}</p>
          </details>
        )}
      </div>
    </Card>
  );
}
