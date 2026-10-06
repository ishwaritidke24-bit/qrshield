import React from "react";
import { Chip } from "./ui.jsx";
import { RISK_TONE, RISK_SOURCE_LABELS, riskLabel } from "../lib/labels.js";

/**
 * Big colour-coded verdict. Pure presentation of report.risk plus the two
 * availability badges (model unavailable / demo fixture).
 */
export default function RiskBanner({ risk, reasoningMeta, meta }) {
  if (!risk) return null;
  const tone = RISK_TONE[risk.level] || "insufficient";
  const confidence = Math.max(0, Math.min(1, Number(risk.confidence) || 0));
  const pct = Math.round(confidence * 100);
  const modelDown = reasoningMeta && reasoningMeta.available === false;
  const usage = (reasoningMeta && reasoningMeta.usage) || {};
  const sawImage = Boolean(usage.prompt_image_tokens);
  const modelUp = reasoningMeta && reasoningMeta.available === true;

  return (
    <section className={`risk-banner risk-${tone}`} aria-live="polite">
      <div className="risk-top">
        <div className="risk-label">{risk.label || riskLabel(risk.level)}</div>
        <div className="risk-badges">
          <Chip tone="outline" title="Which component decided the final level">
            source: {RISK_SOURCE_LABELS[risk.source] || risk.source || "unknown"}
          </Chip>
          {modelUp && (
            <Chip tone="hybrid" title="Gemma 4 received the poster image and the deterministic evidence packet in one multimodal request">
              Gemma 4 multimodal: {sawImage ? "poster image + " : ""}destination evidence
            </Chip>
          )}
          {modelDown && <Chip tone="warn">Model unavailable: deterministic fallback</Chip>}
          {meta && meta.mock && <Chip tone="info">Demo fixture</Chip>}
        </div>
      </div>

      <div className="confidence">
        <div className="confidence-row">
          <span>Confidence</span>
          <span className="mono">{pct}%</span>
        </div>
        <div
          className="bar"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
        >
          <div className="bar-fill" style={{ width: `${pct}%` }} />
        </div>
      </div>

      {risk.summary && <p className="risk-summary">{risk.summary}</p>}
      {risk.recommended_action && (
        <p className="risk-action">
          <strong>Recommended action:</strong> {risk.recommended_action}
        </p>
      )}
    </section>
  );
}
