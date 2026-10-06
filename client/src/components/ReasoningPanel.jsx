import React from "react";
import { Card, Chip, KvTable, Empty } from "./ui.jsx";
import { fmtMs } from "../lib/labels.js";

const MATCH_TONE = { match: "low", partial: "medium", mismatch: "critical", unknown: "insufficient" };
const SEVERITY_TONE = { low: "weak", medium: "medium", high: "critical" };
const SUPPORTS_TONE = { risk: "strong", safety: "low", neutral: "info" };
const YESNO_TONE = { yes: "strong", no: "low", unknown: "insufficient" };

function Flag({ value, tones = YESNO_TONE }) {
  if (value === null || value === undefined) return null;
  return <Chip tone={tones[value] || "info"}>{String(value).replace(/_/g, " ")}</Chip>;
}

/**
 * Right column: Gemma's structured output, labelled as model-derived.
 * Hovering an evidence item that cites a server fact calls onHoverFact(id)
 * so FactsPanel can highlight it.
 */
export default function ReasoningPanel({ reasoning, reasoningMeta, serverAdjustments, serverFactIds, onHoverFact }) {
  const meta = reasoningMeta || {};
  const adjustments = Array.isArray(serverAdjustments) ? serverAdjustments : [];
  const known = new Set(serverFactIds || []);

  if (!reasoning) {
    return (
      <Card title="Gemma 4 reasoning (model-derived)" className="reasoning-panel">
        <Empty>
          {meta.available === false
            ? `Model output unavailable${meta.error ? `: ${meta.error}` : "."} The verdict above comes from the deterministic fallback table.`
            : "No model reasoning for this report."}
        </Empty>
        {meta.raw_text_excerpt && (
          <details className="excerpt">
            <summary>Raw model text excerpt</summary>
            <pre className="json">{meta.raw_text_excerpt}</pre>
          </details>
        )}
        <Adjustments items={adjustments} />
        <SmallPrint meta={meta} />
      </Card>
    );
  }

  const p = reasoning.poster_analysis || {};
  const d = reasoning.destination_analysis || {};
  const contradictions = Array.isArray(reasoning.contradictions) ? reasoning.contradictions : [];
  const evidence = Array.isArray(reasoning.evidence) ? reasoning.evidence : [];
  const uncertainties = Array.isArray(reasoning.uncertainties) ? reasoning.uncertainties : [];

  return (
    <Card
      title="Gemma 4 reasoning (model-derived)"
      subtitle="The model saw the original poster image plus a sanitized evidence packet. Everything here is inference unless it cites a verified fact."
      className="reasoning-panel"
      aside={<Flag value={d.matches_poster_claims} tones={MATCH_TONE} />}
    >
      <ul className="plain small gemma-inputs" aria-label="Inputs Gemma 4 received">
        <li>
          <Chip tone={meta.usage && meta.usage.prompt_image_tokens ? "verified" : "insufficient"}>
            {meta.usage && meta.usage.prompt_image_tokens
              ? `Poster image received (${meta.usage.prompt_image_tokens} image tokens)`
              : "No poster image in this request"}
          </Chip>
        </li>
        <li>
          <Chip tone="verified">Evidence packet received ({known.size} verified fact{known.size === 1 ? "" : "s"})</Chip>
        </li>
        <li>
          <Chip tone="hybrid">Semantic comparison: poster claims vs destination</Chip>
        </li>
      </ul>
      <div className="sub">
        <h3 className="h3">What the poster claims</h3>
        <KvTable
          rows={[
            ["Claimed organization", p.claimed_organization],
            ["Offer", p.offer],
            ["Requested action", p.requested_action],
            ["Payment claim", <Flag value={p.payment_claim} tones={{ free: "low", paid: "medium", refund_or_prize: "strong", unspecified: "info" }} />],
            ["Urgency", <Flag value={p.urgency_claim} tones={{ none: "info", mild: "weak", strong: "strong" }} />],
            ["Deadline", p.deadline],
            [
              "Other claims",
              Array.isArray(p.other_claims) && p.other_claims.length > 0 ? (
                <ul className="plain small">
                  {p.other_claims.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              ) : null,
            ],
          ]}
        />
      </div>

      <div className="sub">
        <h3 className="h3">What the destination appears to be</h3>
        <KvTable
          rows={[
            ["Apparent purpose", d.apparent_purpose],
            ["Apparent organization", d.apparent_organization],
            ["Requested user action", d.requested_user_action],
            ["Collects credentials", <Flag value={d.collects_credentials} />],
            ["Requests payment", <Flag value={d.requests_payment} />],
            ["Matches poster claims", <Flag value={d.matches_poster_claims} tones={MATCH_TONE} />],
          ]}
        />
      </div>

      <div className="sub">
        <h3 className="h3">Contradictions</h3>
        {contradictions.length === 0 ? (
          <Empty>No contradictions reported by the model.</Empty>
        ) : (
          <ul className="plain contradictions">
            {contradictions.map((c, i) => (
              <li key={i} className="contradiction">
                <Chip tone={SEVERITY_TONE[c.severity] || "info"}>{c.severity} severity</Chip>
                <div>
                  <div>
                    <span className="label">Poster:</span> {c.poster_claim}
                  </div>
                  <div>
                    <span className="label">Destination:</span> {c.destination_observation}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="sub">
        <h3 className="h3">Evidence</h3>
        {evidence.length === 0 ? (
          <Empty>No evidence items.</Empty>
        ) : (
          <ul className="plain evidence">
            {evidence.map((e, i) => {
              const verified = e.source === "deterministic" && e.fact_id && known.has(e.fact_id);
              return (
                <li
                  key={i}
                  className={`evidence-row ${verified ? "evidence-verified" : ""}`}
                  onMouseEnter={() => verified && onHoverFact && onHoverFact(e.fact_id)}
                  onMouseLeave={() => onHoverFact && onHoverFact(null)}
                  onFocus={() => verified && onHoverFact && onHoverFact(e.fact_id)}
                  onBlur={() => onHoverFact && onHoverFact(null)}
                  tabIndex={0}
                >
                  <span className="chips">
                    {verified ? (
                      <Chip tone="verified" title="Cites a server fact; hover to highlight it">
                        Verified {e.fact_id}
                      </Chip>
                    ) : (
                      <Chip tone="hybrid">Model inference</Chip>
                    )}
                    <Chip tone={SUPPORTS_TONE[e.supports] || "info"}>supports {e.supports}</Chip>
                  </span>
                  <span>{e.fact}</span>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {uncertainties.length > 0 && (
        <div className="sub">
          <h3 className="h3">Uncertainties</h3>
          <ul className="plain small uncertainties">
            {uncertainties.map((u, i) => (
              <li key={i}>{u}</li>
            ))}
          </ul>
        </div>
      )}

      <Adjustments items={adjustments} />
      <SmallPrint meta={meta} />
    </Card>
  );
}

function Adjustments({ items }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="sub">
      <h3 className="h3">Server adjustments to the model output</h3>
      <ul className="plain small adjustments">
        {items.map((a, i) => (
          <li key={i}>
            <span className="mono">{a.rule}</span>
            {a.from !== undefined && a.to !== undefined && (
              <>
                : <span className="mono">{String(a.from)}</span> to <span className="mono">{String(a.to)}</span>
              </>
            )}
            {a.note && <div className="muted">{a.note}</div>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function SmallPrint({ meta }) {
  const parts = [];
  if (meta.model) parts.push(`model ${meta.model}`);
  if (meta.parse_path) parts.push(`parse path ${meta.parse_path}`);
  if (meta.latency_ms !== undefined && meta.latency_ms !== null) parts.push(`latency ${fmtMs(meta.latency_ms)}`);
  if (meta.generation && meta.generation.thinkingLevel) parts.push(`thinking ${meta.generation.thinkingLevel}`);
  if (meta.usage) {
    const u = meta.usage;
    if (u.prompt_image_tokens) parts.push(`image tokens ${u.prompt_image_tokens}`);
    if (u.prompt_tokens) parts.push(`prompt tokens ${u.prompt_tokens}`);
    if (u.output_tokens) parts.push(`output tokens ${u.output_tokens}`);
    if (u.thoughts_tokens) parts.push(`thought tokens ${u.thoughts_tokens}`);
    if (u.finish_reason) parts.push(`finish ${u.finish_reason}`);
  }
  if (meta.calls) parts.push(`${meta.calls} model call${meta.calls === 1 ? "" : "s"}`);
  if (meta.cached) parts.push("cached");
  if (Array.isArray(meta.validation_notes) && meta.validation_notes.length) {
    parts.push(`${meta.validation_notes.length} validation note${meta.validation_notes.length === 1 ? "" : "s"}`);
  }
  if (parts.length === 0) return null;
  return (
    <p className="small-print mono" title={(meta.validation_notes || []).join("\n")}>
      {parts.join(" | ")}
    </p>
  );
}
