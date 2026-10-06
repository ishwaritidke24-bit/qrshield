import React from "react";

/**
 * The visual centrepiece: what the poster claims (physical evidence) versus
 * what the QR destination does (digital evidence), joined by the cross-check
 * that produced the contradictions. Pure presentation of report data.
 */
function val(v) {
  return v === null || v === undefined || v === "" ? null : String(v);
}

function Line({ k, v }) {
  const text = val(v);
  return (
    <div className="xc-line">
      <span className="xc-k">{k}</span>
      <span className={`xc-v ${text ? "" : "xc-none"}`}>{text || "not stated"}</span>
    </div>
  );
}

export default function CrossCheck({ report }) {
  if (!report) return null;
  const facts = report.facts || {};
  const reasoning = report.reasoning || null;
  const meta = report.reasoning_meta || {};
  const available = meta.available === true && reasoning;
  const p = (reasoning && reasoning.poster_analysis) || {};
  const d = (reasoning && reasoning.destination_analysis) || {};
  const contradictions = (reasoning && Array.isArray(reasoning.contradictions) ? reasoning.contradictions : []).slice(0, 3);
  const payload = facts.payload || {};
  const dest = facts.destination || {};
  const chain = Array.isArray(facts.redirect_chain) ? facts.redirect_chain : [];
  const where = dest.final_url || (chain.length ? chain[chain.length - 1].url : null) || payload.raw || payload.value || null;
  const match = d.matches_poster_claims || "unknown";
  const hasImage = report.input && report.input.mode === "image";

  return (
    <section className={`xc xc-${match}`} aria-label="Cross-check of poster claims against the QR destination">
      <header className="xc-head">
        <span className="xc-tag">Cross-check</span>
        <h2>What the poster claims <span className="xc-vs">vs</span> what the QR destination does</h2>
      </header>

      <div className="xc-grid">
        <div className="xc-side xc-physical">
          <div className="xc-side-head">
            <span className="xc-num">A</span>
            <span>Physical evidence</span>
            <span className="xc-src">{hasImage ? "read from the poster image by Gemma 4" : "no poster image supplied"}</span>
          </div>
          <Line k="Claims to be" v={p.claimed_organization} />
          <Line k="Offers" v={p.offer} />
          <Line k="Asks you to" v={p.requested_action} />
          <Line k="About money" v={p.payment_claim && p.payment_claim !== "unspecified" ? p.payment_claim.replace(/_/g, " ") : null} />
          <Line k="Deadline" v={p.deadline} />
        </div>

        <div className="xc-join" aria-hidden="true">
          <span className="xc-join-line" />
          <span className={`xc-join-badge xc-badge-${match}`}>
            {match === "mismatch" ? "MISMATCH" : match === "match" ? "CONSISTENT" : match === "partial" ? "PARTIAL" : "UNVERIFIED"}
          </span>
          <span className="xc-join-line" />
        </div>

        <div className="xc-side xc-digital">
          <div className="xc-side-head">
            <span className="xc-num">B</span>
            <span>Digital destination</span>
            <span className="xc-src">decoded and inspected by the server</span>
          </div>
          <Line k="QR contains" v={payload.kind ? `${payload.kind.replace(/_/g, " ")} payload` : null} />
          <div className="xc-line">
            <span className="xc-k">Leads to</span>
            <span className={`xc-v mono xc-url ${where ? "" : "xc-none"}`}>{where || "nothing decodable"}</span>
          </div>
          <Line k="Appears to be" v={d.apparent_purpose} />
          <Line k="Asks you to" v={d.requested_user_action} />
          <Line
            k="Wants"
            v={
              d.collects_credentials === "yes" && d.requests_payment === "yes"
                ? "credentials and payment"
                : d.collects_credentials === "yes"
                  ? "credentials"
                  : d.requests_payment === "yes"
                    ? "payment"
                    : d.collects_credentials === "no" && d.requests_payment === "no"
                      ? "nothing sensitive"
                      : null
            }
          />
        </div>
      </div>

      {available ? (
        contradictions.length > 0 ? (
          <ol className="xc-contras" aria-label="Contradictions found">
            {contradictions.map((c, i) => (
              <li key={i} className={`xc-contra xc-sev-${c.severity || "medium"}`}>
                <div className="xc-claim">
                  <span className="xc-mini">Poster says</span>
                  <q>{c.poster_claim}</q>
                </div>
                <div className="xc-arrow">
                  <span className="xc-arrow-line" />
                  <span className="xc-arrow-label">{(c.severity || "medium")} severity contradiction</span>
                  <span className="xc-arrow-line" />
                </div>
                <div className="xc-observed">
                  <span className="xc-mini">Destination does</span>
                  <q>{c.destination_observation}</q>
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="xc-clear">No contradiction between the poster and the destination was found by Gemma 4. Technical facts still apply.</p>
        )
      ) : (
        <p className="xc-clear xc-unavail">Gemma 4 cross-check unavailable for this report; the verdict rests on the verified technical facts below.</p>
      )}
    </section>
  );
}
