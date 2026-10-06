import React from "react";
import { Card, Chip, Empty } from "./ui.jsx";

/** Hop-by-hop redirect chain with blocked hops highlighted. */
export default function RedirectChain({ chain, destination }) {
  const hops = Array.isArray(chain) ? chain : [];
  if (hops.length === 0) {
    if (destination && destination.fetched === false && destination.error_code) {
      return (
        <Card title="Redirect chain">
          <Empty>
            Not fetched: <span className="mono">{destination.error_code}</span>
            {destination.error_message ? ` - ${destination.error_message}` : ""}
          </Empty>
        </Card>
      );
    }
    return null;
  }
  const finalUrl = destination && destination.final_url;

  return (
    <Card
      title="Redirect chain"
      subtitle="Only HTTP 3xx redirects are followed. meta-refresh and JavaScript redirects are recorded, not followed."
    >
      <ol className="hops">
        {hops.map((hop, i) => (
          <li key={i} className={`hop ${hop.blocked ? "hop-blocked" : ""}`}>
            <div className="hop-head">
              <span className="hop-n">{i + 1}</span>
              <span className="hop-host mono">{hop.host || "?"}</span>
              {hop.status !== null && hop.status !== undefined && (
                <Chip tone={hop.status >= 400 ? "warn" : "outline"}>HTTP {hop.status}</Chip>
              )}
              {hop.downgrade && <Chip tone="strong">HTTPS to HTTP downgrade</Chip>}
              {hop.cross_domain && <Chip tone="medium">cross-domain</Chip>}
              {hop.blocked && <Chip tone="critical">blocked</Chip>}
            </div>
            <div className="hop-url mono break">{hop.url}</div>
            {Array.isArray(hop.addresses) && hop.addresses.length > 0 && (
              <div className="hop-addr muted mono">resolves to {hop.addresses.join(", ")}</div>
            )}
            {hop.location && (
              <div className="hop-loc muted">
                redirects to <span className="mono break">{hop.location}</span>
              </div>
            )}
            {hop.blocked && hop.blocked_reason && <div className="hop-reason">Blocked: {hop.blocked_reason}</div>}
          </li>
        ))}
      </ol>
      {finalUrl && (
        <div className="final-url">
          <span className="label">Final URL</span> <span className="mono break">{finalUrl}</span>
        </div>
      )}
    </Card>
  );
}
