import React from "react";
import { Card, Chip, KvTable, Empty } from "./ui.jsx";

const HIDDEN_KEY = /pass|psk|pin|secret/i;

/** Render parsed payload fields, never a Wi-Fi password or PIN-like field. */
function parsedRows(parsed) {
  if (!parsed || typeof parsed !== "object") return [];
  return Object.entries(parsed).map(([k, v]) => {
    if (HIDDEN_KEY.test(k) || k === "P") {
      return [k, <Chip tone="outline">hidden</Chip>];
    }
    let text;
    if (Array.isArray(v)) text = v.join(", ");
    else if (v !== null && typeof v === "object") text = JSON.stringify(v);
    else text = String(v);
    return [k, <span className="mono break">{text}</span>];
  });
}

/** Raw payload safe to display: Wi-Fi passwords are masked in place. */
function displayPayload(raw, kind) {
  const s = String(raw ?? "");
  if (kind === "wifi" || /^WIFI:/i.test(s)) {
    return s.replace(/(;|^)(P):([^;]*)/gi, "$1$2:********");
  }
  return s;
}

/** Decoded QR payload, its classification and whether it was fetchable. */
export default function PayloadCard({ qr, payload }) {
  if (!qr) return null;
  const kind = payload && payload.kind;
  const isUrl = kind === "url";
  const count = qr.count || 1;
  const shown = displayPayload(qr.payload, kind);

  return (
    <Card
      title="QR payload"
      aside={
        qr.found ? (
          <Chip tone="outline" title="Decoder method and number of codes found">
            {qr.decode_method || "decoded"} / {count} code{count === 1 ? "" : "s"}
          </Chip>
        ) : (
          <Chip tone="warn">no QR found</Chip>
        )
      }
    >
      {!qr.found ? (
        <Empty>{qr.error || "No QR code could be decoded from this image."}</Empty>
      ) : (
        <>
          <div className="payload-raw">
            <div className="label">Decoded payload</div>
            <code className="mono break payload-text">{shown}</code>
          </div>
          <div className="row gap">
            <span className="label">Kind</span>
            <Chip tone={isUrl ? "info" : "neutral"}>{kind || "unknown"}</Chip>
            {payload && payload.fetchable === false && <Chip tone="outline">destination not fetched</Chip>}
          </div>
          {payload && !isUrl && (
            <p className="notice">
              Not a web link: destination not fetched.
              {payload.reason ? ` ${payload.reason}` : ""}
            </p>
          )}
          {payload && payload.parsed && Object.keys(payload.parsed).length > 0 && (
            <KvTable rows={parsedRows(payload.parsed)} />
          )}
          {payload && Array.isArray(payload.embedded_urls) && payload.embedded_urls.length > 0 && (
            <div className="sub">
              <div className="label">Embedded URLs</div>
              <ul className="plain mono break">
                {payload.embedded_urls.map((u) => (
                  <li key={u}>{u}</li>
                ))}
              </ul>
            </div>
          )}
          {Array.isArray(qr.all_payloads) && qr.all_payloads.length > 1 && (
            <div className="sub">
              <div className="label">All payloads found</div>
              <ul className="plain mono break">
                {qr.all_payloads.map((p, i) => (
                  <li key={i}>{displayPayload(p, kind)}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </Card>
  );
}
