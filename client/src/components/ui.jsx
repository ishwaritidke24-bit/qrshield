import React, { useState } from "react";

/** Small coloured pill. tone -> .chip-<tone> */
export function Chip({ tone = "neutral", children, title }) {
  return (
    <span className={`chip chip-${tone}`} title={title}>
      {children}
    </span>
  );
}

/** Card with a heading and optional subtitle/aside. */
export function Card({ title, subtitle, aside, children, className = "" }) {
  return (
    <section className={`card ${className}`}>
      {(title || aside) && (
        <header className="card-head">
          <div>
            {title && <h2 className="card-title">{title}</h2>}
            {subtitle && <p className="card-subtitle">{subtitle}</p>}
          </div>
          {aside && <div className="card-aside">{aside}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

/** Collapsible pre-formatted JSON. */
export function JsonToggle({ label = "Raw JSON", value }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="json-toggle">
      <button type="button" className="link-btn" onClick={() => setOpen((v) => !v)}>
        {open ? "Hide" : "Show"} {label}
      </button>
      {open && <pre className="json">{JSON.stringify(value, null, 2)}</pre>}
    </div>
  );
}

/** Two-column key/value table. rows: [label, node][] ; nullish values show as a dash. */
export function KvTable({ rows }) {
  return (
    <table className="kv">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <th scope="row">{k}</th>
            <td>{v === null || v === undefined || v === "" ? <span className="muted">-</span> : v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function Empty({ children }) {
  return <p className="muted empty">{children}</p>;
}
