// Hand-written validation of Gemma output against server/prompts/schema.json
// plus the deterministic guardrail pass. No dependencies beyond node core.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
export const SCHEMA = JSON.parse(
  readFileSync(path.join(here, "..", "prompts", "schema.json"), "utf8"),
);

/** Payload kinds whose "destination" is the payload itself, not an HTTP page. */
const NON_HTTP_KINDS = new Set([
  "upi",
  "tel",
  "sms",
  "mailto",
  "wifi",
  "geo",
  "crypto",
  "appstore",
  "intent",
]);

const VOCAB_RE = /\b(malicious|definitely|certainly|confirmed scam)\b/gi;

/**
 * Default value for a schema node, used when a required key is missing.
 * @param {object} node
 */
function defaultFor(node) {
  if (!node) return null;
  if (node.enum) {
    for (const pref of ["unspecified", "unknown", "none", "neutral", "model", "INSUFFICIENT_EVIDENCE"]) {
      if (node.enum.includes(pref)) return pref;
    }
    return node.enum[0];
  }
  const types = Array.isArray(node.type) ? node.type : [node.type];
  if (types.includes("null")) return null;
  if (types.includes("array")) return [];
  if (types.includes("object")) {
    const out = {};
    for (const key of node.required || []) out[key] = defaultFor(node.properties?.[key]);
    return out;
  }
  if (types.includes("number") || types.includes("integer")) return 0;
  if (types.includes("boolean")) return false;
  if (types.includes("string")) return "";
  return null;
}

/**
 * Map a loosely formatted enum value onto a schema enum member.
 * @returns {string|null}
 */
function coerceEnum(value, members) {
  if (typeof value !== "string") return null;
  if (members.includes(value)) return value;
  const norm = value.trim().replace(/[\s-]+/g, "_");
  const hit = members.find((m) => m.toLowerCase() === norm.toLowerCase());
  return hit || null;
}

/**
 * Validate `value` against schema `node`, returning the cleaned value.
 * Pushes to errors (hard) and notes (soft coercions). Returns undefined when
 * the value must be dropped.
 */
function validateNode(value, node, pathStr, errors, notes, ctx) {
  const types = Array.isArray(node.type) ? node.type : [node.type];
  const nullable = types.includes("null");

  if (value === null || value === undefined) {
    if (nullable) return null;
    if (ctx.inArrayItem) {
      errors.push(`${pathStr}: missing value`);
      return undefined;
    }
    notes.push(`${pathStr}: missing, defaulted`);
    return defaultFor(node);
  }

  if (node.enum) {
    const coerced = coerceEnum(value, node.enum);
    if (coerced === null) {
      errors.push(`${pathStr}: invalid enum value ${JSON.stringify(value).slice(0, 60)}`);
      return undefined;
    }
    if (coerced !== value) notes.push(`${pathStr}: enum normalized`);
    return coerced;
  }

  if (types.includes("object")) {
    if (typeof value !== "object" || Array.isArray(value)) {
      if (ctx.inArrayItem) {
        errors.push(`${pathStr}: expected object`);
        return undefined;
      }
      notes.push(`${pathStr}: expected object, defaulted`);
      return defaultFor(node);
    }
    const out = {};
    const props = node.properties || {};
    for (const key of Object.keys(value)) {
      if (!(key in props)) notes.push(`${pathStr}.${key}: unknown key dropped`);
    }
    for (const key of Object.keys(props)) {
      const sub = validateNode(value[key], props[key], `${pathStr}.${key}`, errors, notes, ctx);
      if (sub !== undefined) out[key] = sub;
    }
    return out;
  }

  if (types.includes("array")) {
    let arr = value;
    if (!Array.isArray(arr)) {
      if (typeof arr === "string" && arr.trim()) {
        notes.push(`${pathStr}: string wrapped into array`);
        arr = [arr];
      } else {
        notes.push(`${pathStr}: expected array, defaulted to []`);
        return [];
      }
    }
    if (node.maxItems !== undefined && arr.length > node.maxItems) {
      notes.push(`${pathStr}: truncated from ${arr.length} to ${node.maxItems} items`);
      arr = arr.slice(0, node.maxItems);
    }
    const out = [];
    arr.forEach((item, i) => {
      const itemErrors = [];
      const sub = validateNode(item, node.items || {}, `${pathStr}[${i}]`, itemErrors, notes, {
        ...ctx,
        inArrayItem: true,
      });
      if (itemErrors.length || sub === undefined) {
        notes.push(`${pathStr}[${i}]: dropped (${itemErrors.join("; ") || "invalid"})`);
      } else {
        out.push(sub);
      }
    });
    return out;
  }

  if (types.includes("number") || types.includes("integer")) {
    let n = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(n)) {
      notes.push(`${pathStr}: not a number, set to 0`);
      n = 0;
    } else if (typeof value !== "number") {
      notes.push(`${pathStr}: coerced to number`);
    }
    if (node.minimum !== undefined && n < node.minimum) {
      notes.push(`${pathStr}: clamped up to ${node.minimum}`);
      n = node.minimum;
    }
    if (node.maximum !== undefined && n > node.maximum) {
      notes.push(`${pathStr}: clamped down to ${node.maximum}`);
      n = node.maximum;
    }
    return n;
  }

  if (types.includes("boolean")) {
    if (typeof value === "boolean") return value;
    notes.push(`${pathStr}: coerced to boolean`);
    return value === "true" || value === 1;
  }

  if (types.includes("string")) {
    let s = value;
    if (typeof s !== "string") {
      if (typeof s === "object") {
        if (ctx.inArrayItem) {
          errors.push(`${pathStr}: expected string`);
          return undefined;
        }
        notes.push(`${pathStr}: expected string, defaulted`);
        return nullable ? null : "";
      }
      notes.push(`${pathStr}: coerced to string`);
      s = String(s);
    }
    // strip control characters
    s = s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
    if (node.maxLength !== undefined && s.length > node.maxLength) {
      notes.push(`${pathStr}: truncated to ${node.maxLength} chars`);
      s = s.slice(0, node.maxLength - 1) + "…";
    }
    return s;
  }

  return value;
}

/**
 * Validate a parsed model object against the Gemma output schema.
 * Hard errors only for a missing/invalid risk_level or an invalid enum
 * outside array items (invalid array items are dropped with a note).
 * Everything else is coerced with a note.
 * @param {unknown} obj
 * @param {object|null} [packet] evidence packet (context only)
 * @returns {{ ok: boolean, value: object|null, errors: string[], notes: string[] }}
 */
export function validateReasoning(obj, packet = null) {
  const errors = [];
  const notes = [];
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    return { ok: false, value: null, errors: ["root: not an object"], notes };
  }
  if (obj.risk_level === undefined || obj.risk_level === null) {
    return { ok: false, value: null, errors: ["risk_level: missing"], notes };
  }
  const value = validateNode(obj, SCHEMA, "$", errors, notes, { inArrayItem: false, packet });
  if (errors.length) return { ok: false, value: null, errors, notes };

  // Deterministic evidence must carry a fact id (the guardrail pass checks it exists).
  for (const [i, ev] of (value.evidence || []).entries()) {
    if (ev.source === "deterministic" && !ev.fact_id) {
      notes.push(`$.evidence[${i}]: deterministic without fact_id, relabeled model`);
      ev.source = "model";
      ev.fact_id = null;
    }
  }
  return { ok: true, value, errors, notes };
}

/** Collect the set of citable fact ids from the packet and/or facts result. */
function knownFactIds(packet, facts) {
  const ids = new Set();
  for (const f of packet?.server_facts || []) if (f && f.id) ids.add(f.id);
  for (const f of facts?.server_facts || []) if (f && f.id) ids.add(f.id);
  return ids;
}

/**
 * Apply the deterministic guardrails (a)-(e) to a validated reasoning object.
 * Does NOT raise the risk floor; report.js does that.
 * @param {object} reasoning validated Gemma output
 * @param {{ packet: object, facts?: object }} ctx
 * @returns {{ reasoning: object, adjustments: Array<{rule:string, from:any, to:any, note:string}> }}
 */
export function applyGuardrails(reasoning, { packet, facts } = {}) {
  const adjustments = [];
  if (!reasoning || typeof reasoning !== "object") return { reasoning, adjustments };
  const out = structuredClone(reasoning);
  const ids = knownFactIds(packet, facts);
  const fetched = packet?.destination?.fetched === true;
  const payloadKind = packet?.payload?.kind || null;
  // UPI/tel/wifi... payloads have no HTTP destination; the payload itself is the
  // fully known destination, so the "not fetched" caps (c) and (d) do not apply.
  const nonHttpPayload = NON_HTTP_KINDS.has(payloadKind) && packet?.payload?.fetchable === false;

  // (a) unverified deterministic citations become model inference.
  out.evidence = (out.evidence || []).map((ev, i) => {
    if (ev.source === "deterministic" && !ids.has(ev.fact_id)) {
      adjustments.push({
        rule: "unverified_fact_relabeled",
        from: `deterministic:${ev.fact_id}`,
        to: "model:null",
        note: `evidence[${i}] cited ${ev.fact_id || "no fact id"}, which is not a server fact`,
      });
      return { ...ev, source: "model", fact_id: null };
    }
    return ev;
  });

  const highContradiction = (out.contradictions || []).some((c) => c.severity === "high");
  const deterministicRisk = out.evidence.some(
    (e) => e.source === "deterministic" && e.supports === "risk",
  );
  // Semantic basis = something only the cross-check can know: a high-severity
  // poster-versus-destination contradiction, or the destination asking for
  // credentials or payment, or an outright mismatch. Technical URL/network
  // signals are NOT a semantic basis; the server already weighs those in the
  // deterministic floor, and the model may not out-escalate the floor with them.
  const dest = out.destination_analysis || {};
  const semanticBasis =
    highContradiction ||
    dest.collects_credentials === "yes" ||
    dest.requests_payment === "yes" ||
    dest.matches_poster_claims === "mismatch";
  const floorLevel = packet?.deterministic_floor?.level || null;
  const escalated = out.risk_level === "HIGH_RISK" || out.risk_level === "CRITICAL";

  // (b) HIGH/CRITICAL about an unfetched destination needs a semantic basis.
  if (!fetched && escalated && !semanticBasis) {
    adjustments.push({
      rule: "downgraded_insufficient_destination_evidence",
      from: out.risk_level,
      to: "INSUFFICIENT_EVIDENCE",
      note: "destination not fetched and no semantic basis (no high-severity contradiction, credential or payment collection, or mismatch); the deterministic floor still applies",
    });
    out.risk_level = "INSUFFICIENT_EVIDENCE";
  }

  // (b2) Technical signals alone never justify a model level above the
  // deterministic floor. Cap at the floor, or at MEDIUM_RISK when there is none.
  if (escalated && !semanticBasis && out.risk_level !== "INSUFFICIENT_EVIDENCE") {
    const RANK = { LOW_RISK: 1, MEDIUM_RISK: 2, HIGH_RISK: 3, CRITICAL: 4 };
    const cap = floorLevel && RANK[floorLevel] ? floorLevel : "MEDIUM_RISK";
    if ((RANK[out.risk_level] || 0) > (RANK[cap] || 0)) {
      adjustments.push({
        rule: "technical_only_escalation_capped",
        from: out.risk_level,
        to: cap,
        note: floorLevel
          ? "no semantic basis; technical signals are already weighed by the deterministic floor"
          : "no semantic basis and no deterministic floor; technical signals alone justify at most MEDIUM_RISK",
      });
      out.risk_level = cap;
    }
  }

  // (c) confidence cap when the destination page was not fetched.
  if (!fetched && !nonHttpPayload && typeof out.confidence === "number" && out.confidence > 0.5) {
    adjustments.push({
      rule: "confidence_capped",
      from: out.confidence,
      to: 0.5,
      note: "destination not fetched; confidence capped at 0.5",
    });
    out.confidence = 0.5;
  }

  // (d) no organization claim about an unfetched destination.
  if (
    !fetched &&
    !nonHttpPayload &&
    out.destination_analysis &&
    out.destination_analysis.apparent_organization
  ) {
    adjustments.push({
      rule: "unfetched_destination_organization_cleared",
      from: out.destination_analysis.apparent_organization,
      to: null,
      note: "destination not fetched; apparent_organization cannot be observed",
    });
    out.destination_analysis.apparent_organization = null;
  }

  // (e) vocabulary guard.
  if (!highContradiction && !deterministicRisk) {
    for (const key of ["summary_for_user", "recommended_action"]) {
      const text = out[key];
      if (typeof text !== "string") continue;
      VOCAB_RE.lastIndex = 0;
      if (VOCAB_RE.test(text)) {
        VOCAB_RE.lastIndex = 0;
        const softened = text.replace(VOCAB_RE, "appears suspicious");
        adjustments.push({
          rule: "vocabulary_softened",
          from: text,
          to: softened,
          note: `${key} used absolute wording without strong evidence`,
        });
        out[key] = softened;
      }
      VOCAB_RE.lastIndex = 0;
    }
  }

  return { reasoning: out, adjustments };
}
