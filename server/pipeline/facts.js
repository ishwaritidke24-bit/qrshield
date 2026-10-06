// Deterministic facts layer: dedupes and ranks signals from every stage,
// restates them as plain-English server facts (F1..Fn), computes the risk
// floor and the fallback risk table, and builds the sanitized evidence packet
// that is the ONLY destination/page information Gemma ever sees.

import {
  PACKET_CAPS,
  RISK_RANK,
  STRENGTH_RANK,
  clampText,
} from "./contracts.js";

const PACKET_SCHEMA_VERSION = "1.0";

/** Signal ids that mean the page asks for secrets. */
export const SENSITIVE_FIELD_SIGNALS = Object.freeze([
  "credential_form_present",
  "payment_or_identity_fields_present",
]);

const HIGH_RISK_PARTNERS = Object.freeze([
  "form_action_cross_origin",
  "form_action_http",
  "ip_literal_host",
  "confusable_host",
  "brand_keyword_outside_registrable_domain",
  "free_hosting_or_form_builder",
]);
const CRITICAL_PARTNERS = Object.freeze(["confusable_host", "brand_keyword_outside_registrable_domain"]);
const HIGH_RISK_SOLO = Object.freeze([
  "apk_download",
  "redirect_to_blocked_target",
  "destination_resolves_to_private_network",
  "blocked_scheme",
]);

// Neutral signal ids whose content is already covered by the synthesized
// destination fact, so they are not repeated in server_facts.
const NEUTRAL_COVERED = new Set([
  "destination_fetched_ok",
  "dns_nxdomain",
  "fetch_timeout",
  "destination_http_error",
]);

// Keys that must never leave the server, whatever stage produced them.
const SECRET_KEY_RE = /(password|passwd|pwd|secret|token|api[_-]?key|cookie|authorization|credential|pin)/i;
const MAX_PARSED_KEYS = 12;
const MAX_PARSED_VALUE = 200;

// Local copy of the sanitizeForPrompt contract so this module works even when
// sanitizeHtml.js is unavailable; the real implementation is preferred.
const INJECTION_LINE_RE = /ignore (all|previous|prior) instructions|^\s*(system|assistant)\s*:|you are (now|an?) /i;
// Control chars, DEL, zero-width chars, line/paragraph separators and BOM.
// Built from code points so no escape sequence can be mangled by tooling.
const NON_PRINTABLE_RE = new RegExp(
  "[" +
    [[0x00, 0x08], [0x0b, 0x0c], [0x0e, 0x1f], [0x7f, 0x7f], [0x200b, 0x200f], [0x2028, 0x2029], [0xfeff, 0xfeff]]
      .map(([a, b]) => (a === b ? String.fromCodePoint(a) : String.fromCodePoint(a) + "-" + String.fromCodePoint(b)))
      .join("") +
    "]",
  "g",
);
function localSanitizeForPrompt(text, maxChars = PACKET_CAPS.visibleText) {
  if (text === null || text === undefined) return "";
  const lines = String(text)
    .replace(NON_PRINTABLE_RE, "")
    .split(/\r?\n/)
    .filter((line) => !INJECTION_LINE_RE.test(line));
  const collapsed = lines.join("\n").replace(/\s+/g, " ").trim();
  return collapsed.length > maxChars ? collapsed.slice(0, maxChars - 1) + "…" : collapsed;
}
let sanitizeForPrompt = localSanitizeForPrompt;
try {
  const mod = await import("./sanitizeHtml.js");
  if (typeof mod.sanitizeForPrompt === "function") sanitizeForPrompt = mod.sanitizeForPrompt;
} catch {
  /* sanitizeHtml.js missing or broken: keep the local implementation */
}

/**
 * @typedef {import('./contracts.js').signal extends (...a: any) => infer R ? R : never} Signal
 */

/** @param {Signal} s */
function rank(s) {
  return STRENGTH_RANK[s && s.strength] ?? 0;
}

/**
 * Dedupe by id (keep the strongest), sort by strength desc then id asc, cap.
 * @param {Signal[]} signals
 * @param {number} cap
 * @returns {Signal[]}
 */
export function normalizeSignals(signals, cap = PACKET_CAPS.signals) {
  /** @type {Map<string, Signal>} */
  const byId = new Map();
  for (const s of signals || []) {
    if (!s || typeof s.id !== "string" || !s.id) continue;
    const prev = byId.get(s.id);
    if (!prev || rank(s) > rank(prev)) byId.set(s.id, s);
  }
  return [...byId.values()]
    .sort((a, b) => rank(b) - rank(a) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .slice(0, cap);
}

/**
 * Deterministic risk floor. Only strong/critical combinations ever produce a
 * floor; weak and neutral signals alone never do.
 * @param {Signal[]} signals
 * @returns {{ level: string|null, triggered_by: string[] }}
 */
export function computeFloor(signals) {
  const ids = new Set((signals || []).map((s) => s && s.id).filter(Boolean));
  const has = (id) => ids.has(id);
  const sensitive = SENSITIVE_FIELD_SIGNALS.filter(has);

  if (sensitive.length) {
    const partners = CRITICAL_PARTNERS.filter(has);
    if (partners.length) return { level: "CRITICAL", triggered_by: [...sensitive, ...partners] };
  }

  /** @type {string[]} */
  const high = [];
  if (sensitive.length) {
    const partners = HIGH_RISK_PARTNERS.filter(has);
    if (partners.length) high.push(...sensitive, ...partners);
  }
  for (const id of HIGH_RISK_SOLO) if (has(id)) high.push(id);
  if (high.length) return { level: "HIGH_RISK", triggered_by: [...new Set(high)] };

  const strongOrCritical = (signals || []).filter((s) => rank(s) >= STRENGTH_RANK.strong).map((s) => s.id);
  if (strongOrCritical.length) return { level: "MEDIUM_RISK", triggered_by: [...new Set(strongOrCritical)] };

  return { level: null, triggered_by: [] };
}

/**
 * Deterministic verdict used when Gemma is unavailable (table from
 * docs/ARCHITECTURE.md), raised by the floor when the floor is higher.
 * @param {Signal[]} signals
 * @param {{ destinationFetched?: boolean, qrFound?: boolean, payloadKind?: string|null }} ctx
 * @returns {string}
 */
export function fallbackRisk(signals, { destinationFetched = false, qrFound = false, payloadKind = null } = {}) {
  const list = normalizeSignals(signals, Number.MAX_SAFE_INTEGER);
  const noPayload = !payloadKind || payloadKind === "none";
  if (!qrFound && noPayload) return "INSUFFICIENT_EVIDENCE";

  const count = (strength) => list.filter((s) => s.strength === strength).length;
  let level;
  if (count("critical") >= 1) level = "CRITICAL";
  else if (count("strong") >= 2) level = "HIGH_RISK";
  else if (count("strong") === 1 || count("medium") >= 2) level = "MEDIUM_RISK";
  else if (destinationFetched && list.every((s) => rank(s) <= STRENGTH_RANK.weak)) level = "LOW_RISK";
  else return "INSUFFICIENT_EVIDENCE";

  const floor = computeFloor(list);
  if (floor.level && RISK_RANK[floor.level] > RISK_RANK[level]) level = floor.level;
  return level;
}

/**
 * Keep a parsed payload object small and free of secrets.
 * @param {object|null|undefined} parsed
 */
function sanitizeParsed(parsed) {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  /** @type {Record<string, unknown>} */
  const out = {};
  let n = 0;
  for (const [k, v] of Object.entries(parsed)) {
    if (n >= MAX_PARSED_KEYS) break;
    if (SECRET_KEY_RE.test(k) && !/_present$/.test(k)) continue;
    if (v === null || v === undefined) {
      out[k] = null;
    } else if (typeof v === "boolean" || typeof v === "number") {
      out[k] = v;
    } else if (typeof v === "string") {
      out[k] = clampText(v, MAX_PARSED_VALUE);
    } else if (Array.isArray(v)) {
      out[k] = v
        .slice(0, 5)
        .filter((x) => ["string", "number", "boolean"].includes(typeof x))
        .map((x) => (typeof x === "string" ? clampText(x, MAX_PARSED_VALUE) : x));
    } else {
      continue; // nested objects are dropped
    }
    n++;
  }
  return out;
}

/** @param {unknown} v */
function valueToText(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === "string") return clampText(v, MAX_PARSED_VALUE);
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return clampText(JSON.stringify(v), MAX_PARSED_VALUE);
  } catch {
    return null;
  }
}

/**
 * Accept either the full analyzeUrl() result ({ url, signals }) or the inner
 * url parts object.
 * @param {object|null|undefined} url
 */
function urlParts(url) {
  if (!url || typeof url !== "object") return null;
  if (url.url && typeof url.url === "object" && "scheme" in url.url) return url.url;
  if ("scheme" in url || "hostname" in url) return url;
  return null;
}

/**
 * Plain-English neutral facts about what the pipeline observed, independent
 * of any signal.
 * @returns {string[]}
 */
function synthesizedFacts({ qr, payload, parts, fetch }) {
  /** @type {string[]} */
  const out = [];
  const kind = (payload && payload.kind) || "none";

  if (qr && qr.found) {
    const extra = qr.count > 1 ? ` (${qr.count} QR codes found; the first was analyzed)` : "";
    out.push(`A QR code was decoded from the image${extra}; its payload was classified as "${kind}".`);
  } else if (qr && qr.found === false) {
    out.push(`No QR code could be decoded from the image${qr.error ? ` (${qr.error})` : ""}.`);
  } else if (payload) {
    out.push(`The analyzed link was supplied manually and classified as "${kind}".`);
  }

  if (payload && payload.fetchable === false && payload.reason) {
    out.push(`The destination was not fetched: ${payload.reason}.`);
  }

  if (fetch) {
    const hops = Math.max(0, (fetch.chain || []).length - 1);
    if (fetch.ok) {
      const status = fetch.status !== null && fetch.status !== undefined ? ` (HTTP ${fetch.status})` : "";
      const hopText = hops ? ` after ${hops} redirect${hops === 1 ? "" : "s"}` : " with no redirects";
      const ct = fetch.headers && fetch.headers.content_type ? `, content type ${String(fetch.headers.content_type).split(";")[0].trim()}` : "";
      out.push(`The destination page was fetched successfully${status}${hopText}${ct}.`);
    } else if (fetch.error) {
      const hopText = hops ? ` after ${hops} redirect${hops === 1 ? "" : "s"}` : "";
      out.push(`The destination could not be fetched${hopText}: ${fetch.error.code}${fetch.error.message ? ` (${fetch.error.message})` : ""}.`);
    }
    if (fetch.truncated) out.push("The destination response was larger than the read limit and was truncated.");
  } else if (parts && payload && payload.fetchable !== false && kind === "url") {
    out.push("The destination was not fetched.");
  }

  return out;
}

/**
 * @typedef {{ id: string, text: string, signal_id: string|null }} ServerFact
 */

/**
 * Build server facts F1..Fn: every signal of strength >= weak in order, then
 * synthesized neutral facts, then remaining neutral signals. Capped.
 * @param {Signal[]} signals
 * @param {string[]} neutralTexts
 * @returns {ServerFact[]}
 */
function buildServerFacts(signals, neutralTexts) {
  /** @type {{ text: string, signal_id: string|null }[]} */
  const items = [];
  for (const s of signals) if (rank(s) >= STRENGTH_RANK.weak) items.push({ text: s.fact, signal_id: s.id });
  for (const t of neutralTexts) items.push({ text: t, signal_id: null });
  for (const s of signals) {
    if (rank(s) === STRENGTH_RANK.neutral && !NEUTRAL_COVERED.has(s.id)) items.push({ text: s.fact, signal_id: s.id });
  }
  return items
    .filter((i) => typeof i.text === "string" && i.text.trim())
    .slice(0, PACKET_CAPS.serverFacts)
    .map((i, idx) => ({ id: `F${idx + 1}`, text: clampText(i.text.trim(), PACKET_CAPS.factText), signal_id: i.signal_id }));
}

/**
 * Build the deterministic facts bundle and the Gemma evidence packet.
 * @param {{
 *   investigation_id: string,
 *   qr: object|null,
 *   payload: object|null,
 *   url: object|null,
 *   fetch: object|null,
 *   page: object|null,
 *   signals: Signal[]
 * }} input
 */
export function buildFacts({ investigation_id, qr = null, payload = null, url = null, fetch = null, page = null, signals = [] }) {
  const parts = urlParts(url);
  const ranked = normalizeSignals(signals, PACKET_CAPS.signals);
  const floor = computeFloor(ranked);
  const server_facts = buildServerFacts(ranked, synthesizedFacts({ qr, payload, parts, fetch }));

  const chain = Array.isArray(fetch && fetch.chain) ? fetch.chain : [];
  const hopCount = Math.max(0, chain.length - 1);
  const requestedHost = chain[0] && chain[0].host ? chain[0].host : parts ? parts.hostname : null;
  const finalHost = (() => {
    try {
      return fetch && fetch.final_url ? new URL(fetch.final_url).hostname : null;
    } catch {
      return null;
    }
  })();
  const shortener = ranked.some((s) => s.id === "url_shortener");
  const fetched = Boolean(fetch && fetch.ok);
  const kind = (payload && payload.kind) || "none";

  const packet = {
    schema_version: PACKET_SCHEMA_VERSION,
    investigation_id,
    qr: {
      decoded: Boolean(qr && qr.found),
      payload_type: kind,
      raw: clampText((qr && qr.payload) ?? (payload && payload.raw) ?? null, PACKET_CAPS.rawPayload),
      decode_error: (qr && qr.error) || null,
      count: qr && Number.isFinite(qr.count) ? qr.count : 0,
    },
    payload: {
      kind,
      parsed: sanitizeParsed(payload && payload.parsed),
      fetchable: Boolean(payload && payload.fetchable),
      reason: payload && payload.reason ? clampText(payload.reason, PACKET_CAPS.factText) : null,
    },
    url_parts: parts
      ? {
          scheme: parts.scheme ?? null,
          host: parts.host ?? null,
          registrable_domain: parts.registrable_domain ?? null,
          subdomain_labels: parts.subdomain_labels ?? 0,
          port: parts.port ?? null,
          path: clampText(parts.path ?? "", PACKET_CAPS.path),
          query_keys: (parts.query_keys || []).slice(0, PACKET_CAPS.queryKeys).map((k) => clampText(k, 64)),
          is_ip_literal: Boolean(parts.is_ip_literal),
          is_punycode: Boolean(parts.is_punycode),
          userinfo_present: Boolean(parts.userinfo_present),
        }
      : null,
    technical_signals: ranked.map((s) => ({
      id: s.id,
      strength: s.strength,
      fact: clampText(s.fact, PACKET_CAPS.factText),
      value: valueToText(s.value),
      hybrid: Boolean(s.hybrid),
    })),
    redirect_chain: chain.slice(0, PACKET_CAPS.hops).map((h) => ({
      url: clampText(h.url, PACKET_CAPS.hopUrl),
      status: h.status ?? null,
      host: h.host ?? null,
      blocked: Boolean(h.blocked),
      blocked_reason: h.blocked_reason ?? null,
    })),
    redirect_chain_meta: {
      hop_count: hopCount,
      cross_domain: chain.some((h) => h && h.cross_domain === true),
      shortener_expanded: Boolean(shortener && fetched && finalHost && requestedHost && finalHost !== requestedHost),
      chain_truncated: chain.length > PACKET_CAPS.hops,
    },
    destination: {
      fetched,
      fetch_error: fetch && fetch.error ? fetch.error.code ?? null : null,
      final_url: clampText(fetch && fetch.final_url ? fetch.final_url : null, PACKET_CAPS.hopUrl),
      http_status: fetch && fetch.status !== undefined ? fetch.status : null,
      content_type: fetch && fetch.headers && fetch.headers.content_type ? clampText(fetch.headers.content_type, 100) : null,
      page_title: clampText(page && page.title ? page.title : null, PACKET_CAPS.title),
      meta_description: clampText(page && page.meta_description ? page.meta_description : null, PACKET_CAPS.metaDescription),
      visible_text_excerpt: page && page.visible_text_excerpt ? sanitizeForPrompt(page.visible_text_excerpt, PACKET_CAPS.visibleText) : null,
      forms: (Array.isArray(page && page.forms) ? page.forms : []).slice(0, PACKET_CAPS.forms).map((f) => ({
        method: f.method ? String(f.method).toUpperCase() : "GET",
        action_same_origin: !f.cross_origin,
        field_types: (f.field_types || []).slice(0, PACKET_CAPS.fieldsPerForm),
      })),
      sensitive_inputs: {
        password: Boolean(page && page.sensitive_inputs && page.sensitive_inputs.password),
        payment_card: Boolean(page && page.sensitive_inputs && page.sensitive_inputs.payment_card),
        otp: Boolean(page && page.sensitive_inputs && page.sensitive_inputs.otp),
        upi: Boolean(page && page.sensitive_inputs && page.sensitive_inputs.upi),
        aadhaar: Boolean(page && page.sensitive_inputs && page.sensitive_inputs.aadhaar),
        pan: Boolean(page && page.sensitive_inputs && page.sensitive_inputs.pan),
        bank: Boolean(page && page.sensitive_inputs && page.sensitive_inputs.bank),
      },
      external_links_count: page && Number.isFinite(page.external_links_count) ? page.external_links_count : 0,
      top_external_hosts: (Array.isArray(page && page.external_hosts) ? page.external_hosts : []).slice(0, PACKET_CAPS.externalHosts),
      has_download_links: Boolean(page && page.has_download_links),
      language_hint: page && page.lang ? clampText(page.lang, 16) : null,
      meta_refresh_target: clampText(page && page.meta_refresh_target ? page.meta_refresh_target : null, PACKET_CAPS.hopUrl),
      bot_wall_detected: Boolean(page && page.bot_wall_detected),
    },
    server_facts: server_facts.map((f) => ({ id: f.id, text: f.text })),
    deterministic_floor: { level: floor.level, triggered_by: [...floor.triggered_by] },
  };

  return { signals: ranked, server_facts, floor, packet };
}
