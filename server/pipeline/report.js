// Final risk reconciliation and report assembly.
//
// Rules (docs/ARCHITECTURE.md "Risk reconciliation"):
//   1. Start from Gemma risk_level when available.
//   2. The deterministic floor from facts.floor can only RAISE the level.
//   3. Thin-evidence downgrades are done by validate.js, not here.
//   4. If Gemma failed, use the deterministic fallback table over signals.
//   5. No QR and no manual URL -> forced INSUFFICIENT_EVIDENCE.
//
// This module is pure: no I/O, no network, no environment reads.

import {
  RISK_LEVELS,
  RISK_LABELS,
  RISK_RANK,
  STRENGTH_RANK,
  STAGE_STATUS,
  VERSION,
  DEFAULT_MODEL,
} from "./contracts.js";

const INSUFFICIENT = "INSUFFICIENT_EVIDENCE";
const STAGE_NAMES = ["intake", "qr", "payload", "url", "fetch", "gemma"];

/**
 * Inline copy of the deterministic fallback table. facts.js exports the
 * canonical fallbackRisk(); this one keeps report.js testable standalone.
 * @param {Array<{strength:string}>} signals
 * @param {{destinationFetched?:boolean, qrFound?:boolean, payloadKind?:string|null}} ctx
 * @returns {string} RISK_LEVEL
 */
export function inlineFallbackRisk(signals, { destinationFetched = false } = {}) {
  const list = Array.isArray(signals) ? signals : [];
  let critical = 0;
  let strong = 0;
  let medium = 0;
  let aboveWeak = 0;
  for (const s of list) {
    const rank = STRENGTH_RANK[s && s.strength] ?? 0;
    if (rank === 4) critical += 1;
    else if (rank === 3) strong += 1;
    else if (rank === 2) medium += 1;
    if (rank >= 2) aboveWeak += 1;
  }
  if (critical >= 1) return "CRITICAL";
  if (strong >= 2) return "HIGH_RISK";
  if (strong === 1 || medium >= 2) return "MEDIUM_RISK";
  if (destinationFetched && aboveWeak === 0) return "LOW_RISK";
  return INSUFFICIENT;
}

// Prefer the canonical table from facts.js when it is present; fall back to
// the inline copy so this module (and its tests) run before integration.
let factsFallbackRisk = null;
try {
  const mod = await import("./facts.js");
  if (mod && typeof mod.fallbackRisk === "function") factsFallbackRisk = mod.fallbackRisk;
} catch {
  factsFallbackRisk = null;
}

/** Plain-language default actions per level. No absolute vocabulary. */
export const DEFAULT_ACTIONS = Object.freeze({
  LOW_RISK:
    "No strong warning signs were found. Proceed with normal caution and never enter passwords, OTPs or payment details unless you are certain the site is the organization's own.",
  MEDIUM_RISK:
    "Proceed carefully. Verify the organization through an official channel before entering personal information or making a payment.",
  HIGH_RISK:
    "Do not enter personal details, passwords, OTPs or payment information. Confirm the offer directly with the organization through an official channel first.",
  CRITICAL:
    "Do not proceed. Do not enter any information or make a payment through this QR code, and consider reporting the poster to the venue or organization.",
  INSUFFICIENT_EVIDENCE:
    "The destination could not be fully inspected. Verify the organization through an official channel before scanning or entering any details.",
});

const FALLBACK_CONFIDENCE = Object.freeze({
  LOW_RISK: 0.4,
  MEDIUM_RISK: 0.5,
  HIGH_RISK: 0.6,
  CRITICAL: 0.7,
  INSUFFICIENT_EVIDENCE: 0,
});

function clamp01(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0;
  return Math.min(1, Math.max(0, x));
}

function labelFor(level) {
  return RISK_LABELS[level] || RISK_LABELS[INSUFFICIENT];
}

function topFactTexts(serverFacts, max = 3) {
  return (serverFacts || [])
    .slice(0, max)
    .map((f) => (f && f.text ? String(f.text) : null))
    .filter(Boolean);
}

function fallbackSummary(level, serverFacts, reasoningMeta) {
  const why = reasoningMeta && reasoningMeta.error ? " (model error recorded)" : "";
  const facts = topFactTexts(serverFacts);
  const lead = `The AI reasoning engine was unavailable${why}, so this verdict comes from deterministic technical checks only.`;
  if (facts.length === 0) {
    return `${lead} No technical findings were available to assess the QR destination.`;
  }
  return `${lead} Key technical findings: ${facts.join(" ")}`;
}

function floorSummary(floorLevel, triggeredBy, serverFacts) {
  const ids = new Set(triggeredBy || []);
  const texts = (serverFacts || [])
    .filter((f) => f && ids.has(f.signal_id))
    .slice(0, 3)
    .map((f) => f.text);
  const because = texts.length
    ? ` because: ${texts.join(" ")}`
    : triggeredBy && triggeredBy.length
      ? ` (triggered by ${triggeredBy.join(", ")})`
      : "";
  return `Deterministic technical checks set the risk to ${labelFor(floorLevel)}${because}`;
}

/**
 * Reconcile the final risk level.
 * @param {object} args
 * @param {object|null} args.reasoning validated Gemma output
 * @param {object|null} args.reasoning_meta { available, error, ... }
 * @param {object} args.facts { signals, server_facts, floor }
 * @param {boolean} args.qrFound
 * @param {string|null} args.manualUrl
 * @param {string|null} args.payloadKind
 * @param {boolean} args.destinationFetched
 * @param {Function} [args.fallbackRiskFn] test injection; defaults to facts.js or the inline table
 * @returns {{level:string,label:string,source:string,confidence:number,summary:string,recommended_action:string,adjustments:Array}}
 */
export function reconcileRisk({
  reasoning,
  reasoning_meta,
  facts,
  qrFound,
  manualUrl,
  payloadKind,
  destinationFetched,
  fallbackRiskFn,
} = {}) {
  const adjustments = [];
  const signals = (facts && facts.signals) || [];
  const serverFacts = (facts && facts.server_facts) || [];
  const floor = (facts && facts.floor) || { level: null, triggered_by: [] };
  const hasManual = typeof manualUrl === "string" && manualUrl.trim().length > 0;
  const modelLevel =
    reasoning && typeof reasoning === "object" && RISK_LEVELS.includes(reasoning.risk_level)
      ? reasoning.risk_level
      : null;

  // Rule 5: nothing to investigate.
  if (!qrFound && !hasManual) {
    if (modelLevel && modelLevel !== INSUFFICIENT) {
      adjustments.push({
        rule: "forced_insufficient_no_input",
        from: modelLevel,
        to: INSUFFICIENT,
        note: "No QR code was decoded and no URL was supplied; a destination verdict is not possible.",
      });
    }
    let summary =
      "No QR code could be decoded from the image and no URL was supplied, so there is no destination to investigate.";
    if (reasoning && typeof reasoning.summary_for_user === "string" && reasoning.summary_for_user.trim()) {
      summary += ` Model note from the poster alone: ${reasoning.summary_for_user.trim()}`;
    }
    return {
      level: INSUFFICIENT,
      label: labelFor(INSUFFICIENT),
      source: "forced_insufficient",
      confidence: 0,
      summary,
      recommended_action:
        "Retake the photo with the QR code sharp, well lit and filling more of the frame, or paste the URL manually.",
      adjustments,
    };
  }

  let level;
  let source;
  let confidence;
  let summary;
  let recommendedAction;

  const modelAvailable =
    modelLevel !== null && (!reasoning_meta || reasoning_meta.available !== false);

  if (modelAvailable) {
    // Rule 1.
    level = modelLevel;
    source = "gemma";
    confidence = clamp01(reasoning.confidence);
    summary =
      typeof reasoning.summary_for_user === "string" && reasoning.summary_for_user.trim()
        ? reasoning.summary_for_user.trim()
        : `Gemma assessed this QR code as ${labelFor(level)}.`;
    recommendedAction =
      typeof reasoning.recommended_action === "string" && reasoning.recommended_action.trim()
        ? reasoning.recommended_action.trim()
        : DEFAULT_ACTIONS[level];
  } else {
    // Rule 4.
    const fn = fallbackRiskFn || factsFallbackRisk || inlineFallbackRisk;
    let computed;
    try {
      computed = fn(signals, { destinationFetched: Boolean(destinationFetched), qrFound: Boolean(qrFound), payloadKind: payloadKind || null });
    } catch {
      computed = inlineFallbackRisk(signals, { destinationFetched: Boolean(destinationFetched) });
    }
    level = RISK_LEVELS.includes(computed) ? computed : INSUFFICIENT;
    source = "deterministic_fallback";
    confidence = FALLBACK_CONFIDENCE[level];
    summary = fallbackSummary(level, serverFacts, reasoning_meta);
    recommendedAction = DEFAULT_ACTIONS[level];
    adjustments.push({
      rule: "deterministic_fallback_used",
      from: modelLevel,
      to: level,
      note:
        reasoning_meta && reasoning_meta.error
          ? `Model output unavailable: ${String(reasoning_meta.error).slice(0, 160)}`
          : "Model output unavailable; deterministic table applied.",
    });
  }

  // Rule 2: the floor can only raise.
  const floorLevel = floor && RISK_RANK[floor.level] ? floor.level : null;
  if (floorLevel) {
    const currentRank = RISK_RANK[level] || 0; // INSUFFICIENT ranks 0 and is raised
    if (currentRank < RISK_RANK[floorLevel]) {
      adjustments.push({
        rule: "deterministic_floor_raised",
        from: level,
        to: floorLevel,
        note: `Triggered by: ${(floor.triggered_by || []).join(", ") || "deterministic floor"}`,
      });
      level = floorLevel;
      source = "floor_override";
      confidence = Math.max(confidence, 0.6);
      summary = `${floorSummary(floorLevel, floor.triggered_by, serverFacts)} ${summary}`.trim();
      recommendedAction = DEFAULT_ACTIONS[level];
    }
  }

  return {
    level,
    label: labelFor(level),
    source,
    confidence: clamp01(confidence),
    summary,
    recommended_action: recommendedAction,
    adjustments,
  };
}

function stageOrDefault(stages, name) {
  const s = stages && stages[name];
  if (!s) return { status: STAGE_STATUS.SKIPPED, duration_ms: 0, note: "not_run" };
  return {
    status: s.status || STAGE_STATUS.SKIPPED,
    duration_ms: Number.isFinite(s.duration_ms) ? s.duration_ms : 0,
    note: s.note === undefined ? null : s.note,
  };
}

const EMPTY_QR = Object.freeze({
  found: false,
  count: 0,
  payload: null,
  payload_type: "none",
  decode_method: null,
  error: null,
  all_payloads: [],
});

const EMPTY_PAYLOAD = Object.freeze({
  kind: "none",
  parsed: {},
  embedded_urls: [],
  fetchable: false,
  reason: null,
});

const EMPTY_DESTINATION = Object.freeze({
  fetched: false,
  error_code: null,
  error_message: null,
  final_url: null,
  http_status: null,
  content_type: null,
  content_length: null,
  bytes_read: 0,
  truncated: false,
  is_html: false,
  title: null,
  meta_description: null,
  site_name: null,
  canonical_host: null,
  lang: null,
  visible_text_excerpt: null,
  forms: [],
  sensitive_inputs: {
    password: false,
    payment_card: false,
    otp: false,
    upi: false,
    aadhaar: false,
    pan: false,
    bank: false,
  },
  external_hosts: [],
  external_script_hosts: [],
  iframe_hosts: [],
  has_download_links: false,
  meta_refresh_target: null,
  bot_wall_detected: false,
});

/**
 * Assemble the final Report with every key from docs/ARCHITECTURE.md present.
 * @returns {object} Report
 */
export function assembleReport({
  investigation_id,
  created_at,
  input,
  stages,
  facts,
  reasoning,
  reasoning_meta,
  server_adjustments,
  risk,
  meta,
} = {}) {
  const f = facts || {};
  const outStages = {};
  for (const name of STAGE_NAMES) outStages[name] = stageOrDefault(stages, name);

  const outMeta = {
    version: (meta && meta.version) || VERSION,
    model: (meta && meta.model) || DEFAULT_MODEL,
    mock: Boolean(meta && meta.mock),
    timings: (meta && meta.timings) || { total_ms: 0 },
  };

  const outRisk = risk || {
    level: INSUFFICIENT,
    label: labelFor(INSUFFICIENT),
    source: "forced_insufficient",
    confidence: 0,
    summary: "No verdict could be produced.",
    recommended_action: DEFAULT_ACTIONS[INSUFFICIENT],
  };

  return {
    investigation_id: investigation_id || null,
    created_at: created_at || new Date().toISOString(),
    input: {
      mode: (input && input.mode) || "image",
      image: (input && input.image) || null,
      manual_url: Boolean(input && input.manual_url),
    },
    stages: outStages,
    facts: {
      qr: { ...EMPTY_QR, ...(f.qr || {}) },
      payload: { ...EMPTY_PAYLOAD, ...(f.payload || {}) },
      url: f.url || null,
      redirect_chain: Array.isArray(f.redirect_chain) ? f.redirect_chain : [],
      destination: {
        ...EMPTY_DESTINATION,
        ...(f.destination || {}),
        sensitive_inputs: {
          ...EMPTY_DESTINATION.sensitive_inputs,
          ...((f.destination && f.destination.sensitive_inputs) || {}),
        },
      },
      signals: Array.isArray(f.signals) ? f.signals : [],
      server_facts: Array.isArray(f.server_facts) ? f.server_facts : [],
      floor: f.floor || { level: null, triggered_by: [] },
    },
    reasoning: reasoning || null,
    reasoning_meta: reasoning_meta || {
      available: false,
      model: outMeta.model,
      latency_ms: 0,
      parse_path: "fallback",
      error: null,
      raw_text_excerpt: null,
      validation_notes: [],
    },
    server_adjustments: Array.isArray(server_adjustments) ? server_adjustments : [],
    risk: {
      level: outRisk.level,
      label: outRisk.label || labelFor(outRisk.level),
      source: outRisk.source,
      confidence: clamp01(outRisk.confidence),
      summary: outRisk.summary,
      recommended_action: outRisk.recommended_action,
    },
    meta: outMeta,
  };
}
