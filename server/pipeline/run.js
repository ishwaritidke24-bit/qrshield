// Pipeline orchestrator. Every stage is wrapped in runStage so a failure in
// one module degrades the report instead of crashing the request.
//
//   intake -> qr -> payload -> url -> fetch(+extractPage +destinationSignals)
//          -> facts -> gemma -> validate/guardrails -> reconcile -> assemble
//
// The only exceptions thrown out of investigate() are InputError instances
// (status 400): rejected input such as an undecodable or oversized image.

import { randomUUID } from "node:crypto";

import {
  IMAGE_LIMITS,
  FETCH_LIMITS,
  PACKET_CAPS,
  STAGE_STATUS,
  DEFAULT_MODEL,
  VERSION,
  runStage,
  signal,
  clampText,
} from "./contracts.js";
import { prepareImage, decodeQr, imageForGemma } from "./qr.js";
import { classifyPayload } from "./payload.js";
import { analyzeUrl } from "./urlAnalysis.js";
import { safeFetch } from "./fetchDestination.js";
import { extractPage } from "./sanitizeHtml.js";
import { destinationSignals } from "./destinationSignals.js";
import { buildFacts } from "./facts.js";
import { callGemma } from "./gemma.js";
import { applyGuardrails } from "./validate.js";
import { reconcileRisk, assembleReport } from "./report.js";

const { OK, DEGRADED, SKIPPED, FAILED, BLOCKED } = STAGE_STATUS;

/** Error codes that map to HTTP 400 at the route layer. */
export const INPUT_ERROR_CODES = Object.freeze([
  "no_input",
  "bad_mime",
  "image_too_large",
  "image_invalid",
  "url_too_long",
  "url_not_string",
]);

export class InputError extends Error {
  /**
   * @param {string} code one of INPUT_ERROR_CODES
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = "InputError";
    this.code = code;
    this.status = 400;
  }
}

/** Fetch error codes that mean "policy refused", shown as stage status blocked. */
const BLOCKED_FETCH_CODES = new Set([
  "blocked_scheme",
  "blocked_hostname",
  "blocked_private_ip",
  "non_standard_port",
  "not_fetchable",
]);

/**
 * Decide whether Gemma runs in mock mode.
 * @param {boolean|string|undefined} mockOption explicit override; undefined -> env
 */
export function resolveMockMode(mockOption) {
  if (mockOption !== undefined && mockOption !== null) return Boolean(mockOption);
  const m = process.env.GEMMA_MOCK;
  if (m === "1" || m === "true" || m === "fail") return true;
  return !process.env.GEMINI_API_KEY;
}

export function currentModel() {
  return process.env.GEMMA_MODEL || DEFAULT_MODEL;
}

function emptyQr() {
  return {
    found: false,
    count: 0,
    payload: null,
    all_payloads: [],
    decode_method: null,
    location: null,
    error: null,
    attempts: 0,
  };
}

function emptyPayload(raw, reason) {
  return {
    kind: raw ? "text" : "none",
    raw: raw || null,
    normalized: null,
    parsed: {},
    embedded_urls: [],
    fetchable: false,
    reason: reason || null,
    signals: [],
  };
}

/** Replace the P: (password) field of a WIFI: payload with a placeholder. */
export function maskWifiSecret(s) {
  if (typeof s !== "string") return s;
  return s.replace(/(^|;)P:((?:\\.|[^;\\])*)/gi, (_m, sep, pw) => (pw ? `${sep}P:[redacted]` : `${sep}P:`));
}

function emptySensitive() {
  return { password: false, payment_card: false, otp: false, upi: false, aadhaar: false, pan: false, bank: false };
}

/** Merge FetchResult + PageEvidence into report.facts.destination. */
function destinationFacts(fetchResult, page) {
  const fr = fetchResult || null;
  const headers = (fr && fr.headers) || {};
  const pg = page || {};
  return {
    fetched: Boolean(fr && fr.ok),
    error_code: fr && fr.error ? fr.error.code || null : null,
    error_message: fr && fr.error ? clampText(fr.error.message, 300) : null,
    final_url: (fr && fr.final_url) || null,
    http_status: fr && Number.isFinite(fr.status) ? fr.status : null,
    content_type: headers.content_type || null,
    content_length: headers.content_length ?? null,
    bytes_read: (fr && fr.bytes_read) || 0,
    truncated: Boolean(fr && fr.truncated),
    is_html: Boolean(fr && fr.is_html),
    title: pg.title ?? null,
    meta_description: pg.meta_description ?? null,
    site_name: pg.site_name ?? null,
    canonical_host: pg.canonical_host ?? null,
    lang: pg.lang ?? null,
    visible_text_excerpt: pg.visible_text_excerpt ?? null,
    forms: Array.isArray(pg.forms) ? pg.forms : [],
    sensitive_inputs: { ...emptySensitive(), ...(pg.sensitive_inputs || {}) },
    external_hosts: Array.isArray(pg.external_hosts) ? pg.external_hosts : [],
    external_script_hosts: Array.isArray(pg.external_script_hosts) ? pg.external_script_hosts : [],
    iframe_hosts: Array.isArray(pg.iframe_hosts) ? pg.iframe_hosts : [],
    has_download_links: Boolean(pg.has_download_links),
    meta_refresh_target: pg.meta_refresh_target ?? null,
    bot_wall_detected: Boolean(pg.bot_wall_detected),
  };
}

/** Minimal facts/packet used only if facts.js itself throws. */
function minimalFacts({ investigation_id, qr, payload, signals, fetchResult, page }) {
  const dest = destinationFacts(fetchResult, page);
  return {
    signals,
    server_facts: [],
    floor: { level: null, triggered_by: [] },
    packet: {
      schema_version: "1.0",
      investigation_id,
      qr: {
        decoded: Boolean(qr.found),
        payload_type: payload.kind,
        raw: clampText(payload.raw, PACKET_CAPS.rawPayload),
        decode_error: qr.error || null,
        count: qr.count || 0,
      },
      payload: { kind: payload.kind, parsed: {}, fetchable: Boolean(payload.fetchable), reason: payload.reason || null },
      url_parts: null,
      technical_signals: signals.map((s) => ({ id: s.id, strength: s.strength, fact: s.fact, value: s.value ?? null, hybrid: Boolean(s.hybrid) })),
      redirect_chain: [],
      redirect_chain_meta: { hop_count: 0, cross_domain: false, shortener_expanded: false, chain_truncated: false },
      destination: {
        fetched: dest.fetched,
        fetch_error: dest.error_code,
        final_url: dest.final_url,
        http_status: dest.http_status,
        content_type: dest.content_type,
        page_title: dest.title,
        meta_description: dest.meta_description,
        visible_text_excerpt: null,
        forms: [],
        sensitive_inputs: dest.sensitive_inputs,
        external_links_count: 0,
        top_external_hosts: [],
        has_download_links: dest.has_download_links,
        language_hint: dest.lang,
        meta_refresh_target: dest.meta_refresh_target,
        bot_wall_detected: dest.bot_wall_detected,
      },
      server_facts: [],
      deterministic_floor: { level: null, triggered_by: [] },
    },
  };
}

function stageView(stage) {
  return { status: stage.status, duration_ms: stage.duration_ms, note: stage.note };
}

/**
 * Run the whole investigation. Never throws for pipeline failures; throws
 * InputError (status 400) only for rejected input.
 *
 * @param {object} args
 * @param {Buffer|null} args.imageBuffer
 * @param {string|null} [args.imageMime]
 * @param {string|null} [args.manualUrl]
 * @param {{allowOrigins?:Set<string>, mock?:boolean|string}} [args.options]
 * @returns {Promise<object>} Report
 */
export async function investigate({ imageBuffer = null, imageMime = null, manualUrl = null, options = {} } = {}) {
  const t0 = Date.now();
  const investigation_id = randomUUID();
  const created_at = new Date().toISOString();
  const allowOrigins = options.allowOrigins instanceof Set ? options.allowOrigins : new Set();
  const model = currentModel();
  const mockMode = resolveMockMode(options.mock);
  const hasImage = Buffer.isBuffer(imageBuffer) && imageBuffer.length > 0;
  const manual = typeof manualUrl === "string" && manualUrl.trim() ? manualUrl.trim() : null;

  if (!hasImage && !manual) throw new InputError("no_input", "Provide an image or a url.");
  if (manual && manual.length > 4096) throw new InputError("url_too_long", "url exceeds 4096 characters.");

  const stages = {};
  const timings = {};

  // ---- intake -------------------------------------------------------------
  let intakeErr = null;
  const intake = await runStage(
    "intake",
    async () => {
      if (!hasImage) return { status: SKIPPED, note: "url_mode", data: { prepared: null, imagePart: null } };
      const mime = (imageMime || "").toLowerCase().split(";")[0].trim();
      if (!IMAGE_LIMITS.allowedMimes.includes(mime)) {
        throw Object.assign(new Error(`Unsupported image type "${mime || "unknown"}".`), { code: "bad_mime" });
      }
      const prepared = await prepareImage(imageBuffer, {
        maxPixels: IMAGE_LIMITS.maxPixels,
        allowedMimes: IMAGE_LIMITS.allowedMimes,
      });
      let imagePart = null;
      let note = `${prepared.width}x${prepared.height}`;
      let status = OK;
      try {
        const g = await imageForGemma(prepared.buffer, { maxEdge: IMAGE_LIMITS.gemmaMaxEdge });
        imagePart = { data: g.data, mimeType: g.mimeType };
      } catch (err) {
        status = DEGRADED;
        note = `gemma_image_unavailable: ${String(err && err.message).slice(0, 120)}`;
      }
      return { status, note, data: { prepared, imagePart } };
    },
    { onError: (e) => { intakeErr = e; } },
  );
  stages.intake = intake;
  timings.intake_ms = intake.duration_ms;

  if (intake.status === FAILED) {
    const code = intakeErr && intakeErr.code;
    if (code === "image_too_large") throw new InputError(code, "Image has too many pixels.");
    if (code === "bad_mime") throw new InputError(code, intakeErr.message);
    if (code === "image_invalid" || !manual) throw new InputError("image_invalid", "Image could not be decoded.");
    // Unexpected failure but a manual URL exists: continue in url-only mode.
  }
  const prepared = (intake.data && intake.data.prepared) || null;
  const imagePart = (intake.data && intake.data.imagePart) || null;

  // ---- qr -----------------------------------------------------------------
  const qrStage = await runStage("qr", async () => {
    if (manual) return { status: SKIPPED, note: "manual_override", data: emptyQr() };
    if (!prepared) return { status: SKIPPED, note: "url_mode", data: emptyQr() };
    const res = await decodeQr(prepared.buffer);
    if (!res || !res.found) {
      return { status: DEGRADED, note: (res && res.error) || "no_qr_found", data: res || emptyQr() };
    }
    const note = res.count > 1 ? `multiple_qr_codes:${res.count}` : res.decode_method || null;
    return { status: OK, note, data: res };
  });
  stages.qr = qrStage;
  timings.qr_ms = qrStage.duration_ms;
  const qr = qrStage.data || emptyQr();

  const extraSignals = [];
  if (qr.count > 1) {
    extraSignals.push(
      signal("multiple_qr_codes", "weak", `The image contains ${qr.count} QR codes; only the first was analyzed.`, {
        value: qr.count,
        stage: "qr",
      }),
    );
  }

  // ---- payload --------------------------------------------------------------
  const rawPayload = manual || qr.payload || null;
  const payloadStage = await runStage("payload", async () => {
    if (!rawPayload) return { status: SKIPPED, note: "no_payload", data: emptyPayload(null, "no QR payload") };
    const p = classifyPayload(rawPayload);
    const note = `${manual ? "manual_url:" : ""}${p.kind}`;
    return { status: OK, note, data: p };
  });
  stages.payload = payloadStage;
  timings.payload_ms = payloadStage.duration_ms;
  const payloadRaw = payloadStage.data || emptyPayload(rawPayload, "payload classification failed");

  // Secrets carried inside the QR itself (Wi-Fi passwords) must never reach
  // the report, the server facts or the Gemma packet. Classification is done,
  // so mask the raw strings everywhere downstream.
  const mask = payloadRaw.kind === "wifi" ? maskWifiSecret : (s) => s;
  const payload = { ...payloadRaw, raw: mask(payloadRaw.raw), normalized: mask(payloadRaw.normalized) };
  if (payloadRaw.kind === "wifi") {
    qr.payload = mask(qr.payload);
    qr.all_payloads = Array.isArray(qr.all_payloads) ? qr.all_payloads.map(mask) : [];
  }

  // ---- url ------------------------------------------------------------------
  const urlStage = await runStage("url", async () => {
    if (!payload.fetchable || !payload.normalized) {
      const note = payload.kind === "blocked_scheme" ? "blocked_scheme" : payload.kind === "none" ? "no_payload" : "payload_not_url";
      return { status: SKIPPED, note, data: null };
    }
    const a = analyzeUrl(payload.normalized);
    return { status: OK, note: (a.url && (a.url.registrable_domain || a.url.host)) || null, data: a };
  });
  stages.url = urlStage;
  timings.url_ms = urlStage.duration_ms;
  const urlAnalysis = urlStage.data || null;

  // ---- fetch (+ page extraction + destination signals) ----------------------
  const fetchStage = await runStage("fetch", async () => {
    if (!urlAnalysis || !urlAnalysis.url) {
      const note = urlStage.status === FAILED ? "url_invalid" : urlStage.note || "not_fetchable";
      return { status: SKIPPED, note, data: { fetchResult: null, page: null, signals: [] } };
    }
    const fetchUrl = urlAnalysis.url.fetch_url || urlAnalysis.url.normalized;
    const fetchResult = await safeFetch(fetchUrl, { ...FETCH_LIMITS, allowOrigins });
    let page = null;
    let pageNote = null;
    if (fetchResult && fetchResult.ok && fetchResult.is_html && fetchResult.body_text) {
      try {
        page = extractPage(fetchResult.body_text, fetchResult.final_url || fetchUrl);
      } catch (err) {
        pageNote = `page_extract_failed: ${String(err && err.message).slice(0, 100)}`;
      }
    }
    let dsignals = [];
    try {
      dsignals = destinationSignals(fetchResult, page, urlAnalysis) || [];
    } catch (err) {
      pageNote = (pageNote ? pageNote + "; " : "") + `destination_signals_failed: ${String(err && err.message).slice(0, 100)}`;
    }
    if (fetchResult && fetchResult.ok) {
      const bits = [`http_${fetchResult.status}`];
      if (fetchResult.truncated) bits.push("truncated");
      if (!fetchResult.is_html) bits.push("non_html");
      if (fetchResult.pinned === false) bits.push("unpinned");
      if (pageNote) bits.push(pageNote);
      return { status: pageNote ? DEGRADED : OK, note: bits.join(","), data: { fetchResult, page, signals: dsignals } };
    }
    const code = (fetchResult && fetchResult.error && fetchResult.error.code) || "fetch_failed";
    const status = BLOCKED_FETCH_CODES.has(code) ? BLOCKED : DEGRADED;
    return { status, note: code, data: { fetchResult, page, signals: dsignals } };
  });
  stages.fetch = fetchStage;
  timings.fetch_ms = fetchStage.duration_ms;
  const fetchData = fetchStage.data || { fetchResult: null, page: null, signals: [] };
  const fetchResult = fetchData.fetchResult || null;
  const page = fetchData.page || null;
  const destinationFetched = Boolean(fetchResult && fetchResult.ok);

  // ---- facts ----------------------------------------------------------------
  const allSignals = [
    ...extraSignals,
    ...((payload && payload.signals) || []),
    ...((urlAnalysis && urlAnalysis.signals) || []),
    ...(fetchData.signals || []),
  ].filter((s) => s && typeof s.id === "string");

  const tFacts = Date.now();
  let facts;
  let factsNote = null;
  try {
    facts = buildFacts({
      investigation_id,
      qr,
      payload,
      url: urlAnalysis,
      fetch: fetchResult,
      page,
      signals: allSignals,
    });
    if (!facts || !facts.packet) throw new Error("buildFacts returned no packet");
  } catch (err) {
    factsNote = `facts_failed: ${String(err && err.message).slice(0, 120)}`;
    facts = minimalFacts({ investigation_id, qr, payload, signals: allSignals, fetchResult, page });
  }
  timings.facts_ms = Date.now() - tFacts;

  // ---- gemma + guardrails -----------------------------------------------------
  const gemmaStage = await runStage("gemma", async () => {
    const envTimeout = Number(process.env.GEMMA_TIMEOUT_MS);
    const out = await callGemma({
      packet: facts.packet,
      image: imagePart,
      mock: options.mock,
      model,
      ...(Number.isFinite(envTimeout) && envTimeout > 0 ? { timeoutMs: envTimeout } : {}),
      ...(options.gemmaOptions || {}),
    });
    const meta = (out && out.meta) || null;
    let reasoning = (out && out.reasoning) || null;
    let adjustments = [];
    let note = meta && meta.available ? meta.parse_path : (meta && meta.error) || "model_unavailable";
    if (reasoning) {
      try {
        const g = applyGuardrails(reasoning, { packet: facts.packet, facts });
        if (g && g.reasoning) reasoning = g.reasoning;
        adjustments = (g && g.adjustments) || [];
      } catch (err) {
        note = `${note}; guardrails_failed: ${String(err && err.message).slice(0, 100)}`;
      }
    }
    if (factsNote) note = `${note}; ${factsNote}`;
    const status = meta && meta.available ? (factsNote ? DEGRADED : OK) : DEGRADED;
    return { status, note, data: { reasoning, meta, adjustments } };
  });
  stages.gemma = gemmaStage;
  timings.gemma_ms = gemmaStage.duration_ms;
  const gemmaData = gemmaStage.data || { reasoning: null, meta: null, adjustments: [] };
  const reasoning = gemmaData.reasoning || null;
  const reasoning_meta = gemmaData.meta || {
    available: false,
    model,
    latency_ms: gemmaStage.duration_ms,
    parse_path: "fallback",
    error: gemmaStage.note || "gemma stage failed",
    raw_text_excerpt: null,
    validation_notes: [],
  };

  // ---- reconcile ----------------------------------------------------------------
  const risk = reconcileRisk({
    reasoning,
    reasoning_meta,
    facts,
    qrFound: Boolean(qr.found),
    manualUrl: manual,
    payloadKind: payload.kind,
    destinationFetched,
  });
  const server_adjustments = [...(gemmaData.adjustments || []), ...(risk.adjustments || [])];

  timings.total_ms = Date.now() - t0;

  const stageViews = {};
  for (const [k, v] of Object.entries(stages)) stageViews[k] = stageView(v);

  return assembleReport({
    investigation_id,
    created_at,
    input: {
      mode: hasImage ? "image" : "url",
      image: prepared
        ? { width: prepared.width, height: prepared.height, bytes: imageBuffer.length, mime: imageMime || null }
        : null,
      manual_url: Boolean(manual),
    },
    stages: stageViews,
    facts: {
      qr: {
        found: Boolean(qr.found),
        count: qr.count || 0,
        payload: qr.payload ?? null,
        payload_type: payload.kind,
        decode_method: qr.decode_method ?? null,
        error: qr.error ?? null,
        all_payloads: Array.isArray(qr.all_payloads) ? qr.all_payloads : [],
      },
      payload: {
        kind: payload.kind,
        parsed: payload.parsed || {},
        embedded_urls: Array.isArray(payload.embedded_urls) ? payload.embedded_urls : [],
        fetchable: Boolean(payload.fetchable),
        reason: payload.reason ?? null,
      },
      url: urlAnalysis && urlAnalysis.url ? urlAnalysis.url : null,
      redirect_chain: fetchResult && Array.isArray(fetchResult.chain) ? fetchResult.chain : [],
      destination: destinationFacts(fetchResult, page),
      signals: facts.signals || allSignals,
      server_facts: facts.server_facts || [],
      floor: facts.floor || { level: null, triggered_by: [] },
    },
    reasoning,
    reasoning_meta,
    server_adjustments,
    risk,
    meta: { version: VERSION, model, mock: mockMode || (reasoning_meta && reasoning_meta.parse_path === "mock"), timings },
  });
}
