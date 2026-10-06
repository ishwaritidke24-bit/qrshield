// Single source of truth for enums, labels and small helpers shared by every
// pipeline module, the routes and the tests. Keep this file dependency-free.

export const VERSION = "0.1.0";
export const DEFAULT_MODEL = "gemma-4-26b-a4b-it";

export const RISK_LEVELS = Object.freeze([
  "LOW_RISK",
  "MEDIUM_RISK",
  "HIGH_RISK",
  "CRITICAL",
  "INSUFFICIENT_EVIDENCE",
]);

export const RISK_LABELS = Object.freeze({
  LOW_RISK: "LOW RISK",
  MEDIUM_RISK: "MEDIUM RISK",
  HIGH_RISK: "HIGH RISK",
  CRITICAL: "CRITICAL",
  INSUFFICIENT_EVIDENCE: "INSUFFICIENT EVIDENCE",
});

// Ordering used when a deterministic floor must RAISE a model verdict.
// INSUFFICIENT_EVIDENCE sits outside the ordering and is handled explicitly.
export const RISK_RANK = Object.freeze({
  LOW_RISK: 1,
  MEDIUM_RISK: 2,
  HIGH_RISK: 3,
  CRITICAL: 4,
});

export const STAGE_STATUS = Object.freeze({
  OK: "ok",
  DEGRADED: "degraded",
  SKIPPED: "skipped",
  FAILED: "failed",
  BLOCKED: "blocked",
});

export const SIGNAL_STRENGTH = Object.freeze([
  "neutral",
  "weak",
  "medium",
  "strong",
  "critical",
]);

export const SIGNAL_LABELS = Object.freeze({
  neutral: "Info",
  weak: "Weak signal",
  medium: "Suspicious",
  strong: "Highly suspicious",
  critical: "Critical signal",
});

export const STRENGTH_RANK = Object.freeze({
  neutral: 0,
  weak: 1,
  medium: 2,
  strong: 3,
  critical: 4,
});

export const PAYLOAD_KINDS = Object.freeze([
  "url",
  "upi",
  "tel",
  "sms",
  "mailto",
  "wifi",
  "vcard",
  "geo",
  "intent",
  "appstore",
  "crypto",
  "blocked_scheme",
  "text",
  "none",
]);

export const FETCH_ERROR_CODES = Object.freeze([
  "blocked_scheme",
  "blocked_hostname",
  "blocked_private_ip",
  "non_standard_port",
  "dns_nxdomain",
  "dns_error",
  "fetch_timeout",
  "redirect_limit_exceeded",
  "redirect_loop",
  "redirect_missing_location",
  "tls_error",
  "connection_error",
  "http_error",
  "too_large",
  "non_html",
  "not_fetchable",
]);

export const FETCH_LIMITS = Object.freeze({
  maxHops: 5,
  hopTimeoutMs: 6000,
  totalTimeoutMs: 12000,
  bodyReadTimeoutMs: 5000,
  maxBytes: 1024 * 1024,
  maxNonHtmlBytes: 64 * 1024,
  allowedPorts: [80, 443],
  userAgent:
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
});

export const IMAGE_LIMITS = Object.freeze({
  maxUploadBytes: 8 * 1024 * 1024,
  maxPixels: 25_000_000,
  allowedMimes: ["image/png", "image/jpeg", "image/webp"],
  gemmaMaxEdge: 1280,
});

export const PACKET_CAPS = Object.freeze({
  rawPayload: 2048,
  path: 256,
  queryKeys: 20,
  signals: 25,
  hops: 6,
  hopUrl: 512,
  title: 200,
  metaDescription: 300,
  visibleText: 3000,
  forms: 5,
  fieldsPerForm: 15,
  externalHosts: 8,
  serverFacts: 30,
  factText: 200,
});

/**
 * Create a signal object. Throws on an unknown strength so bugs surface in tests.
 */
export function signal(id, strength, fact, extra = {}) {
  if (!SIGNAL_STRENGTH.includes(strength)) {
    throw new Error(`Unknown signal strength "${strength}" for ${id}`);
  }
  return { id, strength, fact, value: null, hybrid: false, stage: "url", ...extra };
}

/**
 * Wrap a stage so it can never throw out of the pipeline. Returns
 * { status, duration_ms, note, data }.
 */
export async function runStage(name, fn, { onError } = {}) {
  const started = Date.now();
  try {
    const out = await fn();
    const data = out && typeof out === "object" && "data" in out ? out.data : out;
    const status = (out && out.status) || STAGE_STATUS.OK;
    const note = (out && out.note) || null;
    return { name, status, duration_ms: Date.now() - started, note, data };
  } catch (err) {
    const message = err && err.message ? String(err.message).slice(0, 300) : "unknown error";
    if (onError) {
      try {
        onError(err);
      } catch {
        /* ignore */
      }
    }
    return {
      name,
      status: STAGE_STATUS.FAILED,
      duration_ms: Date.now() - started,
      note: message,
      data: null,
    };
  }
}

export function clampText(value, max) {
  if (value === null || value === undefined) return null;
  const s = String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

export function maxStrength(signals) {
  let best = "neutral";
  for (const s of signals || []) {
    if (STRENGTH_RANK[s.strength] > STRENGTH_RANK[best]) best = s.strength;
  }
  return best;
}

/**
 * Remove anything that could be an API secret from a string: the literal
 * GEMINI_API_KEY value, Google-style key tokens (AIza..., AQ....) and any
 * key=... query parameter value. Safe to call on undefined.
 */
export function redactSecrets(text) {
  if (text === null || text === undefined) return "";
  let s = String(text);
  const key = process.env.GEMINI_API_KEY;
  if (key && key.length >= 8) s = s.split(key).join("[REDACTED]");
  s = s.replace(/\b(AIza[0-9A-Za-z_-]{10,}|AQ\.[0-9A-Za-z_-]{10,})/g, "[REDACTED]");
  s = s.replace(/([?&](?:key|api_key|apikey|x-goog-api-key)=)[^&\s"']+/gi, "$1[REDACTED]");
  return s;
}
