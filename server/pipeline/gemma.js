// Gemma 4 multimodal reasoning: prompt building, live call with retry/timeout,
// defensive parse ladder, one repair call, fallback object and mock mode.
// The API key is read from process.env only inside the live client factory
// and never logged or returned.

import fs, { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createHash } from "node:crypto";

import { DEFAULT_MODEL, redactSecrets } from "./contracts.js";
import { SCHEMA, validateReasoning } from "./validate.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const PROMPTS_DIR = path.join(here, "..", "prompts");
const FIXTURES_DIR = path.join(here, "..", "fixtures");

const SYSTEM_PROMPT = readFileSync(path.join(PROMPTS_DIR, "system.txt"), "utf8").trim();
const USER_TEMPLATE = readFileSync(path.join(PROMPTS_DIR, "user.txt"), "utf8").trim();

export const MOCK_SCENARIOS = Object.freeze([
  "legit-event",
  "scholarship-phish",
  "no-fee-upi",
  "fetch-failed",
  "no-qr",
]);

/** Keywords the Gemini API schema dialect does not accept. */
const DROP_KEYWORDS = new Set([
  "$schema",
  "title",
  "additionalProperties",
  "maxLength",
  "maxItems",
  "minItems",
  "minLength",
  "minimum",
  "maximum",
  "pattern",
  "const",
  "default",
  "examples",
]);

// Generation defaults for the free tier. Gemma 4 "thinks" before answering and
// those hidden tokens count toward maxOutputTokens; thinkingLevel "minimal"
// switches that off for this structured-report task (verified live), so the
// output budget only has to hold the JSON answer (~500-900 tokens).
const GENERATION_DEFAULTS = Object.freeze({
  thinkingLevel: "minimal", // "minimal" | "high" | null (null = model default)
  maxOutputTokens: 2048,
  mediaResolution: null, // e.g. "MEDIA_RESOLUTION_LOW" | "MEDIA_RESOLUTION_MEDIUM" | "MEDIA_RESOLUTION_HIGH" | null
  temperature: 0.1,
});

/** Merge env + explicit overrides onto the defaults. Explicit null disables a field. */
export function resolveGeneration(overrides = {}) {
  const env = process.env;
  const out = { ...GENERATION_DEFAULTS };
  if (env.GEMMA_THINKING_LEVEL) out.thinkingLevel = env.GEMMA_THINKING_LEVEL === "none" ? null : env.GEMMA_THINKING_LEVEL;
  if (Number(env.GEMMA_MAX_OUTPUT_TOKENS) > 0) out.maxOutputTokens = Number(env.GEMMA_MAX_OUTPUT_TOKENS);
  if (env.GEMMA_MEDIA_RESOLUTION) out.mediaResolution = env.GEMMA_MEDIA_RESOLUTION === "none" ? null : env.GEMMA_MEDIA_RESOLUTION;
  if (env.GEMMA_TEMPERATURE !== undefined && env.GEMMA_TEMPERATURE !== "") out.temperature = Number(env.GEMMA_TEMPERATURE);
  for (const [k, v] of Object.entries(overrides || {})) if (v !== undefined && k in out) out[k] = v;
  return out;
}

// Extra Gemma calls are expensive on a free quota: one transport retry lives in
// generateWithRetry (only after a 429/5xx/network failure, i.e. when the first
// call produced nothing), and at most ONE content retry per investigation here.
const RETRY_MIN_BUDGET_MS = 30000;

// ---- optional development cache -------------------------------------------
// Set GEMMA_CACHE_DIR (or pass cache: "<dir>") to reuse identical requests
// across runs so repeated testing does not consume API quota.
function cacheDirFor(option) {
  if (option === false) return null;
  if (typeof option === "string" && option) return option;
  if (option === true) return process.env.GEMMA_CACHE_DIR || path.join(process.cwd(), ".cache", "gemma");
  return process.env.GEMMA_CACHE_DIR || null;
}
function cacheKeyFor({ model, gen, system, user, image }) {
  const h = createHash("sha256");
  h.update(JSON.stringify({ model, gen, system, user: user.replace(/"investigation_id":\s*"[^"]*"/g, '"investigation_id":"-"') }));
  if (image?.data) h.update(image.data);
  return h.digest("hex");
}
function cacheRead(dir, key) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, key + ".json"), "utf8"));
  } catch {
    return null;
  }
}
function cacheWrite(dir, key, value) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, key + ".json"), JSON.stringify(value));
  } catch {
    /* cache is best-effort */
  }
}

const KEY_RE = /\b(AIza[0-9A-Za-z_-]{10,}|AQ\.[0-9A-Za-z_-]{10,})/g;

/** Remove anything that looks like an API key from a string. */
export function redact(text) {
  return redactSecrets(String(text ?? "")).replace(KEY_RE, "[REDACTED]");
}

/**
 * Convert the JSON-Schema file into the trimmed OpenAPI-style subset the
 * Gemini API accepts. ["string","null"] becomes type:"string" + nullable:true.
 * @param {object} schema
 * @returns {object}
 */
export function toApiSchema(schema) {
  if (Array.isArray(schema)) return schema.map(toApiSchema);
  if (!schema || typeof schema !== "object") return schema;
  const out = {};
  for (const [key, val] of Object.entries(schema)) {
    if (DROP_KEYWORDS.has(key)) continue;
    if (key === "type") {
      const types = Array.isArray(val) ? val : [val];
      const nonNull = types.filter((t) => t !== "null");
      out.type = (nonNull[0] || "string").toUpperCase();
      if (types.includes("null")) out.nullable = true;
      continue;
    }
    if (key === "properties") {
      out.properties = {};
      for (const [p, sub] of Object.entries(val)) out.properties[p] = toApiSchema(sub);
      out.propertyOrdering = Object.keys(val);
      continue;
    }
    if (key === "items") {
      out.items = toApiSchema(val);
      continue;
    }
    out[key] = val;
  }
  return out;
}

export const API_SCHEMA = toApiSchema(SCHEMA);

/**
 * Build the system prompt and the user prompt for a packet.
 * @param {object} packet evidence packet
 * @param {{ hasImage?: boolean }} [opts]
 * @returns {{ system: string, user: string }}
 */
export function buildPrompt(packet, { hasImage = true } = {}) {
  const imageNote = hasImage
    ? "The attached image is the PHYSICAL CLAIM: the poster on which this QR code was printed. Read every visible claim on it."
    : "No poster image is available for this investigation. Treat the poster claim as unknown: set the nullable poster strings to null, payment_claim to \"unspecified\", urgency_claim to \"none\", and note the gap in uncertainties.";
  const json = JSON.stringify(packet ?? {}, null, 2);
  const user = USER_TEMPLATE.replace("{{IMAGE_NOTE}}", imageNote).replace(
    "{{EVIDENCE_PACKET_JSON}}",
    json,
  );
  return { system: SYSTEM_PROMPT, user };
}

/* -------------------------------------------------------------------------- */
/* Parsing                                                                    */
/* -------------------------------------------------------------------------- */

function tryParse(text) {
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/** Scan for the first balanced top-level {...} block, string-aware. */
function balancedSlice(text) {
  const start = text.indexOf("{");
  if (start < 0) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

/**
 * Defensive parse ladder for model text.
 * @param {string} text
 * @returns {{ value: object|null, path: 'native'|'fenced'|'sliced'|'balanced'|null, error: string|null }}
 */
export function parseModelText(text) {
  if (typeof text !== "string" || !text.trim()) {
    return { value: null, path: null, error: "empty model output" };
  }
  const trimmed = text.trim();
  let v = tryParse(trimmed);
  if (v) return { value: v, path: "native", error: null };

  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    v = tryParse(fence[1].trim());
    if (v) return { value: v, path: "fenced", error: null };
  }

  const first = trimmed.indexOf("{");
  const last = trimmed.lastIndexOf("}");
  if (first >= 0 && last > first) {
    v = tryParse(trimmed.slice(first, last + 1));
    if (v) return { value: v, path: "sliced", error: null };
  }

  const balanced = balancedSlice(trimmed);
  if (balanced) {
    v = tryParse(balanced);
    if (v) return { value: v, path: "balanced", error: null };
  }

  return { value: null, path: null, error: "no JSON object found in model output" };
}

/* -------------------------------------------------------------------------- */
/* Fallback                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Schema-valid object used when the model is unavailable or unparseable.
 * @param {string[]} uncertainties
 */
export function fallbackReasoning(uncertainties = ["Model output could not be parsed"]) {
  return {
    risk_level: "INSUFFICIENT_EVIDENCE",
    confidence: 0,
    poster_analysis: {
      claimed_organization: null,
      offer: null,
      requested_action: null,
      payment_claim: "unspecified",
      urgency_claim: "none",
      deadline: null,
      other_claims: [],
    },
    destination_analysis: {
      apparent_purpose: null,
      apparent_organization: null,
      requested_user_action: null,
      collects_credentials: "unknown",
      requests_payment: "unknown",
      matches_poster_claims: "unknown",
    },
    contradictions: [],
    evidence: [],
    uncertainties: uncertainties.slice(0, 5),
    recommended_action:
      "Model reasoning was unavailable; rely on the verified technical facts and treat the QR code with caution.",
    summary_for_user:
      "The AI reasoning step could not be completed, so this report is limited to the verified technical findings. Review them before trusting the QR code.",
  };
}

/* -------------------------------------------------------------------------- */
/* Mock mode                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Pick the fixture scenario that best matches an evidence packet.
 * @param {object} packet
 * @returns {string}
 */
export function pickMockScenario(packet) {
  const p = packet || {};
  if (p.payload?.kind === "upi") return "no-fee-upi";
  if (p.qr?.decoded === false && !p.url_parts) return "no-qr";
  if (p.destination?.fetched === false) return "fetch-failed";
  const s = p.destination?.sensitive_inputs || {};
  if (s.password || s.payment_card || s.otp) return "scholarship-phish";
  return "legit-event";
}

function loadFixture(scenario, name) {
  const file = path.join(FIXTURES_DIR, scenario, name);
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function tokens(text) {
  return new Set(
    String(text || "")
      .toLowerCase()
      .split(/[^a-z0-9.]+/)
      .filter((t) => t.length > 2),
  );
}

function overlap(a, b) {
  const ta = tokens(a);
  const tb = tokens(b);
  if (!ta.size || !tb.size) return 0;
  let n = 0;
  for (const t of ta) if (tb.has(t)) n++;
  return n / Math.min(ta.size, tb.size);
}

/**
 * Rewrite fixture fact ids so they point to facts that exist in the real packet.
 * Facts are matched by text similarity against the fixture's own packet; items
 * that cannot be matched are relabeled as model inference.
 */
function remapFactIds(reasoning, fixturePacket, packet) {
  const real = packet?.server_facts || [];
  const realIds = new Set(real.map((f) => f.id));
  const fixtureFacts = new Map((fixturePacket?.server_facts || []).map((f) => [f.id, f.text]));
  const notes = [];
  reasoning.evidence = (reasoning.evidence || []).map((ev) => {
    if (ev.source !== "deterministic") return ev;
    if (realIds.has(ev.fact_id) && !fixturePacket) return ev;
    const wanted = fixtureFacts.get(ev.fact_id) || ev.fact;
    let best = null;
    let bestScore = 0;
    for (const f of real) {
      const score = Math.max(overlap(wanted, f.text), overlap(ev.fact, f.text));
      if (score > bestScore) {
        bestScore = score;
        best = f;
      }
    }
    if (best && bestScore >= 0.5) {
      if (best.id !== ev.fact_id) notes.push(`mock: evidence fact_id ${ev.fact_id} -> ${best.id}`);
      return { ...ev, fact_id: best.id };
    }
    if (realIds.has(ev.fact_id)) return ev;
    notes.push(`mock: evidence fact_id ${ev.fact_id} had no matching server fact, relabeled model`);
    return { ...ev, source: "model", fact_id: null };
  });
  return notes;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function mockCall({ packet, model, delayMs, scenario: forced }) {
  const started = Date.now();
  await sleep(delayMs);
  const scenario = forced || pickMockScenario(packet);
  const fixture = loadFixture(scenario, "gemma.json");
  const fixturePacket = loadFixture(scenario, "packet.json");
  if (!fixture) {
    return {
      reasoning: fallbackReasoning([`Mock fixture ${scenario} is missing`]),
      meta: {
        available: false,
        model,
        latency_ms: Date.now() - started,
        parse_path: "fallback",
        error: `mock fixture ${scenario} missing`,
        raw_text_excerpt: null,
        validation_notes: [],
        scenario,
      },
    };
  }
  const notes = remapFactIds(fixture, fixturePacket, packet);
  const validated = validateReasoning(fixture, packet);
  return {
    reasoning: validated.ok ? validated.value : fallbackReasoning(["Mock fixture failed validation"]),
    meta: {
      available: validated.ok,
      model,
      latency_ms: Date.now() - started,
      parse_path: validated.ok ? "mock" : "fallback",
      error: validated.ok ? null : validated.errors.join("; "),
      raw_text_excerpt: null,
      validation_notes: [...notes, ...validated.notes],
      scenario,
    },
  };
}

/* -------------------------------------------------------------------------- */
/* Live call                                                                  */
/* -------------------------------------------------------------------------- */

let warnedNoKey = false;
let cachedClient = null;

async function liveClient() {
  if (cachedClient) return cachedClient;
  const { GoogleGenAI } = await import("@google/genai");
  cachedClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  return cachedClient;
}

function errorStatus(err) {
  if (!err) return null;
  if (typeof err.status === "number") return err.status;
  if (typeof err.code === "number") return err.code;
  const m = String(err.message || "").match(/\b(4\d\d|5\d\d)\b/);
  return m ? Number(m[1]) : null;
}

// Free-tier 429s carry the wait Google wants (RetryInfo.retryDelay "23s" or
// "Please retry in 23.4s"). Waiting that long once is cheaper than a second
// doomed request; the wait is capped so the investigation still fits its timeout.
const RETRY_429_MAX_WAIT_MS = 30000;
export function suggestedRetryDelayMs(err) {
  const msg = String(err?.message || "");
  const m = msg.match(/"retryDelay"\s*:\s*"(\d+(?:\.\d+)?)s"/) || msg.match(/retry in (\d+(?:\.\d+)?)\s*s/i);
  if (!m) return null;
  const ms = Math.ceil(Number(m[1]) * 1000);
  return Number.isFinite(ms) && ms > 0 ? ms : null;
}

function isRetryable(err) {
  const status = errorStatus(err);
  if (status === null) return true; // network / unknown
  if (status === 429) return true;
  if (status >= 500) return true;
  return false;
}

function responseText(response) {
  if (!response) return "";
  const t = typeof response.text === "function" ? response.text() : response.text;
  if (typeof t === "string") return t;
  const parts = response.candidates?.[0]?.content?.parts || [];
  return parts.map((p) => p.text || "").join("");
}

function finishReason(response) {
  return response?.candidates?.[0]?.finishReason || null;
}

/** Compact, secret-free usage summary from a generateContent response. */
function usageSummary(response) {
  const u = response?.usageMetadata;
  if (!u) return null;
  const byModality = (details) => {
    const out = {};
    for (const d of Array.isArray(details) ? details : []) if (d && d.modality) out[String(d.modality).toLowerCase()] = d.tokenCount ?? null;
    return out;
  };
  const prompt = byModality(u.promptTokensDetails);
  return {
    finish_reason: finishReason(response),
    prompt_tokens: u.promptTokenCount ?? null,
    prompt_text_tokens: prompt.text ?? null,
    prompt_image_tokens: prompt.image ?? null,
    output_tokens: u.candidatesTokenCount ?? null,
    thoughts_tokens: u.thoughtsTokenCount ?? null,
    total_tokens: u.totalTokenCount ?? null,
  };
}

/**
 * One generateContent call with timeout; retries once on 429/5xx/network.
 */
async function generateWithRetry(client, request, { timeoutMs, retryDelayMs }) {
  let lastErr = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("gemma timeout")), timeoutMs);
    try {
      const req = { ...request, config: { ...request.config, abortSignal: controller.signal } };
      const response = await Promise.race([
        client.models.generateContent(req),
        new Promise((_, reject) =>
          controller.signal.addEventListener("abort", () =>
            reject(Object.assign(new Error("gemma timeout"), { code: "timeout" })),
          ),
        ),
      ]);
      clearTimeout(timer);
      return response;
    } catch (err) {
      clearTimeout(timer);
      lastErr = err;
      if (err?.code === "timeout" || !isRetryable(err) || attempt === 1) break;
      let wait = retryDelayMs;
      if (errorStatus(err) === 429) {
        const hinted = suggestedRetryDelayMs(err);
        if (hinted) wait = Math.min(Math.max(hinted, retryDelayMs), RETRY_429_MAX_WAIT_MS, Math.max(0, timeoutMs - 5000));
      }
      await sleep(wait);
    }
  }
  throw lastErr;
}

function describeError(err) {
  const status = errorStatus(err);
  let msg = redact(err?.message || String(err));
  const quota = msg.match(/Quota exceeded for metric:[^"\n]*/);
  if (quota) msg = `${quota[0].trim()} (${msg.slice(0, 120)})`;
  msg = msg.slice(0, 300);
  return status ? `${status}: ${msg}` : msg;
}

/**
 * Call Gemma 4 with the poster image and the evidence packet.
 * Never throws.
 * @param {object} args
 * @param {object} args.packet evidence packet from facts.js
 * @param {{ data: string, mimeType: string }|null} [args.image]
 * @param {boolean|string} [args.mock] undefined -> read env GEMMA_MOCK
 * @param {string} [args.model]
 * @param {number} [args.timeoutMs]
 * @param {{ models: { generateContent: Function } }} [args.client] injectable client
 * @param {number} [args.mockDelayMs] artificial mock delay (default 600)
 * @param {number} [args.retryDelayMs] backoff before the single retry (default 2000)
 * @param {string} [args.mockScenario] force a fixture scenario
 * @param {object} [args.generation] overrides for { thinkingLevel, maxOutputTokens, mediaResolution, temperature }
 * @param {boolean|string} [args.cache] development cache: true / directory / false (default: env GEMMA_CACHE_DIR)
 * @returns {Promise<{ reasoning: object|null, meta: object }>}
 */
export async function callGemma({
  packet,
  image = null,
  mock,
  model,
  timeoutMs = 60000,
  client,
  mockDelayMs = 600,
  retryDelayMs = 2000,
  mockScenario,
  generation,
  cache,
} = {}) {
  const resolvedModel = model || process.env.GEMMA_MODEL || DEFAULT_MODEL;
  const envMock = process.env.GEMMA_MOCK;
  let mode = mock;
  if (mode === undefined) {
    if (envMock === "fail") mode = "fail";
    else if (envMock === "1" || envMock === "true") mode = true;
    else mode = false;
  }
  if (mode === false && !client && !process.env.GEMINI_API_KEY) {
    if (!warnedNoKey) {
      console.warn("[gemma] GEMINI_API_KEY is not set; using mock Gemma responses.");
      warnedNoKey = true;
    }
    mode = true;
  }

  if (mode === "fail") {
    await sleep(Math.min(mockDelayMs, 200));
    return {
      reasoning: fallbackReasoning(["Model reasoning was unavailable (simulated failure)"]),
      meta: {
        available: false,
        model: resolvedModel,
        latency_ms: 0,
        parse_path: "fallback",
        error: "simulated model failure (GEMMA_MOCK=fail)",
        raw_text_excerpt: null,
        validation_notes: [],
      },
    };
  }
  if (mode === true) {
    return mockCall({ packet, model: resolvedModel, delayMs: mockDelayMs, scenario: mockScenario });
  }

  const started = Date.now();
  const meta = {
    available: false,
    model: resolvedModel,
    latency_ms: 0,
    parse_path: "fallback",
    error: null,
    raw_text_excerpt: null,
    validation_notes: [],
  };

  try {
    const ai = client || (await liveClient());
    const { system, user } = buildPrompt(packet, { hasImage: Boolean(image?.data) });
    const parts = [];
    if (image?.data) parts.push({ inlineData: { data: image.data, mimeType: image.mimeType || "image/jpeg" } });
    parts.push({ text: user });
    const gen = resolveGeneration(generation);
    const config = {
      systemInstruction: system,
      responseMimeType: "application/json",
      responseSchema: API_SCHEMA,
      temperature: gen.temperature,
      maxOutputTokens: gen.maxOutputTokens,
      ...(gen.thinkingLevel ? { thinkingConfig: { thinkingLevel: gen.thinkingLevel } } : {}),
      ...(gen.mediaResolution ? { mediaResolution: gen.mediaResolution } : {}),
    };
    meta.generation = { ...gen };
    meta.calls = 0;
    const request = { model: resolvedModel, contents: [{ role: "user", parts }], config };

    const cacheDir = client ? null : cacheDirFor(cache);
    const cacheKey = cacheDir ? cacheKeyFor({ model: resolvedModel, gen, system, user, image }) : null;
    if (cacheDir && cacheKey) {
      const hit = cacheRead(cacheDir, cacheKey);
      if (hit && hit.reasoning && hit.meta) {
        return { reasoning: hit.reasoning, meta: { ...hit.meta, cached: true, latency_ms: Date.now() - started } };
      }
    }

    let response = await generateWithRetry(ai, request, { timeoutMs, retryDelayMs });
    meta.calls += 1;
    let text = responseText(response);
    let extraCallUsed = false;

    if (finishReason(response) === "MAX_TOKENS" || !text.trim()) {
      // Truncated or empty: one more call, SAME low-cost configuration, more compact ask.
      meta.validation_notes.push(finishReason(response) === "MAX_TOKENS" ? "model output hit maxOutputTokens" : "model returned empty output");
      const lastPart = parts[parts.length - 1];
      const compactParts = [
        ...parts.slice(0, -1),
        {
          text:
            (lastPart && lastPart.text ? lastPart.text : "") +
            "\n\nBe compact: every string under 120 characters, every array at most 3 items, no repetition. Return only the JSON object.",
        },
      ];
      const remaining = Math.max(RETRY_MIN_BUDGET_MS, timeoutMs - (Date.now() - started));
      try {
        const retryResp = await generateWithRetry(
          ai,
          { ...request, contents: [{ role: "user", parts: compactParts }] },
          { timeoutMs: remaining, retryDelayMs },
        );
        meta.calls += 1;
        extraCallUsed = true;
        const retryText = responseText(retryResp);
        if (retryText.trim() && finishReason(retryResp) !== "MAX_TOKENS") {
          response = retryResp;
          text = retryText;
          meta.validation_notes.push("compact retry succeeded");
        } else {
          meta.validation_notes.push("compact retry also truncated or empty");
        }
      } catch (err) {
        extraCallUsed = true;
        meta.validation_notes.push(`compact retry failed: ${describeError(err)}`);
      }
    }
    meta.raw_text_excerpt = text.slice(0, 400);
    meta.usage = usageSummary(response);

    let parsed = parseModelText(text);
    let validated = parsed.value ? validateReasoning(parsed.value, packet) : null;
    let parsePath = parsed.path;

    if ((!validated || !validated.ok) && !extraCallUsed && text.trim()) {
      // Schema-invalid but complete output: one text-only repair call, same config.
      const problem = parsed.value ? validated.errors.join("; ") : parsed.error;
      meta.validation_notes.push(`first response rejected: ${problem}`);
      const repairText =
        "Your previous answer did not match the required JSON schema.\n" +
        `Problem: ${problem}\n` +
        "Return ONLY the corrected JSON object, no commentary. Preserve the substance of your analysis.\n" +
        "Previous answer:\n" +
        text.slice(0, 6000);
      const repairReq = {
        model: resolvedModel,
        contents: [{ role: "user", parts: [{ text: repairText }] }],
        config,
      };
      const remaining = Math.max(RETRY_MIN_BUDGET_MS, timeoutMs - (Date.now() - started));
      const repairResp = await generateWithRetry(ai, repairReq, { timeoutMs: remaining, retryDelayMs });
      meta.calls += 1;
      const repairTextOut = responseText(repairResp);
      parsed = parseModelText(repairTextOut);
      validated = parsed.value ? validateReasoning(parsed.value, packet) : null;
      if (validated && validated.ok) {
        parsePath = "repaired";
        meta.raw_text_excerpt = repairTextOut.slice(0, 400);
      } else {
        meta.validation_notes.push(`repair rejected: ${parsed.value ? validated.errors.join("; ") : parsed.error}`);
      }
    } else if ((!validated || !validated.ok) && !meta.validation_notes.some((n) => n.startsWith("first response rejected"))) {
      meta.validation_notes.push(`response rejected: ${parsed.value ? validated.errors.join("; ") : parsed.error}`);
    }

    meta.latency_ms = Date.now() - started;
    if (validated && validated.ok) {
      meta.available = true;
      meta.parse_path = parsePath;
      meta.validation_notes.push(...validated.notes);
      if (cacheDir && cacheKey) cacheWrite(cacheDir, cacheKey, { reasoning: validated.value, meta });
      return { reasoning: validated.value, meta };
    }
    meta.error = "model output could not be parsed into the schema";
    return { reasoning: fallbackReasoning(["Model output could not be parsed"]), meta };
  } catch (err) {
    meta.latency_ms = Date.now() - started;
    meta.error = describeError(err);
    return {
      reasoning: fallbackReasoning(["Model reasoning was unavailable"]),
      meta,
    };
  }
}
