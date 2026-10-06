// HTTP routes: GET /health, POST /investigate (multipart), POST /investigate-url (json).
// Mounted under /api by server/index.js.

import express from "express";
import multer from "multer";

import { IMAGE_LIMITS, VERSION, redactSecrets } from "../pipeline/contracts.js";
import { investigate, InputError, resolveMockMode, currentModel } from "../pipeline/run.js";

const MAX_URL_CHARS = 4096;

/** Never let anything that looks like an API key reach a response or a log line. */
export function redact(text) {
  if (text === null || text === undefined) return text;
  return redactSecrets(String(text));
}

/**
 * Sliding-window per-IP limiter. Health is exempt; both POST routes share it.
 * @param {number} perMinute
 */
export function createRateLimiter(perMinute) {
  const limit = Number.isFinite(perMinute) && perMinute > 0 ? Math.floor(perMinute) : 10;
  const windowMs = 60_000;
  const hits = new Map(); // ip -> number[] (timestamps)
  let calls = 0;

  function sweep(now) {
    for (const [ip, stamps] of hits) {
      const kept = stamps.filter((t) => now - t < windowMs);
      if (kept.length) hits.set(ip, kept);
      else hits.delete(ip);
    }
  }

  function middleware(req, res, next) {
    const now = Date.now();
    calls += 1;
    if (calls % 500 === 0 || hits.size > 5000) sweep(now);
    const ip = req.ip || (req.socket && req.socket.remoteAddress) || "unknown";
    const stamps = (hits.get(ip) || []).filter((t) => now - t < windowMs);
    if (stamps.length >= limit) {
      const retryAfter = Math.max(1, Math.ceil((windowMs - (now - stamps[0])) / 1000));
      res.set("Retry-After", String(retryAfter));
      return res.status(429).json({
        error: "rate_limited",
        message: `Too many investigations from this address. Try again in ${retryAfter}s.`,
        retry_after_s: retryAfter,
      });
    }
    stamps.push(now);
    hits.set(ip, stamps);
    return next();
  }

  middleware.limit = limit;
  middleware.reset = () => hits.clear();
  return middleware;
}

function badRequest(res, code, message) {
  return res.status(400).json({ error: code, message: redact(message) });
}

/**
 * Validate the optional/required url field shared by both POST routes.
 * @returns {{ok:true, url:string|null}|{ok:false, code:string, message:string}}
 */
function readUrlField(value, { required }) {
  if (value === undefined || value === null || value === "") {
    return required
      ? { ok: false, code: "url_missing", message: "Body must contain a non-empty string field \"url\"." }
      : { ok: true, url: null };
  }
  if (typeof value !== "string") return { ok: false, code: "url_not_string", message: "\"url\" must be a string." };
  if (value.length > MAX_URL_CHARS) {
    return { ok: false, code: "url_too_long", message: `"url" exceeds ${MAX_URL_CHARS} characters.` };
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return required
      ? { ok: false, code: "url_missing", message: "\"url\" is empty." }
      : { ok: true, url: null };
  }
  return { ok: true, url: trimmed };
}

/**
 * @param {{allowOrigins?:Set<string>, rateLimitPerMin?:number, mock?:boolean|string}} opts
 * @returns {import('express').Router}
 */
export function createRouter({ allowOrigins = new Set(), rateLimitPerMin = 10, mock } = {}) {
  const router = express.Router();
  const limiter = createRateLimiter(rateLimitPerMin);
  const options = { allowOrigins, mock };

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: IMAGE_LIMITS.maxUploadBytes, files: 1, fields: 4, fieldSize: 8 * 1024 },
    fileFilter(_req, file, cb) {
      const mime = String(file.mimetype || "").toLowerCase().split(";")[0].trim();
      if (!IMAGE_LIMITS.allowedMimes.includes(mime)) {
        const err = new Error(`Unsupported image type "${mime || "unknown"}". Allowed: ${IMAGE_LIMITS.allowedMimes.join(", ")}.`);
        err.code = "bad_mime";
        err.status = 400;
        return cb(err);
      }
      return cb(null, true);
    },
  });

  router.get("/health", (_req, res) => {
    res.json({
      ok: true,
      version: VERSION,
      model: currentModel(),
      gemma_configured: Boolean(process.env.GEMINI_API_KEY),
      mock_mode: resolveMockMode(mock),
      allow_origins: [...allowOrigins],
    });
  });

  async function runAndRespond(res, { imageBuffer, imageMime, manualUrl }) {
    try {
      const report = await investigate({ imageBuffer, imageMime, manualUrl, options });
      return res.status(200).json(report);
    } catch (err) {
      if (err instanceof InputError || (err && err.status === 400 && err.code)) {
        return badRequest(res, err.code, err.message);
      }
      console.error("[qrshield] investigate failed:", redact(err && err.stack ? err.stack : String(err)));
      return res.status(500).json({ error: "internal_error", message: "Investigation failed unexpectedly." });
    }
  }

  // multipart: field "image" (file) + optional text field "url"
  router.post("/investigate", limiter, (req, res) => {
    upload.single("image")(req, res, (err) => {
      if (err) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return badRequest(res, "image_too_large", `Image exceeds ${IMAGE_LIMITS.maxUploadBytes} bytes.`);
        }
        if (err.code === "bad_mime") return badRequest(res, "bad_mime", err.message);
        if (err.code === "LIMIT_UNEXPECTED_FILE") return badRequest(res, "unexpected_file", "Upload the image in the \"image\" field.");
        return badRequest(res, "upload_error", err.message || "Malformed upload.");
      }
      const file = req.file || null;
      const rawUrl = req.body ? (req.body.url ?? req.body.manual_url) : undefined;
      const urlField = readUrlField(rawUrl, { required: !file });
      if (!urlField.ok) {
        if (!file && urlField.code === "url_missing") {
          return badRequest(res, "no_input", "Send an image file in the \"image\" field or a \"url\" text field.");
        }
        return badRequest(res, urlField.code, urlField.message);
      }
      return runAndRespond(res, {
        imageBuffer: file ? file.buffer : null,
        imageMime: file ? file.mimetype : null,
        manualUrl: urlField.url,
      });
    });
  });

  // json: { url }
  router.post("/investigate-url", limiter, express.json({ limit: "16kb", strict: true }), (req, res) => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const urlField = readUrlField(body.url, { required: true });
    if (!urlField.ok) return badRequest(res, urlField.code, urlField.message);
    return runAndRespond(res, { imageBuffer: null, imageMime: null, manualUrl: urlField.url });
  });

  // Router-level error handler so malformed JSON and multer errors become 400 here.
  // eslint-disable-next-line no-unused-vars
  router.use((err, _req, res, _next) => {
    if (err && (err.type === "entity.parse.failed" || err.type === "entity.too.large" || err.type === "charset.unsupported")) {
      return badRequest(res, "bad_json", "Request body must be valid JSON under 16 KiB.");
    }
    if (err && err.name === "MulterError") return badRequest(res, "upload_error", err.message);
    if (err && err.status === 400) return badRequest(res, err.code || "bad_request", err.message);
    console.error("[qrshield] route error:", redact(err && err.stack ? err.stack : String(err)));
    return res.status(500).json({ error: "internal_error", message: "Unexpected server error." });
  });

  return router;
}
