// Express bootstrap. Exports the app for tests; listens only when run directly.

import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import express from "express";
import cors from "cors";

import { createRouter, redact } from "./routes/investigate.js";
import { VERSION } from "./pipeline/contracts.js";
import { currentModel, resolveMockMode } from "./pipeline/run.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const CLIENT_DIST = path.join(ROOT, "client", "dist");

/**
 * Parse QRSHIELD_ALLOW_ORIGINS: comma-separated exact origins. Anything that
 * does not round-trip through new URL(x).origin is dropped with a warning.
 * @param {string|undefined} raw
 * @returns {Set<string>}
 */
export function parseAllowOrigins(raw) {
  const out = new Set();
  for (const part of String(raw || "").split(",")) {
    const s = part.trim();
    if (!s) continue;
    try {
      const u = new URL(s);
      if ((u.protocol === "http:" || u.protocol === "https:") && u.origin === s) out.add(u.origin);
      else console.warn(`[qrshield] ignoring allow-origin "${s}": must be an exact http(s) origin like http://127.0.0.1:4555`);
    } catch {
      console.warn(`[qrshield] ignoring allow-origin "${s}": not a URL`);
    }
  }
  return out;
}

export function configFromEnv(env = process.env) {
  const rate = Number(env.QRSHIELD_RATE_LIMIT_PER_MIN);
  return {
    allowOrigins: parseAllowOrigins(env.QRSHIELD_ALLOW_ORIGINS),
    rateLimitPerMin: Number.isFinite(rate) && rate > 0 ? rate : 10,
    mock: undefined, // undefined -> callGemma reads GEMMA_MOCK / key presence itself
    port: Number(env.PORT) || 3001,
  };
}

/**
 * Build the Express app.
 * @param {{allowOrigins?:Set<string>, rateLimitPerMin?:number, mock?:boolean|string}} [opts]
 */
export function createApp(opts = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", false);
  app.use(cors({ origin: true, methods: ["GET", "POST"], maxAge: 600 }));

  app.use("/api", createRouter(opts));
  app.use("/api", (_req, res) => res.status(404).json({ error: "not_found" }));

  // Static client (if built) with SPA fallback for non-/api GETs.
  if (fs.existsSync(path.join(CLIENT_DIST, "index.html"))) {
    // Hashed assets may be cached; the HTML shell must not be, or a rebuilt client
    // keeps loading the previous bundle for up to an hour.
    app.use(
      express.static(CLIENT_DIST, {
        index: "index.html",
        maxAge: "1h",
        setHeaders(res, filePath) {
          if (filePath.endsWith("index.html")) res.setHeader("Cache-Control", "no-cache");
        },
      }),
    );
    app.use((req, res, next) => {
      if (req.method !== "GET" || req.path.startsWith("/api")) return next();
      return res.sendFile(path.join(CLIENT_DIST, "index.html"));
    });
  } else {
    app.get("/", (_req, res) => {
      res
        .type("text/plain")
        .send(`QRShield API ${VERSION}. Client not built: run "npm run build:client" or use "npm run dev:client". API at /api/health.`);
    });
  }

  // Global JSON error handler. Never leaks internals or secrets.
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err && err.name === "MulterError") return res.status(400).json({ error: "upload_error", message: redact(err.message) });
    if (err && (err.type === "entity.parse.failed" || err.type === "entity.too.large")) {
      return res.status(400).json({ error: "bad_json", message: "Request body must be valid JSON." });
    }
    if (err && err.status === 400) return res.status(400).json({ error: err.code || "bad_request", message: redact(err.message) });
    console.error("[qrshield] unhandled error:", redact(err && err.stack ? err.stack : String(err)));
    return res.status(500).json({ error: "internal_error", message: "Unexpected server error." });
  });

  return app;
}

const config = configFromEnv();
export const app = createApp(config);
export default app;

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  // Degrade, never crash: a stray rejection from a third-party client (e.g. an
  // SDK request settling after our own timeout) must not take the server down.
  process.on("unhandledRejection", (reason) => {
    console.error("[qrshield] unhandled rejection (ignored):", redact(reason && reason.stack ? reason.stack : String(reason)).slice(0, 600));
  });
  process.on("uncaughtException", (err) => {
    console.error("[qrshield] uncaught exception (server kept alive):", redact(err && err.stack ? err.stack : String(err)).slice(0, 600));
  });

  const server = app.listen(config.port, () => {
    console.log(`[qrshield] v${VERSION} listening on http://localhost:${config.port}`);
    console.log(`[qrshield] model=${currentModel()} gemma_configured=${Boolean(process.env.GEMINI_API_KEY)} mock_mode=${resolveMockMode(undefined)}`);
    if (config.allowOrigins.size) {
      console.warn("[qrshield] ***********************************************************");
      console.warn(`[qrshield] SSRF ALLOWLIST ACTIVE (dev/tests only): ${[...config.allowOrigins].join(", ")}`);
      console.warn("[qrshield] These exact origins bypass hostname/IP/port gates.");
      console.warn("[qrshield] ***********************************************************");
    }
    if (!fs.existsSync(path.join(CLIENT_DIST, "index.html"))) {
      console.log("[qrshield] client/dist not found; API only. Build with: npm run build:client");
    }
  });
  const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
