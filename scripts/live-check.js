// Runs the REAL pipeline (live Gemma, no mock) on each fixture poster through
// the API, saves every response under demo/<fixture>.json and prints a table.
// Skips gracefully when GEMINI_API_KEY is not set.
//
//   node scripts/live-check.js [fixture-name ...]     (LIVE_PAUSE_MS between fixtures, default 15000)

import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { start as startFixtures } from "./fixture-server.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_DIR = path.join(ROOT, "tests", "fixtures");
const DEMO_DIR = path.join(ROOT, "demo");
const FIXTURE_PORT = 4555;
const API_PORT = Number(process.env.LIVE_API_PORT) || 3103;
// Free-tier per-minute quota: pause between fixtures (ms). Override with LIVE_PAUSE_MS.
const PAUSE_MS = process.env.LIVE_PAUSE_MS !== undefined ? Number(process.env.LIVE_PAUSE_MS) : 15000;
const ONLY = new Set(process.argv.slice(2).filter((a) => !a.startsWith("-")));
const FX = `http://127.0.0.1:${FIXTURE_PORT}`;
const BANNED = /\b(malicious|definitely|certainly|confirmed scam)\b/i;
const redact = (s) => String(s).replace(/AIza[0-9A-Za-z_-]+|AQ\.[0-9A-Za-z_-]{10,}/g, "[REDACTED]");

if (!process.env.GEMINI_API_KEY) {
  console.log("[live-check] GEMINI_API_KEY not set; skipping live check (exit 0).");
  process.exit(0);
}

function loadFixtures() {
  const manifestPath = path.join(FIXTURE_DIR, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    return fs.existsSync(FIXTURE_DIR)
      ? fs.readdirSync(FIXTURE_DIR).filter((f) => f.endsWith(".png")).map((f) => ({ name: f.replace(/\.png$/, ""), file: f }))
      : [];
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  let entries = [];
  if (Array.isArray(manifest)) entries = manifest;
  else if (manifest && Array.isArray(manifest.fixtures)) entries = manifest.fixtures;
  else entries = Object.entries(manifest).map(([k, v]) => ({ name: k, ...(typeof v === "object" ? v : { file: v }) }));
  return entries.map((e, i) => {
    const file = e.file || e.filename || e.path || e.image || (e.name ? `${e.name}.png` : `fixture-${i}.png`);
    const expected = e.expected && Array.isArray(e.expected.risk_level_one_of) ? e.expected.risk_level_one_of : null;
    return { name: e.name || e.id || e.scenario || path.basename(file, path.extname(file)), file: path.basename(file), expected };
  });
}

async function startApi(port) {
  const env = { ...process.env, PORT: String(port), QRSHIELD_ALLOW_ORIGINS: FX, QRSHIELD_RATE_LIMIT_PER_MIN: "1000" };
  delete env.GEMMA_MOCK;
  const child = spawn(process.execPath, [path.join(ROOT, "server", "index.js")], { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  let logs = "";
  child.stdout.on("data", (d) => { logs += d; });
  child.stderr.on("data", (d) => { logs += d; });
  const deadline = Date.now() + 25_000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(1000) });
      if (r.ok) {
        const h = await r.json();
        if (h.mock_mode) throw new Error("API started in mock mode; unset GEMMA_MOCK");
        return { stop: () => child.kill(), logs: () => redact(logs) };
      }
    } catch (e) {
      if (/mock mode/.test(e.message)) { child.kill(); throw e; }
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  child.kill();
  throw new Error(`API did not start:\n${redact(logs)}`);
}

async function main() {
  const fixtures = loadFixtures().filter((f) => !ONLY.size || ONLY.has(f.name));
  if (!fixtures.length) {
    console.log(`[live-check] no fixtures in ${FIXTURE_DIR}; run "npm run fixtures" first.`);
    process.exit(1);
  }
  fs.mkdirSync(DEMO_DIR, { recursive: true });
  const fx = await startFixtures({ port: FIXTURE_PORT });
  let api = null;
  let apiLogs = null;
  const rows = [];
  let failures = 0;
  try {
    api = await startApi(API_PORT);
    apiLogs = api.logs;
    let first = true;
    for (const f of fixtures) {
      if (!first && PAUSE_MS > 0) await new Promise((r) => setTimeout(r, PAUSE_MS));
      first = false;
      const file = path.join(FIXTURE_DIR, f.file);
      if (!fs.existsSync(file)) { rows.push({ name: f.name, note: "missing file" }); failures += 1; continue; }
      const fd = new FormData();
      const mime = /\.jpe?g$/i.test(f.file) ? "image/jpeg" : "image/png";
      fd.append("image", new Blob([fs.readFileSync(file)], { type: mime }), f.file);
      const t = Date.now();
      let status = 0;
      let report = null;
      try {
        const r = await fetch(`http://127.0.0.1:${API_PORT}/api/investigate`, { method: "POST", body: fd, signal: AbortSignal.timeout(120_000) });
        status = r.status;
        report = await r.json();
      } catch (e) {
        rows.push({ name: f.name, note: `request failed: ${redact(e.message)}` });
        failures += 1;
        continue;
      }
      const wall = Date.now() - t;
      if (status !== 200) { rows.push({ name: f.name, note: `HTTP ${status} ${JSON.stringify(report).slice(0, 120)}` }); failures += 1; continue; }
      fs.writeFileSync(path.join(DEMO_DIR, `${f.name}.json`), JSON.stringify(report, null, 2));
      const texts = [report.risk.summary, report.risk.recommended_action, report.reasoning && report.reasoning.summary_for_user, report.reasoning && report.reasoning.recommended_action].filter(Boolean).join(" ");
      const vocabOk = !BANNED.test(texts);
      const detMiscite = (report.reasoning && report.reasoning.evidence || []).filter((e) => e.source === "deterministic" && !report.facts.server_facts.some((sf) => sf.id === e.fact_id)).length;
      const expectedOk = !f.expected || f.expected.includes(report.risk.level);
      if (!vocabOk || !report.reasoning_meta.available || detMiscite || !expectedOk) failures += 1;
      rows.push({
        name: f.name,
        risk: `${report.risk.level} (${report.risk.source})${expectedOk ? "" : " UNEXPECTED"}`,
        expected: f.expected ? f.expected.join("|") : "-",
        gemma: report.reasoning && report.reasoning.risk_level,
        parse: report.reasoning_meta.parse_path,
        latency: `${report.reasoning_meta.latency_ms} ms (wall ${wall})`,
        available: report.reasoning_meta.available,
        vocab: vocabOk ? "ok" : "VIOLATION",
        adjustments: report.server_adjustments.map((a) => a.rule).join(",") || "-",
        note: detMiscite ? `${detMiscite} unverified deterministic cite(s)` : report.reasoning_meta.error ? redact(report.reasoning_meta.error).slice(0, 80) : "",
      });
    }
  } finally {
    if (api) api.stop();
    await fx.close();
  }
  console.log("\n" + "=".repeat(110));
  console.log(["FIXTURE".padEnd(18), "FINAL RISK".padEnd(32), "GEMMA".padEnd(22), "PARSE".padEnd(9), "LATENCY".padEnd(22), "VOCAB"].join(" "));
  console.log("-".repeat(110));
  for (const r of rows) {
    console.log([
      String(r.name).slice(0, 18).padEnd(18),
      String(r.risk || "-").slice(0, 32).padEnd(32),
      String(r.gemma || "-").padEnd(22),
      String(r.parse || "-").padEnd(9),
      String(r.latency || "-").padEnd(22),
      String(r.vocab || "-"),
    ].join(" "));
    if (r.expected && r.expected !== "-" && /UNEXPECTED/.test(r.risk)) console.log(`   expected one of: ${r.expected}`);
    if (r.adjustments && r.adjustments !== "-") console.log(`   adjustments: ${r.adjustments}`);
    if (r.note) console.log(`   note: ${r.note}`);
  }
  console.log("=".repeat(110));
  console.log(`responses saved under ${DEMO_DIR}; ${rows.length - failures}/${rows.length} clean`);
  if (failures && apiLogs) console.log(`\n[live-check] API logs (redacted, tail):\n${apiLogs().slice(-6000)}`);
  await flushAndExit(failures ? 1 : 0);
}

// process.exit() right after console.log can truncate piped stdout; flush first.
function flushAndExit(code) {
  return new Promise((resolve) => {
    process.stdout.write("", () => {
      process.stderr.write("", () => {
        process.exit(code);
        resolve();
      });
    });
  });
}

main().catch(async (e) => { console.error("[live-check] fatal:", redact(e.stack || e)); await flushAndExit(1); });
