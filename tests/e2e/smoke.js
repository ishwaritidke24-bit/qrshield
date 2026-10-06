// End-to-end smoke test: fixture server + API in mock mode. No Gemini calls.
//
//   node tests/e2e/smoke.js
//
// Exits non-zero on any failure and prints a result table.

import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { start as startFixtures } from "../../scripts/fixture-server.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const FIXTURE_DIR = path.join(ROOT, "tests", "fixtures");
const FIXTURE_PORT = 4555;
const API_PORT = Number(process.env.SMOKE_API_PORT) || 3101;
const RATE_PORT = API_PORT + 1;
const FX = `http://127.0.0.1:${FIXTURE_PORT}`;
const BANNED = /\b(malicious|definitely|certainly|confirmed scam)\b/i;

const results = [];
function record(name, pass, detail = "") {
  results.push({ name, pass, detail: String(detail).slice(0, 160) });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? `  -- ${detail}` : ""}`);
}

async function check(name, fn) {
  try {
    const detail = await fn();
    record(name, true, detail || "");
  } catch (err) {
    record(name, false, err && err.message ? err.message : String(err));
  }
}

function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

// ---------------------------------------------------------------- API process
async function startApi({ port, env }) {
  const child = spawn(process.execPath, [path.join(ROOT, "server", "index.js")], {
    cwd: ROOT,
    env: { ...process.env, ...env, PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let logs = "";
  child.stdout.on("data", (d) => { logs += d; });
  child.stderr.on("data", (d) => { logs += d; });
  let exited = false;
  child.on("exit", () => { exited = true; });

  const deadline = Date.now() + 25_000;
  while (Date.now() < deadline) {
    if (exited) break;
    try {
      const r = await fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(1000) });
      if (r.ok) return { child, port, logs: () => logs, stop: () => child.kill() };
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  child.kill();
  throw new Error(`API on port ${port} did not become healthy. Logs:\n${logs.replace(/AIza[0-9A-Za-z_-]+|AQ\.[0-9A-Za-z_-]{10,}/g, "[REDACTED]")}`);
}

const api = (port) => `http://127.0.0.1:${port}/api`;

async function postUrl(port, url, { raw } = {}) {
  const body = raw !== undefined ? raw : JSON.stringify({ url });
  const r = await fetch(`${api(port)}/investigate-url`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    signal: AbortSignal.timeout(45_000),
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep text */ }
  return { status: r.status, json, text };
}

async function postImage(port, fileBuffer, { filename = "poster.png", mime = "image/png", url } = {}) {
  const fd = new FormData();
  if (fileBuffer) fd.append("image", new Blob([fileBuffer], { type: mime }), filename);
  if (url) fd.append("url", url);
  const r = await fetch(`${api(port)}/investigate`, { method: "POST", body: fd, signal: AbortSignal.timeout(45_000) });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep text */ }
  return { status: r.status, json, text };
}

async function secretHits() {
  const r = await fetch(`${FX}/status`);
  return (await r.json()).secret_hits;
}

// ------------------------------------------------------------ fixture loading
function loadFixtures() {
  const manifestPath = path.join(FIXTURE_DIR, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    const pngs = fs.existsSync(FIXTURE_DIR) ? fs.readdirSync(FIXTURE_DIR).filter((f) => f.endsWith(".png")) : [];
    return pngs.map((f) => ({ name: f.replace(/\.png$/, ""), file: f, payload: null }));
  }
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")); } catch (e) { throw new Error(`manifest.json unreadable: ${e.message}`); }
  let entries = [];
  if (Array.isArray(manifest)) entries = manifest;
  else if (manifest && Array.isArray(manifest.fixtures)) entries = manifest.fixtures;
  else if (manifest && typeof manifest === "object") entries = Object.entries(manifest).map(([k, v]) => ({ name: k, ...(typeof v === "object" ? v : { file: v }) }));
  return entries.map((e, i) => {
    const file = e.file || e.filename || e.path || e.image || (e.name ? `${e.name}.png` : `fixture-${i}.png`);
    const name = e.name || e.id || e.scenario || path.basename(file, path.extname(file));
    const payload = e.payload ?? e.qr ?? e.qr_payload ?? e.content ?? e.data ?? null;
    return { name, file: path.basename(file), payload: typeof payload === "string" ? payload : null, meta: e };
  });
}

/** Infer what to assert for a fixture from its name and QR payload. */
function expectationsFor({ name, payload }) {
  const n = name.toLowerCase();
  const p = payload || "";
  const checks = [];
  const fetched = (r) => r.facts.destination.fetched;

  if (/no[-_]?qr|blank|noqr/.test(n) || (payload === null && /none|null/.test(n))) {
    checks.push((r) => expect(r.facts.qr.found === false, "qr.found should be false"));
    checks.push((r) => expect(r.risk.level === "INSUFFICIENT_EVIDENCE", `risk ${r.risk.level} != INSUFFICIENT_EVIDENCE`));
    checks.push((r) => expect(r.risk.source === "forced_insufficient", `source ${r.risk.source}`));
    return checks;
  }
  checks.push((r) => expect(r.facts.qr.found === true, `qr.found false (${r.facts.qr.error || r.stages.qr.note})`));

  if (/^upi:/i.test(p) || /upi|no[-_]?fee/.test(n)) {
    checks.push((r) => expect(r.facts.payload.kind === "upi", `kind ${r.facts.payload.kind} != upi`));
    checks.push((r) => expect(!fetched(r) && r.stages.fetch.status === "skipped", "upi must not be fetched"));
    checks.push((r) => expect(r.facts.signals.some((s) => s.id === "upi_payment_request"), "missing upi_payment_request signal"));
  } else if (/^wifi:/i.test(p) || /wifi/.test(n)) {
    checks.push((r) => expect(r.facts.payload.kind === "wifi", `kind ${r.facts.payload.kind} != wifi`));
    checks.push((r) => expect(!fetched(r) && r.stages.fetch.status === "skipped", "wifi must not be fetched"));
    checks.push((r) => expect(!JSON.stringify(r.facts.payload.parsed).match(/"password"\s*:\s*"/), "wifi password must not be exposed"));
  } else if (/^(javascript|data|file|vbscript|blob|about|chrome):/i.test(p) || /blocked|javascript|scheme/.test(n)) {
    checks.push((r) => expect(r.facts.payload.kind === "blocked_scheme", `kind ${r.facts.payload.kind} != blocked_scheme`));
    checks.push((r) => expect(!fetched(r) && r.stages.fetch.status === "skipped", "blocked scheme must not be fetched"));
    checks.push((r) => expect(r.facts.signals.some((s) => s.strength === "critical"), "expected a critical signal"));
    checks.push((r) => expect(["HIGH_RISK", "CRITICAL"].includes(r.risk.level), `risk ${r.risk.level}`));
  } else if (/to-private|to-metadata|to-localhost|to-loopback|to-decimal|to-ipv6/.test(p) || /private|ssrf|internal/.test(n)) {
    checks.push((r) => expect(r.facts.payload.kind === "url", `kind ${r.facts.payload.kind}`));
    checks.push((r) => expect(!fetched(r), "private target must not be fetched"));
    checks.push((r) => expect(r.facts.redirect_chain.some((h) => h.blocked) || /blocked/.test(r.facts.destination.error_code || ""), `no blocked hop (error ${r.facts.destination.error_code})`));
    checks.push((r) => expect(r.facts.signals.some((s) => ["redirect_to_blocked_target", "destination_resolves_to_private_network"].includes(s.id)), "missing blocked-target signal"));
  } else if (/\/r\/chain/.test(p) || /chain|redirect|shortener/.test(n)) {
    checks.push((r) => expect(r.facts.payload.kind === "url", `kind ${r.facts.payload.kind}`));
    checks.push((r) => expect(r.facts.redirect_chain.length >= 3, `chain length ${r.facts.redirect_chain.length} < 3`));
    checks.push((r) => expect(fetched(r), `destination not fetched (${r.facts.destination.error_code})`));
  } else if (/\/phish/.test(p) || /phish|scholarship/.test(n)) {
    checks.push((r) => expect(fetched(r), `destination not fetched (${r.facts.destination.error_code})`));
    checks.push((r) => expect(r.facts.destination.sensitive_inputs.password === true, "password field not detected"));
    checks.push((r) => expect(r.facts.destination.sensitive_inputs.otp || r.facts.destination.sensitive_inputs.payment_card, "otp/card field not detected"));
    checks.push((r) => expect(r.facts.server_facts.some((f) => /password|otp|card|credential|payment/i.test(f.text)), "no sensitive-field server fact"));
    checks.push((r) => expect(["HIGH_RISK", "CRITICAL"].includes(r.risk.level), `risk ${r.risk.level}`));
  } else if (/\/legit/.test(p) || /legit|event|benign/.test(n)) {
    checks.push((r) => expect(fetched(r), `destination not fetched (${r.facts.destination.error_code})`));
    checks.push((r) => expect(["LOW_RISK", "MEDIUM_RISK"].includes(r.risk.level), `risk ${r.risk.level}`));
    checks.push((r) => expect(r.facts.destination.title && /Northfield/.test(r.facts.destination.title), `title ${r.facts.destination.title}`));
  } else if (/^https?:/i.test(p)) {
    checks.push((r) => expect(r.facts.payload.kind === "url", `kind ${r.facts.payload.kind}`));
  }
  return checks;
}

function commonReportChecks(r, status) {
  expect(status === 200, `HTTP ${status}: ${JSON.stringify(r).slice(0, 200)}`);
  for (const s of ["intake", "qr", "payload", "url", "fetch", "gemma"]) {
    expect(r.stages && r.stages[s] && ["ok", "degraded", "skipped", "failed", "blocked"].includes(r.stages[s].status), `stage ${s} missing/invalid`);
    expect(r.stages[s].status !== "failed", `stage ${s} failed: ${r.stages[s].note}`);
  }
  expect(r.risk && r.risk.level && r.risk.label, "risk missing");
  expect(!BANNED.test(`${r.risk.summary} ${r.risk.recommended_action}`), `banned vocabulary in risk text`);
  expect(!/AIza[0-9A-Za-z_-]{10,}|AQ\.[0-9A-Za-z_-]{10,}/.test(JSON.stringify(r)), "API key pattern leaked into report");
  expect(Array.isArray(r.facts.signals) && Array.isArray(r.facts.server_facts), "facts arrays missing");
  expect(r.meta && r.meta.mock === true, "expected mock mode");
}

// ------------------------------------------------------------------------ main
const WATCHDOG_MS = Number(process.env.SMOKE_WATCHDOG_MS) || 300_000;
async function main() {
  const watchdog = setTimeout(async () => {
    record("watchdog", false, `smoke run exceeded ${WATCHDOG_MS} ms; aborting with partial results`);
    for (const r of results) console.log(`${(r.pass ? "PASS" : "FAIL").padEnd(6)} ${r.name.slice(0, 44).padEnd(44)} ${r.detail}`);
    await flushAndExit(1);
  }, WATCHDOG_MS);
  watchdog.unref();
  console.log(`[smoke] starting fixture server on ${FX}`);
  const fx = await startFixtures({ port: FIXTURE_PORT });
  let apiMain = null;
  let apiRate = null;
  try {
    console.log(`[smoke] starting API on ${API_PORT} (mock, allowlist ${FX})`);
    apiMain = await startApi({
      port: API_PORT,
      env: { GEMMA_MOCK: "1", QRSHIELD_ALLOW_ORIGINS: FX, QRSHIELD_RATE_LIMIT_PER_MIN: "1000" },
    });

    await check("health endpoint", async () => {
      const r = await fetch(`${api(API_PORT)}/health`);
      const j = await r.json();
      expect(r.status === 200 && j.ok === true, `status ${r.status}`);
      expect(j.mock_mode === true, "mock_mode should be true");
      expect(j.allow_origins.includes(FX), "allow_origins missing fixture origin");
      expect(!/AIza|AQ\./.test(JSON.stringify(j)) && !("GEMINI_API_KEY" in j), "health must not leak key");
      return `version ${j.version} model ${j.model}`;
    });

    // ---- fixture posters -----------------------------------------------------
    const fixtures = loadFixtures();
    if (fixtures.length === 0) record("fixture posters present", false, `no fixtures in ${FIXTURE_DIR} (run: npm run fixtures)`);
    for (const fxt of fixtures) {
      const file = path.join(FIXTURE_DIR, fxt.file);
      await check(`poster ${fxt.name}`, async () => {
        expect(fs.existsSync(file), `missing ${fxt.file}`);
        const { status, json } = await postImage(API_PORT, fs.readFileSync(file), { filename: fxt.file });
        commonReportChecks(json, status);
        for (const c of expectationsFor(fxt)) c(json);
        // manifest-declared expectations (tests/fixtures/manifest.json "expected")
        const exp = (fxt.meta && fxt.meta.expected) || {};
        if (exp.payload_kind) expect(json.facts.payload.kind === exp.payload_kind, `manifest kind ${exp.payload_kind}, got ${json.facts.payload.kind}`);
        if (Array.isArray(exp.risk_level_one_of)) expect(exp.risk_level_one_of.includes(json.risk.level), `manifest risk one of ${exp.risk_level_one_of.join("|")}, got ${json.risk.level}`);
        // Wi-Fi: the literal password must not appear anywhere in the report
        const wifiPw = /^WIFI:/i.test(fxt.payload || "") ? (fxt.payload.match(/(?:^|;)P:([^;]*)/) || [])[1] : null;
        if (wifiPw) expect(!JSON.stringify(json).includes(wifiPw), "wifi password leaked into report JSON");
        return `${json.facts.payload.kind} -> ${json.risk.level} (${json.risk.source}, hops ${json.facts.redirect_chain.length}, fetch ${json.stages.fetch.status})`;
      });
    }

    // ---- url mode: SSRF redirect targets ---------------------------------------
    for (const p of ["/to-private", "/to-metadata", "/to-localhost", "/to-loopback-ip", "/to-decimal-ip", "/to-ipv6-loopback"]) {
      await check(`url ${p} blocked`, async () => {
        const { status, json } = await postUrl(API_PORT, `${FX}${p}`);
        commonReportChecks(json, status);
        expect(json.input.mode === "url" && json.stages.qr.status === "skipped", "url mode expected");
        expect(json.facts.destination.fetched === false, "must not be fetched");
        const blockedHop = json.facts.redirect_chain.some((h) => h.blocked);
        const code = json.facts.destination.error_code || "";
        expect(blockedHop || /blocked|non_standard_port/.test(code), `no blocked hop; error ${code}`);
        expect(["blocked", "degraded"].includes(json.stages.fetch.status), `fetch status ${json.stages.fetch.status}`);
        return `error ${code}, hops ${json.facts.redirect_chain.length}, risk ${json.risk.level}`;
      });
    }

    await check("fixture /secret never fetched", async () => {
      const hits = await secretHits();
      expect(hits === 0, `secret_hits=${hits}`);
      return "secret_hits=0";
    });

    await check("url /r/chain follows 2 hops to /phish", async () => {
      const { status, json } = await postUrl(API_PORT, `${FX}/r/chain`);
      commonReportChecks(json, status);
      expect(json.facts.redirect_chain.length >= 3, `chain ${json.facts.redirect_chain.length}`);
      expect(json.facts.destination.fetched, `not fetched ${json.facts.destination.error_code}`);
      expect(/\/phish$/.test(json.facts.destination.final_url || ""), `final ${json.facts.destination.final_url}`);
      expect(json.facts.destination.sensitive_inputs.password === true, "password field expected at /phish");
      return `risk ${json.risk.level}`;
    });

    await check("url /loop -> redirect loop handled", async () => {
      const { status, json } = await postUrl(API_PORT, `${FX}/loop`);
      commonReportChecks(json, status);
      expect(!json.facts.destination.fetched, "must not be fetched");
      expect(/redirect_loop|redirect_limit_exceeded/.test(json.facts.destination.error_code || ""), `error ${json.facts.destination.error_code}`);
      return `error ${json.facts.destination.error_code}`;
    });

    await check("url /huge -> body capped", async () => {
      const { status, json } = await postUrl(API_PORT, `${FX}/huge`);
      commonReportChecks(json, status);
      const d = json.facts.destination;
      expect((d.fetched && d.truncated && d.bytes_read <= 1024 * 1024 + 65536) || d.error_code === "too_large", `fetched ${d.fetched} truncated ${d.truncated} bytes ${d.bytes_read} err ${d.error_code}`);
      return `bytes_read ${d.bytes_read} truncated ${d.truncated}`;
    });

    await check("url /binary -> non-html, not parsed", async () => {
      const { status, json } = await postUrl(API_PORT, `${FX}/binary`);
      commonReportChecks(json, status);
      const d = json.facts.destination;
      expect(d.is_html === false, "is_html should be false");
      expect(d.title === null && d.forms.length === 0, "no page extraction for binary");
      expect(json.facts.signals.some((s) => /binary_download|non_html/.test(s.id)) || d.error_code === "non_html" || d.fetched, "binary should be recorded");
      return `content_type ${d.content_type} bytes ${d.bytes_read}`;
    });

    await check("url /apk -> apk_download strong signal", async () => {
      const { status, json } = await postUrl(API_PORT, `${FX}/apk`);
      commonReportChecks(json, status);
      expect(json.facts.destination.is_html === false, "is_html should be false");
      const sig = json.facts.signals.find((s) => s.id === "apk_download");
      expect(sig, "apk_download signal missing");
      expect(["strong", "critical"].includes(sig.strength), `strength ${sig.strength}`);
      expect(["HIGH_RISK", "CRITICAL"].includes(json.risk.level), `risk ${json.risk.level}`);
      return `risk ${json.risk.level} (${json.risk.source})`;
    });

    await check("url /slow -> timeout handled", async () => {
      const t = Date.now();
      const { status, json } = await postUrl(API_PORT, `${FX}/slow`);
      commonReportChecks(json, status);
      expect(!json.facts.destination.fetched, "slow page must not count as fetched");
      expect(/fetch_timeout|connection_error/.test(json.facts.destination.error_code || ""), `error ${json.facts.destination.error_code}`);
      expect(Date.now() - t < 30_000, "took too long");
      return `error ${json.facts.destination.error_code} in ${Date.now() - t} ms`;
    });

    await check("url non-standard port refused", async () => {
      const { status, json } = await postUrl(API_PORT, "http://127.0.0.1:8080/secret");
      commonReportChecks(json, status);
      expect(!json.facts.destination.fetched, "must not be fetched");
      expect(/non_standard_port|blocked/.test(json.facts.destination.error_code || ""), `error ${json.facts.destination.error_code}`);
      expect(json.facts.signals.some((s) => /non_standard_port|private_network|blocked/.test(s.id)), "expected port/blocked signal");
      return `error ${json.facts.destination.error_code}`;
    });

    await check("url javascript:alert(1) -> blocked scheme, no fetch", async () => {
      const { status, json } = await postUrl(API_PORT, "javascript:alert(1)");
      commonReportChecks(json, status);
      expect(json.facts.payload.kind === "blocked_scheme", `kind ${json.facts.payload.kind}`);
      expect(json.stages.fetch.status === "skipped" && !json.facts.destination.fetched, "must not fetch");
      expect(json.facts.signals.some((s) => s.strength === "critical"), "critical signal expected");
      expect(["HIGH_RISK", "CRITICAL"].includes(json.risk.level), `risk ${json.risk.level}`);
      return `risk ${json.risk.level}`;
    });

    await check("url 'not a url' -> handled (text payload or 400)", async () => {
      const { status, json } = await postUrl(API_PORT, "not a url");
      if (status === 400) return "400";
      commonReportChecks(json, status);
      expect(json.facts.payload.fetchable === false, "must not be fetchable");
      expect(json.risk.level === "INSUFFICIENT_EVIDENCE" || json.facts.payload.kind !== "url", `kind ${json.facts.payload.kind} risk ${json.risk.level}`);
      return `kind ${json.facts.payload.kind} risk ${json.risk.level}`;
    });

    await check("url 5000 chars -> 400", async () => {
      const { status, json } = await postUrl(API_PORT, "http://example.com/" + "a".repeat(5000));
      expect(status === 400, `status ${status}`);
      expect(json && json.error, "json error body expected");
      return json.error;
    });

    await check("url non-string -> 400", async () => {
      const { status } = await postUrl(API_PORT, null, { raw: JSON.stringify({ url: 123 }) });
      expect(status === 400, `status ${status}`);
    });

    await check("malformed json -> 400", async () => {
      const { status } = await postUrl(API_PORT, null, { raw: "{not json" });
      expect(status === 400, `status ${status}`);
    });

    await check("multipart without file -> 400", async () => {
      const { status, json } = await postImage(API_PORT, null);
      expect(status === 400, `status ${status}`);
      return json && json.error;
    });

    await check("text file as image -> 400", async () => {
      const { status, json } = await postImage(API_PORT, Buffer.from("hello, not an image"), { filename: "x.txt", mime: "text/plain" });
      expect(status === 400, `status ${status}`);
      return json && json.error;
    });

    await check("garbage bytes with image mime -> 400", async () => {
      const { status, json } = await postImage(API_PORT, Buffer.from("definitely not png bytes"), { filename: "x.png", mime: "image/png" });
      expect(status === 400, `status ${status}`);
      return json && json.error;
    });

    await check("unknown /api route -> 404 json", async () => {
      const r = await fetch(`${api(API_PORT)}/nope`);
      expect(r.status === 404, `status ${r.status}`);
    });

    // ---- rate limit on a separate instance with the default 10/min -----------
    await check("rate limit -> 429 after 10/min", async () => {
      apiRate = await startApi({ port: RATE_PORT, env: { GEMMA_MOCK: "1", QRSHIELD_RATE_LIMIT_PER_MIN: "10" } });
      const statuses = await Promise.all(
        Array.from({ length: 12 }, () => postUrl(RATE_PORT, "not a url").then((r) => r.status)),
      );
      const n429 = statuses.filter((s) => s === 429).length;
      expect(n429 >= 2, `expected >=2 429s, got ${n429}: ${statuses.join(",")}`);
      const h = await fetch(`${api(RATE_PORT)}/health`);
      expect(h.status === 200, "health must be exempt from the limiter");
      return `${n429} x 429 of 12`;
    });

    await check("fixture /secret still never fetched", async () => {
      const hits = await secretHits();
      expect(hits === 0, `secret_hits=${hits}`);
    });
  } finally {
    if (apiMain) apiMain.stop();
    if (apiRate) apiRate.stop();
    await fx.close();
  }

  const failed = results.filter((r) => !r.pass);
  console.log("\n" + "=".repeat(78));
  console.log(`${"RESULT".padEnd(6)} ${"CHECK".padEnd(44)} DETAIL`);
  console.log("-".repeat(78));
  for (const r of results) console.log(`${(r.pass ? "PASS" : "FAIL").padEnd(6)} ${r.name.slice(0, 44).padEnd(44)} ${r.detail}`);
  console.log("=".repeat(78));
  console.log(`${results.length - failed.length}/${results.length} passed`);
  if (apiMain && failed.length) {
    console.log("\n[smoke] API logs (redacted):\n" + apiMain.logs().replace(/AIza[0-9A-Za-z_-]+|AQ\.[0-9A-Za-z_-]{10,}/g, "[REDACTED]").slice(-4000));
  }
  await flushAndExit(failed.length ? 1 : 0);
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

main().catch(async (err) => {
  console.error("[smoke] fatal:", String(err && err.stack ? err.stack : err).replace(/AIza[0-9A-Za-z_-]+|AQ\.[0-9A-Za-z_-]{10,}/g, "[REDACTED]"));
  await flushAndExit(1);
});
