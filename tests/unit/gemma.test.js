import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  callGemma,
  buildPrompt,
  parseModelText,
  toApiSchema,
  pickMockScenario,
  fallbackReasoning,
  redact,
  API_SCHEMA,
} from "../../server/pipeline/gemma.js";
import { validateReasoning, SCHEMA } from "../../server/pipeline/validate.js";

const fixturesDir = new URL("../../server/fixtures/", import.meta.url);
const load = (scenario, name) =>
  JSON.parse(readFileSync(new URL(`${scenario}/${name}`, fixturesDir), "utf8"));

const GOOD = load("legit-event", "gemma.json");
const PACKET = load("legit-event", "packet.json");

/** Fake @google/genai client. Each queued value is a text or an Error. */
function fakeClient(queue) {
  const calls = [];
  return {
    calls,
    models: {
      async generateContent(req) {
        calls.push(req);
        const next = queue.shift();
        if (next instanceof Error) throw next;
        return { text: next, candidates: [{ finishReason: "STOP", content: { parts: [{ text: next }] } }] };
      },
    },
  };
}

const fast = { mock: false, retryDelayMs: 1, mockDelayMs: 1 };

/* ------------------------------- schema ----------------------------------- */

test("toApiSchema drops unsupported keywords and maps nullable types", () => {
  const api = toApiSchema(SCHEMA);
  const walk = (node) => {
    assert.equal(typeof node, "object");
    for (const k of ["$schema", "title", "additionalProperties", "maxLength", "maxItems", "minimum", "maximum", "pattern", "const"]) {
      assert.equal(k in node, false, `keyword ${k} leaked`);
    }
    if (node.type) assert.equal(node.type, node.type.toUpperCase());
    if (node.properties) {
      assert.deepEqual(node.propertyOrdering, Object.keys(node.properties));
      Object.values(node.properties).forEach(walk);
    }
    if (node.items) walk(node.items);
  };
  walk(api);
  assert.equal(api.type, "OBJECT");
  assert.equal(api.properties.poster_analysis.properties.claimed_organization.type, "STRING");
  assert.equal(api.properties.poster_analysis.properties.claimed_organization.nullable, true);
  assert.equal(api.properties.risk_level.nullable, undefined);
  assert.deepEqual(api.properties.risk_level.enum, SCHEMA.properties.risk_level.enum);
  assert.deepEqual(api.required, SCHEMA.required);
  assert.deepEqual(API_SCHEMA, api);
});

/* ------------------------------- prompt ----------------------------------- */

test("buildPrompt embeds the packet inside evidence_packet tags and states the rules", () => {
  const { system, user } = buildPrompt(PACKET);
  assert.match(user, /<evidence_packet>\s*\{[\s\S]*\}\s*<\/evidence_packet>/);
  assert.ok(user.includes('"investigation_id": "fixture-legit-event"'));
  assert.match(user, /PHYSICAL CLAIM/);
  assert.match(system, /untrusted/i);
  assert.match(system, /INSUFFICIENT_EVIDENCE/);
  assert.match(system, /server_facts/);
  assert.match(system, /"malicious"/);
  assert.match(system, /compare/i);
  const noImg = buildPrompt(PACKET, { hasImage: false });
  assert.match(noImg.user, /No poster image is available/);
});

/* ------------------------------- parsing ---------------------------------- */

test("parseModelText: native JSON", () => {
  const r = parseModelText(JSON.stringify(GOOD));
  assert.equal(r.path, "native");
  assert.equal(r.value.risk_level, "LOW_RISK");
});

test("parseModelText: fenced JSON", () => {
  const r = parseModelText("Here you go:\n```json\n" + JSON.stringify(GOOD) + "\n```\nThanks");
  assert.equal(r.path, "fenced");
  assert.equal(r.value.risk_level, "LOW_RISK");
});

test("parseModelText: prose-wrapped JSON with trailing text", () => {
  const r = parseModelText("Sure. " + JSON.stringify(GOOD) + " Let me know if you need more.");
  assert.equal(r.path, "sliced");
  assert.equal(r.value.confidence, 0.78);
});

test("parseModelText: balanced scan when trailing braces confuse the slice", () => {
  const text = "Result: " + JSON.stringify({ risk_level: "LOW_RISK", confidence: 0.3 }) + " and then } a stray brace }";
  const r = parseModelText(text);
  assert.equal(r.path, "balanced");
  assert.equal(r.value.risk_level, "LOW_RISK");
});

test("parseModelText: truncated / empty output fails cleanly", () => {
  assert.equal(parseModelText(JSON.stringify(GOOD).slice(0, 200)).value, null);
  assert.equal(parseModelText("").value, null);
  assert.equal(parseModelText(null).value, null);
  assert.equal(parseModelText("[1,2]").value, null);
});

test("redact removes key-like tokens", () => {
  assert.equal(redact("key AIzaSyA1234567890abcdefXYZ bad"), "key [REDACTED] bad");
  assert.equal(redact("x AQ.Ab8RN6J0ONEWyDG1GvzrgCabc y"), "x [REDACTED] y");
  assert.equal(redact("nothing here"), "nothing here");
});

test("fallbackReasoning is schema valid", () => {
  const r = validateReasoning(fallbackReasoning());
  assert.equal(r.ok, true);
  assert.equal(r.value.risk_level, "INSUFFICIENT_EVIDENCE");
});

/* ------------------------------- live path with fakes --------------------- */

test("live: native JSON response is validated and returned", async () => {
  const client = fakeClient([JSON.stringify(GOOD)]);
  const out = await callGemma({ packet: PACKET, image: { data: "AAAA", mimeType: "image/jpeg" }, client, ...fast });
  assert.equal(out.meta.available, true);
  assert.equal(out.meta.parse_path, "native");
  assert.equal(out.reasoning.risk_level, "LOW_RISK");
  assert.equal(client.calls.length, 1);
  const req = client.calls[0];
  assert.equal(req.config.responseMimeType, "application/json");
  assert.deepEqual(req.config.responseSchema, API_SCHEMA);
  assert.ok(typeof req.config.systemInstruction === "string" && req.config.systemInstruction.length > 100);
  assert.equal(req.contents[0].parts[0].inlineData.mimeType, "image/jpeg");
  assert.match(req.contents[0].parts[1].text, /<evidence_packet>/);
  assert.equal(req.config.temperature, 0.1);
});

test("live: no image -> no inlineData part", async () => {
  const client = fakeClient([JSON.stringify(GOOD)]);
  await callGemma({ packet: PACKET, image: null, client, ...fast });
  assert.equal(client.calls[0].contents[0].parts.length, 1);
  assert.ok("text" in client.calls[0].contents[0].parts[0]);
});

test("live: fenced JSON -> parse_path fenced", async () => {
  const client = fakeClient(["```json\n" + JSON.stringify(GOOD) + "\n```"]);
  const out = await callGemma({ packet: PACKET, client, ...fast });
  assert.equal(out.meta.parse_path, "fenced");
  assert.equal(out.meta.available, true);
});

test("live: truncated JSON triggers exactly one repair call, then succeeds", async () => {
  const client = fakeClient([JSON.stringify(GOOD).slice(0, 150), JSON.stringify(GOOD)]);
  const out = await callGemma({ packet: PACKET, client, ...fast });
  assert.equal(client.calls.length, 2);
  assert.equal(out.meta.parse_path, "repaired");
  assert.equal(out.meta.available, true);
  const repair = client.calls[1];
  assert.equal(repair.contents[0].parts.length, 1);
  assert.match(repair.contents[0].parts[0].text, /did not match the required JSON schema/);
  assert.ok(out.meta.validation_notes.some((n) => /first response rejected/.test(n)));
});

test("live: invalid enum triggers repair; repair failure -> fallback", async () => {
  const bad = { ...GOOD, risk_level: "SAFE" };
  const client = fakeClient([JSON.stringify(bad), "still not json"]);
  const out = await callGemma({ packet: PACKET, client, ...fast });
  assert.equal(client.calls.length, 2);
  assert.equal(out.meta.available, false);
  assert.equal(out.meta.parse_path, "fallback");
  assert.equal(out.reasoning.risk_level, "INSUFFICIENT_EVIDENCE");
  assert.deepEqual(out.reasoning.uncertainties, ["Model output could not be parsed"]);
  assert.match(out.meta.error, /could not be parsed/);
});

test("live: retries once on 503 then succeeds", async () => {
  const err = Object.assign(new Error("Service Unavailable"), { status: 503 });
  const client = fakeClient([err, JSON.stringify(GOOD)]);
  const out = await callGemma({ packet: PACKET, client, ...fast });
  assert.equal(client.calls.length, 2);
  assert.equal(out.meta.available, true);
});

test("live: 429 waits for Google's hinted retryDelay (capped) and retries once", async () => {
  const body = JSON.stringify({ error: { code: 429, message: "You exceeded your current quota. * Quota exceeded for metric: generate_requests_per_minute, limit: 5", status: "RESOURCE_EXHAUSTED", details: [{ "@type": "type.googleapis.com/google.rpc.RetryInfo", retryDelay: "1s" }] } });
  const err = Object.assign(new Error(body), { status: 429 });
  const client = fakeClient([err, JSON.stringify(GOOD)]);
  const t = Date.now();
  const out = await callGemma({ packet: PACKET, client, ...fast });
  assert.equal(client.calls.length, 2);
  assert.equal(out.meta.available, true);
  assert.ok(Date.now() - t >= 900, "should have waited about the hinted 1s");
  const twice = fakeClient([err, err]);
  const out2 = await callGemma({ packet: PACKET, client: twice, ...fast });
  assert.equal(twice.calls.length, 2, "never more than one retry");
  assert.match(out2.meta.error, /^429: Quota exceeded for metric/);
});

test("live: does not retry on 400", async () => {
  const err = Object.assign(new Error("Bad Request: key=AIzaSyFAKEFAKEFAKEFAKE"), { status: 400 });
  const client = fakeClient([err, JSON.stringify(GOOD)]);
  const out = await callGemma({ packet: PACKET, client, ...fast });
  assert.equal(client.calls.length, 1);
  assert.equal(out.meta.available, false);
  assert.match(out.meta.error, /^400/);
  assert.equal(/AIza/.test(out.meta.error), false);
  assert.equal(out.reasoning.risk_level, "INSUFFICIENT_EVIDENCE");
});

test("live: two consecutive failures -> fallback, never throws", async () => {
  const client = fakeClient([new Error("fetch failed"), new Error("fetch failed")]);
  const out = await callGemma({ packet: PACKET, client, ...fast });
  assert.equal(client.calls.length, 2);
  assert.equal(out.meta.available, false);
  assert.equal(out.meta.parse_path, "fallback");
});

test("live: timeout -> fallback", async () => {
  const client = {
    models: { generateContent: () => new Promise(() => {}) },
  };
  const out = await callGemma({ packet: PACKET, client, timeoutMs: 30, ...fast });
  assert.equal(out.meta.available, false);
  assert.match(out.meta.error, /timeout/);
});

test("live: validation notes (truncation) surface in meta", async () => {
  const noisy = { ...GOOD, uncertainties: Array.from({ length: 7 }, (_, i) => `u${i}`), extra: 1 };
  const client = fakeClient([JSON.stringify(noisy)]);
  const out = await callGemma({ packet: PACKET, client, ...fast });
  assert.equal(out.reasoning.uncertainties.length, 5);
  assert.ok(out.meta.validation_notes.some((n) => /truncated/.test(n)));
  assert.ok(out.meta.validation_notes.some((n) => /unknown key dropped/.test(n)));
});

/* ------------------------------- mock mode -------------------------------- */

test("pickMockScenario covers every branch", () => {
  assert.equal(pickMockScenario(load("no-fee-upi", "packet.json")), "no-fee-upi");
  assert.equal(pickMockScenario(load("no-qr", "packet.json")), "no-qr");
  assert.equal(pickMockScenario(load("fetch-failed", "packet.json")), "fetch-failed");
  assert.equal(pickMockScenario(load("scholarship-phish", "packet.json")), "scholarship-phish");
  assert.equal(pickMockScenario(load("legit-event", "packet.json")), "legit-event");
  assert.equal(pickMockScenario(null), "legit-event");
  // decoded false but a manual url present -> not no-qr
  const manual = { ...load("legit-event", "packet.json"), qr: { decoded: false } };
  assert.equal(pickMockScenario(manual), "legit-event");
});

test("mock: each scenario returns a validated fixture with real F-ids", async () => {
  for (const s of ["legit-event", "scholarship-phish", "no-fee-upi", "fetch-failed", "no-qr"]) {
    const packet = load(s, "packet.json");
    const out = await callGemma({ packet, mock: true, mockDelayMs: 1 });
    assert.equal(out.meta.available, true, s);
    assert.equal(out.meta.parse_path, "mock", s);
    assert.equal(out.meta.scenario, s);
    const ids = new Set(packet.server_facts.map((f) => f.id));
    for (const ev of out.reasoning.evidence) {
      if (ev.source === "deterministic") assert.ok(ids.has(ev.fact_id), `${s} cites ${ev.fact_id}`);
    }
  }
});

test("mock: fact ids are remapped to the incoming packet's facts", async () => {
  const packet = structuredClone(load("scholarship-phish", "packet.json"));
  // shuffle fact ids: move the OTP/card fact to F1 and shift others
  const facts = packet.server_facts;
  packet.server_facts = [{ ...facts[3], id: "F1" }, ...facts.filter((_, i) => i !== 3).map((f, i) => ({ ...f, id: `F${i + 2}` }))];
  const out = await callGemma({ packet, mock: true, mockDelayMs: 1 });
  const cardEv = out.reasoning.evidence.find((e) => /card number, CVV and OTP/.test(e.fact));
  assert.equal(cardEv.fact_id, "F1");
  const ids = new Set(packet.server_facts.map((f) => f.id));
  for (const ev of out.reasoning.evidence) {
    if (ev.source === "deterministic") assert.ok(ids.has(ev.fact_id));
  }
});

test("mock: unmatched deterministic items are relabeled as model", async () => {
  const packet = structuredClone(load("scholarship-phish", "packet.json"));
  packet.server_facts = [{ id: "F1", text: "Totally unrelated fact about weather." }];
  const out = await callGemma({ packet, mock: true, mockDelayMs: 1 });
  assert.ok(out.reasoning.evidence.every((e) => e.source === "model" && e.fact_id === null));
  assert.ok(out.meta.validation_notes.some((n) => /relabeled model/.test(n)));
});

test("mock: env GEMMA_MOCK=1 is honoured when mock is undefined", async () => {
  const prev = process.env.GEMMA_MOCK;
  process.env.GEMMA_MOCK = "1";
  try {
    const out = await callGemma({ packet: PACKET, mockDelayMs: 1 });
    assert.equal(out.meta.parse_path, "mock");
  } finally {
    if (prev === undefined) delete process.env.GEMMA_MOCK;
    else process.env.GEMMA_MOCK = prev;
  }
});

test("mock: GEMMA_MOCK=fail -> available=false and INSUFFICIENT_EVIDENCE fallback", async () => {
  const out = await callGemma({ packet: PACKET, mock: "fail", mockDelayMs: 1 });
  assert.equal(out.meta.available, false);
  assert.equal(out.meta.parse_path, "fallback");
  assert.equal(out.reasoning.risk_level, "INSUFFICIENT_EVIDENCE");
  assert.equal(out.reasoning.confidence, 0);
  assert.match(out.meta.error, /simulated/);
  const prev = process.env.GEMMA_MOCK;
  process.env.GEMMA_MOCK = "fail";
  try {
    const viaEnv = await callGemma({ packet: PACKET, mockDelayMs: 1 });
    assert.equal(viaEnv.meta.available, false);
  } finally {
    if (prev === undefined) delete process.env.GEMMA_MOCK;
    else process.env.GEMMA_MOCK = prev;
  }
});

test("mock: missing API key and no client falls back to mock", async () => {
  const prevKey = process.env.GEMINI_API_KEY;
  const prevMock = process.env.GEMMA_MOCK;
  delete process.env.GEMINI_API_KEY;
  delete process.env.GEMMA_MOCK;
  const origWarn = console.warn;
  const warnings = [];
  console.warn = (...a) => warnings.push(a.join(" "));
  try {
    const out = await callGemma({ packet: PACKET, mockDelayMs: 1 });
    assert.equal(out.meta.parse_path, "mock");
  } finally {
    console.warn = origWarn;
    if (prevKey !== undefined) process.env.GEMINI_API_KEY = prevKey;
    if (prevMock !== undefined) process.env.GEMMA_MOCK = prevMock;
  }
  assert.ok(warnings.length <= 1);
});
