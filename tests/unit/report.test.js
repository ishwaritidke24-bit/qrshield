import { test } from "node:test";
import assert from "node:assert/strict";

import {
  reconcileRisk,
  assembleReport,
  inlineFallbackRisk,
  DEFAULT_ACTIONS,
} from "../../server/pipeline/report.js";
import { RISK_LABELS, signal } from "../../server/pipeline/contracts.js";

const BANNED = /\b(malicious|definitely|certainly|confirmed scam)\b/i;

function gemma(level, extra = {}) {
  return {
    risk_level: level,
    confidence: 0.8,
    summary_for_user: `Model summary for ${level}.`,
    recommended_action: `Model action for ${level}.`,
    ...extra,
  };
}

function facts({ signals = [], floor = { level: null, triggered_by: [] }, server_facts = [] } = {}) {
  return { signals, server_facts, floor };
}

const META_OK = { available: true, model: "m", latency_ms: 1, parse_path: "native", error: null };
const META_DOWN = { available: false, model: "m", latency_ms: 1, parse_path: "fallback", error: "boom" };

test("gemma level is honoured when no floor applies", () => {
  const r = reconcileRisk({
    reasoning: gemma("MEDIUM_RISK"),
    reasoning_meta: META_OK,
    facts: facts(),
    qrFound: true,
    manualUrl: null,
    payloadKind: "url",
    destinationFetched: true,
  });
  assert.equal(r.level, "MEDIUM_RISK");
  assert.equal(r.label, RISK_LABELS.MEDIUM_RISK);
  assert.equal(r.source, "gemma");
  assert.equal(r.confidence, 0.8);
  assert.equal(r.summary, "Model summary for MEDIUM_RISK.");
  assert.equal(r.recommended_action, "Model action for MEDIUM_RISK.");
  assert.deepEqual(r.adjustments, []);
});

test("deterministic floor raises a lower gemma level and records an adjustment", () => {
  const r = reconcileRisk({
    reasoning: gemma("LOW_RISK"),
    reasoning_meta: META_OK,
    facts: facts({
      floor: { level: "HIGH_RISK", triggered_by: ["apk_download"] },
      server_facts: [{ id: "F1", text: "Destination serves an Android APK download.", signal_id: "apk_download" }],
    }),
    qrFound: true,
    manualUrl: null,
    payloadKind: "url",
    destinationFetched: true,
  });
  assert.equal(r.level, "HIGH_RISK");
  assert.equal(r.source, "floor_override");
  assert.ok(r.confidence >= 0.6);
  assert.equal(r.adjustments.length, 1);
  assert.equal(r.adjustments[0].rule, "deterministic_floor_raised");
  assert.equal(r.adjustments[0].from, "LOW_RISK");
  assert.equal(r.adjustments[0].to, "HIGH_RISK");
  assert.match(r.summary, /HIGH RISK/);
  assert.match(r.summary, /APK download/);
  // the model's "safe" action must not survive a raise
  assert.equal(r.recommended_action, DEFAULT_ACTIONS.HIGH_RISK);
});

test("floor never lowers a higher gemma level", () => {
  const r = reconcileRisk({
    reasoning: gemma("CRITICAL"),
    reasoning_meta: META_OK,
    facts: facts({ floor: { level: "MEDIUM_RISK", triggered_by: ["scheme_http"] } }),
    qrFound: true,
    manualUrl: null,
    payloadKind: "url",
    destinationFetched: true,
  });
  assert.equal(r.level, "CRITICAL");
  assert.equal(r.source, "gemma");
  assert.deepEqual(r.adjustments, []);
});

test("floor raises INSUFFICIENT_EVIDENCE from the model (e.g. blocked scheme)", () => {
  const r = reconcileRisk({
    reasoning: gemma("INSUFFICIENT_EVIDENCE"),
    reasoning_meta: META_OK,
    facts: facts({ floor: { level: "HIGH_RISK", triggered_by: ["blocked_scheme"] } }),
    qrFound: true,
    manualUrl: null,
    payloadKind: "blocked_scheme",
    destinationFetched: false,
  });
  assert.equal(r.level, "HIGH_RISK");
  assert.equal(r.source, "floor_override");
});

test("gemma unavailable -> deterministic fallback (critical signal -> CRITICAL)", () => {
  const sig = signal("blocked_scheme", "critical", "Payload uses a javascript: scheme.", { stage: "payload" });
  const r = reconcileRisk({
    reasoning: null,
    reasoning_meta: META_DOWN,
    facts: facts({ signals: [sig], server_facts: [{ id: "F1", text: sig.fact, signal_id: sig.id }] }),
    qrFound: true,
    manualUrl: null,
    payloadKind: "blocked_scheme",
    destinationFetched: false,
  });
  assert.equal(r.level, "CRITICAL");
  assert.equal(r.source, "deterministic_fallback");
  assert.equal(r.adjustments[0].rule, "deterministic_fallback_used");
  assert.match(r.summary, /deterministic technical checks/i);
  assert.match(r.summary, /javascript: scheme/);
  assert.doesNotMatch(r.summary, BANNED);
});

test("gemma unavailable honours an injected fallback function and still applies the floor", () => {
  const r = reconcileRisk({
    reasoning: { risk_level: "LOW_RISK", confidence: 0.9 },
    reasoning_meta: META_DOWN, // available=false overrides the fallback object's level
    facts: facts({ floor: { level: "MEDIUM_RISK", triggered_by: ["ip_literal_host"] } }),
    qrFound: true,
    manualUrl: null,
    payloadKind: "url",
    destinationFetched: true,
    fallbackRiskFn: () => "LOW_RISK",
  });
  assert.equal(r.level, "MEDIUM_RISK");
  assert.equal(r.source, "floor_override");
  assert.equal(r.adjustments.map((a) => a.rule).join(","), "deterministic_fallback_used,deterministic_floor_raised");
});

test("inline fallback table matches docs/ARCHITECTURE.md", () => {
  const s = (strength) => signal("x", strength, "f");
  assert.equal(inlineFallbackRisk([s("critical")]), "CRITICAL");
  assert.equal(inlineFallbackRisk([s("strong"), s("strong")]), "HIGH_RISK");
  assert.equal(inlineFallbackRisk([s("strong")]), "MEDIUM_RISK");
  assert.equal(inlineFallbackRisk([s("medium"), s("medium")]), "MEDIUM_RISK");
  assert.equal(inlineFallbackRisk([s("weak"), s("neutral")], { destinationFetched: true }), "LOW_RISK");
  assert.equal(inlineFallbackRisk([s("weak")], { destinationFetched: false }), "INSUFFICIENT_EVIDENCE");
  assert.equal(inlineFallbackRisk([s("medium")], { destinationFetched: true }), "INSUFFICIENT_EVIDENCE");
  assert.equal(inlineFallbackRisk([]), "INSUFFICIENT_EVIDENCE");
});

test("no QR and no manual URL -> forced INSUFFICIENT_EVIDENCE even if the model said HIGH", () => {
  const r = reconcileRisk({
    reasoning: gemma("HIGH_RISK"),
    reasoning_meta: META_OK,
    facts: facts(),
    qrFound: false,
    manualUrl: null,
    payloadKind: "none",
    destinationFetched: false,
  });
  assert.equal(r.level, "INSUFFICIENT_EVIDENCE");
  assert.equal(r.label, "INSUFFICIENT EVIDENCE");
  assert.equal(r.source, "forced_insufficient");
  assert.equal(r.confidence, 0);
  assert.equal(r.adjustments[0].rule, "forced_insufficient_no_input");
  assert.match(r.summary, /Model note from the poster alone/);
});

test("manual URL with no QR is not forced insufficient", () => {
  const r = reconcileRisk({
    reasoning: gemma("HIGH_RISK"),
    reasoning_meta: META_OK,
    facts: facts(),
    qrFound: false,
    manualUrl: "http://example.com/x",
    payloadKind: "url",
    destinationFetched: true,
  });
  assert.equal(r.level, "HIGH_RISK");
  assert.equal(r.source, "gemma");
});

test("missing model text falls back to default wording and clamps confidence", () => {
  const r = reconcileRisk({
    reasoning: { risk_level: "LOW_RISK", confidence: 7 },
    reasoning_meta: META_OK,
    facts: facts(),
    qrFound: true,
    manualUrl: null,
    payloadKind: "url",
    destinationFetched: true,
  });
  assert.equal(r.confidence, 1);
  assert.equal(r.recommended_action, DEFAULT_ACTIONS.LOW_RISK);
  assert.match(r.summary, /LOW RISK/);
});

test("default vocabulary contains no absolute claims", () => {
  for (const text of Object.values(DEFAULT_ACTIONS)) assert.doesNotMatch(text, BANNED);
});

test("assembleReport produces the full report shape with defaults", () => {
  const risk = reconcileRisk({
    reasoning: gemma("LOW_RISK"),
    reasoning_meta: META_OK,
    facts: facts(),
    qrFound: true,
    manualUrl: null,
    payloadKind: "url",
    destinationFetched: true,
  });
  const report = assembleReport({
    investigation_id: "abc",
    created_at: "2026-10-06T00:00:00.000Z",
    input: { mode: "image", image: { width: 1, height: 1, bytes: 10, mime: "image/png" }, manual_url: false },
    stages: { intake: { status: "ok", duration_ms: 3, note: null }, qr: { status: "ok", duration_ms: 5, note: null } },
    facts: { qr: { found: true, payload: "http://x" }, signals: [], server_facts: [], floor: { level: null, triggered_by: [] } },
    reasoning: gemma("LOW_RISK"),
    reasoning_meta: META_OK,
    server_adjustments: [],
    risk,
    meta: { version: "0.1.0", model: "m", mock: true, timings: { total_ms: 9 } },
  });
  for (const name of ["intake", "qr", "payload", "url", "fetch", "gemma"]) {
    assert.ok(report.stages[name], `stage ${name} present`);
    assert.ok("status" in report.stages[name] && "duration_ms" in report.stages[name] && "note" in report.stages[name]);
  }
  assert.equal(report.stages.payload.status, "skipped");
  assert.equal(report.facts.qr.found, true);
  assert.equal(report.facts.qr.count, 0);
  assert.equal(report.facts.url, null);
  assert.deepEqual(report.facts.redirect_chain, []);
  assert.equal(report.facts.destination.fetched, false);
  assert.equal(report.facts.destination.sensitive_inputs.otp, false);
  assert.equal(report.facts.payload.kind, "none");
  assert.equal(report.risk.label, "LOW RISK");
  assert.equal(report.meta.mock, true);
  assert.equal(report.input.manual_url, false);
  assert.deepEqual(report.server_adjustments, []);
});

test("assembleReport tolerates an empty call", () => {
  const report = assembleReport();
  assert.equal(report.risk.level, "INSUFFICIENT_EVIDENCE");
  assert.equal(report.reasoning, null);
  assert.equal(report.reasoning_meta.available, false);
  assert.equal(Object.keys(report.stages).length, 6);
});
