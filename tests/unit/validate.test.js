import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validateReasoning, applyGuardrails } from "../../server/pipeline/validate.js";

const fixturesDir = new URL("../../server/fixtures/", import.meta.url);
const load = (scenario, name) =>
  JSON.parse(readFileSync(new URL(`${scenario}/${name}`, fixturesDir), "utf8"));

const SCENARIOS = ["legit-event", "scholarship-phish", "no-fee-upi", "fetch-failed", "no-qr"];

test("every fixture gemma.json validates cleanly and cites only existing F-ids", () => {
  for (const s of SCENARIOS) {
    const packet = load(s, "packet.json");
    const gemma = load(s, "gemma.json");
    const r = validateReasoning(gemma, packet);
    assert.equal(r.ok, true, `${s}: ${r.errors.join("; ")}`);
    assert.deepEqual(r.notes, [], `${s}: unexpected notes ${r.notes.join("; ")}`);
    const ids = new Set(packet.server_facts.map((f) => f.id));
    for (const ev of gemma.evidence) {
      if (ev.source === "deterministic") assert.ok(ids.has(ev.fact_id), `${s}: ${ev.fact_id} missing`);
    }
    const { adjustments } = applyGuardrails(r.value, { packet });
    assert.deepEqual(adjustments, [], `${s}: guardrails fired ${JSON.stringify(adjustments)}`);
  }
});

test("missing risk_level is a hard error", () => {
  const r = validateReasoning({ confidence: 0.5 });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /risk_level/);
});

test("non-object input is rejected", () => {
  assert.equal(validateReasoning(null).ok, false);
  assert.equal(validateReasoning([1]).ok, false);
  assert.equal(validateReasoning("x").ok, false);
});

test("invalid enum is a hard error; loosely cased enum is normalized with a note", () => {
  const good = load("legit-event", "gemma.json");
  const bad = structuredClone(good);
  bad.risk_level = "SAFE";
  const r1 = validateReasoning(bad);
  assert.equal(r1.ok, false);
  assert.match(r1.errors[0], /invalid enum/);

  const nested = structuredClone(good);
  nested.destination_analysis.collects_credentials = "maybe";
  const r2 = validateReasoning(nested);
  assert.equal(r2.ok, false);

  const loose = structuredClone(good);
  loose.risk_level = "low risk";
  loose.poster_analysis.payment_claim = "Free";
  const r3 = validateReasoning(loose);
  assert.equal(r3.ok, true);
  assert.equal(r3.value.risk_level, "LOW_RISK");
  assert.equal(r3.value.poster_analysis.payment_claim, "free");
  assert.ok(r3.notes.some((n) => /enum normalized/.test(n)));
});

test("invalid array items are dropped with a note instead of failing", () => {
  const good = load("legit-event", "gemma.json");
  const obj = structuredClone(good);
  obj.evidence.push({ fact: "x", source: "hearsay", fact_id: null, supports: "risk" });
  const r = validateReasoning(obj);
  assert.equal(r.ok, true);
  assert.equal(r.value.evidence.length, good.evidence.length);
  assert.ok(r.notes.some((n) => /dropped/.test(n)));
});

test("maxItems truncation produces a note", () => {
  const obj = structuredClone(load("legit-event", "gemma.json"));
  obj.uncertainties = Array.from({ length: 9 }, (_, i) => `u${i}`);
  const r = validateReasoning(obj);
  assert.equal(r.ok, true);
  assert.equal(r.value.uncertainties.length, 5);
  assert.ok(r.notes.some((n) => /truncated from 9 to 5/.test(n)));
});

test("maxLength truncation produces a note", () => {
  const obj = structuredClone(load("legit-event", "gemma.json"));
  obj.summary_for_user = "a".repeat(700);
  const r = validateReasoning(obj);
  assert.equal(r.ok, true);
  assert.equal(r.value.summary_for_user.length, 500);
  assert.ok(r.notes.some((n) => /summary_for_user: truncated/.test(n)));
});

test("confidence is clamped and coerced", () => {
  const obj = structuredClone(load("legit-event", "gemma.json"));
  obj.confidence = 1.7;
  let r = validateReasoning(obj);
  assert.equal(r.value.confidence, 1);
  assert.ok(r.notes.some((n) => /clamped down/.test(n)));

  obj.confidence = -2;
  r = validateReasoning(obj);
  assert.equal(r.value.confidence, 0);

  obj.confidence = "0.75";
  r = validateReasoning(obj);
  assert.equal(r.value.confidence, 0.75);
  assert.ok(r.notes.some((n) => /coerced to number/.test(n)));

  obj.confidence = "high";
  r = validateReasoning(obj);
  assert.equal(r.value.confidence, 0);
});

test("unknown keys are dropped with a note", () => {
  const obj = structuredClone(load("legit-event", "gemma.json"));
  obj.extra_thoughts = "hello";
  obj.poster_analysis.vibe = "good";
  const r = validateReasoning(obj);
  assert.equal(r.ok, true);
  assert.equal("extra_thoughts" in r.value, false);
  assert.equal("vibe" in r.value.poster_analysis, false);
  assert.ok(r.notes.some((n) => /extra_thoughts: unknown key dropped/.test(n)));
});

test("missing arrays and objects are defaulted with notes", () => {
  const r = validateReasoning({ risk_level: "MEDIUM_RISK", confidence: 0.5 });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.contradictions, []);
  assert.deepEqual(r.value.evidence, []);
  assert.deepEqual(r.value.uncertainties, []);
  assert.equal(r.value.poster_analysis.payment_claim, "unspecified");
  assert.equal(r.value.destination_analysis.collects_credentials, "unknown");
  assert.equal(r.value.recommended_action, "");
  assert.ok(r.notes.length >= 5);
});

test("deterministic evidence without a fact_id is relabeled as model", () => {
  const obj = structuredClone(load("legit-event", "gemma.json"));
  obj.evidence = [{ fact: "x", source: "deterministic", fact_id: null, supports: "risk" }];
  const r = validateReasoning(obj);
  assert.equal(r.value.evidence[0].source, "model");
});

/* ---------------------------- guardrails ---------------------------------- */

test("guardrail (a): unverified fact id relabeled as model", () => {
  const packet = load("legit-event", "packet.json");
  const reasoning = structuredClone(load("legit-event", "gemma.json"));
  reasoning.evidence[0].fact_id = "F99";
  const { reasoning: out, adjustments } = applyGuardrails(reasoning, { packet });
  assert.equal(out.evidence[0].source, "model");
  assert.equal(out.evidence[0].fact_id, null);
  assert.equal(adjustments[0].rule, "unverified_fact_relabeled");
  // original untouched
  assert.equal(reasoning.evidence[0].source, "deterministic");
});

test("guardrail (b): HIGH_RISK on unfetched destination without basis -> INSUFFICIENT_EVIDENCE", () => {
  const packet = load("fetch-failed", "packet.json");
  const reasoning = structuredClone(load("fetch-failed", "gemma.json"));
  reasoning.risk_level = "HIGH_RISK";
  reasoning.contradictions = [];
  reasoning.evidence = [reasoning.evidence[1]]; // a single weak risk item
  const { reasoning: out, adjustments } = applyGuardrails(reasoning, { packet });
  assert.equal(out.risk_level, "INSUFFICIENT_EVIDENCE");
  assert.ok(adjustments.some((a) => a.rule === "downgraded_insufficient_destination_evidence"));
});

test("guardrail (b2): technical-only CRITICAL is capped at the deterministic floor; semantic CRITICAL survives", () => {
  const base = load("legit-event", "gemma.json");
  base.risk_level = "CRITICAL";
  base.contradictions = [];
  base.destination_analysis = { ...base.destination_analysis, collects_credentials: "unknown", requests_payment: "unknown", matches_poster_claims: "unknown" };
  const packet = load("legit-event", "packet.json");
  packet.destination = { ...(packet.destination || {}), fetched: true };
  packet.deterministic_floor = { level: "HIGH_RISK", triggered_by: ["destination_resolves_to_private_network"] };
  const capped = applyGuardrails(base, { packet });
  assert.equal(capped.reasoning.risk_level, "HIGH_RISK");
  assert.ok(capped.adjustments.some((a) => a.rule === "technical_only_escalation_capped"));

  packet.deterministic_floor = { level: null, triggered_by: [] };
  const noFloor = applyGuardrails(base, { packet });
  assert.equal(noFloor.reasoning.risk_level, "MEDIUM_RISK");

  const semantic = JSON.parse(JSON.stringify(base));
  semantic.contradictions = [{ poster_claim: "No Application Fee", destination_observation: "UPI payment request for 499 INR", severity: "high" }];
  const kept = applyGuardrails(semantic, { packet });
  assert.equal(kept.reasoning.risk_level, "CRITICAL");
  assert.ok(!kept.adjustments.some((a) => a.rule === "technical_only_escalation_capped"));
});

test("guardrail (b) does not fire with a high-severity contradiction", () => {
  const packet = load("fetch-failed", "packet.json");
  const reasoning = structuredClone(load("fetch-failed", "gemma.json"));
  reasoning.risk_level = "HIGH_RISK";
  reasoning.contradictions = [
    { poster_claim: "free", destination_observation: "URL path is /pay-fee", severity: "high" },
  ];
  reasoning.evidence = [];
  const { reasoning: out } = applyGuardrails(reasoning, { packet });
  assert.equal(out.risk_level, "HIGH_RISK");
});

test("guardrail (c): confidence capped at 0.5 when destination not fetched", () => {
  const packet = load("fetch-failed", "packet.json");
  const reasoning = structuredClone(load("fetch-failed", "gemma.json"));
  reasoning.confidence = 0.9;
  const { reasoning: out, adjustments } = applyGuardrails(reasoning, { packet });
  assert.equal(out.confidence, 0.5);
  assert.ok(adjustments.some((a) => a.rule === "confidence_capped"));
});

test("guardrail (d): apparent_organization cleared when destination not fetched", () => {
  const packet = load("fetch-failed", "packet.json");
  const reasoning = structuredClone(load("fetch-failed", "gemma.json"));
  reasoning.destination_analysis.apparent_organization = "Some Org";
  const { reasoning: out, adjustments } = applyGuardrails(reasoning, { packet });
  assert.equal(out.destination_analysis.apparent_organization, null);
  assert.ok(adjustments.some((a) => a.rule === "unfetched_destination_organization_cleared"));
});

test("guardrails (c)/(d) are skipped for non-HTTP payloads such as UPI", () => {
  const packet = load("no-fee-upi", "packet.json");
  const reasoning = load("no-fee-upi", "gemma.json");
  const { reasoning: out, adjustments } = applyGuardrails(reasoning, { packet });
  assert.equal(out.confidence, 0.82);
  assert.ok(out.destination_analysis.apparent_organization);
  assert.deepEqual(adjustments, []);
});

test("guardrail (e): absolute vocabulary softened when evidence is thin", () => {
  const packet = load("legit-event", "packet.json");
  const reasoning = structuredClone(load("legit-event", "gemma.json"));
  reasoning.summary_for_user = "This site is definitely malicious.";
  reasoning.recommended_action = "Avoid this confirmed scam.";
  const { reasoning: out, adjustments } = applyGuardrails(reasoning, { packet });
  assert.equal(out.summary_for_user, "This site is appears suspicious appears suspicious.");
  assert.equal(out.recommended_action, "Avoid this appears suspicious.");
  assert.equal(adjustments.filter((a) => a.rule === "vocabulary_softened").length, 2);
});

test("guardrail (e) leaves wording alone when deterministic risk evidence exists", () => {
  const packet = load("scholarship-phish", "packet.json");
  const reasoning = structuredClone(load("scholarship-phish", "gemma.json"));
  reasoning.summary_for_user = "This is definitely a phishing page.";
  const { reasoning: out, adjustments } = applyGuardrails(reasoning, { packet });
  assert.equal(out.summary_for_user, "This is definitely a phishing page.");
  assert.deepEqual(adjustments, []);
});
