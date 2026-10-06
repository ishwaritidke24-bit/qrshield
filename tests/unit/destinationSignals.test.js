import { test } from "node:test";
import assert from "node:assert/strict";
import { destinationSignals } from "../../server/pipeline/destinationSignals.js";
import { SIGNAL_STRENGTH } from "../../server/pipeline/contracts.js";

const BANNED = /\b(malicious|definitely|certainly|confirmed scam)\b/i;

function hop(url, extra = {}) {
  return { url, host: new URL(url).host, addresses: [], status: 302, location: null, blocked: false, blocked_reason: null, downgrade: false, cross_domain: false, ...extra };
}

function okFetch(extra = {}) {
  return {
    ok: true,
    requested_url: "https://a.example.com/",
    final_url: "https://a.example.com/",
    chain: [hop("https://a.example.com/", { status: 200 })],
    status: 200,
    headers: { content_type: "text/html; charset=utf-8", content_length: null, content_disposition: null, server: null },
    bytes_read: 100,
    truncated: false,
    is_html: true,
    body_text: "<html></html>",
    error: null,
    pinned: true,
    userinfo_stripped: false,
    redirects: 0,
    ...extra,
  };
}

const ids = (sigs) => sigs.map((s) => s.id);
const byId = (sigs, id) => sigs.find((s) => s.id === id);

function assertWellFormed(sigs) {
  for (const s of sigs) {
    assert.ok(SIGNAL_STRENGTH.includes(s.strength), `strength ${s.strength}`);
    assert.ok(["fetch", "destination"].includes(s.stage), `stage ${s.stage}`);
    assert.equal(typeof s.fact, "string");
    assert.doesNotMatch(s.fact, BANNED, `banned vocabulary in ${s.id}`);
    assert.equal(typeof s.hybrid, "boolean");
  }
}

test("null / missing input yields no signals", () => {
  assert.deepEqual(destinationSignals(null, null, null), []);
  assert.deepEqual(destinationSignals(undefined, null, null), []);
});

test("clean fetch yields only the neutral fetched_ok fact", () => {
  const sigs = destinationSignals(okFetch(), { sensitive_inputs: {}, forms: [] }, null);
  assertWellFormed(sigs);
  assert.deepEqual(ids(sigs), ["destination_fetched_ok"]);
  assert.equal(sigs[0].strength, "neutral");
});

test("redirect count, cross-domain and downgrade", () => {
  const chain = [
    hop("https://a.example.com/"),
    hop("https://b.example.org/", { cross_domain: true }),
    hop("http://b.example.org/x", { downgrade: true }),
    hop("http://b.example.org/y"),
    hop("http://b.example.org/z", { status: 200 }),
  ];
  const sigs = destinationSignals(okFetch({ chain, redirects: 4, final_url: "http://b.example.org/z" }), null, null);
  assertWellFormed(sigs);
  assert.equal(byId(sigs, "redirect_count").strength, "medium");
  assert.equal(byId(sigs, "cross_domain_redirect").strength, "medium");
  assert.equal(byId(sigs, "redirect_scheme_downgrade").strength, "strong");

  const two = destinationSignals(okFetch({ chain: chain.slice(0, 3), redirects: 2 }), null, null);
  assert.equal(byId(two, "redirect_count").strength, "weak");
  const one = destinationSignals(okFetch({ chain: chain.slice(0, 2), redirects: 1 }), null, null);
  assert.equal(byId(one, "redirect_count"), undefined);
});

test("shortener expansion keeps cross-domain redirect weak (opacity, not maliciousness)", () => {
  const chain = [hop("https://bit.ly/abc"), hop("https://real.example.com/", { cross_domain: true, status: 200 })];
  const urlAnalysis = { url: {}, signals: [{ id: "url_shortener" }] };
  const sigs = destinationSignals(okFetch({ chain, redirects: 1 }), null, urlAnalysis);
  assert.equal(byId(sigs, "cross_domain_redirect").strength, "weak");
  assert.match(byId(sigs, "cross_domain_redirect").fact, /real\.example\.com/);
});

test("blocked redirect target vs private destination at hop 0", () => {
  const redirected = okFetch({
    ok: false,
    status: null,
    final_url: null,
    chain: [hop("https://a.example.com/r"), hop("http://169.254.169.254/latest/meta-data/", { blocked: true, blocked_reason: "link_local", cross_domain: true })],
    error: { code: "blocked_private_ip", message: "x", hop: 1 },
    redirects: 1,
  });
  const s1 = destinationSignals(redirected, null, null);
  assertWellFormed(s1);
  assert.equal(byId(s1, "redirect_to_blocked_target").strength, "critical");
  assert.equal(byId(s1, "destination_fetched_ok"), undefined);
  assert.equal(byId(s1, "cross_domain_redirect"), undefined, "blocked hop is not double-counted as cross-domain");

  const direct = okFetch({
    ok: false,
    status: null,
    final_url: null,
    chain: [hop("http://10.0.0.1/", { blocked: true })],
    error: { code: "blocked_private_ip", message: "x", hop: 0 },
  });
  const s2 = destinationSignals(direct, null, null);
  assert.equal(byId(s2, "destination_resolves_to_private_network").strength, "critical");

  const hostname = okFetch({ ok: false, status: null, chain: [hop("http://x.example.com/"), hop("http://localhost/", { blocked: true, cross_domain: true })], error: { code: "blocked_hostname", message: "x", hop: 1 }, redirects: 1 });
  assert.equal(byId(destinationSignals(hostname, null, null), "redirect_to_blocked_target").strength, "critical");
});

test("error code mapping", () => {
  const cases = [
    ["non_standard_port", "non_standard_port_refused", "medium"],
    ["dns_nxdomain", "dns_nxdomain", "neutral"],
    ["fetch_timeout", "fetch_timeout", "neutral"],
    ["http_error", "destination_http_error", "neutral"],
    ["tls_error", "tls_error", "medium"],
    ["redirect_loop", "redirect_loop", "weak"],
    ["redirect_limit_exceeded", "redirect_limit_exceeded", "weak"],
    ["connection_error", "destination_unreachable", "neutral"],
  ];
  for (const [code, id, strength] of cases) {
    const fr = okFetch({ ok: false, error: { code, message: "m", hop: 0 }, status: code === "http_error" ? 404 : null });
    const sigs = destinationSignals(fr, null, null);
    assertWellFormed(sigs);
    const s = byId(sigs, id);
    assert.ok(s, `expected ${id} for ${code}`);
    assert.equal(s.strength, strength, `${id} strength`);
  }
});

test("truncated body, apk and binary downloads", () => {
  const t = destinationSignals(okFetch({ truncated: true, bytes_read: 1048576 }), null, null);
  assert.equal(byId(t, "body_truncated").strength, "neutral");

  const apk = destinationSignals(
    okFetch({ is_html: false, headers: { content_type: "application/vnd.android.package-archive", content_length: 1000, content_disposition: 'attachment; filename="app.apk"', server: null } }),
    null,
    null,
  );
  assert.equal(byId(apk, "apk_download").strength, "strong");
  assert.equal(byId(apk, "binary_download"), undefined);

  const pdf = destinationSignals(okFetch({ is_html: false, headers: { content_type: "application/pdf", content_length: 1000, content_disposition: null, server: null } }), null, null);
  assert.equal(byId(pdf, "binary_download").strength, "medium");
  assert.equal(byId(pdf, "apk_download"), undefined);

  const apkByUrl = destinationSignals(okFetch({ is_html: false, final_url: "https://a.example.com/app.apk", headers: { content_type: "application/octet-stream", content_length: null, content_disposition: null, server: null } }), null, null);
  assert.equal(byId(apkByUrl, "apk_download").strength, "strong");
});

test("page-derived: credentials, payment/identity fields, form action, meta refresh, bot wall", () => {
  const page = {
    title: "Verify your identity to receive scholarship",
    og_title: null,
    site_name: null,
    visible_text_excerpt: "National Scholarship Portal",
    sensitive_inputs: { password: true, payment_card: true, otp: true, upi: false, aadhaar: false, pan: false, bank: false },
    forms: [{ method: "post", action_host: "collector.example.net", cross_origin: true, action_is_http: true, field_types: ["email", "password", "card", "otp"] }],
    meta_refresh_target: "https://a.example.com/phish",
    bot_wall_detected: false,
    has_download_links: true,
  };
  const sigs = destinationSignals(okFetch(), page, null);
  assertWellFormed(sigs);
  assert.equal(byId(sigs, "credential_form_present").strength, "strong");
  const pay = byId(sigs, "payment_or_identity_fields_present");
  assert.equal(pay.strength, "critical");
  assert.match(pay.fact, /OTP/);
  assert.match(pay.fact, /payment card/);
  assert.equal(byId(sigs, "form_action_cross_origin").strength, "strong");
  assert.equal(byId(sigs, "form_action_http").strength, "strong");
  assert.equal(byId(sigs, "meta_refresh_present").strength, "weak");
  assert.equal(byId(sigs, "download_links_present").strength, "weak");
  assert.equal(byId(sigs, "bot_wall"), undefined);

  const wall = destinationSignals(okFetch(), { ...page, sensitive_inputs: {}, forms: [], bot_wall_detected: true, meta_refresh_target: null, has_download_links: false }, null);
  assert.equal(byId(wall, "bot_wall").strength, "neutral");
});

test("UPI / Aadhaar / bank alone trigger the critical payment_or_identity signal without a password", () => {
  const page = { sensitive_inputs: { password: false, payment_card: false, otp: false, upi: true, aadhaar: true, pan: false, bank: true }, forms: [] };
  const sigs = destinationSignals(okFetch(), page, null);
  assert.equal(byId(sigs, "credential_form_present"), undefined);
  assert.equal(byId(sigs, "payment_or_identity_fields_present").strength, "critical");
});

test("no signal strength above weak comes from a clean, boring page", () => {
  const page = { title: "Northfield TechFest", sensitive_inputs: { password: false }, forms: [{ method: "get", action_host: "a.example.com", cross_origin: false, action_is_http: false, field_types: ["text"] }], meta_refresh_target: null, bot_wall_detected: false, has_download_links: false };
  const sigs = destinationSignals(okFetch(), page, null);
  assert.ok(sigs.every((s) => s.strength === "neutral" || s.strength === "weak"), ids(sigs).join(","));
});
