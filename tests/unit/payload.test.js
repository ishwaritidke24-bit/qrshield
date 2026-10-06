import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyPayload } from "../../server/pipeline/payload.js";
import { PAYLOAD_KINDS, SIGNAL_STRENGTH } from "../../server/pipeline/contracts.js";

const ids = (r) => r.signals.map((s) => s.id);

function assertWellFormed(r) {
  assert.ok(PAYLOAD_KINDS.includes(r.kind), `unknown kind ${r.kind}`);
  assert.equal(typeof r.raw, "string");
  assert.ok(r.normalized === null || typeof r.normalized === "string");
  assert.equal(typeof r.parsed, "object");
  assert.ok(Array.isArray(r.embedded_urls));
  assert.ok(r.embedded_urls.length <= 3);
  assert.equal(typeof r.fetchable, "boolean");
  assert.ok(r.reason === null || typeof r.reason === "string");
  for (const s of r.signals) {
    assert.equal(s.stage, "payload");
    assert.ok(SIGNAL_STRENGTH.includes(s.strength));
    assert.equal(typeof s.fact, "string");
    assert.ok(!/malicious|definitely|confirmed scam/i.test(s.fact), `forbidden vocabulary in ${s.id}`);
  }
  if (r.fetchable) {
    assert.ok(/^https?:\/\//i.test(r.normalized), "fetchable payloads must normalise to http(s)");
  } else {
    assert.ok(r.kind !== "url");
  }
}

/** @type {Array<{name:string, raw:any, kind:string, fetchable:boolean, normalized?:string, signals?:string[], check?:(r:any)=>void}>} */
const TABLE = [
  { name: "https url", raw: "https://example.com/apply?x=1", kind: "url", fetchable: true, normalized: "https://example.com/apply?x=1", signals: [] },
  { name: "http url", raw: "http://127.0.0.1:4555/legit", kind: "url", fetchable: true, normalized: "http://127.0.0.1:4555/legit" },
  { name: "uppercase scheme", raw: "HTTPS://Example.COM/", kind: "url", fetchable: true, normalized: "https://Example.COM/" },
  { name: "surrounding whitespace and BOM", raw: String.fromCharCode(0xfeff) + "  https://example.com/x \n", kind: "url", fetchable: true, normalized: "https://example.com/x" },
  { name: "bare domain", raw: "example.com", kind: "url", fetchable: true, normalized: "https://example.com", signals: ["scheme_added"] },
  { name: "bare www domain with path", raw: "www.example.co.uk/apply", kind: "url", fetchable: true, normalized: "https://www.example.co.uk/apply", signals: ["scheme_added"] },
  { name: "bare domain with port", raw: "example.com:8080/x", kind: "url", fetchable: true, normalized: "https://example.com:8080/x", signals: ["scheme_added"] },

  { name: "javascript scheme", raw: "javascript:alert(1)", kind: "blocked_scheme", fetchable: false, signals: ["blocked_scheme"], check: (r) => {
    assert.equal(r.signals[0].strength, "critical");
    assert.equal(r.parsed.scheme, "javascript");
  } },
  { name: "javascript scheme mixed case with whitespace", raw: "  JaVa\tScRiPt:alert(1)", kind: "blocked_scheme", fetchable: false, signals: ["blocked_scheme"] },
  { name: "data uri", raw: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", kind: "blocked_scheme", fetchable: false },
  { name: "file uri", raw: "file:///etc/passwd", kind: "blocked_scheme", fetchable: false },
  { name: "blob uri", raw: "blob:https://example.com/uuid", kind: "blocked_scheme", fetchable: false },
  { name: "vbscript", raw: "vbscript:MsgBox(1)", kind: "blocked_scheme", fetchable: false },
  { name: "about", raw: "about:blank", kind: "blocked_scheme", fetchable: false },
  { name: "chrome", raw: "chrome://settings", kind: "blocked_scheme", fetchable: false },

  { name: "upi payment with amount", raw: "upi://pay?pa=rahul1998@ybl&pn=Scholarship%20Cell&am=499&cu=INR&tn=Application%20Fee", kind: "upi", fetchable: false, check: (r) => {
    assert.equal(r.parsed.vpa, "rahul1998@ybl");
    assert.equal(r.parsed.payee_name, "Scholarship Cell");
    assert.equal(r.parsed.amount, "499");
    assert.equal(r.parsed.currency, "INR");
    assert.equal(r.parsed.note, "Application Fee");
    assert.equal(r.parsed.merchant_code, null);
    const got = ids(r);
    assert.ok(got.includes("upi_payment_request"));
    assert.ok(got.includes("upi_amount_prefilled"));
    assert.ok(got.includes("upi_individual_looking_vpa"));
    assert.equal(r.signals.find((s) => s.id === "upi_individual_looking_vpa").strength, "weak");
    assert.equal(r.signals.find((s) => s.id === "upi_amount_prefilled").strength, "medium");
    assert.equal(r.signals.find((s) => s.id === "upi_payment_request").strength, "medium");
  } },
  { name: "upi merchant without amount", raw: "upi://pay?pa=bigstore@icici&pn=Big%20Store&mc=5411&cu=INR", kind: "upi", fetchable: false, check: (r) => {
    assert.equal(r.parsed.amount, null);
    assert.equal(r.parsed.merchant_code, "5411");
    const got = ids(r);
    assert.ok(got.includes("upi_payment_request"));
    assert.ok(!got.includes("upi_amount_prefilled"));
    assert.ok(!got.includes("upi_individual_looking_vpa"));
  } },

  { name: "wifi wpa", raw: "WIFI:T:WPA;S:CampusGuest;P:secret123;;", kind: "wifi", fetchable: false, signals: ["wifi_join_request"], check: (r) => {
    assert.equal(r.parsed.ssid, "CampusGuest");
    assert.equal(r.parsed.password_present, true);
    assert.equal(r.parsed.auth_type, "wpa");
    assert.ok(!("password" in r.parsed));
    const json = JSON.stringify({ ...r, raw: "" });
    assert.ok(!json.includes("secret123"), "password must never leak into parsed/normalized/signals");
  } },
  { name: "wifi open network", raw: "WIFI:T:nopass;S:Free Airport;;", kind: "wifi", fetchable: false, signals: ["wifi_join_request", "wifi_open_network"], check: (r) => {
    assert.equal(r.parsed.password_present, false);
  } },
  { name: "wifi with escaped semicolon in ssid", raw: "WIFI:S:Cafe\\;Bar;T:WPA2;P:p\\;w;H:true;;", kind: "wifi", fetchable: false, check: (r) => {
    assert.equal(r.parsed.ssid, "Cafe;Bar");
    assert.equal(r.parsed.hidden, true);
    assert.equal(r.parsed.password_present, true);
  } },

  { name: "vcard with url", raw: "BEGIN:VCARD\nVERSION:3.0\nFN:Jane Doe\nORG:Northfield University\nTEL:+15551234567\nEMAIL:jane@northfield.edu\nURL:https://northfield.edu/jane\nEND:VCARD", kind: "vcard", fetchable: true, normalized: "https://northfield.edu/jane", signals: ["url_embedded_in_vcard"], check: (r) => {
    assert.deepEqual(r.embedded_urls, ["https://northfield.edu/jane"]);
    assert.equal(r.parsed.name, "Jane Doe");
    assert.equal(r.parsed.org, "Northfield University");
    assert.equal(r.parsed.has_phone, true);
    assert.equal(r.parsed.has_email, true);
  } },
  { name: "vcard without url", raw: "BEGIN:VCARD\nVERSION:3.0\nFN:Jane Doe\nTEL:+15551234567\nEND:VCARD", kind: "vcard", fetchable: false, signals: [] },
  { name: "mecard with bare-domain url", raw: "MECARD:N:Doe,Jane;TEL:15551234567;URL:example.org/jane;;", kind: "vcard", fetchable: true, normalized: "https://example.org/jane", check: (r) => {
    assert.equal(r.parsed.format, "mecard");
  } },

  { name: "tel", raw: "tel:+911234567890", kind: "tel", fetchable: false, check: (r) => assert.equal(r.parsed.number, "+911234567890") },
  { name: "sms with body", raw: "sms:+15551234567?body=Hello%20there", kind: "sms", fetchable: false, check: (r) => {
    assert.equal(r.parsed.number, "+15551234567");
    assert.equal(r.parsed.body, "Hello there");
  } },
  { name: "smsto", raw: "SMSTO:12345:WIN a prize now", kind: "sms", fetchable: false, signals: ["sms_prefilled_body_keywords"] },
  { name: "mailto", raw: "mailto:help@example.com?subject=Hi", kind: "mailto", fetchable: false, check: (r) => {
    assert.equal(r.parsed.address, "help@example.com");
    assert.equal(r.parsed.domain, "example.com");
    assert.equal(r.parsed.subject, "Hi");
  } },
  { name: "geo", raw: "geo:12.9716,77.5946", kind: "geo", fetchable: false, check: (r) => {
    assert.equal(r.parsed.lat, 12.9716);
    assert.equal(r.parsed.lng, 77.5946);
  } },
  { name: "android intent without fallback", raw: "intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end", kind: "intent", fetchable: false, signals: ["android_intent_payload"], check: (r) => {
    assert.equal(r.parsed.package, "com.google.zxing.client.android");
    assert.equal(r.parsed.target_scheme, "zxing");
  } },
  { name: "android intent with browser fallback", raw: "intent://open#Intent;package=com.example;S.browser_fallback_url=https%3A%2F%2Fexample.com%2Fget;end", kind: "intent", fetchable: true, normalized: "https://example.com/get", signals: ["android_intent_payload", "url_embedded_in_intent"] },
  { name: "market", raw: "market://details?id=com.example.app", kind: "appstore", fetchable: false, signals: ["app_store_link"], check: (r) => assert.equal(r.parsed.app_id, "com.example.app") },
  { name: "itms-apps", raw: "itms-apps://itunes.apple.com/app/id123", kind: "appstore", fetchable: false },
  { name: "bitcoin", raw: "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.5", kind: "crypto", fetchable: false, signals: ["crypto_payment_request"], check: (r) => {
    assert.equal(r.parsed.network, "bitcoin");
    assert.equal(r.parsed.amount, "0.5");
    assert.equal(r.parsed.address, "1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
  } },
  { name: "ethereum", raw: "ethereum:0xabc123", kind: "crypto", fetchable: false },

  { name: "plain text", raw: "Hello world, this is just a note", kind: "text", fetchable: false, signals: [], check: (r) => {
    assert.equal(r.reason, "non_url_text");
    assert.deepEqual(r.embedded_urls, []);
  } },
  { name: "text with embedded urls", raw: "Register at https://a.example.com/x or http://b.example.net/y, backup https://c.example.org, extra https://d.example.io", kind: "text", fetchable: true, normalized: "https://a.example.com/x", signals: ["url_embedded_in_text"], check: (r) => {
    assert.equal(r.embedded_urls.length, 3);
    assert.deepEqual(r.embedded_urls, ["https://a.example.com/x", "http://b.example.net/y", "https://c.example.org"]);
  } },
  { name: "text with url-like token but no scheme and spaces", raw: "visit example dot com today", kind: "text", fetchable: false },
  { name: "text that looks like a domain but has spaces", raw: "example.com is great", kind: "text", fetchable: false },
  { name: "numeric string", raw: "1234567890", kind: "text", fetchable: false },
  { name: "unsupported scheme ftp", raw: "ftp://files.example.com/pub", kind: "text", fetchable: false, signals: ["unsupported_scheme"] },
  { name: "unsupported scheme whatsapp", raw: "whatsapp://send?phone=123", kind: "text", fetchable: false, signals: ["unsupported_scheme"] },
  { name: "malformed http", raw: "http://", kind: "text", fetchable: false, signals: ["url_unparseable"] },
  { name: "http with spaces in host", raw: "http://exa mple.com/", kind: "text", fetchable: false, signals: ["url_unparseable"] },

  { name: "empty string", raw: "", kind: "none", fetchable: false, check: (r) => assert.equal(r.reason, "empty_payload") },
  { name: "whitespace only", raw: "   \n ", kind: "none", fetchable: false },
  { name: "null", raw: null, kind: "none", fetchable: false },
  { name: "undefined", raw: undefined, kind: "none", fetchable: false },
  { name: "non-string", raw: 42, kind: "none", fetchable: false },
];

for (const row of TABLE) {
  test(`classifyPayload: ${row.name}`, () => {
    const r = classifyPayload(row.raw);
    assertWellFormed(r);
    assert.equal(r.kind, row.kind, `kind for ${JSON.stringify(row.raw)}`);
    assert.equal(r.fetchable, row.fetchable, `fetchable for ${JSON.stringify(row.raw)}`);
    if (row.normalized !== undefined) assert.equal(r.normalized, row.normalized);
    if (row.signals !== undefined) assert.deepEqual(ids(r).sort(), [...row.signals].sort());
    if (row.check) row.check(r);
  });
}

test("classifyPayload: raw is preserved verbatim and never mutated", () => {
  const raw = "  https://example.com/x  ";
  const r = classifyPayload(raw);
  assert.equal(r.raw, raw);
  assert.equal(r.normalized, "https://example.com/x");
});

test("classifyPayload: blocked schemes never become fetchable even with embedded http urls", () => {
  const r = classifyPayload("javascript:location='https://example.com'");
  assert.equal(r.kind, "blocked_scheme");
  assert.equal(r.fetchable, false);
  assert.deepEqual(r.embedded_urls, []);
});

test("classifyPayload: every produced signal id is snake_case", () => {
  const samples = TABLE.map((t) => t.raw).filter((x) => typeof x === "string");
  for (const raw of samples) {
    for (const s of classifyPayload(raw).signals) {
      assert.match(s.id, /^[a-z][a-z0-9_]*$/);
    }
  }
});
