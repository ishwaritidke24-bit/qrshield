import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { analyzeUrl, registrableDomain, skeleton } from "../../server/pipeline/urlAnalysis.js";
import { SIGNAL_STRENGTH, STRENGTH_RANK } from "../../server/pipeline/contracts.js";

const ids = (r) => r.signals.map((s) => s.id);
const strengthOf = (r, id) => r.signals.find((s) => s.id === id)?.strength;
const maxRank = (r) => Math.max(0, ...r.signals.map((s) => STRENGTH_RANK[s.strength]));

describe("registrableDomain", () => {
  const cases = [
    ["example.com", "example.com"],
    ["www.example.com", "example.com"],
    ["a.b.c.d.example.co.in", "example.co.in"],
    ["scholarships.gov.in", "scholarships.gov.in"],
    ["portal.scholarships.gov.in", "scholarships.gov.in"],
    ["foo.bar.co.uk", "bar.co.uk"],
    ["localhost", "localhost"],
    ["127.0.0.1", "127.0.0.1"],
    ["[::1]", "[::1]"],
    ["Example.COM.", "example.com"],
    ["co.in", "co.in"],
    ["", ""],
  ];
  for (const [input, expected] of cases) {
    test(`${JSON.stringify(input)} -> ${expected}`, () => {
      assert.equal(registrableDomain(input), expected);
    });
  }
});

describe("skeleton", () => {
  test("folds Cyrillic and digit confusables", () => {
    assert.equal(skeleton("xn--80ak6aa92e.com"), "apple.com");
    assert.equal(skeleton("g00gle.com"), "google.com");
    assert.equal(skeleton("paytrn.com"), "paytm.com");
    assert.equal(skeleton("vvhatsapp.com"), "whatsapp.com");
  });
  test("is identity for plain ASCII without confusable chars", () => {
    assert.equal(skeleton("example.com"), "example.com");
  });
});

describe("analyzeUrl table", () => {
  /** @type {Array<[string, (r: ReturnType<typeof analyzeUrl>) => void]>} */
  const table = [
    [
      "https://sbi.co.in@evil.tld/",
      (r) => {
        assert.equal(r.url.hostname, "evil.tld");
        assert.equal(r.url.userinfo_present, true);
        assert.equal(r.url.fetch_url, "https://evil.tld/");
        assert.equal(strengthOf(r, "userinfo_in_authority"), "strong");
      },
    ],
    [
      "http://2130706433/",
      (r) => {
        assert.equal(r.url.hostname, "127.0.0.1");
        assert.equal(r.url.is_ip_literal, true);
        assert.equal(strengthOf(r, "ip_literal_host"), "strong");
        assert.equal(strengthOf(r, "scheme_http"), "medium");
        assert.ok(!ids(r).includes("uses_https"));
      },
    ],
    [
      "https://xn--sb-eka.co.in",
      (r) => {
        assert.equal(r.url.is_punycode, true);
        assert.equal(r.url.unicode_host, "ösb.co.in");
        assert.equal(strengthOf(r, "punycode_host"), "medium");
        assert.ok(!ids(r).includes("many_hyphens_or_digits_in_domain"), "punycode hyphens must not count");
      },
    ],
    [
      "https://sbi.secure-login.xyz/sbi",
      (r) => {
        assert.equal(r.url.registrable_domain, "secure-login.xyz");
        assert.equal(strengthOf(r, "brand_keyword_outside_registrable_domain"), "strong");
        assert.equal(strengthOf(r, "suspicious_tld"), "weak");
      },
    ],
    [
      "https://bit.ly/abc",
      (r) => {
        assert.equal(strengthOf(r, "url_shortener"), "medium");
      },
    ],
    [
      "https://forms.gle/x",
      (r) => {
        assert.equal(strengthOf(r, "free_hosting_or_form_builder"), "medium");
      },
    ],
    [
      "https://docs.google.com/forms/d/e/abc/viewform",
      (r) => {
        assert.equal(r.url.registrable_domain, "google.com");
        assert.equal(strengthOf(r, "free_hosting_or_form_builder"), "medium");
        assert.ok(!ids(r).includes("brand_keyword_outside_registrable_domain"));
      },
    ],
    [
      "https://scholarships.gov.in/",
      (r) => {
        assert.equal(r.url.registrable_domain, "scholarships.gov.in");
        assert.ok(maxRank(r) <= STRENGTH_RANK.weak, `benign url produced ${ids(r)}`);
        assert.equal(strengthOf(r, "uses_https"), "neutral");
      },
    ],
    [
      "https://hdfcbank.com/netbanking",
      (r) => {
        assert.ok(!ids(r).includes("gov_or_bank_lookalike"), "known bank domain must not be a lookalike");
        assert.ok(!ids(r).includes("brand_keyword_outside_registrable_domain"));
      },
    ],
    [
      "https://a.b.c.d.example.co.in/",
      (r) => {
        assert.equal(r.url.registrable_domain, "example.co.in");
        assert.equal(r.url.subdomain_labels, 4);
        assert.equal(strengthOf(r, "excessive_subdomain_depth"), "weak");
      },
    ],
    [
      "https://xn--80ak6aa92e.com/",
      (r) => {
        assert.equal(strengthOf(r, "confusable_host"), "strong");
        assert.equal(strengthOf(r, "punycode_host"), "medium");
      },
    ],
    [
      "https://g00gle.com/",
      (r) => {
        assert.equal(strengthOf(r, "confusable_host"), "strong");
      },
    ],
    [
      "https://sbi-bank-verify-now.top/",
      (r) => {
        assert.equal(strengthOf(r, "gov_or_bank_lookalike"), "medium");
        assert.equal(strengthOf(r, "suspicious_tld"), "weak");
      },
    ],
    [
      "https://example.com:8443/login?next=https://other.example/x",
      (r) => {
        assert.equal(r.url.port, 8443);
        assert.equal(strengthOf(r, "non_standard_port"), "medium");
        assert.equal(strengthOf(r, "login_or_verify_keywords_in_path"), "weak");
        assert.equal(strengthOf(r, "redirect_param_in_query"), "weak");
        assert.deepEqual(r.url.query_keys, ["next"]);
      },
    ],
    [
      "https://example.com/" + "a%20b".repeat(5),
      (r) => {
        assert.equal(strengthOf(r, "high_percent_encoding"), "weak");
      },
    ],
    [
      "https://example.com/" + "x".repeat(250),
      (r) => {
        assert.equal(strengthOf(r, "long_url"), "weak");
      },
    ],
    [
      "https://[::1]:8080/x",
      (r) => {
        assert.equal(r.url.is_ip_literal, true);
        assert.equal(strengthOf(r, "ip_literal_host"), "strong");
      },
    ],
    [
      "javascript:alert(1)",
      (r) => {
        assert.equal(r.url.scheme, "javascript");
        assert.equal(strengthOf(r, "non_http_scheme"), "critical");
        assert.equal(r.signals.length, 1);
      },
    ],
    [
      "mailto:someone@example.com",
      (r) => {
        assert.equal(strengthOf(r, "non_http_scheme"), "medium");
      },
    ],
  ];

  for (const [input, check] of table) {
    test(input.length > 80 ? input.slice(0, 77) + "..." : input, () => {
      const r = analyzeUrl(input);
      check(r);
    });
  }
});

describe("analyzeUrl invariants", () => {
  test("throws url_invalid for unparseable strings", () => {
    assert.throws(() => analyzeUrl("not a url"), (e) => e.code === "url_invalid");
    assert.throws(() => analyzeUrl(""), (e) => e.code === "url_invalid");
    assert.throws(() => analyzeUrl("http://"), (e) => e.code === "url_invalid");
  });

  test("every signal has stage url, a fact sentence, a value and a known strength", () => {
    const samples = [
      "https://sbi.co.in@evil.tld/",
      "http://2130706433/",
      "https://sbi.secure-login.xyz/sbi?redirect=https://x.y",
      "https://xn--80ak6aa92e.com/",
      "https://a.b.c.d.example.co.in/",
      "javascript:alert(1)",
    ];
    for (const s of samples) {
      for (const sig of analyzeUrl(s).signals) {
        assert.equal(sig.stage, "url");
        assert.ok(SIGNAL_STRENGTH.includes(sig.strength));
        assert.ok(typeof sig.fact === "string" && sig.fact.length > 10, `${sig.id} needs a fact`);
        assert.ok(sig.value !== undefined, `${sig.id} needs a value`);
        assert.equal(sig.hybrid, false);
        assert.doesNotMatch(sig.fact, /\b(malicious|definitely|confirmed scam)\b/i);
      }
    }
  });

  test("suspicious_tld is never stronger than weak", () => {
    for (const tld of ["zip", "xyz", "top", "tk", "cyou"]) {
      const r = analyzeUrl(`https://plain-site.${tld}/`);
      assert.equal(strengthOf(r, "suspicious_tld"), "weak");
    }
  });

  test("url parts are populated", () => {
    const r = analyzeUrl("HTTPS://User:pw@Www.Example.CO.IN:443/Path/To?b=2&a=1&a=3#frag");
    assert.equal(r.url.scheme, "https");
    assert.equal(r.url.hostname, "www.example.co.in");
    assert.equal(r.url.port, null);
    assert.equal(r.url.path, "/Path/To");
    assert.deepEqual(r.url.query_keys, ["b", "a"]);
    assert.equal(r.url.subdomain_labels, 1);
    assert.equal(r.url.userinfo_present, true);
    assert.ok(!r.url.fetch_url.includes("User"));
    assert.ok(!r.url.fetch_url.includes("pw"));
    assert.equal(r.url.length, r.url.normalized.length);
  });
});
