// Deterministic URL analysis: WHATWG parsing, registrable-domain extraction
// (PSL subset), confusable folding and a fixed table of URL-level signals.
// Everything here is a fact about the string itself; no network access.

import net from "node:net";
import { domainToUnicode, fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import path from "node:path";
import { signal } from "./contracts.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const listsDir = path.join(here, "..", "lists");

/** @param {string} name */
function loadList(name) {
  return JSON.parse(readFileSync(path.join(listsDir, name), "utf8"));
}

/** @type {string[]} */
const SHORTENERS = loadList("shorteners.json");
/** @type {string[]} */
const SUSPICIOUS_TLDS = loadList("suspiciousTlds.json").tlds;
/** @type {{name:string,domains:string[],keywords:string[]}[]} */
const BRANDS = loadList("brands.json");
/** @type {string[]} */
const FREE_HOSTS = loadList("freeHosts.json");
/** @type {string[]} */
const PSL_SUFFIXES = loadList("pslSubset.json").suffixes;

const STAGE = "url";
const LONG_URL_CHARS = 200;
const DEEP_SUBDOMAIN_LABELS = 3;
const DANGEROUS_SCHEMES = new Set([
  "javascript",
  "data",
  "file",
  "blob",
  "vbscript",
  "about",
  "chrome",
  "chrome-extension",
]);
const LOGIN_KEYWORDS =
  /(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|password|kyc|otp|unlock|suspend|wallet)/i;
const REDIRECT_KEYS = new Set([
  "url",
  "u",
  "r",
  "redirect",
  "redirect_uri",
  "redirect_url",
  "redir",
  "next",
  "return",
  "returnurl",
  "return_url",
  "return_to",
  "goto",
  "go",
  "dest",
  "destination",
  "continue",
  "target",
  "link",
  "forward",
  "to",
]);

// Small confusables map: homoglyph -> ASCII skeleton.
// U+0300..U+036F combining diacritical marks, built from code points so the
// range survives any editor or tool that rewrites escape sequences.
const COMBINING_MARKS_RE = new RegExp("[" + String.fromCodePoint(0x0300) + "-" + String.fromCodePoint(0x036f) + "]", "g");

const CONFUSABLE_SEQUENCES = [
  ["rn", "m"],
  ["vv", "w"],
];
const CONFUSABLE_CHARS = new Map([
  ["а", "a"], // Cyrillic a
  ["о", "o"], // Cyrillic o
  ["е", "e"], // Cyrillic ie
  ["і", "i"], // Cyrillic/Ukrainian i
  ["с", "c"], // Cyrillic es
  ["р", "p"], // Cyrillic er
  ["ѕ", "s"], // Cyrillic dze
  ["у", "y"], // Cyrillic u
  ["х", "x"], // Cyrillic ha
  ["ԁ", "d"], // Cyrillic komi de
  ["ɡ", "g"], // Latin script g
  ["ո", "n"], // Armenian vo
  ["һ", "h"], // Cyrillic shha
  ["ј", "j"], // Cyrillic je
  ["ӏ", "l"], // Cyrillic palochka
  ["0", "o"],
  ["1", "l"],
]);

/**
 * Strip IPv6 brackets.
 * @param {string} hostname
 */
function bareHost(hostname) {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

/**
 * Registrable domain (eTLD+1) using the bundled PSL subset. Multi-label public
 * suffixes come from pslSubset.json; the default public suffix is the last
 * label. IP literals and single labels are returned unchanged.
 * @param {string} hostname
 * @returns {string}
 */
export function registrableDomain(hostname) {
  if (!hostname) return "";
  const host = String(hostname).toLowerCase().replace(/\.+$/, "");
  if (net.isIP(bareHost(host))) return host;
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  for (const suffix of PSL_SUFFIXES) {
    const sl = suffix.split(".");
    if (labels.length > sl.length && host.endsWith("." + suffix)) {
      return labels.slice(-(sl.length + 1)).join(".");
    }
  }
  return labels.slice(-2).join(".");
}

const BRAND_REGISTRABLE = new Set();
for (const b of BRANDS) for (const d of b.domains) BRAND_REGISTRABLE.add(registrableDomain(d));

/**
 * Number of labels in front of the registrable domain.
 * @param {string} hostname
 * @param {string} registrable
 */
function subdomainLabelCount(hostname, registrable) {
  if (!hostname || !registrable || hostname === registrable) return 0;
  if (!hostname.endsWith("." + registrable)) return 0;
  return hostname.slice(0, -(registrable.length + 1)).split(".").filter(Boolean).length;
}

/**
 * Fold a hostname to an ASCII "skeleton" so lookalikes compare equal.
 * Punycode labels are converted to Unicode first, diacritics are stripped,
 * then the confusables table is applied.
 * @param {string} hostname
 * @returns {string}
 */
export function skeleton(hostname) {
  if (!hostname) return "";
  let s = String(hostname).toLowerCase();
  if (s.includes("xn--")) {
    try {
      s = domainToUnicode(s) || s;
    } catch {
      /* keep punycode form */
    }
  }
  s = s.normalize("NFKD").replace(COMBINING_MARKS_RE, "");
  let out = "";
  for (const ch of s) out += CONFUSABLE_CHARS.get(ch) ?? ch;
  for (const [seq, rep] of CONFUSABLE_SEQUENCES) out = out.split(seq).join(rep);
  return out;
}

/**
 * Split a string into lowercase alphanumeric tokens.
 * @param {string} s
 */
function tokens(s) {
  return String(s || "")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/**
 * Does a brand keyword appear in the token list? Short keywords (<= 4 chars)
 * must match a whole token; longer ones may be substrings of a token.
 * @param {string[]} toks
 * @param {string} keyword
 */
function keywordInTokens(toks, keyword) {
  const k = keyword.toLowerCase();
  return toks.some((t) => (k.length <= 4 ? t === k : t.includes(k)));
}

/** @param {string} hostname @param {string} suffix */
function hostMatches(hostname, suffix) {
  return hostname === suffix || hostname.endsWith("." + suffix);
}

/** @param {string} s */
function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * @typedef {object} UrlParts
 * @property {string} normalized
 * @property {string} fetch_url      userinfo stripped
 * @property {string} scheme
 * @property {string} host           hostname[:port]
 * @property {string} hostname
 * @property {string} registrable_domain
 * @property {number} subdomain_labels
 * @property {number|null} port
 * @property {string} path
 * @property {string[]} query_keys
 * @property {boolean} is_ip_literal
 * @property {boolean} is_punycode
 * @property {string} unicode_host
 * @property {boolean} userinfo_present
 * @property {number} length
 */

/**
 * Analyze a URL string. Accepts any parseable URL; non-http(s) schemes are
 * reported through the `non_http_scheme` signal (payload.js is what stops
 * fetching). Throws an Error with code 'url_invalid' when the WHATWG parser
 * rejects the string.
 * @param {string} urlString
 * @returns {{ url: UrlParts, signals: ReturnType<typeof signal>[] }}
 */
export function analyzeUrl(urlString) {
  let u;
  try {
    u = new URL(String(urlString).trim());
  } catch {
    const err = new Error("URL could not be parsed");
    err.code = "url_invalid";
    throw err;
  }

  const scheme = u.protocol.replace(/:$/, "").toLowerCase();
  const isHttp = scheme === "http" || scheme === "https";
  const hostname = u.hostname.toLowerCase();
  const bare = bareHost(hostname);
  const is_ip_literal = net.isIP(bare) !== 0;
  const is_punycode = hostname.split(".").some((l) => l.startsWith("xn--"));
  let unicode_host = hostname;
  if (is_punycode) {
    try {
      unicode_host = domainToUnicode(hostname) || hostname;
    } catch {
      unicode_host = hostname;
    }
  }
  const registrable_domain = hostname ? registrableDomain(hostname) : "";
  const subdomain_labels = is_ip_literal ? 0 : subdomainLabelCount(hostname, registrable_domain);
  const port = u.port ? Number(u.port) : null;
  const userinfo_present = Boolean(u.username || u.password);

  const fetchUrl = new URL(u.href);
  fetchUrl.username = "";
  fetchUrl.password = "";

  const query_keys = [];
  for (const k of u.searchParams.keys()) if (!query_keys.includes(k)) query_keys.push(k);

  /** @type {UrlParts} */
  const url = {
    normalized: u.href,
    fetch_url: fetchUrl.href,
    scheme,
    host: u.host,
    hostname,
    registrable_domain,
    subdomain_labels,
    port,
    path: u.pathname,
    query_keys,
    is_ip_literal,
    is_punycode,
    unicode_host,
    userinfo_present,
    length: u.href.length,
  };

  /** @type {ReturnType<typeof signal>[]} */
  const signals = [];
  const add = (id, strength, fact, value = null) =>
    signals.push(signal(id, strength, fact, { value, stage: STAGE }));

  // --- scheme -------------------------------------------------------------
  if (!isHttp) {
    const dangerous = DANGEROUS_SCHEMES.has(scheme);
    add(
      "non_http_scheme",
      dangerous ? "critical" : "medium",
      dangerous
        ? `The QR link uses the "${scheme}:" scheme, which can run code or open local resources instead of a web page.`
        : `The link uses the "${scheme}:" scheme rather than a normal web address.`,
      scheme,
    );
    return { url, signals };
  }
  if (scheme === "https") {
    add(
      "uses_https",
      "neutral",
      "The link uses HTTPS (encrypted transport). This says nothing about who runs the site.",
      "https",
    );
  } else {
    add(
      "scheme_http",
      "medium",
      "The link uses plain HTTP, so anything typed on the page can be read or altered in transit.",
      "http",
    );
  }

  // --- authority ----------------------------------------------------------
  if (userinfo_present) {
    add(
      "userinfo_in_authority",
      "strong",
      `The address contains a username before the "@" sign; the real destination is ${hostname}, not the text before "@".`,
      hostname,
    );
  }
  if (is_ip_literal) {
    add("ip_literal_host", "strong", `Destination host ${bare} is a bare IP address, not a domain name.`, bare);
  }
  if (port !== null && port !== 80 && port !== 443) {
    add(
      "non_standard_port",
      "medium",
      `The link points at non-standard port ${port}; ordinary websites use 80 or 443.`,
      String(port),
    );
  }
  if (is_punycode) {
    add(
      "punycode_host",
      "medium",
      `The host uses internationalized (punycode) labels and displays as "${unicode_host}".`,
      unicode_host,
    );
  }

  const brandRegistrable = BRAND_REGISTRABLE.has(registrable_domain);
  const brandHostExact = BRANDS.some((b) => b.domains.some((d) => hostMatches(hostname, d)));

  // --- lookalikes ---------------------------------------------------------
  if (!is_ip_literal && registrable_domain && !brandRegistrable) {
    const sk = skeleton(registrable_domain);
    for (const b of BRANDS) {
      const hit = b.domains.map(registrableDomain).find((reg) => reg !== registrable_domain && skeleton(reg) === sk);
      if (hit) {
        add(
          "confusable_host",
          "strong",
          `Domain "${unicode_host}" looks like ${b.name}'s domain ${hit} but is a different domain.`,
          registrable_domain,
        );
        break;
      }
    }
  }

  if (!is_ip_literal && !brandHostExact) {
    const subPart = subdomain_labels > 0 ? hostname.slice(0, -(registrable_domain.length + 1)) : "";
    const toks = [...tokens(subPart), ...tokens(safeDecode(u.pathname))];
    for (const b of BRANDS) {
      const kw = b.keywords.find((k) => keywordInTokens(toks, k));
      if (kw && !b.domains.some((d) => registrableDomain(d) === registrable_domain)) {
        add(
          "brand_keyword_outside_registrable_domain",
          "strong",
          `"${kw}" (${b.name}) appears in the subdomain or path, but the site is actually ${registrable_domain}, which is not a ${b.name} domain.`,
          kw,
        );
        break;
      }
    }
  }

  if (!is_ip_literal && registrable_domain && !brandRegistrable) {
    const regLabels = registrable_domain.split(".");
    const suffixIsGov = regLabels.slice(1).some((l) => /^(gov|govt|nic|gob|go)$/.test(l));
    if (!suffixIsGov) {
      const name = regLabels[0];
      const nameToks = tokens(name);
      const hit =
        nameToks.find((t) => /^(gov|govt|nic)$/.test(t)) ||
        nameToks.find((t) => t.includes("bank")) ||
        (name.match(/govt|gov/) || [null])[0];
      if (hit) {
        add(
          "gov_or_bank_lookalike",
          "medium",
          `Domain ${registrable_domain} contains "${hit}" but is not a government (.gov.in/.nic.in) or recognised bank domain.`,
          hit,
        );
      }
    }
  }

  // --- hosting -------------------------------------------------------------
  if (!is_ip_literal) {
    const tld = registrable_domain.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      add(
        "suspicious_tld",
        "weak",
        `The ".${tld}" top-level domain is cheap and frequently abused; many legitimate sites use it too.`,
        tld,
      );
    }
    const shortener = SHORTENERS.find((s) => hostMatches(hostname, s));
    if (shortener) {
      add(
        "url_shortener",
        "medium",
        `${shortener} is a URL shortener, so the real destination is hidden until the link is followed.`,
        shortener,
      );
    }
    const freeHost = FREE_HOSTS.find((h) => hostMatches(hostname, h));
    if (freeHost) {
      add(
        "free_hosting_or_form_builder",
        "medium",
        `${freeHost} is a free hosting or form-builder service; anyone can publish a page there, so the brand on the page is not verified.`,
        freeHost,
      );
    }
    if (subdomain_labels >= DEEP_SUBDOMAIN_LABELS) {
      add(
        "excessive_subdomain_depth",
        "weak",
        `The host has ${subdomain_labels} subdomain labels in front of ${registrable_domain}, which can be used to hide the real domain.`,
        String(subdomain_labels),
      );
    }
    // Measure on the Unicode form so punycode's own "xn--" hyphens/digits do not count.
    const regName = registrableDomain(unicode_host).split(".")[0] || "";
    const hyphens = (regName.match(/-/g) || []).length;
    const digits = (regName.match(/\d/g) || []).length;
    if (hyphens >= 3 || digits >= 4) {
      add(
        "many_hyphens_or_digits_in_domain",
        "weak",
        `The domain name "${registrable_domain}" has ${hyphens} hyphens and ${digits} digits, a pattern common in auto-generated domains.`,
        `${hyphens} hyphens, ${digits} digits`,
      );
    }
  }

  // --- path / query ---------------------------------------------------------
  if (url.length > LONG_URL_CHARS) {
    add(
      "long_url",
      "weak",
      `The link is ${url.length} characters long; very long links can hide their real target.`,
      String(url.length),
    );
  }
  const pct = (u.href.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (pct >= 5 || pct / Math.max(u.href.length, 1) > 0.1) {
    add(
      "high_percent_encoding",
      "weak",
      `The link contains ${pct} percent-encoded sequences, which can obscure what it contains.`,
      String(pct),
    );
  }
  const pathAndKeys = safeDecode(u.pathname) + " " + query_keys.join(" ");
  const loginHit = pathAndKeys.match(LOGIN_KEYWORDS);
  if (loginHit) {
    add(
      "login_or_verify_keywords_in_path",
      "weak",
      `The path or query contains "${loginHit[1]}", wording commonly used on credential-harvesting pages.`,
      loginHit[1].toLowerCase(),
    );
  }
  for (const k of query_keys) {
    const v = u.searchParams.get(k) || "";
    const looksLikeUrl = /^https?:\/\//i.test(v) || v.startsWith("//") || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(v);
    if (REDIRECT_KEYS.has(k.toLowerCase()) && looksLikeUrl) {
      add(
        "redirect_param_in_query",
        "weak",
        `Query parameter "${k}" carries another web address, so the page may forward visitors elsewhere.`,
        k,
      );
      break;
    }
  }

  return { url, signals };
}
