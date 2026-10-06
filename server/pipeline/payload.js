// Payload stage: classify the raw string decoded from a QR code.
//
// Pure function, no I/O. Decides whether the payload is something the fetch
// stage may follow (http/https only), extracts small sanitized parsed fields
// for the evidence packet, and emits stage:'payload' signals.

import { PAYLOAD_KINDS, signal as makeSignal, clampText } from "./contracts.js";

/**
 * @typedef {object} PayloadResult
 * @property {string} kind            one of PAYLOAD_KINDS
 * @property {string} raw
 * @property {string|null} normalized  the string later stages should use (URL when fetchable)
 * @property {object} parsed           small, sanitized; never contains secrets
 * @property {string[]} embedded_urls  http(s) URLs found inside text/vcard payloads (max 3)
 * @property {boolean} fetchable       true only when a http/https URL is available
 * @property {string|null} reason      why it is not fetchable, or a note
 * @property {import('./contracts.js').signal[]} signals
 */

const BLOCKED_SCHEMES = new Set([
  "javascript",
  "data",
  "file",
  "blob",
  "vbscript",
  "about",
  "chrome",
  "chrome-extension",
  "moz-extension",
  "ms-appx",
  "ms-appx-web",
  "res",
  "view-source",
  "jar",
  "wyciwyg",
]);

const CRYPTO_SCHEMES = new Set([
  "bitcoin",
  "bitcoincash",
  "ethereum",
  "litecoin",
  "monero",
  "dogecoin",
  "ripple",
  "tron",
  "solana",
]);

const APPSTORE_SCHEMES = new Set(["market", "itms", "itms-apps", "itms-appss", "ms-windows-store"]);

// Consumer PSP handles where VPAs are usually personal accounts, not merchants.
const CONSUMER_UPI_HANDLES = new Set([
  "ybl", "ibl", "axl", "paytm", "apl", "upi", "okaxis", "oksbi", "okicici", "okhdfcbank",
  "oksbi", "ptyes", "ptaxis", "pthdfc", "ptsbi", "waaxis", "wahdfcbank", "waicici", "wasbi",
  "sbi", "axisbank", "icici", "hdfcbank", "yapl", "fbl", "indus", "kotak", "barodampay", "freecharge",
]);

const URL_TOKEN_RE = /https?:\/\/[^\s<>"'`\]\)\}]+/gi;
const BARE_DOMAIN_RE =
  /^(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:[\/?#][^\s]*)?$/i;

function sig(id, strength, fact, extra = {}) {
  return makeSignal(id, strength, fact, { stage: "payload", ...extra });
}

// Built with char codes so the source stays ASCII-only.
const C = (n) => String.fromCharCode(n);
const BOM_RE = new RegExp("^" + C(0xfeff));
// U+200B-U+200F zero-width/marks, U+2028-U+202E separators/bidi controls, U+2060-U+206F invisible operators.
const ZERO_WIDTH_RE = new RegExp("[" + C(0x200b) + "-" + C(0x200f) + C(0x2028) + "-" + C(0x202e) + C(0x2060) + "-" + C(0x206f) + "]", "g");

/** Remove BOM, zero-width and control characters that could hide a scheme. */
function cleanRaw(raw) {
  return String(raw)
    .replace(BOM_RE, "")
    .replace(ZERO_WIDTH_RE, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim();
}

/**
 * Detect the URI scheme. Dots are deliberately excluded so "host:port/path"
 * is not mistaken for a scheme.
 */
function detectScheme(text) {
  const m = /^([a-z][a-z0-9+\-]*):/i.exec(text);
  return m ? m[1].toLowerCase() : null;
}

/**
 * Browsers strip tabs/newlines when parsing URLs, so "java\tscript:" opens as
 * javascript:. Detect that evasion for blocked schemes only.
 */
function detectBlockedScheme(text) {
  const compact = text.slice(0, 40).replace(/\s+/g, "").toLowerCase();
  const m = /^([a-z][a-z0-9+\-]*):/.exec(compact);
  if (m && BLOCKED_SCHEMES.has(m[1])) return m[1];
  return null;
}

/** Parse a query string into a plain object (first value wins), lower-cased keys. */
function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  for (const part of qs.split("&")) {
    if (!part) continue;
    const eq = part.indexOf("=");
    const k = decodeSafe(eq === -1 ? part : part.slice(0, eq)).toLowerCase();
    const v = eq === -1 ? "" : decodeSafe(part.slice(eq + 1));
    if (!(k in out)) out[k] = v;
  }
  return out;
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(String(s).replace(/\+/g, " "));
  } catch {
    return String(s);
  }
}

/** Extract up to `max` distinct http(s) URLs from free text. */
function extractUrls(text, max = 3) {
  const found = [];
  for (const m of text.matchAll(URL_TOKEN_RE)) {
    const u = m[0].replace(/[.,;:!?]+$/, "");
    if (!found.includes(u) && isParsableHttpUrl(u)) found.push(u);
    if (found.length >= max) break;
  }
  return found;
}

function isParsableHttpUrl(s) {
  try {
    const u = new URL(s);
    return (u.protocol === "http:" || u.protocol === "https:") && !!u.hostname;
  } catch {
    return false;
  }
}

function base(kind, raw, extra = {}) {
  if (!PAYLOAD_KINDS.includes(kind)) throw new Error(`Unknown payload kind ${kind}`);
  return {
    kind,
    raw,
    normalized: null,
    parsed: {},
    embedded_urls: [],
    fetchable: false,
    reason: null,
    signals: [],
    ...extra,
  };
}

/* ------------------------------------------------------------------ */
/* Per-kind parsers                                                    */
/* ------------------------------------------------------------------ */

function parseUpi(text, raw) {
  const res = base("upi", raw);
  const qIndex = text.indexOf("?");
  const q = parseQuery(qIndex === -1 ? "" : text.slice(qIndex + 1));
  const vpa = clampText(q.pa || null, 120);
  const amount = q.am != null && q.am !== "" ? q.am : null;
  res.parsed = {
    vpa,
    payee_name: clampText(q.pn || null, 120),
    amount,
    currency: clampText(q.cu || null, 10),
    note: clampText(q.tn || null, 160),
    merchant_code: clampText(q.mc || null, 20),
    transaction_ref: clampText(q.tr || null, 60),
  };
  res.normalized = text;
  res.reason = "upi_payment_uri_not_fetchable";
  res.signals.push(
    sig("upi_payment_request", "medium", `QR encodes a UPI payment request${vpa ? ` to ${vpa}` : ""}.`, {
      value: vpa,
    }),
  );
  if (amount !== null) {
    res.signals.push(
      sig(
        "upi_amount_prefilled",
        "medium",
        `UPI request carries a prefilled amount of ${amount}${q.cu ? ` ${q.cu}` : ""}.`,
        { value: amount },
      ),
    );
  }
  if (vpa) {
    const at = vpa.indexOf("@");
    const local = at === -1 ? vpa : vpa.slice(0, at);
    const handle = at === -1 ? "" : vpa.slice(at + 1).toLowerCase();
    const looksPersonal = /^[a-z]+[._-]?\d{2,}$|^\d{10}$|^[a-z]+\d{2,}[a-z]*$/i.test(local);
    if (looksPersonal && (handle === "" || CONSUMER_UPI_HANDLES.has(handle))) {
      res.signals.push(
        sig(
          "upi_individual_looking_vpa",
          "weak",
          `Payee VPA ${vpa} follows a personal-account pattern (name plus digits) rather than a merchant id.`,
          { value: vpa },
        ),
      );
    }
    if (!q.mc) {
      res.signals.push(
        sig("upi_no_merchant_code", "weak", "UPI request has no merchant code (mc), typical of person-to-person transfers.", {
          value: null,
        }),
      );
    }
  }
  return res;
}

function parseWifi(text, raw) {
  const res = base("wifi", raw);
  const body = text.replace(/^wifi:/i, "");
  const fields = {};
  // Fields are KEY:VALUE separated by ';' with '\' escaping.
  let i = 0;
  while (i < body.length) {
    const colon = body.indexOf(":", i);
    if (colon === -1) break;
    const key = body.slice(i, colon).trim().toUpperCase();
    let j = colon + 1;
    let value = "";
    while (j < body.length && body[j] !== ";") {
      if (body[j] === "\\" && j + 1 < body.length) {
        value += body[j + 1];
        j += 2;
      } else {
        value += body[j];
        j += 1;
      }
    }
    fields[key] = value;
    i = j + 1;
  }
  const auth = (fields.T || "").toUpperCase() || "nopass";
  const open = auth === "NOPASS" || auth === "" || (!fields.P && auth !== "WPA" && auth !== "WPA2" && auth !== "WEP" && auth !== "WPA3" && auth !== "SAE");
  res.parsed = {
    ssid: clampText(fields.S || null, 64),
    auth_type: auth.toLowerCase(),
    password_present: Boolean(fields.P && fields.P.length > 0),
    hidden: /^true$/i.test(fields.H || ""),
  };
  res.normalized = `WIFI:T:${auth};S:${fields.S || ""};;`;
  res.reason = "wifi_config_not_fetchable";
  res.signals.push(
    sig("wifi_join_request", "medium", `QR asks the device to join Wi-Fi network "${res.parsed.ssid || "(unnamed)"}".`, {
      value: res.parsed.ssid,
    }),
  );
  if (open) {
    res.signals.push(
      sig("wifi_open_network", "medium", "The Wi-Fi network has no password (open network); traffic could be observed.", {
        value: auth.toLowerCase(),
      }),
    );
  }
  return res;
}

function parseVcard(text, raw) {
  const res = base("vcard", raw);
  const isMecard = /^mecard:/i.test(text);
  // vCard: one property per line. MECARD: one line, properties separated by ';'.
  const lines = isMecard
    ? text.replace(/^mecard:/i, "").split(/(?<!\\);/)
    : text.split(/\r?\n/);
  const get = (re) => {
    for (const l of lines) {
      const m = re.exec(l.trim());
      if (m) return m[1].trim();
    }
    return null;
  };
  let name = null, org = null;
  if (isMecard) {
    name = get(/^N:(.*)$/i);
    org = get(/^ORG:(.*)$/i);
  } else {
    name = get(/^FN[^:]*:(.*)$/i) || get(/^N[^:]*:(.*)$/i);
    org = get(/^ORG[^:]*:(.*)$/i);
  }
  const explicit = [];
  for (const l of lines) {
    const m = /^URL[^:]*:(.+)$/i.exec(l.trim());
    if (m) explicit.push(m[1].trim());
  }
  const urls = [];
  for (const u of [...explicit, ...extractUrls(text, 3)]) {
    const candidate = /^https?:\/\//i.test(u) ? u : BARE_DOMAIN_RE.test(u) ? `https://${u}` : null;
    if (candidate && isParsableHttpUrl(candidate) && !urls.includes(candidate)) urls.push(candidate);
    if (urls.length >= 3) break;
  }
  res.parsed = {
    format: isMecard ? "mecard" : "vcard",
    name: clampText(name, 80),
    org: clampText(org, 80),
    has_phone: /^(TEL|TEL;)/im.test(text) || /TEL:/i.test(text),
    has_email: /^(EMAIL|EMAIL;)/im.test(text) || /EMAIL:/i.test(text),
    url_count: urls.length,
  };
  res.embedded_urls = urls;
  if (urls.length > 0) {
    res.normalized = urls[0];
    res.fetchable = true;
    res.reason = "url_embedded_in_vcard";
    res.signals.push(
      sig("url_embedded_in_vcard", "weak", `Contact card contains a web link (${urls[0]}); analysing that link.`, {
        value: urls[0],
      }),
    );
  } else {
    res.normalized = text;
    res.reason = "contact_card_without_url";
  }
  return res;
}

function parseTel(scheme, text, raw) {
  const kind = scheme === "tel" ? "tel" : "sms";
  const res = base(kind, raw);
  const rest = text.slice(scheme.length + 1);
  if (kind === "tel") {
    res.parsed = { number: clampText(rest.split(/[?;]/)[0], 40) };
  } else {
    // sms:+1555?body=... or smsto:+1555:message
    let number = rest, body = null;
    const q = rest.indexOf("?");
    if (q !== -1) {
      number = rest.slice(0, q);
      body = parseQuery(rest.slice(q + 1)).body ?? null;
    } else if (scheme === "smsto" && rest.includes(":")) {
      const c = rest.indexOf(":");
      number = rest.slice(0, c);
      body = rest.slice(c + 1);
    }
    res.parsed = { number: clampText(number, 40), body: clampText(body, 200), body_present: Boolean(body) };
    if (body && /\b(premium|subscribe|STOP|win|prize|claim)\b/i.test(body)) {
      res.signals.push(
        sig("sms_prefilled_body_keywords", "weak", "Prefilled SMS text contains promotional or subscription keywords.", {
          value: clampText(body, 60),
        }),
      );
    }
  }
  res.normalized = text;
  res.reason = `${kind}_uri_not_fetchable`;
  return res;
}

function parseMailto(text, raw) {
  const res = base("mailto", raw);
  const rest = text.slice("mailto:".length);
  const q = rest.indexOf("?");
  const address = q === -1 ? rest : rest.slice(0, q);
  const params = q === -1 ? {} : parseQuery(rest.slice(q + 1));
  res.parsed = {
    address: clampText(address, 120),
    domain: clampText(address.includes("@") ? address.split("@").pop().toLowerCase() : null, 80),
    subject: clampText(params.subject || null, 120),
  };
  res.normalized = text;
  res.reason = "mailto_not_fetchable";
  return res;
}

function parseGeo(text, raw) {
  const res = base("geo", raw);
  const m = /^geo:(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/i.exec(text);
  res.parsed = m ? { lat: Number(m[1]), lng: Number(m[2]) } : { lat: null, lng: null };
  res.normalized = text;
  res.reason = "geo_uri_not_fetchable";
  return res;
}

function parseIntent(text, raw) {
  const res = base("intent", raw);
  const pkg = /;package=([^;]+)/i.exec(text);
  const scheme = /;scheme=([^;]+)/i.exec(text);
  const fallback = /;S\.browser_fallback_url=([^;]+)/i.exec(text);
  res.parsed = {
    package: clampText(pkg ? pkg[1] : null, 120),
    target_scheme: clampText(scheme ? scheme[1] : null, 40),
    has_browser_fallback: Boolean(fallback),
  };
  res.normalized = text;
  res.reason = "android_intent_not_fetchable";
  res.signals.push(
    sig(
      "android_intent_payload",
      "medium",
      `QR encodes an Android intent${res.parsed.package ? ` targeting package ${res.parsed.package}` : ""}; it can launch an app directly.`,
      { value: res.parsed.package },
    ),
  );
  if (fallback) {
    const fb = decodeSafe(fallback[1]);
    if (isParsableHttpUrl(fb)) {
      res.embedded_urls = [fb];
      res.normalized = fb;
      res.fetchable = true;
      res.reason = "intent_browser_fallback_url";
      res.signals.push(
        sig("url_embedded_in_intent", "weak", `Intent carries a browser fallback URL (${fb}); analysing that link.`, {
          value: fb,
        }),
      );
    }
  }
  return res;
}

function parseAppstore(scheme, text, raw) {
  const res = base("appstore", raw);
  const q = text.indexOf("?");
  const params = parseQuery(q === -1 ? "" : text.slice(q + 1));
  res.parsed = { store_scheme: scheme, app_id: clampText(params.id || null, 160) };
  res.normalized = text;
  res.reason = "app_store_link_not_fetchable";
  res.signals.push(
    sig("app_store_link", "weak", `QR opens an app store listing${res.parsed.app_id ? ` (${res.parsed.app_id})` : ""}.`, {
      value: res.parsed.app_id,
    }),
  );
  return res;
}

function parseCrypto(scheme, text, raw) {
  const res = base("crypto", raw);
  const rest = text.slice(scheme.length + 1);
  const q = rest.indexOf("?");
  const address = q === -1 ? rest : rest.slice(0, q);
  const params = parseQuery(q === -1 ? "" : rest.slice(q + 1));
  res.parsed = {
    network: scheme,
    address: clampText(address.replace(/^\/\//, ""), 120),
    amount: clampText(params.amount || params.value || null, 40),
  };
  res.normalized = text;
  res.reason = "crypto_payment_uri_not_fetchable";
  res.signals.push(
    sig("crypto_payment_request", "medium", `QR encodes a ${scheme} payment request${res.parsed.amount ? ` for ${res.parsed.amount}` : ""}.`, {
      value: res.parsed.address,
    }),
  );
  return res;
}

function parseHttpUrl(text, raw, { schemeAdded = false } = {}) {
  const res = base("url", raw);
  if (!isParsableHttpUrl(text)) {
    const t = base("text", raw);
    t.normalized = text;
    t.reason = "url_unparseable";
    t.parsed = { length: text.length, excerpt: clampText(text, 200) };
    t.signals.push(sig("url_unparseable", "weak", "Payload looks like a web address but could not be parsed as a URL.", { value: clampText(text, 120) }));
    return t;
  }
  res.normalized = text;
  res.fetchable = true;
  res.parsed = { scheme_added: schemeAdded };
  if (schemeAdded) {
    res.signals.push(
      sig("scheme_added", "weak", "QR payload was a bare domain without http/https; https:// was assumed.", {
        value: text,
      }),
    );
  }
  return res;
}

function parseText(text, raw) {
  const res = base("text", raw);
  const urls = extractUrls(text, 3);
  res.parsed = { length: text.length, excerpt: clampText(text, 200) };
  res.embedded_urls = urls;
  if (urls.length > 0) {
    res.normalized = urls[0];
    res.fetchable = true;
    res.reason = "url_embedded_in_text";
    res.signals.push(
      sig("url_embedded_in_text", "weak", `Free-text payload contains a web link (${urls[0]}); analysing that link.`, {
        value: urls[0],
      }),
    );
  } else {
    res.normalized = text;
    res.reason = "non_url_text";
  }
  return res;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

/**
 * Classify a decoded QR payload.
 * @param {string|null|undefined} raw
 * @returns {PayloadResult}
 */
export function classifyPayload(raw) {
  if (raw === null || raw === undefined || typeof raw !== "string") {
    const r = base("none", "");
    r.reason = "empty_payload";
    return r;
  }
  const text = cleanRaw(raw);
  if (text.length === 0) {
    const r = base("none", raw);
    r.reason = "empty_payload";
    return r;
  }

  const blocked = detectBlockedScheme(text);
  if (blocked) {
    const r = base("blocked_scheme", raw);
    r.normalized = text;
    r.reason = `blocked_scheme:${blocked}`;
    r.parsed = { scheme: blocked, excerpt: clampText(text, 120) };
    r.signals.push(
      sig(
        "blocked_scheme",
        "critical",
        `QR payload uses the "${blocked}:" scheme, which can execute code or load local content when opened; it is never fetched.`,
        { value: blocked },
      ),
    );
    return r;
  }

  const scheme = detectScheme(text);

  if (scheme === "http" || scheme === "https") {
    // Rebuild with a clean lower-case scheme (tolerates "HTTP://" and embedded whitespace in the scheme).
    const rest = text.slice(text.indexOf(":") + 1);
    return parseHttpUrl(`${scheme}:${rest}`, raw);
  }
  if (scheme === "upi") return parseUpi(text, raw);
  if (scheme === "wifi") return parseWifi(text, raw);
  if (scheme === "tel" || scheme === "sms" || scheme === "smsto" || scheme === "mms") return parseTel(scheme === "mms" ? "sms" : scheme, text, raw);
  if (scheme === "mailto") return parseMailto(text, raw);
  if (scheme === "geo") return parseGeo(text, raw);
  if (scheme === "intent") return parseIntent(text, raw);
  if (APPSTORE_SCHEMES.has(scheme)) return parseAppstore(scheme, text, raw);
  if (CRYPTO_SCHEMES.has(scheme)) return parseCrypto(scheme, text, raw);
  if (/^(BEGIN:VCARD|MECARD:)/i.test(text)) return parseVcard(text, raw);

  if (scheme && scheme !== "www" && !/^\d+$/.test(scheme)) {
    // Known-but-unsupported scheme (ftp, ssh, tg, whatsapp, ...): not fetchable.
    const r = base("text", raw);
    r.normalized = text;
    r.reason = `unsupported_scheme:${scheme}`;
    r.parsed = { scheme, length: text.length, excerpt: clampText(text, 200) };
    r.embedded_urls = extractUrls(text, 3);
    r.signals.push(
      sig("unsupported_scheme", "weak", `QR payload uses the "${scheme}:" scheme, which QRShield does not open.`, {
        value: scheme,
      }),
    );
    return r;
  }

  if (!/\s/.test(text) && BARE_DOMAIN_RE.test(text)) {
    return parseHttpUrl(`https://${text}`, raw, { schemeAdded: true });
  }

  return parseText(text, raw);
}
