// Deterministic signals derived from the fetch chain and the extracted page.
// Stage 'fetch' = things learned from HTTP transport; 'destination' = things
// learned from the final page. Nothing here depends on model output.

import fs from "node:fs";
import { signal } from "./contracts.js";

/**
 * @typedef {import('./fetchDestination.js').FetchResult} FetchResult
 * @typedef {import('./sanitizeHtml.js').PageEvidence} PageEvidence
 */

const APK_MIME_RE = /android\.package-archive|vnd\.android/i;
const BINARY_MIME_RE = /^(application\/(octet-stream|pdf|zip|x-zip-compressed|x-rar-compressed|x-7z-compressed|x-msdownload|x-msdos-program|x-ms-installer|java-archive|x-apple-diskimage|vnd\.microsoft\.portable-executable|x-executable)|image\/|audio\/|video\/)/i;
const ATTACHMENT_RE = /attachment/i;
const APK_FILENAME_RE = /\.x?apk(\b|["';]|$)/i;

// ---------------------------------------------------------------------------
// Optional brand list (written by another module; tolerate any shape or absence)
// ---------------------------------------------------------------------------

/** @type {null | Array<{ name: string, keywords: string[], domains: string[] }>} */
let brandsCache;

function loadBrands() {
  if (brandsCache !== undefined) return brandsCache;
  brandsCache = null;
  try {
    const raw = fs.readFileSync(new URL("../lists/brands.json", import.meta.url), "utf8");
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : data && Array.isArray(data.brands) ? data.brands : data && typeof data === "object" ? Object.entries(data).map(([name, v]) => ({ name, ...(Array.isArray(v) ? { domains: v } : v || {}) })) : [];
    const norm = [];
    for (const item of list) {
      if (typeof item === "string") {
        norm.push({ name: item, keywords: [item.toLowerCase()], domains: [] });
        continue;
      }
      if (!item || typeof item !== "object") continue;
      const name = String(item.name || item.brand || item.id || "").trim();
      if (!name) continue;
      const keywords = [name, ...(Array.isArray(item.keywords) ? item.keywords : []), ...(Array.isArray(item.aliases) ? item.aliases : [])]
        .map((k) => String(k).toLowerCase().trim())
        .filter((k) => k.length >= 3);
      const domains = [...(Array.isArray(item.domains) ? item.domains : []), ...(Array.isArray(item.official_domains) ? item.official_domains : []), ...(item.domain ? [item.domain] : [])]
        .map((d) => String(d).toLowerCase().trim())
        .filter(Boolean);
      norm.push({ name, keywords: [...new Set(keywords)], domains: [...new Set(domains)] });
    }
    brandsCache = norm.length ? norm : null;
  } catch {
    brandsCache = null;
  }
  return brandsCache;
}

/** Exposed for tests: force a reload of the brand list. */
export function _resetBrandCache() {
  brandsCache = undefined;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hostMatchesDomain(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/**
 * @param {FetchResult|null} fetchResult
 * @param {PageEvidence|null} page
 * @param {{ url?: object, signals?: Array<{id:string}> }|null} urlAnalysis
 * @returns {ReturnType<typeof signal>[]}
 */
export function destinationSignals(fetchResult, page, urlAnalysis) {
  const out = [];
  if (!fetchResult || typeof fetchResult !== "object") return out;

  const F = (id, strength, fact, extra = {}) => out.push(signal(id, strength, fact, { stage: "fetch", ...extra }));
  const D = (id, strength, fact, extra = {}) => out.push(signal(id, strength, fact, { stage: "destination", ...extra }));

  const chain = Array.isArray(fetchResult.chain) ? fetchResult.chain : [];
  const urlSignalIds = new Set(((urlAnalysis && urlAnalysis.signals) || []).map((s) => s && s.id));
  const startedAtShortener = urlSignalIds.has("url_shortener");

  // ---- redirects ----
  const redirects = Number.isInteger(fetchResult.redirects) ? fetchResult.redirects : Math.max(0, chain.filter((h) => h.status && h.status >= 300 && h.status < 400 && h.location).length);
  if (redirects >= 4) {
    F("redirect_count", "medium", `The link redirected ${redirects} times before reaching a final page.`, { value: redirects });
  } else if (redirects >= 2) {
    F("redirect_count", "weak", `The link redirected ${redirects} times before reaching a final page.`, { value: redirects });
  }

  // A hop that was itself refused is reported by the blocked-target signal; do not
  // double-count it as a cross-domain redirect.
  const crossHop = chain.find((h) => h.cross_domain && !h.blocked);
  if (crossHop) {
    const idx = chain.indexOf(crossHop);
    const from = chain[idx - 1] ? chain[idx - 1].host : "the original host";
    if (startedAtShortener && idx === 1) {
      F("cross_domain_redirect", "weak", `The URL shortener ${from} expands to ${crossHop.host}; the printed link hid the real destination.`, { value: crossHop.host });
    } else {
      F("cross_domain_redirect", "medium", `A redirect moved from ${from} to a different site, ${crossHop.host}.`, { value: `${from} -> ${crossHop.host}` });
    }
  }

  const downgradeHop = chain.find((h) => h.downgrade);
  if (downgradeHop) {
    F("redirect_scheme_downgrade", "strong", `A redirect dropped from encrypted https to plain http at ${downgradeHop.host}.`, { value: downgradeHop.url });
  }

  // ---- fetch errors ----
  const err = fetchResult.error;
  if (err && typeof err === "object") {
    const hop = Number.isInteger(err.hop) ? err.hop : 0;
    const blockedHop = chain[hop] || chain[chain.length - 1] || null;
    const target = blockedHop ? blockedHop.host : "the destination";
    switch (err.code) {
      case "blocked_private_ip":
      case "blocked_hostname":
        if (hop > 0) {
          F("redirect_to_blocked_target", "critical", `A redirect pointed at ${target}, a non-public or internal address. The fetch was refused before connecting.`, { value: target });
        } else {
          F("destination_resolves_to_private_network", "critical", `The destination ${target} is a non-public or internal address. The fetch was refused before connecting.`, { value: target });
        }
        break;
      case "blocked_scheme":
        if (hop > 0) {
          F("redirect_to_blocked_target", "critical", `A redirect pointed at a non-web scheme (${blockedHop ? blockedHop.url.split(":")[0] : "unknown"}:). The fetch was refused.`, { value: blockedHop ? blockedHop.url : null });
        } else {
          F("blocked_scheme_refused", "critical", `The destination uses a scheme that is never fetched (${blockedHop ? blockedHop.url.split(":")[0] : "unknown"}:).`, { value: blockedHop ? blockedHop.url : null });
        }
        break;
      case "non_standard_port":
        F("non_standard_port_refused", "medium", `The destination uses a non-standard port; only ports 80 and 443 are fetched.`, { value: target });
        break;
      case "dns_nxdomain":
        F("dns_nxdomain", "neutral", `The hostname ${target} did not resolve to any address.`, { value: target });
        break;
      case "dns_error":
        F("dns_error", "neutral", `DNS lookup for ${target} failed; the destination could not be inspected.`, { value: target });
        break;
      case "fetch_timeout":
        F("fetch_timeout", "neutral", `The destination did not respond within the time limit; it could not be inspected.`, { value: target });
        break;
      case "http_error":
        F("destination_http_error", "neutral", `The destination answered with HTTP ${fetchResult.status ?? "error"}.`, { value: fetchResult.status ?? null });
        break;
      case "tls_error":
        F("tls_error", "medium", `The secure connection to ${target} failed its TLS/certificate check.`, { value: err.message || null });
        break;
      case "connection_error":
        F("destination_unreachable", "neutral", `A connection to ${target} could not be established.`, { value: target });
        break;
      case "redirect_loop":
        F("redirect_loop", "weak", `The redirects form a loop and never reach a final page.`, { value: target });
        break;
      case "redirect_limit_exceeded":
        F("redirect_limit_exceeded", "weak", `The link kept redirecting beyond the ${redirects}-hop limit; the final page was not reached.`, { value: redirects });
        break;
      case "redirect_missing_location":
        F("redirect_missing_location", "neutral", `A redirect response carried no usable Location header.`, { value: target });
        break;
      default:
        F("fetch_failed", "neutral", `The destination could not be fetched (${err.code || "unknown"}).`, { value: err.code || null });
    }
  }

  if (fetchResult.truncated) {
    F("body_truncated", "neutral", `Only the first ${fetchResult.bytes_read} bytes of the response were read.`, { value: fetchResult.bytes_read });
  }

  // ---- content-type based ----
  const headers = fetchResult.headers || null;
  const contentType = headers && headers.content_type ? String(headers.content_type) : "";
  const disposition = headers && headers.content_disposition ? String(headers.content_disposition) : "";
  const finalUrl = fetchResult.final_url || "";
  const mime = contentType.split(";")[0].trim().toLowerCase();

  if (fetchResult.status !== null && fetchResult.status !== undefined && !err) {
    if (APK_MIME_RE.test(mime) || APK_FILENAME_RE.test(disposition) || /\.x?apk(\?|#|$)/i.test(finalUrl)) {
      D("apk_download", "strong", `The destination delivers an Android app package (APK) for sideloading instead of a web page.`, { value: mime || disposition });
    } else if (!fetchResult.is_html && (BINARY_MIME_RE.test(mime) || ATTACHMENT_RE.test(disposition))) {
      D("binary_download", "medium", `The destination serves a file download (${mime || "attachment"}) rather than a web page.`, { value: mime || disposition });
    }
  }

  if (fetchResult.ok) {
    F("destination_fetched_ok", "neutral", `The final page at ${hostnameOf(finalUrl) || "the destination"} was fetched with HTTP ${fetchResult.status}.`, { value: fetchResult.status });
  }

  // ---- page-derived ----
  if (page && typeof page === "object") {
    if (page.bot_wall_detected) {
      D("bot_wall", "neutral", `The destination showed a bot-protection or challenge page, so the real content could not be inspected.`, { value: page.title || null });
    }

    const si = page.sensitive_inputs || {};
    const paymentOrIdentity = [];
    if (si.otp) paymentOrIdentity.push("OTP / one-time code");
    if (si.upi) paymentOrIdentity.push("UPI ID or UPI PIN");
    if (si.payment_card) paymentOrIdentity.push("payment card details");
    if (si.aadhaar) paymentOrIdentity.push("Aadhaar number");
    if (si.pan) paymentOrIdentity.push("PAN number");
    if (si.bank) paymentOrIdentity.push("bank account details");

    if (si.password) {
      D("credential_form_present", "strong", `The page asks for a password; it is a login or credential-collection form.`, { value: "password" });
    }
    if (paymentOrIdentity.length) {
      D("payment_or_identity_fields_present", "critical", `The page contains fields for ${paymentOrIdentity.join(", ")}. A web form asking for these is a critical signal.`, { value: paymentOrIdentity });
    }

    const forms = Array.isArray(page.forms) ? page.forms : [];
    const crossForm = forms.find((f) => f && f.cross_origin);
    if (crossForm) {
      D("form_action_cross_origin", "strong", `A form on the page submits its data to a different host, ${crossForm.action_host}.`, { value: crossForm.action_host });
    }
    const httpForm = forms.find((f) => f && f.action_is_http);
    if (httpForm) {
      D("form_action_http", "strong", `A form on the page submits its data over unencrypted http.`, { value: httpForm.action_host });
    }

    if (page.meta_refresh_target) {
      D("meta_refresh_present", "weak", `The page declares an automatic meta-refresh redirect to ${hostnameOf(page.meta_refresh_target) || page.meta_refresh_target}; it was recorded but not followed.`, { value: page.meta_refresh_target });
    }

    if (page.has_download_links) {
      D("download_links_present", "weak", `The page links to downloadable installer or archive files.`, { value: true });
    }

    // Brand mention vs serving domain (deterministic list, not model output).
    const brands = loadBrands();
    const finalHost = hostnameOf(finalUrl);
    if (brands && finalHost) {
      // Only the page's self-identification (title / og:title / site_name) counts.
      // Body text mentioning a bank is not evidence that the page claims to BE that bank.
      const haystack = `${page.title || ""} ${page.og_title || ""} ${page.site_name || ""}`.toLowerCase();
      const matched = brands.filter((b) => b.domains.length && b.keywords.some((k) => new RegExp(`\\b${escapeRe(k)}\\b`, "i").test(haystack)));
      const onOfficialDomain = matched.some((b) => b.domains.some((d) => hostMatchesDomain(finalHost, d)));
      if (matched.length && !onOfficialDomain) {
        const brand = matched[0];
        D("page_brand_mentions_vs_domain_mismatch", "medium", `The page presents itself as "${brand.name}" but is served from ${finalHost}, which is not a known domain for that organization.`, { value: `${brand.name} @ ${finalHost}`, hybrid: false });
      }
    }
  }

  return out;
}
