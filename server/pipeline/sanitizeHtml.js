// HTML -> PageEvidence extraction and prompt sanitation.
//
// extractPage() produces deterministic facts about a fetched page (title,
// forms, sensitive fields, external hosts, redirects declared in markup).
// sanitizeForPrompt() is applied by the packet builder before any page text is
// shown to the model: page text is UNTRUSTED content, never instructions.

import { parse } from "node-html-parser";
import { PACKET_CAPS, clampText } from "./contracts.js";

/**
 * @typedef {'password'|'card'|'otp'|'upi'|'aadhaar'|'pan'|'bank'|'phone'|'email'|'text'|'hidden'|'file'|'checkbox'|'other'} FieldClass
 *
 * @typedef {Object} PageForm
 * @property {string} method
 * @property {string|null} action_host
 * @property {boolean} cross_origin
 * @property {boolean} action_is_http
 * @property {FieldClass[]} field_types
 *
 * @typedef {Object} PageEvidence
 * @property {string|null} title
 * @property {string|null} meta_description
 * @property {string|null} site_name
 * @property {string|null} og_title
 * @property {string|null} canonical_host
 * @property {string|null} lang
 * @property {string} visible_text_excerpt
 * @property {PageForm[]} forms
 * @property {{ password: boolean, payment_card: boolean, otp: boolean, upi: boolean, aadhaar: boolean, pan: boolean, bank: boolean }} sensitive_inputs
 * @property {string[]} external_hosts
 * @property {string[]} external_script_hosts
 * @property {string[]} iframe_hosts
 * @property {boolean} has_download_links
 * @property {string|null} meta_refresh_target
 * @property {boolean} bot_wall_detected
 * @property {number} external_links_count
 */

const ZERO_WIDTH_RE = /[​-‍⁠﻿­]/g;
// Control characters except \t \n \r
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
const DOWNLOAD_EXT_RE = /\.(apk|xapk|exe|msi|dmg|pkg|zip|rar|7z|bat|cmd|scr|jar|ipa|hta|ps1)(?:[?#]|$)/i;
const BOT_WALL_TITLE_RE = /just a moment|attention required|checking your browser|verify you are (a )?human|access denied|one more step|ddos-guard|security check|are you a robot/i;
const BOT_WALL_MARKER_RE = /cf-chl|cf_chl|__cf_chl|challenge-platform|cdn-cgi\/challenge|captcha-delivery\.com|cf-browser-verification|_cf_chl_opt|hcaptcha\.com\/1\/api\.js/i;

/** Normalize whitespace and strip invisible characters. */
function cleanText(s) {
  return String(s || "")
    .replace(ZERO_WIDTH_RE, "")
    .replace(CONTROL_RE, "")
    .replace(/\s+/g, " ")
    .trim();
}

function attr(node, name) {
  if (!node || typeof node.getAttribute !== "function") return "";
  const v = node.getAttribute(name);
  return v === undefined || v === null ? "" : String(v);
}

function safeUrl(href, base) {
  try {
    return base ? new URL(href, base) : new URL(href);
  } catch {
    return null;
  }
}

function hostOf(href, base) {
  const u = safeUrl(href, base);
  if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) return null;
  return u.hostname.toLowerCase();
}

function pushUnique(list, value, cap) {
  if (!value) return;
  if (list.includes(value)) return;
  if (list.length >= cap) return;
  list.push(value);
}

/**
 * Classify a form control from its attributes.
 * @param {{ type?: string, name?: string, id?: string, placeholder?: string, autocomplete?: string, ariaLabel?: string }} f
 * @returns {FieldClass}
 */
export function classifyField({ type, name, id, placeholder, autocomplete, ariaLabel } = {}) {
  const t = String(type || "text").trim().toLowerCase();
  const ac = String(autocomplete || "").toLowerCase();
  // Separators become spaces so "mobile_number" / "card-no" / "otp.code" match word boundaries.
  const hay = cleanText(`${name || ""} ${id || ""} ${placeholder || ""} ${ac} ${ariaLabel || ""}`.replace(/[_\-./:]+/g, " ")).toLowerCase();

  if (t === "password") return "password";
  if (t === "hidden") return "hidden";
  if (t === "file") return "file";
  if (t === "checkbox" || t === "radio") return "checkbox";
  if (["submit", "button", "reset", "image", "color", "range"].includes(t)) return "other";

  // Payment card (autocomplete tokens are the most reliable signal)
  if (/\bcc-(number|csc|exp|exp-month|exp-year|name)\b/.test(ac)) return "card";
  // UPI
  if (/\bupi\b|\bvpa\b|upi[-_ ]?(id|pin)|\bmpin\b|@(ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|upi|axl|ibl)\b/.test(hay)) return "upi";
  // Cards
  if (/\b(card ?(number|no|num)|cardnumber|cardno|ccnum|cc[-_ ]?num|credit|debit|cvv2?|cvc|csc|exp(iry|iration)?[-_ ]?(date|month|year|mm|yy)|atm[-_ ]?pin|card[-_ ]?pin)\b/.test(hay)) return "card";
  if (/\bcc\b/.test(hay)) return "card";
  // One-time codes
  if (/\botp\b|one[-_ ]?time[-_ ]?(code|pass(word|code)?)?|verification[-_ ]?code|verify[-_ ]?code|auth[-_ ]?code|security[-_ ]?code|passcode|\b2fa\b|totp|\bsms[-_ ]?code\b/.test(hay)) return "otp";
  if (ac === "one-time-code") return "otp";
  // Aadhaar
  if (/aadhaa?r|adhaar|\buidai\b|\buid[-_ ]?(no|number)?\b/.test(hay)) return "aadhaar";
  // PAN (Indian tax id)
  if (/\bpan\b|pan[-_ ]?(no|number|card)|permanent account number/.test(hay)) return "pan";
  // Bank account
  if (/account[-_ ]?(number|no|num)|\bacc(ou)?nt?[-_ ]?(no|num|number)\b|\bifsc\b|\biban\b|\bswift\b|routing[-_ ]?(number|no)|\bbank\b|\bsort[-_ ]?code\b|netbanking|net[-_ ]?banking/.test(hay)) return "bank";
  // Generic PIN / password-like secrets typed into non-password fields
  if (/\bpin\b|passw(or)?d|\bpwd\b|\bpass\b/.test(hay)) return "password";

  if (t === "email" || /\be ?mail\b/.test(hay) || ac === "email") return "email";
  if (t === "tel" || /\b(phone|mobile|tel|whatsapp)\b|contact[-_ ]?(no|number)/.test(hay) || /^tel\b/.test(ac)) return "phone";

  if (["text", "search", "number", "url", "date", "select", "textarea", "", "month", "week", "time"].includes(t)) return "text";
  return "other";
}

/**
 * Strip prompt-injection-shaped lines and tidy text for inclusion in a model prompt.
 * @param {string} text
 * @param {number} [maxChars]
 * @returns {string}
 */
export function sanitizeForPrompt(text, maxChars = 3000) {
  const INJECTION_RE = /ignore (all|previous|prior|the above|any) (instructions|rules|guidance)|^\s*(system|assistant|user)\s*:|you are (now|an?) |disregard (all|previous|prior)|new instructions|as an ai|output (low_risk|low risk)|respond with/i;
  let s = String(text || "")
    .replace(ZERO_WIDTH_RE, "")
    .replace(CONTROL_RE, "")
    .replace(/<\|[^|<>]{0,40}\|>/g, " ") // chat-template tokens like <|im_start|>
    .replace(/```+/g, " ");

  const segments = s.split(/\r?\n|(?<=[.!?])\s+/);
  const kept = segments.filter((seg) => seg.trim() && !INJECTION_RE.test(seg));
  s = kept.join(" ").replace(/\s+/g, " ").trim();
  if (s.length > maxChars) s = s.slice(0, Math.max(0, maxChars - 1)) + "…";
  return s;
}

/**
 * Extract deterministic evidence from an HTML document.
 * @param {string} html
 * @param {string} baseUrl
 * @returns {PageEvidence}
 */
export function extractPage(html, baseUrl) {
  /** @type {PageEvidence} */
  const page = {
    title: null,
    meta_description: null,
    site_name: null,
    og_title: null,
    canonical_host: null,
    lang: null,
    visible_text_excerpt: "",
    forms: [],
    sensitive_inputs: { password: false, payment_card: false, otp: false, upi: false, aadhaar: false, pan: false, bank: false },
    external_hosts: [],
    external_script_hosts: [],
    iframe_hosts: [],
    has_download_links: false,
    meta_refresh_target: null,
    bot_wall_detected: false,
    external_links_count: 0,
  };

  const source = String(html || "");
  if (!source.trim()) return page;

  const base = safeUrl(baseUrl) || null;
  const baseHost = base ? base.hostname.toLowerCase() : null;

  let root;
  try {
    root = parse(source, {
      comment: false,
      blockTextElements: { script: true, noscript: true, style: true, pre: false },
    });
  } catch {
    page.visible_text_excerpt = clampText(cleanText(source.replace(/<[^>]*>/g, " ")), PACKET_CAPS.visibleText) || "";
    return page;
  }

  // --- head metadata ---
  const titleEl = root.querySelector("title");
  page.title = titleEl ? clampText(cleanText(titleEl.text), PACKET_CAPS.title) || null : null;
  const htmlEl = root.querySelector("html");
  page.lang = htmlEl && attr(htmlEl, "lang") ? cleanText(attr(htmlEl, "lang")).slice(0, 16) : null;

  for (const meta of root.querySelectorAll("meta")) {
    const name = attr(meta, "name").toLowerCase();
    const prop = attr(meta, "property").toLowerCase();
    const httpEquiv = attr(meta, "http-equiv").toLowerCase();
    const content = attr(meta, "content");
    if (name === "description" && !page.meta_description) {
      page.meta_description = clampText(cleanText(content), PACKET_CAPS.metaDescription) || null;
    } else if (prop === "og:title" && !page.og_title) {
      page.og_title = clampText(cleanText(content), PACKET_CAPS.title) || null;
    } else if (prop === "og:site_name" && !page.site_name) {
      page.site_name = clampText(cleanText(content), PACKET_CAPS.title) || null;
    } else if (name === "application-name" && !page.site_name) {
      page.site_name = clampText(cleanText(content), PACKET_CAPS.title) || null;
    } else if (httpEquiv === "refresh" && !page.meta_refresh_target) {
      const m = /url\s*=\s*['"]?([^'"\s;]+)/i.exec(content);
      if (m) {
        const target = safeUrl(m[1], base || undefined);
        page.meta_refresh_target = target ? target.href.slice(0, 512) : clampText(m[1], 512);
      }
    }
  }

  const canonical = root.querySelector('link[rel="canonical"]') || root.querySelector("link[rel=canonical]");
  if (canonical) page.canonical_host = hostOf(attr(canonical, "href"), base || undefined);

  // --- external resources (collected before removal) ---
  for (const s of root.querySelectorAll("script[src]")) {
    const h = hostOf(attr(s, "src"), base || undefined);
    if (h && h !== baseHost) pushUnique(page.external_script_hosts, h, PACKET_CAPS.externalHosts);
  }
  for (const f of root.querySelectorAll("iframe[src], frame[src]")) {
    const h = hostOf(attr(f, "src"), base || undefined);
    if (h) pushUnique(page.iframe_hosts, h, PACKET_CAPS.externalHosts);
  }

  // --- links ---
  for (const a of root.querySelectorAll("a[href]")) {
    const href = attr(a, "href");
    const u = safeUrl(href, base || undefined);
    if (!u) continue;
    if (u.protocol === "intent:" || u.protocol === "market:") page.has_download_links = true;
    if (u.protocol !== "http:" && u.protocol !== "https:") continue;
    if (DOWNLOAD_EXT_RE.test(u.pathname) || a.hasAttribute("download")) page.has_download_links = true;
    const h = u.hostname.toLowerCase();
    if (baseHost && h !== baseHost) {
      page.external_links_count += 1;
      pushUnique(page.external_hosts, h, PACKET_CAPS.externalHosts);
    }
  }

  // --- forms ---
  const sensitiveCount = { password: 0, card: 0, otp: 0, upi: 0, aadhaar: 0, pan: 0, bank: 0 };
  const classify = (el) => {
    const cls = classifyField({
      type: el.rawTagName && el.rawTagName.toLowerCase() === "input" ? attr(el, "type") : el.rawTagName ? el.rawTagName.toLowerCase() : "text",
      name: attr(el, "name"),
      id: attr(el, "id"),
      placeholder: attr(el, "placeholder"),
      autocomplete: attr(el, "autocomplete"),
      ariaLabel: attr(el, "aria-label"),
    });
    if (cls in sensitiveCount) sensitiveCount[cls] += 1;
    return cls;
  };

  const forms = root.querySelectorAll("form");
  for (const form of forms.slice(0, PACKET_CAPS.forms)) {
    const method = (attr(form, "method") || "get").trim().toLowerCase() || "get";
    const actionRaw = attr(form, "action");
    const actionUrl = actionRaw ? safeUrl(actionRaw, base || undefined) : base;
    const actionHost = actionUrl ? actionUrl.hostname.toLowerCase() : null;
    const fields = form.querySelectorAll("input, select, textarea");
    const field_types = fields.slice(0, PACKET_CAPS.fieldsPerForm).map(classify);
    page.forms.push({
      method,
      action_host: actionHost,
      cross_origin: Boolean(actionHost && baseHost && actionHost !== baseHost),
      action_is_http: Boolean(actionUrl && actionUrl.protocol === "http:"),
      field_types,
    });
  }
  // Inputs outside any <form> still collect data via scripts: count them too.
  for (const el of root.querySelectorAll("input, select, textarea")) {
    if (el.closest && el.closest("form")) continue;
    classify(el);
  }
  page.sensitive_inputs = {
    password: sensitiveCount.password > 0,
    payment_card: sensitiveCount.card > 0,
    otp: sensitiveCount.otp > 0,
    upi: sensitiveCount.upi > 0,
    aadhaar: sensitiveCount.aadhaar > 0,
    pan: sensitiveCount.pan > 0,
    bank: sensitiveCount.bank > 0,
  };

  // --- bot wall ---
  page.bot_wall_detected =
    BOT_WALL_TITLE_RE.test(page.title || "") || BOT_WALL_MARKER_RE.test(source.slice(0, 200_000));

  // --- visible text ---
  for (const el of root.querySelectorAll("script, style, noscript, template, svg, iframe, frame, head, canvas, object, embed")) {
    try {
      el.remove();
    } catch {
      /* ignore */
    }
  }
  const body = root.querySelector("body") || root;
  let text = "";
  try {
    // structuredText separates block elements with newlines so words do not fuse.
    text = typeof body.structuredText === "string" ? body.structuredText : body.text || "";
  } catch {
    try {
      text = body.text || "";
    } catch {
      text = "";
    }
  }
  // Keep the title visible to the model even though <head> was removed.
  const combined = page.title ? `${page.title} ${text}` : text;
  page.visible_text_excerpt = clampText(cleanText(combined), PACKET_CAPS.visibleText) || "";

  return page;
}
