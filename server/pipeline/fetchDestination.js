// SSRF-protected destination fetcher.
//
// Every hop (the first URL and each HTTP redirect) is validated by ipGuard
// before a socket is opened. The connection is pinned to the validated
// address through an undici Agent whose connector uses a custom lookup, so a
// DNS answer that changes between validation and connect (DNS rebinding)
// cannot swap the target. TLS SNI and the Host header stay the hostname.
//
// This module never throws: every failure is returned as result.error.

import { fetch as undiciFetch, Agent } from "undici";
import { FETCH_LIMITS, redactSecrets } from "./contracts.js";
import { validateTarget } from "./ipGuard.js";

/**
 * @typedef {Object} ChainHop
 * @property {string} url
 * @property {string} host
 * @property {string[]} addresses
 * @property {number|null} status
 * @property {string|null} location
 * @property {boolean} blocked
 * @property {string|null} blocked_reason
 * @property {boolean} downgrade
 * @property {boolean} cross_domain
 *
 * @typedef {Object} FetchResult
 * @property {boolean} ok
 * @property {string} requested_url
 * @property {string|null} final_url
 * @property {ChainHop[]} chain
 * @property {number|null} status
 * @property {{ content_type: string|null, content_length: number|null, content_disposition: string|null, server: string|null }|null} headers
 * @property {number} bytes_read
 * @property {boolean} truncated
 * @property {boolean} is_html
 * @property {string|null} body_text
 * @property {{ code: string, message: string, hop: number }|null} error
 * @property {boolean} pinned
 * @property {boolean} userinfo_stripped
 * @property {number} redirects
 */

// ---------------------------------------------------------------------------
// registrableDomain: prefer the real implementation, fall back to last 2 labels
// so this module (and its tests) work while urlAnalysis.js is being written.
// ---------------------------------------------------------------------------

/** @param {string} hostname */
function fallbackRegistrable(hostname) {
  const labels = String(hostname || "").toLowerCase().replace(/\.$/, "").split(".");
  return labels.length <= 2 ? labels.join(".") : labels.slice(-2).join(".");
}

let registrableDomainImpl = fallbackRegistrable;
try {
  const mod = await import("./urlAnalysis.js");
  if (mod && typeof mod.registrableDomain === "function") registrableDomainImpl = mod.registrableDomain;
} catch {
  /* urlAnalysis.js missing or broken: keep fallback */
}

/** @param {string} hostname */
function registrable(hostname) {
  try {
    const r = registrableDomainImpl(hostname);
    return typeof r === "string" && r ? r.toLowerCase() : fallbackRegistrable(hostname);
  } catch {
    return fallbackRegistrable(hostname);
  }
}

// ---------------------------------------------------------------------------
// Concurrency gate (module-level semaphore)
// ---------------------------------------------------------------------------

const MAX_INFLIGHT = (() => {
  const n = Number.parseInt(process.env.QRSHIELD_MAX_INFLIGHT_FETCHES || "", 10);
  return Number.isInteger(n) && n > 0 ? n : 3;
})();

let inflight = 0;
/** @type {Array<(ok: boolean) => void>} */
const waiters = [];

export function getInflightCount() {
  return inflight;
}

/**
 * Acquire a slot or give up after waitMs.
 * @param {number} waitMs
 * @returns {Promise<boolean>}
 */
function acquire(waitMs) {
  if (inflight < MAX_INFLIGHT) {
    inflight += 1;
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const i = waiters.indexOf(grant);
      if (i !== -1) waiters.splice(i, 1);
      resolve(false);
    }, waitMs);
    function grant() {
      if (settled) return false;
      settled = true;
      clearTimeout(timer);
      inflight += 1;
      resolve(true);
      return true;
    }
    waiters.push(grant);
  });
}

function release() {
  inflight = Math.max(0, inflight - 1);
  while (waiters.length) {
    const next = waiters.shift();
    if (next && next()) break;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const TLS_CODE_RE = /^(ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|SELF_SIGNED|DEPTH_ZERO|HOSTNAME_MISMATCH)/;

/** Remove anything that could be a secret from a message and cap its length. */
function redact(msg) {
  return redactSecrets(String(msg || ""))
    .replace(/\/\/[^/@\s]+@/g, "//[redacted]@")
    .slice(0, 300);
}

/** @param {URL} u */
function stripUserinfo(u) {
  const had = u.username !== "" || u.password !== "";
  if (had) {
    u.username = "";
    u.password = "";
  }
  return had;
}

/** Headers may be a Headers object, a Map, or a plain object (fakes in tests). */
function headerGet(headers, name) {
  if (!headers) return null;
  let v = null;
  if (typeof headers.get === "function") v = headers.get(name);
  else {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
    v = key ? headers[key] : null;
  }
  if (v === undefined || v === null) return null;
  return Array.isArray(v) ? String(v[0]) : String(v);
}

function classifyNetworkError(err) {
  const name = err && err.name;
  const cause = err && err.cause;
  const code = (cause && cause.code) || (err && err.code) || "";
  const text = `${(err && err.message) || ""} ${(cause && cause.message) || ""}`;
  if (name === "AbortError" || name === "TimeoutError" || code === "UND_ERR_CONNECT_TIMEOUT" || code === "UND_ERR_HEADERS_TIMEOUT" || code === "UND_ERR_BODY_TIMEOUT") {
    return { code: "fetch_timeout", message: "Destination did not respond in time" };
  }
  if (TLS_CODE_RE.test(String(code)) || /certificate|ssl|tls|handshake/i.test(text)) {
    return { code: "tls_error", message: redact(`TLS problem: ${code || text.trim()}`) };
  }
  return { code: "connection_error", message: redact(`Connection failed: ${code || text.trim() || "unknown"}`) };
}

/** Errors that mean the pinned-Agent approach itself is broken, not the network. */
function isAgentSetupError(err) {
  const code = (err && err.code) || (err && err.cause && err.cause.code) || "";
  if (code === "UND_ERR_INVALID_ARG") return true;
  if (err && err.name === "TypeError" && /dispatcher|lookup|connect|option/i.test(err.message || "")) return true;
  return false;
}

/**
 * Build a net.connect-compatible lookup that only ever returns the validated addresses.
 * Supports both callback shapes Node uses ({all:true} -> array, else single address).
 * @param {{address:string,family:number}[]} addresses
 */
function pinnedLookup(addresses) {
  const list = addresses.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
  return function lookup(hostname, options, callback) {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    if (options && options.all) {
      process.nextTick(callback, null, list);
    } else {
      const wantFamily = options && (options.family === 6 || options.family === "IPv6") ? 6 : options && (options.family === 4 || options.family === "IPv4") ? 4 : 0;
      const pick = (wantFamily && list.find((a) => a.family === wantFamily)) || list[0];
      process.nextTick(callback, null, pick.address, pick.family);
    }
  };
}

/**
 * Read a body with a byte cap and a time budget. Never throws.
 * @returns {Promise<{ bytes: Uint8Array, bytes_read: number, truncated: boolean, timed_out: boolean }>}
 */
async function readBodyCapped(res, cap, timeoutMs) {
  const chunks = [];
  let total = 0;
  let truncated = false;
  let timedOut = false;
  const body = res && res.body;

  if (!body) {
    // Fakes may expose text()/arrayBuffer() only.
    try {
      let buf = null;
      if (res && typeof res.arrayBuffer === "function") buf = new Uint8Array(await res.arrayBuffer());
      else if (res && typeof res.text === "function") buf = new TextEncoder().encode(await res.text());
      if (buf) {
        if (buf.byteLength > cap) {
          truncated = true;
          buf = buf.subarray(0, cap);
        }
        return { bytes: buf, bytes_read: buf.byteLength, truncated, timed_out: false };
      }
    } catch {
      /* fall through */
    }
    return { bytes: new Uint8Array(0), bytes_read: 0, truncated: false, timed_out: false };
  }

  if (typeof body.getReader !== "function") {
    return { bytes: new Uint8Array(0), bytes_read: 0, truncated: false, timed_out: false };
  }

  const reader = body.getReader();
  let timer = null;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => {
      timedOut = true;
      resolve({ done: true, timeout: true });
    }, timeoutMs);
  });

  try {
    for (;;) {
      const step = await Promise.race([reader.read(), deadline]);
      if (!step || step.done) break;
      let chunk = step.value instanceof Uint8Array ? step.value : new Uint8Array(step.value || []);
      if (total + chunk.byteLength >= cap) {
        chunk = chunk.subarray(0, cap - total);
        chunks.push(chunk);
        total += chunk.byteLength;
        truncated = true;
        break;
      }
      chunks.push(chunk);
      total += chunk.byteLength;
    }
  } catch {
    /* stream error: keep what we have */
  } finally {
    clearTimeout(timer);
    try {
      reader.cancel().catch(() => {});
    } catch {
      /* ignore */
    }
  }
  if (timedOut) truncated = true;

  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return { bytes: out, bytes_read: total, truncated, timed_out: timedOut };
}

function decodeText(bytes, contentType) {
  const m = /charset=["']?([\w-]+)/i.exec(contentType || "");
  let label = m ? m[1].toLowerCase() : "utf-8";
  try {
    return new TextDecoder(label, { fatal: false }).decode(bytes);
  } catch {
    label = "utf-8";
    return new TextDecoder(label, { fatal: false }).decode(bytes);
  }
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

/**
 * Fetch a destination with SSRF protections. Never throws.
 * @param {string} urlString
 * @param {{
 *   maxHops?: number, hopTimeoutMs?: number, totalTimeoutMs?: number, bodyReadTimeoutMs?: number,
 *   maxBytes?: number, maxNonHtmlBytes?: number, allowOrigins?: Set<string>, lookup?: Function,
 *   fetchImpl?: Function, pinIp?: boolean, userAgent?: string, allowedPorts?: number[]
 * }} [opts]
 * @returns {Promise<FetchResult>}
 */
export async function safeFetch(urlString, opts = {}) {
  const maxHops = Number.isInteger(opts.maxHops) ? opts.maxHops : FETCH_LIMITS.maxHops;
  const hopTimeoutMs = opts.hopTimeoutMs ?? FETCH_LIMITS.hopTimeoutMs;
  const totalTimeoutMs = opts.totalTimeoutMs ?? FETCH_LIMITS.totalTimeoutMs;
  const bodyReadTimeoutMs = opts.bodyReadTimeoutMs ?? FETCH_LIMITS.bodyReadTimeoutMs;
  const maxBytes = opts.maxBytes ?? FETCH_LIMITS.maxBytes;
  const maxNonHtmlBytes = opts.maxNonHtmlBytes ?? FETCH_LIMITS.maxNonHtmlBytes;
  const allowOrigins = opts.allowOrigins instanceof Set ? opts.allowOrigins : new Set();
  const fetchImpl = typeof opts.fetchImpl === "function" ? opts.fetchImpl : undiciFetch;
  const pinIp = opts.pinIp !== false;
  const userAgent = opts.userAgent || FETCH_LIMITS.userAgent;

  /** @type {FetchResult} */
  const result = {
    ok: false,
    requested_url: String(urlString || "").slice(0, 2048),
    final_url: null,
    chain: [],
    status: null,
    headers: null,
    bytes_read: 0,
    truncated: false,
    is_html: false,
    body_text: null,
    error: null,
    pinned: false,
    userinfo_stripped: false,
    redirects: 0,
  };

  const fail = (code, message, hop) => {
    result.error = { code, message: redact(message), hop };
    return result;
  };

  let current;
  try {
    current = new URL(String(urlString));
  } catch {
    return fail("not_fetchable", "Not a valid absolute URL", 0);
  }
  if (stripUserinfo(current)) result.userinfo_stripped = true;
  result.requested_url = current.href.slice(0, 2048);

  // Scheme check before even queueing for a slot.
  if (current.protocol !== "http:" && current.protocol !== "https:") {
    const v = await validateTarget(current, { allowOrigins, lookup: opts.lookup, allowedPorts: opts.allowedPorts });
    result.chain.push({
      url: current.href.slice(0, 2048),
      host: current.host,
      addresses: [],
      status: null,
      location: null,
      blocked: true,
      blocked_reason: v.reason,
      downgrade: false,
      cross_domain: false,
    });
    return fail(v.code || "blocked_scheme", v.reason || "Scheme not fetched", 0);
  }

  const gotSlot = await acquire(totalTimeoutMs);
  if (!gotSlot) return fail("fetch_timeout", "Too many destination fetches in progress; try again shortly", 0);

  const totalController = new AbortController();
  const totalTimer = setTimeout(() => totalController.abort(new Error("total timeout")), totalTimeoutMs);
  /** @type {Agent[]} */
  const agents = [];
  const visited = new Set();
  let prev = null;

  try {
    for (let hop = 0; ; hop += 1) {
      const key = current.href;
      const isLoop = visited.has(key);
      visited.add(key);

      /** @type {ChainHop} */
      const entry = {
        url: current.href.slice(0, 2048),
        host: current.host,
        addresses: [],
        status: null,
        location: null,
        blocked: false,
        blocked_reason: null,
        downgrade: Boolean(prev && prev.protocol === "https:" && current.protocol === "http:"),
        cross_domain: Boolean(prev && registrable(prev.hostname) !== registrable(current.hostname)),
      };
      result.chain.push(entry);

      if (isLoop) {
        entry.blocked = true;
        entry.blocked_reason = "already visited in this redirect chain";
        return fail("redirect_loop", `Redirect loop: ${current.host}${current.pathname} was already visited`, hop);
      }

      if (totalController.signal.aborted) return fail("fetch_timeout", "Total time budget exhausted", hop);

      // ---- validate this hop before any connection ----
      const verdict = await validateTarget(current, { allowOrigins, lookup: opts.lookup, allowedPorts: opts.allowedPorts });
      if (!verdict.ok) {
        entry.blocked = true;
        entry.blocked_reason = verdict.reason;
        entry.addresses = (verdict.addresses || []).map((a) => a.address);
        return fail(verdict.code || "not_fetchable", verdict.reason || "Target refused", hop);
      }
      entry.addresses = verdict.addresses.map((a) => a.address);

      // ---- perform request (GET, manual redirects, pinned dispatcher) ----
      let res = null;
      let hopPinned = false;
      const hopSignal = AbortSignal.any([AbortSignal.timeout(hopTimeoutMs), totalController.signal]);
      const init = {
        method: "GET",
        redirect: "manual",
        credentials: "omit",
        headers: {
          "user-agent": userAgent,
          accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
          "accept-language": "en-US,en;q=0.9",
        },
        signal: hopSignal,
      };

      const doFetch = async (withAgent) => {
        if (withAgent) {
          const agent = new Agent({
            connect: { lookup: pinnedLookup(verdict.addresses), timeout: hopTimeoutMs },
            headersTimeout: hopTimeoutMs,
            bodyTimeout: bodyReadTimeoutMs,
          });
          agents.push(agent);
          return fetchImpl(current.href, { ...init, dispatcher: agent });
        }
        return fetchImpl(current.href, init);
      };

      // result.pinned reports whether every attempted hop went through the pinned
      // Agent. It is decided before the network round-trip so a timeout or
      // connection error does not read as a pinning fallback.
      const canPin = pinIp && fetchImpl === undiciFetch && verdict.addresses.length > 0;
      hopPinned = canPin;
      result.pinned = hop === 0 ? hopPinned : result.pinned && hopPinned;
      try {
        if (canPin) {
          try {
            res = await doFetch(true);
          } catch (err) {
            if (!isAgentSetupError(err)) throw err;
            hopPinned = false;
            result.pinned = false;
            res = await doFetch(false);
          }
        } else {
          res = await doFetch(false);
        }
      } catch (err) {
        const c = classifyNetworkError(err);
        return fail(c.code, c.message, hop);
      }
      const status = Number(res && res.status) || 0;
      entry.status = status;

      // ---- redirect handling ----
      if (REDIRECT_STATUSES.has(status)) {
        const location = headerGet(res.headers, "location");
        entry.location = location ? String(location).slice(0, 2048) : null;
        try {
          if (res.body && typeof res.body.cancel === "function") res.body.cancel().catch(() => {});
        } catch {
          /* ignore */
        }
        if (!location) return fail("redirect_missing_location", `HTTP ${status} without a Location header`, hop);

        let next;
        try {
          next = new URL(location, current);
        } catch {
          return fail("redirect_missing_location", `HTTP ${status} with an unusable Location header`, hop);
        }
        if (result.redirects >= maxHops) {
          return fail("redirect_limit_exceeded", `More than ${maxHops} redirects`, hop);
        }
        if (stripUserinfo(next)) result.userinfo_stripped = true;
        result.redirects += 1;
        prev = current;
        current = next;
        continue;
      }

      // ---- final response ----
      result.final_url = current.href.slice(0, 2048);
      result.status = status;
      const contentType = headerGet(res.headers, "content-type");
      const contentLengthRaw = headerGet(res.headers, "content-length");
      const contentLength = contentLengthRaw !== null && /^\d+$/.test(contentLengthRaw.trim()) ? Number(contentLengthRaw) : null;
      result.headers = {
        content_type: contentType,
        content_length: contentLength,
        content_disposition: headerGet(res.headers, "content-disposition"),
        server: headerGet(res.headers, "server"),
      };
      const mime = (contentType || "").split(";")[0].trim().toLowerCase();
      result.is_html = mime === "text/html" || mime === "application/xhtml+xml";
      const textual = result.is_html || mime.startsWith("text/") || mime === "application/json" || mime === "application/xml";
      const cap = result.is_html ? maxBytes : maxNonHtmlBytes;

      const body = await readBodyCapped(res, cap, bodyReadTimeoutMs);
      result.bytes_read = body.bytes_read;
      result.truncated = body.truncated;
      result.body_text = textual ? decodeText(body.bytes, contentType) : null;

      if (status >= 400) {
        result.ok = false;
        return fail("http_error", `Destination answered HTTP ${status}`, hop);
      }
      result.ok = true;
      return result;
    }
  } catch (err) {
    // Belt and braces: nothing above should throw, but we never propagate.
    const c = classifyNetworkError(err);
    return fail(c.code, c.message, Math.max(0, result.chain.length - 1));
  } finally {
    clearTimeout(totalTimer);
    for (const a of agents) {
      try {
        a.destroy().catch(() => {});
      } catch {
        /* ignore */
      }
    }
    release();
  }
}
