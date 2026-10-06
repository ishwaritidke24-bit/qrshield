// Hostname and IP policy for the SSRF-safe fetcher.
//
// Everything here is deterministic. The fetcher calls validateTarget() for the
// first URL and again for EVERY redirect hop before any socket is opened.
// Policy order: scheme -> allowlist short-circuit -> port -> hostname -> DNS/IP.

import net from "node:net";
import dns from "node:dns/promises";
import { FETCH_LIMITS } from "./contracts.js";

/**
 * @typedef {{ address: string, family: number }} ResolvedAddress
 * @typedef {{ blocked: boolean, reason: string | null }} BlockVerdict
 */

/** Special-use / non-public ranges. Each entry gets its own BlockList so we can name the reason. */
const RANGES = Object.freeze([
  // IPv4
  ["0.0.0.0", 8, "ipv4", "this_network_0/8"],
  ["10.0.0.0", 8, "ipv4", "private_10/8"],
  ["100.64.0.0", 10, "ipv4", "cgnat_100.64/10"],
  ["127.0.0.0", 8, "ipv4", "loopback_127/8"],
  ["169.254.0.0", 16, "ipv4", "link_local_169.254/16"],
  ["172.16.0.0", 12, "ipv4", "private_172.16/12"],
  ["192.0.0.0", 24, "ipv4", "ietf_protocol_192.0.0/24"],
  ["192.0.2.0", 24, "ipv4", "documentation_192.0.2/24"],
  ["192.88.99.0", 24, "ipv4", "6to4_relay_192.88.99/24"],
  ["192.168.0.0", 16, "ipv4", "private_192.168/16"],
  ["198.18.0.0", 15, "ipv4", "benchmark_198.18/15"],
  ["198.51.100.0", 24, "ipv4", "documentation_198.51.100/24"],
  ["203.0.113.0", 24, "ipv4", "documentation_203.0.113/24"],
  ["224.0.0.0", 4, "ipv4", "multicast_224/4"],
  ["240.0.0.0", 4, "ipv4", "reserved_240/4_and_broadcast"],
  // IPv6
  ["::", 128, "ipv6", "unspecified_::"],
  ["::1", 128, "ipv6", "loopback_::1"],
  ["::ffff:0:0", 96, "ipv6", "ipv4_mapped_::ffff/96"],
  ["64:ff9b::", 96, "ipv6", "nat64_64:ff9b::/96"],
  ["100::", 64, "ipv6", "discard_100::/64"],
  ["2001::", 32, "ipv6", "teredo_2001::/32"],
  ["2001:db8::", 32, "ipv6", "documentation_2001:db8::/32"],
  ["2002::", 16, "ipv6", "6to4_2002::/16"],
  ["fc00::", 7, "ipv6", "unique_local_fc00::/7"],
  ["fe80::", 10, "ipv6", "link_local_fe80::/10"],
  ["fec0::", 10, "ipv6", "site_local_fec0::/10"],
  ["ff00::", 8, "ipv6", "multicast_ff00::/8"],
]);

const BLOCK_LISTS = RANGES.map(([addr, prefix, family, reason]) => {
  const list = new net.BlockList();
  list.addSubnet(addr, prefix, family);
  return { list, family, reason };
});

/** Suffixes (and exact names) that are never public. */
const BLOCKED_SUFFIXES = Object.freeze([
  "localhost",
  "localdomain",
  "local",
  "internal",
  "arpa",
  "home",
  "lan",
  "corp",
  "intranet",
  "onion",
  "invalid",
  "test",
]);

const V4_MAPPED_RE = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

/**
 * Normalize an IP literal: strip brackets and zone id, lowercase.
 * @param {string} ip
 */
function normalizeIp(ip) {
  let s = String(ip || "").trim().toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  return s;
}

/**
 * Decide whether a single IP address may be contacted.
 * Unparseable input is treated as blocked.
 * @param {string} ip
 * @returns {BlockVerdict}
 */
export function isBlockedAddress(ip) {
  const s = normalizeIp(ip);
  const version = net.isIP(s);
  if (version === 0) return { blocked: true, reason: "invalid_ip_literal" };

  // An IPv4-mapped IPv6 address is judged by its embedded IPv4 address first so
  // the reason names the real range (e.g. loopback), then by the v6 lists.
  const mapped = version === 6 ? V4_MAPPED_RE.exec(s) : null;
  if (mapped && net.isIP(mapped[1]) === 4) {
    const inner = isBlockedAddress(mapped[1]);
    if (inner.blocked) return { blocked: true, reason: `ipv4_mapped:${inner.reason}` };
  }

  const family = version === 6 ? "ipv6" : "ipv4";
  for (const entry of BLOCK_LISTS) {
    // BlockList.check(v6, 'ipv6') also matches v4-mapped forms against v4 subnets.
    if (entry.family !== family && !(entry.family === "ipv4" && family === "ipv6")) continue;
    let hit = false;
    try {
      hit = entry.list.check(s, family);
    } catch {
      hit = false;
    }
    if (hit) return { blocked: true, reason: entry.reason };
  }
  return { blocked: false, reason: null };
}

/**
 * Hostname policy that needs no DNS: localhost-style names, internal suffixes,
 * single-label names, empty names, and blocked IP literals.
 * @param {string} hostname
 * @returns {BlockVerdict}
 */
export function isBlockedHostname(hostname) {
  let h = String(hostname || "").trim().toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  while (h.endsWith(".")) h = h.slice(0, -1);
  if (!h) return { blocked: true, reason: "empty_hostname" };

  const ipVersion = net.isIP(normalizeIp(h));
  if (ipVersion !== 0) {
    const v = isBlockedAddress(h);
    return v.blocked ? { blocked: true, reason: `ip_literal:${v.reason}` } : { blocked: false, reason: null };
  }

  // Looks numeric (decimal / octal / dotted-hex forms the URL parser did not
  // normalize) but is not a valid IP: refuse rather than guess.
  const labels = h.split(".");
  if (labels.every((p) => /^(0x[0-9a-f]*|\d+)$/i.test(p))) {
    return { blocked: true, reason: "ambiguous_numeric_hostname" };
  }

  if (labels.length < 2) return { blocked: true, reason: "single_label_hostname" };
  if (labels.some((l) => l.length === 0)) return { blocked: true, reason: "empty_label" };

  const tld = labels[labels.length - 1];
  if (BLOCKED_SUFFIXES.includes(tld)) return { blocked: true, reason: `blocked_suffix_.${tld}` };

  return { blocked: false, reason: null };
}

/**
 * Default DNS lookup: all A/AAAA records, in resolver order.
 * @param {string} hostname
 * @returns {Promise<ResolvedAddress[]>}
 */
async function defaultLookup(hostname) {
  const res = await dns.lookup(hostname, { all: true, verbatim: true });
  return Array.isArray(res) ? res : [res];
}

/**
 * Resolve a hostname and refuse if ANY resolved address is non-public.
 * An IP literal is accepted without DNS.
 * @param {string} hostname
 * @param {{ lookup?: (hostname: string) => Promise<ResolvedAddress[]> }} [opts]
 * @returns {Promise<{ ok: boolean, addresses: ResolvedAddress[], reason: string | null, code: string | null }>}
 */
export async function resolveAndValidate(hostname, { lookup } = {}) {
  const h = normalizeIp(hostname);
  const literal = net.isIP(h);
  let addresses = [];

  if (literal !== 0) {
    addresses = [{ address: h, family: literal }];
  } else {
    const fn = typeof lookup === "function" ? lookup : defaultLookup;
    try {
      const res = await fn(hostname);
      addresses = (Array.isArray(res) ? res : res ? [res] : [])
        .filter((a) => a && typeof a.address === "string")
        .map((a) => ({ address: normalizeIp(a.address), family: Number(a.family) || net.isIP(a.address) }));
    } catch (err) {
      const code = err && (err.code === "ENOTFOUND" || err.code === "ENODATA") ? "dns_nxdomain" : "dns_error";
      return {
        ok: false,
        addresses: [],
        reason: code === "dns_nxdomain" ? `Hostname ${hostname} does not resolve` : `DNS lookup failed (${(err && err.code) || "error"})`,
        code,
      };
    }
  }

  if (addresses.length === 0) {
    return { ok: false, addresses: [], reason: `Hostname ${hostname} returned no addresses`, code: "dns_nxdomain" };
  }

  for (const a of addresses) {
    const v = isBlockedAddress(a.address);
    if (v.blocked) {
      return {
        ok: false,
        addresses,
        reason: `Hostname ${hostname} resolves to ${a.address} (${v.reason})`,
        code: "blocked_private_ip",
      };
    }
  }
  return { ok: true, addresses, reason: null, code: null };
}

/**
 * Full gate for one URL hop.
 * @param {URL} url
 * @param {{ allowOrigins?: Set<string>, lookup?: Function, allowedPorts?: number[] }} [opts]
 * @returns {Promise<{ ok: boolean, code: string | null, reason: string | null, addresses: ResolvedAddress[] }>}
 */
export async function validateTarget(url, { allowOrigins, lookup, allowedPorts } = {}) {
  if (!(url instanceof URL)) {
    return { ok: false, code: "not_fetchable", reason: "Target is not a URL object", addresses: [] };
  }

  // 1. scheme gate
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return {
      ok: false,
      code: "blocked_scheme",
      reason: `Scheme ${url.protocol.replace(/:$/, "")} is never fetched`,
      addresses: [],
    };
  }

  // 2. allowlist short-circuit (exact origin; dev/test fixtures only)
  if (allowOrigins instanceof Set && allowOrigins.size > 0 && allowOrigins.has(url.origin)) {
    const h = normalizeIp(url.hostname);
    if (net.isIP(h)) {
      return { ok: true, code: null, reason: "allowlisted_origin", addresses: [{ address: h, family: net.isIP(h) }] };
    }
    const fn = typeof lookup === "function" ? lookup : defaultLookup;
    try {
      const res = await fn(url.hostname);
      const addresses = (Array.isArray(res) ? res : [])
        .filter((a) => a && a.address)
        .map((a) => ({ address: normalizeIp(a.address), family: Number(a.family) || net.isIP(a.address) }));
      return { ok: true, code: null, reason: "allowlisted_origin", addresses };
    } catch (err) {
      return {
        ok: false,
        code: err && err.code === "ENOTFOUND" ? "dns_nxdomain" : "dns_error",
        reason: `Allowlisted origin ${url.origin} did not resolve`,
        addresses: [],
      };
    }
  }

  // 3. hostname gate
  const hv = isBlockedHostname(url.hostname);
  if (hv.blocked) {
    const isIpLiteral = String(hv.reason).startsWith("ip_literal:");
    return {
      ok: false,
      code: isIpLiteral ? "blocked_private_ip" : "blocked_hostname",
      reason: isIpLiteral
        ? `Host ${url.hostname} is a non-public address (${hv.reason.slice("ip_literal:".length)})`
        : `Hostname ${url.hostname} is not a public name (${hv.reason})`,
      addresses: [],
    };
  }

  // 4. port gate (after the hostname gate so loopback/private literals report as blocked targets)
  const ports = Array.isArray(allowedPorts) && allowedPorts.length ? allowedPorts : FETCH_LIMITS.allowedPorts;
  if (url.port !== "") {
    const p = Number(url.port);
    if (!ports.includes(p)) {
      return { ok: false, code: "non_standard_port", reason: `Port ${p} is outside the allowed set (${ports.join(", ")})`, addresses: [] };
    }
  }

  // 5. DNS / IP gate
  const rv = await resolveAndValidate(url.hostname, { lookup });
  if (!rv.ok) return { ok: false, code: rv.code, reason: rv.reason, addresses: rv.addresses };
  return { ok: true, code: null, reason: null, addresses: rv.addresses };
}
