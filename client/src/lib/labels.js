// Client-side view of the shared enums. Imported straight from the server
// contract so the UI can never drift from the single source of truth.
// contracts.js is dependency-free, so bundling it into the client is safe.
import {
  RISK_LABELS,
  SIGNAL_LABELS,
  STAGE_STATUS,
} from "../../../server/pipeline/contracts.js";

export { RISK_LABELS, SIGNAL_LABELS, STAGE_STATUS };

/** @type {Record<string, string>} CSS class suffix per risk level */
export const RISK_TONE = Object.freeze({
  LOW_RISK: "low",
  MEDIUM_RISK: "medium",
  HIGH_RISK: "high",
  CRITICAL: "critical",
  INSUFFICIENT_EVIDENCE: "insufficient",
});

/** @type {Record<string, string>} CSS class suffix per signal strength */
export const STRENGTH_TONE = Object.freeze({
  neutral: "info",
  weak: "weak",
  medium: "medium",
  strong: "strong",
  critical: "critical",
});

export const RISK_SOURCE_LABELS = Object.freeze({
  gemma: "gemma",
  floor_override: "floor override",
  deterministic_fallback: "deterministic fallback",
  forced_insufficient: "forced insufficient",
});

export const STAGE_ORDER = Object.freeze([
  ["intake", "Intake"],
  ["qr", "QR decode"],
  ["payload", "Payload"],
  ["url", "URL analysis"],
  ["fetch", "Destination fetch"],
  ["gemma", "Gemma 4"],
]);

export const STAGE_ICONS = Object.freeze({
  ok: "✓",
  degraded: "△",
  skipped: "–",
  failed: "✗",
  blocked: "⛔",
});

/** Human label for a risk level, falling back to the raw value. */
export function riskLabel(level) {
  return RISK_LABELS[level] || level || "UNKNOWN";
}

/** Human label for a signal strength, falling back to the raw value. */
export function strengthLabel(strength) {
  return SIGNAL_LABELS[strength] || strength || "Info";
}

/** Format milliseconds compactly. */
export function fmtMs(ms) {
  if (ms === null || ms === undefined) return "";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

/** Format a byte count compactly. */
export function fmtBytes(n) {
  if (n === null || n === undefined) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}
