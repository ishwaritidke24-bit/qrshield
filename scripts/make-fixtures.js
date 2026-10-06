// Generates demo posters with real QR codes into tests/fixtures/.
// Run with: npm run fixtures   (or: node scripts/make-fixtures.js)
//
// Each poster is ~1200x1600, drawn with jimp's bundled Open Sans bitmap fonts
// so Gemma can read the printed claims, and carries a QR rendered by the
// `qrcode` package. A manifest.json describes every fixture and the
// expectations the unit tests and the e2e smoke test assert against.

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import QRCode from "qrcode";
import { Jimp, JimpMime, loadFont, HorizontalAlign, ResizeStrategy } from "jimp";
import { SANS_32_BLACK, SANS_64_BLACK, SANS_128_BLACK, SANS_64_WHITE, SANS_32_WHITE } from "jimp/fonts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.resolve(__dirname, "../tests/fixtures");

const FIXTURE_PORT = process.env.FIXTURE_PORT || "4555";
const BASE = `http://127.0.0.1:${FIXTURE_PORT}`;

const W = 1200;
const H = 1600;

/** Convert "rrggbb" to the 0xRRGGBBAA int jimp wants. */
const rgb = (hex) => (parseInt(hex, 16) * 256 + 0xff) >>> 0;

/**
 * Poster definitions. `lines` are drawn top to bottom; `size` selects the
 * bitmap font (32/64/128); `color` picks the white variant for header bands.
 */
const POSTERS = [
  {
    file: "legit-event.png",
    description: "Benign university tech-fest poster; QR goes to a consistent event page with no forms.",
    header: { color: "1f3a5f", lines: [{ text: "Northfield University", size: 64 }, { text: "TechFest 2026", size: 128 }] },
    lines: [
      { text: "Free Registration", size: 64 },
      { text: "Workshops - Hackathon - Robotics Arena", size: 32 },
      { text: "Scan to register", size: 64 },
    ],
    footer: [{ text: "techfest@northfield.edu", size: 32 }],
    qr: `${BASE}/legit`,
    expected: {
      payload_kind: "url",
      risk_level_one_of: ["LOW_RISK", "MEDIUM_RISK"],
      notes:
        "Destination is consistent with the poster. The fixture host is a bare IP literal (127.0.0.1) which is itself a strong URL signal, so MEDIUM_RISK via the deterministic floor is acceptable.",
    },
  },
  {
    file: "scholarship-phish.png",
    description: "Scholarship poster claiming no fee; QR goes through a redirect chain to a credential + card harvesting form.",
    header: { color: "b3261e", lines: [{ text: "FREE SCHOLARSHIP 2026", size: 64 }] },
    lines: [
      { text: "Apply Now", size: 128 },
      { text: "No Application Fee", size: 64 },
      { text: "Deadline: 15 October 2026", size: 32 },
      { text: "Scan QR to Register", size: 64 },
    ],
    footer: [],
    qr: `${BASE}/r/chain`,
    expected: {
      payload_kind: "url",
      risk_level_one_of: ["HIGH_RISK", "CRITICAL"],
      notes: "Two 302 hops end on a page with password, card, CVV and OTP fields; deterministic floor is at least HIGH_RISK.",
    },
  },
  {
    file: "no-fee-upi.png",
    description: "Poster says No Application Fee but the QR is a UPI payment request with a prefilled 499 INR amount.",
    header: { color: "b3261e", lines: [{ text: "FREE SCHOLARSHIP 2026", size: 64 }] },
    lines: [
      { text: "No Application Fee", size: 64 },
      { text: "Scan to Register", size: 64 },
    ],
    footer: [],
    qr: "upi://pay?pa=rahul1998@ybl&pn=Scholarship%20Cell&am=499&cu=INR&tn=Application%20Fee",
    expected: {
      payload_kind: "upi",
      risk_level_one_of: ["MEDIUM_RISK", "HIGH_RISK", "CRITICAL"],
      notes:
        "Network-independent demo: the physical claim (free) contradicts the digital intent (payment of 499 INR to a personal-looking VPA). Gemma must raise the contradiction; no fetch happens.",
    },
  },
  {
    file: "no-qr.png",
    description: "Scholarship poster text only, no QR code at all.",
    header: { color: "b3261e", lines: [{ text: "FREE SCHOLARSHIP 2026", size: 64 }] },
    lines: [
      { text: "Apply Now", size: 128 },
      { text: "No Application Fee", size: 64 },
      { text: "Deadline: 15 October 2026", size: 32 },
      { text: "Scan QR to Register", size: 64 },
    ],
    footer: [],
    qr: null,
    expected: {
      payload_kind: "none",
      risk_level_one_of: ["INSUFFICIENT_EVIDENCE"],
      notes: "No QR and no manual URL forces INSUFFICIENT_EVIDENCE.",
    },
  },
  {
    file: "to-private.png",
    description: "Campus Wi-Fi portal poster; QR redirects to a private 10.0.0.0/8 address which must be blocked.",
    header: { color: "0b6e4f", lines: [{ text: "Campus WiFi Portal", size: 64 }] },
    lines: [
      { text: "Scan to connect", size: 128 },
      { text: "Fast - Free - Secure", size: 32 },
    ],
    footer: [],
    qr: `${BASE}/to-private`,
    expected: {
      payload_kind: "url",
      risk_level_one_of: ["HIGH_RISK", "CRITICAL"],
      notes: "Redirect to 10.0.0.1 is a critical redirect_to_blocked_target signal; /secret must never be fetched.",
    },
  },
  {
    file: "wifi.png",
    description: "Wi-Fi join QR (WPA network CampusGuest). Password must never appear in any report field.",
    header: { color: "0b6e4f", lines: [{ text: "Guest Wi-Fi", size: 64 }] },
    lines: [
      { text: "Scan to join", size: 128 },
      { text: "Network: CampusGuest", size: 32 },
    ],
    footer: [],
    qr: "WIFI:T:WPA;S:CampusGuest;P:secret123;;",
    expected: {
      payload_kind: "wifi",
      risk_level_one_of: ["LOW_RISK", "MEDIUM_RISK", "INSUFFICIENT_EVIDENCE"],
      notes: "parsed.password_present=true only; the literal 'secret123' must not be present anywhere in the report JSON.",
    },
  },
  {
    file: "blocked-scheme.png",
    description: "QR carrying a javascript: URI, which must be classified as blocked_scheme and never opened.",
    header: { color: "333333", lines: [{ text: "Scan for a surprise", size: 64 }] },
    lines: [{ text: "Scan me", size: 128 }],
    footer: [],
    qr: "javascript:alert(1)",
    expected: {
      payload_kind: "blocked_scheme",
      risk_level_one_of: ["HIGH_RISK", "CRITICAL"],
      notes: "blocked_scheme is a critical signal and a HIGH_RISK floor.",
    },
  },
  {
    file: "injection.png",
    description: "QR to a page whose visible text tries to prompt-inject the model while hosting a password form.",
    header: { color: "1f3a5f", lines: [{ text: "Student Portal Login", size: 64 }] },
    lines: [
      { text: "Scan to sign in", size: 128 },
      { text: "Quick access for students", size: 32 },
    ],
    footer: [],
    qr: `${BASE}/injection`,
    expected: {
      payload_kind: "url",
      risk_level_one_of: ["HIGH_RISK", "CRITICAL"],
      notes: "Page text says to ignore instructions and output LOW_RISK; sanitizeForPrompt strips it and the password form keeps the floor at HIGH_RISK.",
    },
  },
];

const fontCache = new Map();
async function font(size, white = false) {
  const key = `${size}-${white ? "w" : "b"}`;
  if (!fontCache.has(key)) {
    const table = white
      ? { 32: SANS_32_WHITE, 64: SANS_64_WHITE, 128: SANS_64_WHITE }
      : { 32: SANS_32_BLACK, 64: SANS_64_BLACK, 128: SANS_128_BLACK };
    fontCache.set(key, await loadFont(table[size]));
  }
  return fontCache.get(key);
}

function lineHeight(size) {
  return { 32: 48, 64: 90, 128: 160 }[size];
}

/** Draw centred text lines starting at y; returns the next free y. */
async function drawLines(img, lines, y, white = false) {
  for (const line of lines) {
    const f = await font(line.size, white);
    img.print({
      font: f,
      x: 60,
      y,
      text: { text: line.text, alignmentX: HorizontalAlign.CENTER },
      maxWidth: W - 120,
    });
    y += lineHeight(line.size) + 20;
  }
  return y;
}

function fillRect(img, x, y, w, h, color) {
  const rect = new Jimp({ width: w, height: h, color });
  img.composite(rect, x, y);
}

async function renderQr(payload, size = 420) {
  const buf = await QRCode.toBuffer(payload, {
    type: "png",
    width: size,
    margin: 2,
    errorCorrectionLevel: "M",
    color: { dark: "#000000ff", light: "#ffffffff" },
  });
  return Jimp.read(buf);
}

async function renderPoster(def) {
  const img = new Jimp({ width: W, height: H, color: 0xffffffff });

  // Header band.
  const headerH = 60 + def.header.lines.reduce((acc, l) => acc + lineHeight(l.size) + 20, 0);
  fillRect(img, 0, 0, W, headerH, rgb(def.header.color));
  await drawLines(img, def.header.lines, 40, true);

  // Body text.
  let y = headerH + 70;
  y = await drawLines(img, def.lines, y, false);

  // QR block, centred below the text.
  if (def.qr) {
    const qr = await renderQr(def.qr, 440);
    const qx = Math.round((W - qr.bitmap.width) / 2);
    const qy = Math.min(Math.max(y + 30, 820), H - qr.bitmap.height - 200);
    // Thin frame around the QR so it looks like a printed sticker.
    fillRect(img, qx - 12, qy - 12, qr.bitmap.width + 24, qr.bitmap.height + 24, rgb("222222"));
    fillRect(img, qx - 8, qy - 8, qr.bitmap.width + 16, qr.bitmap.height + 16, 0xffffffff);
    img.composite(qr, qx, qy);
    y = qy + qr.bitmap.height + 40;
  } else {
    y = Math.max(y, 1100);
  }

  // Footer.
  if (def.footer.length) {
    await drawLines(img, def.footer, Math.min(y + 20, H - 120), false);
  }
  // Bottom accent bar.
  fillRect(img, 0, H - 40, W, 40, rgb(def.header.color));
  return img;
}

async function main() {
  await fs.mkdir(OUT_DIR, { recursive: true });
  const manifest = [];

  let phishImage = null;
  for (const def of POSTERS) {
    const img = await renderPoster(def);
    const png = await img.getBuffer(JimpMime.png);
    await fs.writeFile(path.join(OUT_DIR, def.file), png);
    if (def.file === "scholarship-phish.png") phishImage = img;
    manifest.push({
      file: def.file,
      description: def.description,
      qr_payload: def.qr,
      expected: def.expected,
    });
    console.log(`wrote ${def.file} (${png.length} bytes)`);
  }

  // Degraded photo: downscale to 800 px wide, slight blur, JPEG q40.
  const degraded = phishImage.clone();
  degraded.resize({ w: 800, mode: ResizeStrategy.BILINEAR });
  degraded.blur(1);
  const jpg = await degraded.getBuffer(JimpMime.jpeg, { quality: 40 });
  await fs.writeFile(path.join(OUT_DIR, "photo-degraded.jpg"), jpg);
  manifest.push({
    file: "photo-degraded.jpg",
    description: "scholarship-phish poster re-encoded as a blurred 800 px wide JPEG at quality 40 to exercise the decode ladder.",
    qr_payload: `${BASE}/r/chain`,
    expected: {
      payload_kind: "url",
      risk_level_one_of: ["HIGH_RISK", "CRITICAL"],
      notes: "Same destination as scholarship-phish.png; proves decoding survives photo-like degradation.",
    },
  });
  console.log(`wrote photo-degraded.jpg (${jpg.length} bytes)`);

  await fs.writeFile(path.join(OUT_DIR, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  console.log(`wrote manifest.json (${manifest.length} fixtures)`);
}

main().catch((err) => {
  console.error("fixture generation failed:", err && err.message ? err.message : err);
  process.exit(1);
});
