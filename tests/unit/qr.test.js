import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { Jimp, JimpMime } from "jimp";
import QRCode from "qrcode";

import { prepareImage, decodeQr, imageForGemma, readDimensions, sniffMime } from "../../server/pipeline/qr.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.resolve(__dirname, "../fixtures");
const manifest = JSON.parse(fs.readFileSync(path.join(FIXTURES, "manifest.json"), "utf8"));

const read = (file) => fs.readFileSync(path.join(FIXTURES, file));

test("every fixture with a QR decodes to the exact manifest payload", async (t) => {
  const withQr = manifest.filter((m) => m.qr_payload);
  assert.ok(withQr.length >= 8, "manifest should list the QR fixtures");
  for (const m of withQr) {
    const t0 = Date.now();
    const prep = await prepareImage(read(m.file), {});
    const t1 = Date.now();
    const r = await decodeQr(prep.buffer);
    const t2 = Date.now();
    t.diagnostic(`${m.file}: prepare ${t1 - t0} ms, decode ${t2 - t1} ms, method=${r.decode_method}, attempts=${r.attempts}`);
    assert.equal(prep.mime, "image/png");
    assert.ok(prep.width > 0 && prep.height > 0);
    assert.equal(r.found, true, `${m.file} should contain a QR`);
    assert.equal(r.payload, m.qr_payload, `${m.file} payload mismatch`);
    assert.equal(r.error, null);
    assert.ok(r.count >= 1);
    assert.deepEqual(r.all_payloads, [m.qr_payload]);
    assert.ok(typeof r.decode_method === "string");
    assert.ok(r.location && r.location.topLeftCorner, "location should be reported");
    assert.ok(r.attempts >= 1 && r.attempts <= 8);
  }
});

test("photo-degraded.jpg (800 px, blurred, q40) still decodes", async (t) => {
  const prep = await prepareImage(read("photo-degraded.jpg"), {});
  const t0 = Date.now();
  const r = await decodeQr(prep.buffer);
  t.diagnostic(`photo-degraded.jpg decode ${Date.now() - t0} ms via ${r.decode_method}`);
  assert.equal(r.found, true);
  assert.equal(r.payload, manifest.find((m) => m.file === "photo-degraded.jpg").qr_payload);
});

test("no-qr.png returns found=false with no payload", async (t) => {
  const prep = await prepareImage(read("no-qr.png"), {});
  const t0 = Date.now();
  const r = await decodeQr(prep.buffer, { timeBudgetMs: 3000 });
  t.diagnostic(`no-qr.png decode ${Date.now() - t0} ms, attempts=${r.attempts}, error=${r.error}`);
  assert.equal(r.found, false);
  assert.equal(r.payload, null);
  assert.equal(r.count, 0);
  assert.deepEqual(r.all_payloads, []);
  assert.equal(r.decode_method, null);
  assert.ok(r.error && r.error.startsWith("no_qr_found"));
  assert.ok(r.attempts >= 1);
});

test("decodeQr honours maxAttempts", async () => {
  const prep = await prepareImage(read("no-qr.png"), {});
  const r = await decodeQr(prep.buffer, { maxAttempts: 1 });
  assert.equal(r.found, false);
  assert.equal(r.attempts, 1);
  assert.equal(r.error, "no_qr_found_attempt_limit");
});

test("low-contrast QR is recovered by a later ladder rung", async (t) => {
  // Grey-on-grey QR: the native pass may fail, normalize/contrast/threshold should recover it.
  const payload = "https://example.org/low-contrast";
  const qr = await QRCode.toBuffer(payload, {
    type: "png",
    width: 360,
    margin: 3,
    color: { dark: "#6a6a6aff", light: "#8c8c8cff" },
  });
  const canvas = new Jimp({ width: 700, height: 700, color: 0x8c8c8cff });
  canvas.composite(await Jimp.read(qr), 170, 170);
  const png = await canvas.getBuffer(JimpMime.png);
  const r = await decodeQr(png, { maxAttempts: 8, timeBudgetMs: 6000 });
  t.diagnostic(`low-contrast decode via ${r.decode_method} after ${r.attempts} attempts`);
  assert.equal(r.found, true);
  assert.equal(r.payload, payload);
});

test("small QR image takes the upscale/enhance rungs when needed", async (t) => {
  const payload = "https://example.org/tiny";
  const qr = await QRCode.toBuffer(payload, { type: "png", width: 120, margin: 1 });
  const r = await decodeQr(qr, { maxAttempts: 8, timeBudgetMs: 6000 });
  t.diagnostic(`tiny decode via ${r.decode_method} after ${r.attempts} attempts`);
  assert.equal(r.found, true);
  assert.equal(r.payload, payload);
});

test("prepareImage throws image_too_large when the pixel cap is exceeded (post-decode check)", async () => {
  const img = new Jimp({ width: 300, height: 200, color: 0xffffffff });
  const png = await img.getBuffer(JimpMime.png);
  await assert.rejects(prepareImage(png, { maxPixels: 1000 }), (err) => {
    assert.equal(err.code, "image_too_large");
    return true;
  });
});

test("prepareImage rejects a 6000x5000 PNG from the header alone, before decoding", async () => {
  // Build a PNG whose IHDR claims 6000x5000 but which carries no pixel data.
  // readDimensions must trip the default 25 MP cap without allocating 120 MB.
  const img = new Jimp({ width: 8, height: 8, color: 0xffffffff });
  const png = await img.getBuffer(JimpMime.png);
  png.writeUInt32BE(6000, 16);
  png.writeUInt32BE(5000, 20);
  assert.deepEqual(readDimensions(png), { width: 6000, height: 5000 });
  const t0 = Date.now();
  await assert.rejects(prepareImage(png, {}), (err) => {
    assert.equal(err.code, "image_too_large");
    return true;
  });
  assert.ok(Date.now() - t0 < 500, "header check should be effectively instant");
});

test("prepareImage throws image_invalid for random bytes and for empty input", async () => {
  await assert.rejects(prepareImage(randomBytes(4096), {}), (err) => {
    assert.equal(err.code, "image_invalid");
    return true;
  });
  await assert.rejects(prepareImage(Buffer.alloc(0), {}), (err) => {
    assert.equal(err.code, "image_invalid");
    return true;
  });
  // Valid PNG signature and a plausible 64x64 IHDR, but the rest is garbage.
  const header = await new Jimp({ width: 64, height: 64, color: 0xffffffff }).getBuffer(JimpMime.png);
  const fake = Buffer.concat([header.subarray(0, 33), randomBytes(600)]);
  assert.deepEqual(readDimensions(fake), { width: 64, height: 64 });
  await assert.rejects(prepareImage(fake, {}), (err) => {
    assert.equal(err.code, "image_invalid");
    return true;
  });
  // PNG signature followed by random bytes: header is implausible, so still image_invalid.
  const junk = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(8), Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), randomBytes(200)]);
  await assert.rejects(prepareImage(junk, {}), (err) => {
    assert.equal(err.code, "image_invalid");
    return true;
  });
});

test("prepareImage rejects formats outside allowedMimes", async () => {
  const png = await new Jimp({ width: 8, height: 8, color: 0xffffffff }).getBuffer(JimpMime.png);
  await assert.rejects(prepareImage(png, { allowedMimes: ["image/jpeg"] }), (err) => {
    assert.equal(err.code, "image_invalid");
    return true;
  });
});

test("prepareImage re-encodes to PNG and reports dimensions", async () => {
  const prep = await prepareImage(read("photo-degraded.jpg"), {});
  assert.equal(prep.mime, "image/png");
  assert.equal(sniffMime(prep.buffer), "image/png");
  assert.equal(prep.width, 800);
  assert.equal(prep.bytes, prep.buffer.length);
});

test("readDimensions parses PNG and JPEG headers", () => {
  assert.deepEqual(readDimensions(read("legit-event.png")), { width: 1200, height: 1600 });
  const jpg = readDimensions(read("photo-degraded.jpg"));
  assert.equal(jpg.width, 800);
  assert.ok(jpg.height > 1000);
});

test("imageForGemma downsizes to maxEdge and returns base64 JPEG", async () => {
  const prep = await prepareImage(read("legit-event.png"), {});
  const g = await imageForGemma(prep.buffer, { maxEdge: 640 });
  assert.equal(g.mimeType, "image/jpeg");
  assert.ok(Math.max(g.width, g.height) <= 640);
  assert.ok(g.bytes > 1000);
  const decoded = Buffer.from(g.data, "base64");
  assert.equal(decoded.length, g.bytes);
  assert.equal(sniffMime(decoded), "image/jpeg");
});
