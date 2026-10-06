// QR stage: image intake (pixel cap, re-encode, metadata strip), a pure-JS
// decode ladder (jimp + jsQR) and the downscaled JPEG that is sent to Gemma.
//
// Nothing in this file touches the network. Every function receives a Buffer
// and returns plain data; errors from prepareImage carry a `.code` so the
// route can map them to HTTP 400.

import { Jimp, JimpMime, ResizeStrategy } from "jimp";
import jsQR from "jsqr";
import { IMAGE_LIMITS } from "./contracts.js";

/**
 * @typedef {object} PreparedImage
 * @property {Buffer} buffer       PNG re-encoded, metadata stripped
 * @property {number} width
 * @property {number} height
 * @property {number} bytes        size of the PNG buffer
 * @property {'image/png'} mime
 */

/**
 * @typedef {object} DecodeResult
 * @property {boolean} found
 * @property {number} count               distinct payloads seen
 * @property {string|null} payload        chosen payload (top-left-most when several)
 * @property {string[]} all_payloads
 * @property {string|null} decode_method  ladder rung that produced the payload
 * @property {object|null} location       corner points in original-image pixels
 * @property {string|null} error
 * @property {number} attempts            jsQR invocations performed
 */

function codedError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

/* ------------------------------------------------------------------ */
/* Cheap header sniffing so the pixel cap is enforced before a full    */
/* decode allocates width*height*4 bytes.                              */
/* ------------------------------------------------------------------ */

/**
 * Detect the container format from magic bytes.
 * @param {Buffer} buf
 * @returns {'image/png'|'image/jpeg'|'image/webp'|'image/gif'|'image/bmp'|'image/tiff'|null}
 */
export function sniffMime(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return "image/png";
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "image/jpeg";
  if (buf.toString("ascii", 0, 4) === "RIFF" && buf.toString("ascii", 8, 12) === "WEBP") return "image/webp";
  if (buf.toString("ascii", 0, 3) === "GIF") return "image/gif";
  if (buf[0] === 0x42 && buf[1] === 0x4d) return "image/bmp";
  if ((buf[0] === 0x49 && buf[1] === 0x49 && buf[2] === 0x2a) || (buf[0] === 0x4d && buf[1] === 0x4d && buf[3] === 0x2a)) {
    return "image/tiff";
  }
  return null;
}

/**
 * Read pixel dimensions from the header without decoding pixel data.
 * Returns null when the format is unknown or the header is malformed.
 * @param {Buffer} buf
 * @returns {{width:number,height:number}|null}
 */
export function readDimensions(buf) {
  const mime = sniffMime(buf);
  try {
    if (mime === "image/png" && buf.length >= 24) {
      return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
    }
    if (mime === "image/jpeg") {
      let i = 2;
      while (i + 9 < buf.length) {
        if (buf[i] !== 0xff) {
          i += 1;
          continue;
        }
        const marker = buf[i + 1];
        if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
          i += 2;
          continue;
        }
        const len = buf.readUInt16BE(i + 2);
        const isSof =
          marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
        if (isSof) {
          return { height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
        }
        if (marker === 0xd9 || marker === 0xda) break;
        i += 2 + len;
      }
      return null;
    }
    if (mime === "image/webp" && buf.length >= 30) {
      const chunk = buf.toString("ascii", 12, 16);
      if (chunk === "VP8 ") {
        return { width: buf.readUInt16LE(26) & 0x3fff, height: buf.readUInt16LE(28) & 0x3fff };
      }
      if (chunk === "VP8L") {
        const b0 = buf[21], b1 = buf[22], b2 = buf[23], b3 = buf[24];
        return { width: 1 + (((b1 & 0x3f) << 8) | b0), height: 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6)) };
      }
      if (chunk === "VP8X") {
        return { width: 1 + buf.readUIntLE(24, 3), height: 1 + buf.readUIntLE(27, 3) };
      }
    }
    if (mime === "image/gif" && buf.length >= 10) {
      return { width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) };
    }
    if (mime === "image/bmp" && buf.length >= 26) {
      return { width: Math.abs(buf.readInt32LE(18)), height: Math.abs(buf.readInt32LE(22)) };
    }
  } catch {
    return null;
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* prepareImage                                                        */
/* ------------------------------------------------------------------ */

/**
 * Validate, decode and re-encode an uploaded image as PNG. Enforces the pixel
 * cap from the header before the full decode when the format allows it, and
 * again after decoding as a backstop.
 *
 * @param {Buffer} buffer
 * @param {{maxPixels?:number, allowedMimes?:string[]}} [opts]
 * @returns {Promise<PreparedImage>}
 * @throws {Error & {code:'image_invalid'|'image_too_large'}}
 */
export async function prepareImage(buffer, opts = {}) {
  const maxPixels = opts.maxPixels ?? IMAGE_LIMITS.maxPixels;
  const allowedMimes = opts.allowedMimes ?? IMAGE_LIMITS.allowedMimes;

  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw codedError("image_invalid", "Empty or missing image data");
  }
  const sniffed = sniffMime(buffer);
  if (!sniffed) {
    throw codedError("image_invalid", "Data does not look like a supported image");
  }
  if (allowedMimes && !allowedMimes.includes(sniffed)) {
    throw codedError("image_invalid", `Image format ${sniffed} is not accepted`);
  }
  const dims = readDimensions(buffer);
  if (dims && (dims.width === 0 || dims.height === 0 || dims.width > 65535 || dims.height > 65535)) {
    throw codedError("image_invalid", `Image header declares implausible dimensions ${dims.width}x${dims.height}`);
  }
  if (dims && dims.width * dims.height > maxPixels) {
    throw codedError(
      "image_too_large",
      `Image is ${dims.width}x${dims.height} pixels; the limit is ${maxPixels} pixels`,
    );
  }

  let image;
  try {
    image = await Jimp.read(buffer);
  } catch (err) {
    const msg = err && err.message ? String(err.message).slice(0, 120) : "decode failed";
    throw codedError("image_invalid", `Image could not be decoded (${msg})`);
  }
  const { width, height } = image.bitmap;
  if (!width || !height) {
    throw codedError("image_invalid", "Image has no pixels");
  }
  if (width * height > maxPixels) {
    throw codedError("image_too_large", `Image is ${width}x${height} pixels; the limit is ${maxPixels} pixels`);
  }
  // Re-encoding through jimp writes only IHDR/IDAT/IEND: EXIF, ICC, text chunks are dropped.
  const png = await image.getBuffer(JimpMime.png);
  return { buffer: png, width, height, bytes: png.length, mime: "image/png" };
}

/* ------------------------------------------------------------------ */
/* decodeQr                                                            */
/* ------------------------------------------------------------------ */

/** Wrap jimp RGBA bitmap data so jsQR accepts it without copying. */
function toClamped(bitmap) {
  const d = bitmap.data;
  return new Uint8ClampedArray(d.buffer, d.byteOffset, d.length);
}

/**
 * Run jsQR once on a jimp image. Returns the raw jsQR result or null.
 * @param {import('jimp').Jimp} img
 */
function tryJsQr(img) {
  const { width, height } = img.bitmap;
  if (width < 21 || height < 21) return null;
  try {
    return jsQR(toClamped(img.bitmap), width, height, { inversionAttempts: "attemptBoth" });
  } catch {
    return null;
  }
}

function longestEdge(img) {
  return Math.max(img.bitmap.width, img.bitmap.height);
}

/**
 * Translate jsQR corner points (in working-image pixels) back to the
 * original image coordinate system.
 */
function mapLocation(loc, scale, offsetX, offsetY) {
  if (!loc) return null;
  const pt = (p) => (p ? { x: Math.round(p.x * scale + offsetX), y: Math.round(p.y * scale + offsetY) } : null);
  return {
    topLeftCorner: pt(loc.topLeftCorner),
    topRightCorner: pt(loc.topRightCorner),
    bottomLeftCorner: pt(loc.bottomLeftCorner),
    bottomRightCorner: pt(loc.bottomRightCorner),
  };
}

/**
 * Decode a QR code from a PNG buffer using a fixed ladder of image
 * transforms. Rungs are attempted in order until a payload is found, within
 * `maxAttempts` jsQR calls and `timeBudgetMs` wall-clock time.
 *
 * Ladder: native_grey -> resize_1200 -> upscale_2x -> normalize_contrast ->
 * threshold -> tile_* (2x2 quadrants + centred crop).
 *
 * @param {Buffer} pngBuffer
 * @param {{maxAttempts?:number, timeBudgetMs?:number}} [opts]
 * @returns {Promise<DecodeResult>}
 */
export async function decodeQr(pngBuffer, { maxAttempts = 8, timeBudgetMs = 3000 } = {}) {
  const started = Date.now();
  /** @type {DecodeResult} */
  const result = {
    found: false,
    count: 0,
    payload: null,
    all_payloads: [],
    decode_method: null,
    location: null,
    error: null,
    attempts: 0,
  };

  let base;
  try {
    base = await Jimp.read(pngBuffer);
  } catch (err) {
    result.error = "image_undecodable";
    return result;
  }
  const origW = base.bitmap.width;
  const origH = base.bitmap.height;
  base.greyscale();

  const budgetLeft = () => Date.now() - started < timeBudgetMs && result.attempts < maxAttempts;

  /** @type {{payload:string, method:string, location:object|null, x:number, y:number}[]} */
  const hits = [];

  const attempt = (img, method, scale = 1, offsetX = 0, offsetY = 0) => {
    if (!budgetLeft()) return null;
    result.attempts += 1;
    const r = tryJsQr(img);
    if (r && typeof r.data === "string" && r.data.length > 0) {
      const location = mapLocation(r.location, scale, offsetX, offsetY);
      const tl = location && location.topLeftCorner ? location.topLeftCorner : { x: offsetX, y: offsetY };
      hits.push({ payload: r.data, method, location, x: tl.x, y: tl.y });
      return r;
    }
    return null;
  };

  const finish = () => {
    if (hits.length === 0) {
      if (!result.error) {
        result.error =
          result.attempts >= maxAttempts
            ? "no_qr_found_attempt_limit"
            : Date.now() - started >= timeBudgetMs
              ? "no_qr_found_time_budget"
              : "no_qr_found";
      }
      return result;
    }
    const distinct = [];
    for (const h of hits) if (!distinct.includes(h.payload)) distinct.push(h.payload);
    // Top-left-most hit wins when several distinct codes were seen.
    const sorted = [...hits].sort((a, b) => a.y + a.x - (b.y + b.x));
    const chosen = sorted[0];
    result.found = true;
    result.count = distinct.length;
    result.payload = chosen.payload;
    result.all_payloads = distinct;
    result.decode_method = chosen.method;
    result.location = chosen.location;
    result.error = null;
    return result;
  };

  // Rung 1: greyscale at native size.
  if (attempt(base, "native_grey")) return finish();

  // Rung 2: resize longest edge to 1200 (only when larger; smaller images go to rung 3).
  let work = base;
  let workScale = 1;
  if (longestEdge(base) > 1200) {
    work = base.clone();
    if (work.bitmap.width >= work.bitmap.height) work.resize({ w: 1200, mode: ResizeStrategy.BILINEAR });
    else work.resize({ h: 1200, mode: ResizeStrategy.BILINEAR });
    workScale = origW / work.bitmap.width;
    if (attempt(work, "resize_1200", workScale)) return finish();
  }

  // Rung 3: small images get a 2x nearest-neighbour upscale.
  if (longestEdge(base) < 500) {
    work = base.clone();
    work.resize({ w: origW * 2, h: origH * 2, mode: ResizeStrategy.NEAREST_NEIGHBOR });
    workScale = 0.5;
    if (attempt(work, "upscale_2x", workScale)) return finish();
  }

  // Rung 4: normalize histogram + contrast boost on the working image.
  const enhanced = work.clone();
  try {
    enhanced.normalize();
    enhanced.contrast(0.3);
  } catch {
    /* enhancement failure is not fatal; fall through with whatever we have */
  }
  if (attempt(enhanced, "normalize_contrast", workScale)) return finish();

  // Rung 5: hard threshold to pure black/white.
  const bw = enhanced.clone();
  try {
    bw.threshold({ max: 128, replace: 255, autoGreyscale: false });
  } catch {
    /* ignore */
  }
  if (attempt(bw, "threshold", workScale)) return finish();

  // Rung 6: tile scan on the working image. 2x2 quadrants then a centred
  // crop; this is also the only rung that can find more than one code.
  const W = work.bitmap.width;
  const H = work.bitmap.height;
  const half = (v) => Math.floor(v / 2);
  const tiles = [
    { name: "tile_tl", x: 0, y: 0, w: half(W), h: half(H) },
    { name: "tile_tr", x: half(W), y: 0, w: W - half(W), h: half(H) },
    { name: "tile_bl", x: 0, y: half(H), w: half(W), h: H - half(H) },
    { name: "tile_br", x: half(W), y: half(H), w: W - half(W), h: H - half(H) },
    { name: "tile_centre", x: Math.floor(W / 4), y: Math.floor(H / 4), w: half(W), h: half(H) },
  ];
  for (const t of tiles) {
    if (!budgetLeft()) break;
    if (t.w < 21 || t.h < 21) continue;
    let tile;
    try {
      tile = enhanced.clone().crop({ x: t.x, y: t.y, w: t.w, h: t.h });
    } catch {
      continue;
    }
    attempt(tile, t.name, workScale, t.x * workScale, t.y * workScale);
  }
  return finish();
}

/* ------------------------------------------------------------------ */
/* imageForGemma                                                       */
/* ------------------------------------------------------------------ */

/**
 * Downscale a PNG to at most `maxEdge` on its longest side and encode as
 * JPEG (quality 80) for the multimodal prompt.
 *
 * @param {Buffer} pngBuffer
 * @param {{maxEdge?:number}} [opts]
 * @returns {Promise<{data:string, mimeType:'image/jpeg', width:number, height:number, bytes:number}>}
 */
export async function imageForGemma(pngBuffer, { maxEdge = IMAGE_LIMITS.gemmaMaxEdge } = {}) {
  const img = await Jimp.read(pngBuffer);
  if (longestEdge(img) > maxEdge) {
    img.scaleToFit({ w: maxEdge, h: maxEdge, mode: ResizeStrategy.BILINEAR });
  }
  // JPEG has no alpha; flatten transparent regions onto white first.
  if (img.hasAlpha()) {
    const bg = new Jimp({ width: img.bitmap.width, height: img.bitmap.height, color: 0xffffffff });
    bg.composite(img, 0, 0);
    const jpg = await bg.getBuffer(JimpMime.jpeg, { quality: 80 });
    return { data: jpg.toString("base64"), mimeType: "image/jpeg", width: bg.bitmap.width, height: bg.bitmap.height, bytes: jpg.length };
  }
  const jpg = await img.getBuffer(JimpMime.jpeg, { quality: 80 });
  return { data: jpg.toString("base64"), mimeType: "image/jpeg", width: img.bitmap.width, height: img.bitmap.height, bytes: jpg.length };
}
