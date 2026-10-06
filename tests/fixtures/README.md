# Test fixtures

Generated demo posters (about 1200x1600) that carry real, decodable QR codes,
plus `manifest.json` describing each one. The unit tests (`tests/unit/qr.test.js`),
the e2e smoke test and the demo UI all read from this folder.

## Regenerate

```
npm run fixtures
```

That runs `scripts/make-fixtures.js`, which

* renders each QR with the `qrcode` package (error correction M, 440 px),
* draws the poster text with jimp's bundled Open Sans bitmap fonts so Gemma can
  read the printed claims,
* composites everything onto a white canvas with a coloured header band,
* writes `photo-degraded.jpg` by downscaling `scholarship-phish.png` to 800 px,
  blurring it and re-encoding as JPEG quality 40, and
* writes `manifest.json`.

The fixture server base URL defaults to `http://127.0.0.1:4555`; set
`FIXTURE_PORT` before regenerating if `scripts/fixture-server.js` runs elsewhere.
The QR payloads bake the port in, so regenerate after changing it.

## Manifest entry

```json
{
  "file": "scholarship-phish.png",
  "description": "...",
  "qr_payload": "http://127.0.0.1:4555/r/chain",
  "expected": {
    "payload_kind": "url",
    "risk_level_one_of": ["HIGH_RISK", "CRITICAL"],
    "notes": "..."
  }
}
```

`qr_payload` is `null` for `no-qr.png`. `risk_level_one_of` is the set of
acceptable final `risk.level` values; several fixtures accept more than one
because Gemma's verdict may legitimately vary while the deterministic floor
keeps it inside the set.

## Fixtures

| File | QR payload | Why it exists |
|---|---|---|
| legit-event.png | `/legit` | consistent, benign destination |
| scholarship-phish.png | `/r/chain` | two 302 hops to a credential + card form |
| no-fee-upi.png | `upi://pay?...am=499` | "No Application Fee" poster vs. UPI payment request (no network needed) |
| no-qr.png | none | forces INSUFFICIENT_EVIDENCE |
| photo-degraded.jpg | `/r/chain` | proves the decode ladder on a blurry low-quality JPEG |
| to-private.png | `/to-private` | redirect to 10.0.0.1 must be blocked |
| wifi.png | `WIFI:...` | password must never appear in a report |
| blocked-scheme.png | `javascript:alert(1)` | blocked scheme, critical signal |
| injection.png | `/injection` | prompt-injection text plus password form |

`uploads/test-poster.png` is a copy of `scholarship-phish.png` so the original
`test-image.js` probe exercises a poster with a real QR; the previous poster was
kept as `uploads/test-poster-original.png` (the `uploads/` folder is gitignored).
