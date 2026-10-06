# QRShield

QRShield is a multimodal security layer for QR codes on posters, flyers and
notices. You photograph (or upload) the poster; QRShield decodes the QR code,
inspects the URL, safely visits the destination inside an SSRF-hardened
fetcher, and then asks **Gemma 4** to compare what the poster *claims* with
what the destination *actually does*. The result is an evidence-based trust
report that keeps deterministic technical findings strictly separate from
model-derived reasoning.

```
UPLOAD / SCAN IMAGE
   -> DECODE QR                     (jimp + jsQR decode ladder)
   -> CLASSIFY PAYLOAD              (url | upi | wifi | tel | vcard | blocked_scheme | ...)
   -> INSPECT URL                   (host, PSL domain, punycode, confusables, shorteners, ...)
   -> SAFELY INSPECT DESTINATION    (DNS + IP policy, pinned connect, redirect chain, body caps)
   -> SANITIZE PAGE                 (title, text excerpt, forms, sensitive fields)
   -> SERVER FACTS F1..Fn           (plain-English, deterministic, citable)
   -> GEMMA 4 MULTIMODAL REASONING  (poster image + evidence packet, structured JSON)
   -> VALIDATE + GUARDRAILS         (schema, citations, vocabulary, thin-evidence downgrade)
   -> EVIDENCE-BASED TRUST REPORT
```

## Facts versus reasoning

QRShield's core principle is that **technical signals are facts and model
output is reasoning**, and the two are never blended.

* `report.facts` is produced only by ordinary code: QR decoding, URL parsing,
  DNS and IP checks, redirect following, HTML extraction. It never depends on
  the model.
* `report.reasoning` is Gemma's structured output. Every evidence item it marks
  as `deterministic` must cite a server fact id (`F1`, `F2`, ...). If it cites
  one that does not exist, the server relabels it as model inference and
  records the change in `report.server_adjustments`.
* Signals that compare the destination with something Gemma read off the
  poster are **hybrid** and are rendered as "model-derived fact", never as a
  pure technical fact.
* Suspicious TLDs and URL shorteners are always **weak/opacity** signals. A
  deterministic floor can only ever *raise* the model's risk level, never lower
  it, and a floor never comes from weak or neutral signals alone.
* The vocabulary is deliberately careful: "highly suspicious", "critical
  signal", "appears", "is consistent with". QRShield never says a QR code is
  "malicious" or "definitely" a scam.

## Quick start

```bash
npm install
npm --prefix client install
npm run build:client
npm start
# open http://localhost:3001
```

Put your key in `.env` (never committed):

```
GEMINI_API_KEY=...
```

Without a key the server starts in **mock mode** (`GEMMA_MOCK` behaviour): the
whole deterministic pipeline runs for real and Gemma is replaced by scenario
fixtures, so the UI and the demo work offline.

## Development (two terminals)

```bash
npm run dev:server     # API on :3001 with --watch
npm run dev:client     # Vite dev server on :5173, proxies /api to :3001
```

## Demo script

1. Generate the demo posters (real QR codes rendered into poster images):
   `npm run fixtures` -> `tests/fixtures/*.png` + `manifest.json`.
2. Start the local fixture web server (binds to 127.0.0.1 only):
   `npm run fixture-server` -> `http://127.0.0.1:4555`
   Routes include `/legit` (consistent university event page), `/phish`
   (scholarship "verification" form collecting password, card, CVV and OTP),
   `/r/chain` (two 302 hops into `/phish`), `/to-private`, `/to-metadata`,
   `/to-localhost`, `/to-decimal-ip`, `/to-ipv6-loopback` (redirects into
   blocked ranges), `/loop`, `/huge`, `/binary`, `/apk`, `/slow`, `/injection`,
   `/meta-refresh`, `/upi-info`, and `/status` (counts hits on `/secret`,
   which must stay at 0).
3. Allow the API to reach the fixture origin (dev only, logged loudly):
   `QRSHIELD_ALLOW_ORIGINS=http://127.0.0.1:4555 npm start`
   (PowerShell: `$env:QRSHIELD_ALLOW_ORIGINS="http://127.0.0.1:4555"; npm start`)
4. Upload the posters in the UI. The **"No Application Fee" poster carries a UPI
   payment request with a prefilled amount**: it needs no network at all and
   shows Gemma reasoning about intent (poster says free, QR asks for money)
   rather than URL heuristics. It is the safest poster to run on bad venue
   Wi-Fi.

## Tests

| Command | What it does |
|---|---|
| `npm test` | unit tests (`node --test tests/unit`), no network, no Gemini |
| `npm run e2e` | `tests/e2e/smoke.js`: starts the fixture server and the API in mock mode, posts every fixture poster, exercises redirects, blocked targets, timeouts, body caps, malformed input, non-URL payloads and the rate limiter; asserts `/secret` was never fetched |
| `npm run live-check` | `scripts/live-check.js`: real Gemma on every fixture, saves responses to `demo/<fixture>.json`, prints risk/parse path/latency, checks the vocabulary guard and the manifest's expected risk levels; skips when `GEMINI_API_KEY` is missing. Pass fixture names to run a subset (`node scripts/live-check.js no-fee-upi wifi`); it pauses `LIVE_PAUSE_MS` (default 15000) between fixtures to stay under the free-tier per-minute quota |
| `npm run test:gemma`, `npm run test:image` | the original Gemma 4 text and image probes (kept as-is) |

## Environment variables

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | required for live Gemma. Never logged, never returned by any endpoint. |
| `GEMMA_MODEL` | default `gemma-4-26b-a4b-it` |
| `GEMMA_MOCK` | `1` = mock Gemma only (deterministic pipeline runs for real). `fail` = simulate a model failure to exercise the deterministic fallback. |
| `GEMMA_TIMEOUT_MS` | per-request Gemma timeout, default `60000`. On timeout the report still returns, using the deterministic fallback. |
| `GEMMA_THINKING_LEVEL` | default `minimal`. Gemma 4 thinks before answering and those hidden tokens count toward the output budget; `minimal` turns that off for this structured-report task (verified: zero thought tokens, valid JSON). `none` leaves the model default. |
| `GEMMA_MAX_OUTPUT_TOKENS` | default `2048`. The JSON report itself is roughly 500-900 tokens; keep this small, the free tier is the budget. |
| `GEMMA_MEDIA_RESOLUTION` | optional visual token budget for the poster image, e.g. `MEDIA_RESOLUTION_LOW` / `MEDIA_RESOLUTION_MEDIUM` / `MEDIA_RESOLUTION_HIGH`. Unset = model default. |
| `GEMMA_TEMPERATURE` | default `0.1` |
| `GEMMA_CACHE_DIR` | development cache. When set (e.g. `.cache/gemma`), identical Gemma requests are served from disk so repeated testing does not consume API quota. `reasoning_meta.cached` is `true` on a hit. Off by default; never used when mocking. |
| `PORT` | API port, default `3001` |
| `QRSHIELD_ALLOW_ORIGINS` | comma-separated **exact** origins (e.g. `http://127.0.0.1:4555`) that bypass the SSRF hostname/IP/port gate. Dev and tests only; logged loudly at startup. |
| `QRSHIELD_RATE_LIMIT_PER_MIN` | investigations per IP per sliding minute, default `10` (`/api/health` is exempt) |
| `QRSHIELD_MAX_INFLIGHT_FETCHES` | maximum concurrent destination fetches, default `3` |

## API

| Endpoint | Body | Notes |
|---|---|---|
| `GET /api/health` | - | `{ ok, version, model, gemma_configured, mock_mode, allow_origins }`; never includes the key |
| `POST /api/investigate` | multipart: `image` (png/jpeg/webp, <= 8 MiB, <= 25 MP), optional text `url` | `url` overrides the QR (qr stage `skipped`, note `manual_override`) |
| `POST /api/investigate-url` | JSON `{ "url": "..." }` (<= 4096 chars) | URL-only mode; Gemma runs without an image |

200 whenever a report exists, even if every stage degraded. 400 only for bad
input (missing image and url, wrong mime, too large, undecodable image, bad url
string). 429 when rate limited. The full report shape is in
`docs/ARCHITECTURE.md`.

## Security model

Fetching an attacker-chosen URL from a server is a classic SSRF vector, so the
destination fetcher is the most defensive part of QRShield:

* **Schemes**: only `http` and `https` are ever fetched. `javascript:`, `data:`,
  `file:`, `blob:`, `vbscript:`, `about:`, `chrome:` payloads are classified as
  `blocked_scheme` with a critical signal and never touched.
* **Hostname policy**: `localhost`, `*.localhost`, `*.local`, `*.internal`,
  `*.arpa`, `*.home`, `*.lan`, `*.corp`, `*.intranet`, `*.onion`, empty and
  single-label names are refused before DNS.
* **DNS + IP policy**: every hostname is resolved (`all: true`) and **any**
  blocked address blocks the fetch. Blocked: `0.0.0.0/8`, `127/8`, `10/8`,
  `172.16/12`, `192.168/16`, `169.254/16` (incl. cloud metadata), `100.64/10`,
  `192.0.0.0/24`, `192.0.2/24`, `198.51.100/24`, `203.0.113/24`, `192.88.99/24`,
  `198.18/15`, `224/4`, `240/4`, `::/128`, `::1`, `fc00::/7`, `fe80::/10`,
  `fec0::/10`, `ff00::/8`, `2001:db8::/32`, `100::/64`, IPv4-mapped IPv6,
  NAT64 `64:ff9b::/96`, Teredo `2001::/32`, 6to4 `2002::/16`. Decimal and
  other exotic IP literals are normalised by the URL parser before the check.
* **Ports**: only 80 and 443 (allowlisted dev origins exempt).
* **Redirects**: `redirect: 'manual'`; at most 5 hops; the hostname/DNS/IP/port
  gate is re-run on **every** hop; loops and missing `Location` are recorded;
  https -> http downgrades and cross-domain hops are recorded as signals.
* **Timeouts and size**: 6 s per hop, 12 s total, body streamed with a 1 MiB cap
  (64 KiB for non-HTML). GET only, no cookies, no credentials, fixed mobile UA.
* **Userinfo**: `user:pass@host` is stripped before fetching and recorded as a
  strong signal.
* **Connection pinning**: the connection is pinned to the validated IP through
  an undici `Agent` lookup so a DNS rebinding between check and connect cannot
  swap the target; TLS SNI stays the hostname.
* **Images**: mime allowlist, 8 MiB upload cap and a 25 MP pixel cap enforced
  *before* QR decoding; a text file renamed to `.png` is rejected with 400.
* **Abuse limits**: in-memory per-IP sliding-window rate limit and a cap on
  concurrent fetches.
* **Prompt hygiene**: page text sent to Gemma is sanitized (instruction-like
  lines stripped, non-printables removed, 3000 chars max) and labelled as
  untrusted in the prompt. The `/injection` fixture exercises this.
* **Secrets**: `GEMINI_API_KEY` is read from `.env` only; error messages that
  pass through the API are redacted against `/AIza[0-9A-Za-z_-]+/`.

### Residual risks (documented, not hidden)

* **DNS rebinding**: addresses are validated before connect and the socket is
  pinned to the validated address. If pinning fails at runtime the fetcher falls
  back to plain undici fetch and marks the result `pinned: false`; in that mode
  a time-of-check/time-of-use gap exists between the DNS check and the connect.
* **Only HTTP 3xx redirects are followed**. `meta http-equiv="refresh"` and
  JavaScript redirects are recorded as signals, not followed, so the inspected
  page may be an intermediate one.
* **Cloaking and bot walls** can hide the real destination; a clean fetch is
  never sufficient on its own for `LOW_RISK`.
* **Privacy**: poster images are sent to Google's Gemini API. Nothing is stored
  server-side; uploads live in memory for the duration of the request.

## What Gemma does versus what code does

| Question | Answered by | Where it lands |
|---|---|---|
| Is there a QR code, and what does it contain? | code (jimp + jsQR) | `facts.qr` |
| Is the payload a URL, UPI request, Wi-Fi join, vCard, blocked scheme...? | code | `facts.payload` |
| Is the host an IP literal, punycode, confusable, a shortener, free hosting...? | code | `facts.url`, `facts.signals` |
| Where does the URL really go, through which hops, into which network? | code (SSRF-guarded fetcher) | `facts.redirect_chain`, `facts.destination` |
| Does the page have password / card / OTP / UPI PIN / Aadhaar / bank fields? | code (HTML extraction) | `facts.destination.sensitive_inputs` |
| Plain-English restatement of every finding | code | `facts.server_facts` (F1..Fn) |
| Is there a hard deterministic floor (e.g. APK download, credential form on a lookalike)? | code | `facts.floor` |
| What does the **poster** claim: organization, offer, free/paid, urgency, deadline? | Gemma (image) | `reasoning.poster_analysis` |
| What does the **destination** appear to be and ask for? | Gemma (from sanitized evidence) | `reasoning.destination_analysis` |
| Do the physical claim and the digital destination contradict each other? | Gemma | `reasoning.contradictions` |
| Overall risk level, confidence, user summary, recommended action | Gemma, then validated | `reasoning.*`, `risk.*` |
| Does the model's output obey the schema, cite real facts, avoid absolute vocabulary? | code (validate.js) | `server_adjustments` |
| Final level after floor / fallback / forced-insufficient rules | code (report.js) | `risk` |

## Repository layout

See `docs/ARCHITECTURE.md` for the full module list, the report shape, enum
definitions and the risk reconciliation rules. The server is plain JavaScript
ESM with no build step; the client is Vite + React.
