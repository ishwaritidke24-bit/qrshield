# QRShield architecture and integration contract

QRShield investigates the whole chain behind a QR code on a poster:

```
POSTER IMAGE -> QR DECODE -> PAYLOAD CLASSIFY -> URL ANALYSIS -> SAFE DESTINATION FETCH
             -> SANITIZE -> SERVER FACTS (F1..Fn) -> GEMMA 4 MULTIMODAL REASONING
             -> VALIDATE + GUARDRAILS -> EVIDENCE-BASED TRUST REPORT
```

Two kinds of output are kept strictly apart:

* **Deterministic facts**: produced by ordinary code (QR decoding, URL parsing,
  DNS/IP checks, redirect following, HTML extraction). Stored under
  `report.facts`. Never derived from model output.
* **Model reasoning**: produced by Gemma 4 from the poster image plus a
  sanitized evidence packet. Stored under `report.reasoning`. Every evidence
  item it marks as `deterministic` must cite a server fact id, or the server
  relabels it as model inference.

Signals that compare the destination with something Gemma read off the poster
are **hybrid** (`hybrid: true`) and are rendered as "model-derived fact".

## Runtime layout

```
server/index.js                 Express bootstrap, multer, static client/dist
server/routes/investigate.js    GET /api/health, POST /api/investigate, POST /api/investigate-url
server/pipeline/contracts.js    enums, labels, runStage helper (single source of truth)
server/pipeline/run.js          orchestrates the stages; never throws
server/pipeline/qr.js           decodeQr(buffer) -> jimp + jsqr decode ladder
server/pipeline/payload.js      classifyPayload(raw) -> url | upi | tel | sms | mailto | wifi | vcard | geo | intent | appstore | crypto | blocked_scheme | text
server/pipeline/urlAnalysis.js  analyzeUrl(urlString) -> url parts + signals
server/pipeline/ipGuard.js      hostname + IP policy (net.BlockList), resolveAndValidate(hostname)
server/pipeline/fetchDestination.js safeFetch(url, opts) -> hop chain + body (SSRF-protected)
server/pipeline/sanitizeHtml.js extractPage(html, baseUrl) -> title, text, forms, sensitive fields
server/pipeline/destinationSignals.js signals derived from the fetch + page
server/pipeline/facts.js        buildFacts(...) -> server_facts F1..Fn, floor, evidence packet
server/pipeline/gemma.js        callGemma(packet, imagePart) -> validated reasoning (+ mock mode)
server/pipeline/validate.js     schema validation + guardrail pass -> server_adjustments
server/pipeline/report.js       final risk reconciliation and report assembly
server/prompts/system.txt       Gemma rules and risk vocabulary
server/prompts/schema.json      Gemma output JSON schema (single source of truth)
server/lists/*.json             shorteners, suspicious TLDs, brands, free hosts, UPI handles, PSL subset
server/fixtures/<scenario>/     packet.json + gemma.json used by GEMMA_MOCK=1
client/                         Vite + React UI
scripts/make-fixtures.js        generates demo posters with real QR codes into tests/fixtures/
scripts/fixture-server.js       local HTTP server on 127.0.0.1:4555 with benign/phishy/redirect pages
scripts/live-check.js           runs real Gemma on the fixtures and saves responses under demo/
tests/unit/*.test.js            node:test, no extra deps
tests/e2e/smoke.js              fixture server + API in mock mode
```

## Enums (see `server/pipeline/contracts.js`)

* `RISK_LEVELS`: `LOW_RISK | MEDIUM_RISK | HIGH_RISK | CRITICAL | INSUFFICIENT_EVIDENCE`
  Display labels: "LOW RISK", "MEDIUM RISK", "HIGH RISK", "CRITICAL", "INSUFFICIENT EVIDENCE".
* `STAGE_STATUS`: `ok | degraded | skipped | failed | blocked`
* `SIGNAL_STRENGTH`: `neutral | weak | medium | strong | critical`
  Display labels: "Info", "Weak signal", "Suspicious", "Highly suspicious", "Critical signal".
  Never use the words "malicious", "definitely", "confirmed scam" in signal text.

## Signal shape

```js
{ id: 'ip_literal_host',           // stable snake_case id
  strength: 'strong',              // SIGNAL_STRENGTH
  fact: 'Destination host 185.23.11.9 is a bare IP address, not a domain name.',
  value: '185.23.11.9',            // measured datum, optional
  hybrid: false,                   // true when it depends on Gemma's poster reading
  stage: 'url' }                   // which stage produced it: qr | payload | url | fetch | destination
```

## Server fact shape

```js
{ id: 'F4', text: 'Final destination host 185.23.11.9 is a bare IP address.', signal_id: 'ip_literal_host' }
```

`server_facts` is the only list Gemma may cite as deterministic evidence. The
UI's "Verified facts" column renders from it.

## Report shape (returned by both POST endpoints)

```js
{
  investigation_id: 'uuid', created_at: 'iso',
  input: { mode: 'image' | 'url', image: { width, height, bytes, mime } | null, manual_url: false },
  stages: {
    intake:  { status, duration_ms, note },
    qr:      { status, duration_ms, note },
    payload: { status, duration_ms, note },
    url:     { status, duration_ms, note },
    fetch:   { status, duration_ms, note },
    gemma:   { status, duration_ms, note },
  },
  facts: {
    qr:        { found, count, payload, payload_type, decode_method, error, all_payloads: [] },
    payload:   { kind, parsed, embedded_urls: [], fetchable: bool, reason },
    url:       { normalized, scheme, host, hostname, registrable_domain, subdomain_labels, port,
                 path, query_keys: [], is_ip_literal, is_punycode, unicode_host, userinfo_present } | null,
    redirect_chain: [ { url, status, host, addresses: [], location, blocked, blocked_reason, downgrade, cross_domain } ],
    destination: { fetched, error_code, error_message, final_url, http_status, content_type,
                   content_length, bytes_read, truncated, is_html, title, meta_description, site_name,
                   canonical_host, lang, visible_text_excerpt, forms: [ { method, action_host, cross_origin,
                   action_is_http, field_types: [] } ], sensitive_inputs: { password, payment_card, otp,
                   upi, aadhaar, pan, bank }, external_hosts: [], external_script_hosts: [], iframe_hosts: [],
                   has_download_links, meta_refresh_target, bot_wall_detected },
    signals:   [ Signal ],
    server_facts: [ ServerFact ],
    floor:     { level: RISK_LEVEL | null, triggered_by: [ signal ids ] },
  },
  reasoning: GemmaOutput | null,          // validated model output, see prompts/schema.json
  reasoning_meta: { available, model, latency_ms, parse_path: 'native|fenced|sliced|balanced|repaired|fallback|mock',
                    error, raw_text_excerpt, validation_notes: [] },
  server_adjustments: [ { rule, from, to, note } ],
  risk: { level: RISK_LEVEL, label: 'HIGH RISK', source: 'gemma' | 'floor_override' | 'deterministic_fallback' | 'forced_insufficient',
          confidence: 0..1, summary: 'plain language', recommended_action: '' },
  meta: { version: '0.1.0', model: 'gemma-4-26b-a4b-it', mock: false, timings: { total_ms, ... } }
}
```

HTTP 200 whenever a report exists, even if every stage degraded. 400 only for
bad input (missing image, wrong mime, too large, undecodable image, bad url
body). 429 for rate limiting. 500 is never expected.

## Risk reconciliation (report.js)

1. Start from Gemma `risk_level` when available.
2. Deterministic floor from `facts.floor` can only RAISE the level.
3. The model needs a semantic basis (high-severity contradiction, credential or
   payment collection, or a mismatch verdict) to say HIGH/CRITICAL. Without one:
   an unfetched destination is downgraded to INSUFFICIENT_EVIDENCE, and any
   HIGH/CRITICAL is capped at the deterministic floor (MEDIUM_RISK when there is
   no floor). Both are recorded in server_adjustments. Technical signals are
   weighed once, by the floor, never twice.
4. If Gemma failed, use the deterministic fallback table over signals:
   any critical -> CRITICAL; >= 2 strong -> HIGH_RISK; 1 strong or >= 2 medium -> MEDIUM_RISK;
   destination fetched and no signals above weak -> LOW_RISK; otherwise INSUFFICIENT_EVIDENCE.
5. No QR and no manual URL -> forced INSUFFICIENT_EVIDENCE.

## Environment variables

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | required for live Gemma. Never logged, never returned. |
| `GEMMA_MODEL` | default `gemma-4-26b-a4b-it` |
| `GEMMA_MOCK` | `1` = mock Gemma only (real deterministic pipeline). `fail` = simulate model failure. |
| `PORT` | default 3001 |
| `QRSHIELD_ALLOW_ORIGINS` | comma-separated exact origins (e.g. `http://127.0.0.1:4555`) that bypass the SSRF hostname/IP/port gate. Dev and tests only. Logged loudly at startup. |
| `QRSHIELD_RATE_LIMIT_PER_MIN` | default 10 per IP |
| `QRSHIELD_MAX_INFLIGHT_FETCHES` | default 3 |

## Gemma call budget (gemma.js), free tier only

* One live call per investigation in the normal case. At most one extra call:
  a compact retry with the SAME configuration when the first answer was
  truncated or empty, or a text-only schema repair when the answer was
  complete but invalid. Never both; never a doubled token budget.
* `thinkingLevel: "minimal"` by default: Gemma 4's hidden thinking tokens
  otherwise count toward `maxOutputTokens` and can swallow the whole budget.
* `maxOutputTokens` 2048; the schema answer is ~500-900 tokens.
* `reasoning_meta` records `generation` (the settings used), `usage`
  (finish reason, prompt/image/output/thought tokens), `calls`, `latency_ms`
  and `cached`. Image tokens in `usage.prompt_image_tokens` are the proof
  that the poster was actually sent to the model.
* `GEMMA_CACHE_DIR` enables an opt-in on-disk cache for development runs.
* When the model is unavailable (quota, timeout, invalid output) the report
  still renders from deterministic facts (`risk.source = deterministic_fallback`),
  and `GEMMA_MOCK=1` serves fixture reasoning offline.

## Fetcher limits (fetchDestination.js)

| Limit | Value |
|---|---|
| Schemes fetched | http, https only |
| Ports fetched | 80, 443 only (allowlisted origins exempt) |
| Redirect hops | 5 |
| Per-hop timeout | 6000 ms |
| Total timeout | 12000 ms |
| Body cap | 1 MiB streamed; non-HTML read at most 64 KiB |
| Method | GET only, no cookies, no credentials, mobile Chrome UA |

## Residual risks (documented, not hidden)

* DNS rebinding: addresses are validated before connect and the connection is
  pinned to the validated address through an undici Agent lookup. If pinning
  is disabled, the time-of-check/time-of-use gap is documented in the README.
* Only HTTP 3xx redirects are followed. meta-refresh and JavaScript redirects
  are recorded, not followed; the final page may be an intermediate one.
* Cloaking and bot walls can hide the real destination; a clean fetch is never
  sufficient on its own for LOW_RISK.
* Poster images are sent to Google's Gemini API. Nothing is stored server-side.
