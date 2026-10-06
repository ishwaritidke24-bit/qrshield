# QRShield

### A privacy-first multimodal security layer for the physical-to-digital world.

QRShield is a **multimodal QR security system** that checks whether what a poster claims matches where its QR code actually leads.

A QR may appear on a scholarship notice, event poster, payment notice, job offer, or public announcement. The QR itself may be valid while the surrounding claim is misleading.

### How it works

```text
Poster / Image
      ↓
QR Detection & Decoding
      ↓
URL + Security Inspection
      ↓
Safe Destination Inspection
      ↓
Gemma 4 Multimodal Reasoning
      ↓
Evidence-Based Trust Report
```

### Why Gemma 4?

QRShield uses **Gemma 4 (`gemma-4-26b-a4b-it`)** as its core reasoning engine.

Gemma receives:

* the poster image
* decoded QR information
* technical URL findings
* destination evidence

It then reasons across the visual and digital context to detect **semantic contradictions**.

Example:

```text
Poster:
"No Application Fee"

        vs.

QR Destination:
"UPI payment request: ₹499"

        ↓

Gemma 4
        ↓

HIGH-SEVERITY CONTRADICTION
```

Normal code handles QR decoding, URL analysis, redirects, DNS/IP checks, and other deterministic security checks. Gemma handles the contextual reasoning.

### Tech Stack

* React + Vite
* Node.js + Express
* JavaScript
* Google GenAI SDK
* Gemma 4
* QR decoding
* HTML/destination inspection
* SSRF-safe URL fetching
* JSON schema validation

### Run locally

```bash
npm install
npm --prefix client install
npm run build:client
npm start
```

Open:

```text
http://localhost:3001
```

Add your API key to `.env`:

```env
GEMINI_API_KEY=your_key_here
```

For the bundled demo fixtures:

```bash
npm run fixture-server
```

Then allow the fixture origin when running the API.

### Demo Scenarios

QRShield includes three main demonstrations:

1. **No Application Fee + UPI Payment**
   Poster claims no fee, while the QR requests ₹499.

2. **Scholarship Phishing**
   Suspicious destination collects credentials/payment information.

3. **Legitimate Event**
   Poster and destination are consistent.

### Security

QRShield includes protection against:

* malicious redirects
* private/localhost destinations
* unsafe ports
* SSRF
* oversized images/responses
* suspicious schemes
* sensitive form collection
* prompt injection in fetched page content

Technical findings are kept separate from **Gemma-derived reasoning**.

### Limitations

* Live destination inspection requires internet access.
* Gemma API usage is subject to free-tier rate limits.
* Poor-quality or ambiguous images can reduce confidence.
* QRShield provides risk assessment, not a definitive declaration of fraud.

### License

MIT
