import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { safeFetch, getInflightCount } from "../../server/pipeline/fetchDestination.js";

// ---------------------------------------------------------------------------
// In-test fixture server bound to 127.0.0.1 on a random port.
// ---------------------------------------------------------------------------

let server;
let port;
let origin;
let allow;
const state = { secret_hits: 0, active: 0, maxActive: 0, lastHeaders: null };

function route(req, res) {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const p = url.pathname;
  state.lastHeaders = req.headers;
  const redirect = (to, status = 302) => {
    res.writeHead(status, { location: to });
    res.end();
  };
  const html = (body, status = 200, headers = {}) => {
    res.writeHead(status, { "content-type": "text/html; charset=utf-8", ...headers });
    res.end(body);
  };

  if (p === "/secret") {
    state.secret_hits += 1;
    return html("SHOULD_NEVER_BE_FETCHED");
  }
  if (p === "/legit") return html("<html><head><title>Northfield TechFest</title></head><body>Registration is free.</body></html>");
  if (p === "/echo-host") return html(`<title>${req.headers.host}</title>`);
  if (p === "/r/chain") return redirect("/r/hop2");
  if (p === "/r/hop2") return redirect("/legit");
  if (p.startsWith("/c/")) {
    const n = Number(p.slice(3));
    return n >= 6 ? html("END") : redirect(`/c/${n + 1}`);
  }
  if (p === "/loop") return redirect("/loop");
  if (p === "/no-location") {
    res.writeHead(302);
    return res.end();
  }
  if (p === "/to-private") return redirect("http://10.0.0.1/secret");
  if (p === "/to-metadata") return redirect("http://169.254.169.254/latest/meta-data/");
  if (p === "/to-localhost") return redirect(`http://localhost:${port}/secret`);
  if (p === "/to-loopback-ip") return redirect("http://127.0.0.1:1/secret");
  if (p === "/to-decimal-ip") return redirect("http://2130706433/secret");
  if (p === "/to-ipv6-loopback") return redirect(`http://[::1]:${port}/secret`);
  if (p === "/to-js") return redirect("javascript:alert(1)");
  if (p === "/to-userinfo") return redirect(`http://u:p@127.0.0.1:${port}/legit`);
  if (p === "/slow") return; // never answers
  if (p === "/huge") {
    res.writeHead(200, { "content-type": "text/html" });
    const chunk = Buffer.alloc(64 * 1024, "a");
    let sent = 0;
    const pump = () => {
      while (sent < 3 * 1024 * 1024) {
        sent += chunk.length;
        if (!res.write(chunk)) return res.once("drain", pump);
      }
      res.end();
    };
    return pump();
  }
  if (p === "/binary") {
    res.writeHead(200, { "content-type": "application/pdf", "content-disposition": 'attachment; filename="x.pdf"' });
    return res.end(Buffer.alloc(200 * 1024, 1));
  }
  if (p === "/apk") {
    res.writeHead(200, { "content-type": "application/vnd.android.package-archive", "content-disposition": 'attachment; filename="app.apk"' });
    return res.end(Buffer.alloc(1024, 2));
  }
  if (p === "/notfound") return html("<title>Missing</title>", 404);
  if (p === "/hold") {
    state.active += 1;
    state.maxActive = Math.max(state.maxActive, state.active);
    return setTimeout(() => {
      state.active -= 1;
      html("held");
    }, 150);
  }
  if (p === "/latin1") {
    res.writeHead(200, { "content-type": "text/html; charset=iso-8859-1" });
    return res.end(Buffer.from([0x3c, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3e, 0xe9, 0x3c, 0x2f, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3e]));
  }
  html("fallthrough", 404);
}

before(async () => {
  server = http.createServer(route);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = server.address().port;
  origin = `http://127.0.0.1:${port}`;
  allow = new Set([origin]);
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

const opts = (extra = {}) => ({ allowOrigins: allow, hopTimeoutMs: 2000, totalTimeoutMs: 6000, bodyReadTimeoutMs: 2000, ...extra });

// ---------------------------------------------------------------------------

test("fetches a plain page through the allowlisted origin", async () => {
  const r = await safeFetch(`${origin}/legit`, opts());
  assert.equal(r.error, null);
  assert.equal(r.ok, true);
  assert.equal(r.status, 200);
  assert.equal(r.is_html, true);
  assert.equal(r.final_url, `${origin}/legit`);
  assert.match(r.body_text, /Northfield TechFest/);
  assert.equal(r.chain.length, 1);
  assert.deepEqual(r.chain[0].addresses, ["127.0.0.1"]);
  assert.equal(r.redirects, 0);
  assert.equal(r.truncated, false);
  assert.equal(r.headers.content_type, "text/html; charset=utf-8");
  assert.equal(getInflightCount(), 0);
  // GET only, no cookies, mobile UA, html accept
  assert.equal(state.lastHeaders.cookie, undefined);
  assert.match(state.lastHeaders["user-agent"], /Mobile/);
  assert.match(state.lastHeaders.accept, /text\/html/);
});

test("follows a 2-hop same-origin chain and records every hop", async () => {
  const r = await safeFetch(`${origin}/r/chain`, opts());
  assert.equal(r.ok, true);
  assert.equal(r.redirects, 2);
  assert.deepEqual(r.chain.map((h) => h.status), [302, 302, 200]);
  assert.equal(r.chain[0].location, "/r/hop2");
  assert.equal(r.final_url, `${origin}/legit`);
  assert.ok(r.chain.every((h) => !h.cross_domain && !h.downgrade));
});

test("redirects to private / metadata / localhost / loopback / decimal / IPv6 loopback are blocked before connecting", async () => {
  const cases = [
    ["/to-private", ["blocked_private_ip"]],
    ["/to-metadata", ["blocked_private_ip"]],
    // fixture port is random, so the port gate (which runs before the hostname gate) may fire first
    ["/to-localhost", ["non_standard_port", "blocked_hostname"]],
    ["/to-loopback-ip", ["non_standard_port", "blocked_private_ip"]],
    ["/to-decimal-ip", ["blocked_private_ip"]],
    ["/to-ipv6-loopback", ["non_standard_port", "blocked_private_ip"]],
    ["/to-js", ["blocked_scheme"]],
  ];
  state.secret_hits = 0;
  for (const [path, codes] of cases) {
    const r = await safeFetch(`${origin}${path}`, opts());
    assert.equal(r.ok, false, path);
    assert.ok(r.error, path);
    assert.ok(codes.includes(r.error.code), `${path}: got ${r.error.code}`);
    assert.equal(r.error.hop, 1, path);
    assert.equal(r.chain.length, 2, path);
    assert.equal(r.chain[1].blocked, true, path);
    assert.equal(typeof r.chain[1].blocked_reason, "string", path);
    assert.equal(r.chain[1].status, null, path);
    assert.equal(r.final_url, null, path);
  }
  assert.equal(state.secret_hits, 0, "/secret must never be fetched");
});

test("direct private / localhost / non-standard port / bad scheme / invalid URL are refused at hop 0", async () => {
  assert.equal((await safeFetch("http://10.0.0.1/", opts())).error.code, "blocked_private_ip");
  assert.equal((await safeFetch("http://localhost/", opts())).error.code, "blocked_hostname");
  assert.equal((await safeFetch("http://127.0.0.1:8080/", opts())).error.code, "blocked_private_ip"); // hostname/IP gate precedes the port gate
  assert.equal((await safeFetch("http://example.com:8080/", opts({ lookup: async () => [{ address: "93.184.216.34", family: 4 }] }))).error.code, "non_standard_port");
  const js = await safeFetch("javascript:alert(1)", opts());
  assert.equal(js.error.code, "blocked_scheme");
  assert.equal(js.chain.length, 1);
  assert.equal(js.chain[0].blocked, true);
  assert.equal((await safeFetch("ftp://example.com/", opts())).error.code, "blocked_scheme");
  assert.equal((await safeFetch("not a url", opts())).error.code, "not_fetchable");
  assert.equal((await safeFetch("", opts())).error.code, "not_fetchable");
  assert.equal(getInflightCount(), 0);
});

test("6 redirects stop at maxHops=5 with redirect_limit_exceeded", async () => {
  const r = await safeFetch(`${origin}/c/0`, opts({ maxHops: 5 }));
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "redirect_limit_exceeded");
  assert.equal(r.redirects, 5);
  assert.equal(r.chain.length, 6);
  assert.equal(r.chain[5].status, 302);
  assert.equal(r.chain[5].location, "/c/6");
  assert.equal(r.final_url, null);
});

test("redirect loop is detected", async () => {
  const r = await safeFetch(`${origin}/loop`, opts());
  assert.equal(r.error.code, "redirect_loop");
  assert.equal(r.chain.length, 2);
  assert.equal(r.chain[1].blocked, true);
  assert.equal(r.redirects, 1);
});

test("a redirect to plain localhost on a standard port is refused by the hostname gate", async () => {
  const lookup = async () => [{ address: "93.184.216.34", family: 4 }];
  const fetchImpl = async (url) => {
    if (url === "https://a.example.com/go") return { status: 302, headers: new Headers({ location: "http://localhost/admin" }), body: null };
    throw new Error("must not fetch localhost");
  };
  const r = await safeFetch("https://a.example.com/go", opts({ lookup, fetchImpl }));
  assert.equal(r.error.code, "blocked_hostname");
  assert.equal(r.error.hop, 1);
  assert.equal(r.chain[1].blocked, true);
});

test("3xx without Location -> redirect_missing_location", async () => {
  const r = await safeFetch(`${origin}/no-location`, opts());
  assert.equal(r.error.code, "redirect_missing_location");
});

test("3 MiB html body is truncated at 1 MiB", async () => {
  const r = await safeFetch(`${origin}/huge`, opts({ bodyReadTimeoutMs: 5000 }));
  assert.equal(r.ok, true);
  assert.equal(r.truncated, true);
  assert.equal(r.bytes_read, 1024 * 1024);
  assert.equal(r.body_text.length, 1024 * 1024);
});

test("application/pdf is not parsed as html and at most 64 KiB is read", async () => {
  const r = await safeFetch(`${origin}/binary`, opts());
  assert.equal(r.ok, true);
  assert.equal(r.is_html, false);
  assert.equal(r.body_text, null);
  assert.ok(r.bytes_read <= 64 * 1024);
  assert.equal(r.truncated, true);
  assert.equal(r.headers.content_type, "application/pdf");
  assert.match(r.headers.content_disposition, /attachment/);
  const apk = await safeFetch(`${origin}/apk`, opts());
  assert.equal(apk.is_html, false);
  assert.equal(apk.truncated, false);
  assert.equal(apk.bytes_read, 1024);
});

test("slow server times out per hop", async () => {
  const started = Date.now();
  const r = await safeFetch(`${origin}/slow`, opts({ hopTimeoutMs: 300, totalTimeoutMs: 2000 }));
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "fetch_timeout");
  assert.ok(Date.now() - started < 1500);
  assert.equal(r.pinned, true, "pinning was in effect even though the hop timed out");
  assert.equal(getInflightCount(), 0);
});

test("pinIp:false disables the pinned Agent and reports pinned=false", async () => {
  const r = await safeFetch(`${origin}/legit`, opts({ pinIp: false }));
  assert.equal(r.ok, true);
  assert.equal(r.pinned, false);
});

test("userinfo is stripped before fetching and recorded", async () => {
  const r = await safeFetch(`http://alice:s3cret@127.0.0.1:${port}/legit`, opts());
  assert.equal(r.ok, true);
  assert.equal(r.userinfo_stripped, true);
  assert.equal(r.requested_url.includes("s3cret"), false);
  assert.equal(r.final_url, `${origin}/legit`);
  assert.equal(state.lastHeaders.authorization, undefined);
  // userinfo in a redirect target is also stripped
  const r2 = await safeFetch(`${origin}/to-userinfo`, opts());
  assert.equal(r2.ok, true);
  assert.equal(r2.userinfo_stripped, true);
  assert.equal(r2.chain[1].url.includes("u:p@"), false);
});

test("HTTP 404 is returned as http_error but the body is still kept", async () => {
  const r = await safeFetch(`${origin}/notfound`, opts());
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "http_error");
  assert.equal(r.status, 404);
  assert.match(r.body_text, /Missing/);
});

test("charset from content-type is honoured, non-fatal decoding", async () => {
  const r = await safeFetch(`${origin}/latin1`, opts());
  assert.equal(r.ok, true);
  assert.match(r.body_text, /<title>é<\/title>/);
});

test("nxdomain via injected lookup never calls fetch", async () => {
  let called = 0;
  const r = await safeFetch("http://does-not-exist.example.com/", opts({ lookup: async () => [], fetchImpl: async () => { called += 1; throw new Error("must not be called"); } }));
  assert.equal(r.error.code, "dns_nxdomain");
  assert.equal(called, 0);
  assert.equal(r.chain[0].blocked, true);
});

test("hostname resolving to a private address is refused before fetch", async () => {
  let called = 0;
  const r = await safeFetch("http://rebind.example.com/", opts({ lookup: async () => [{ address: "93.184.216.34", family: 4 }, { address: "127.0.0.1", family: 4 }], fetchImpl: async () => { called += 1; } }));
  assert.equal(r.error.code, "blocked_private_ip");
  assert.equal(called, 0);
  assert.deepEqual(r.chain[0].addresses, ["93.184.216.34", "127.0.0.1"]);
});

test("https -> http downgrade and cross-domain redirect are flagged (injected fetchImpl)", async () => {
  const lookup = async () => [{ address: "93.184.216.34", family: 4 }];
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, init });
    if (url === "https://a.example.com/start") return { status: 302, headers: new Headers({ location: "http://b.example.org/landing" }), body: null };
    return { status: 200, headers: new Headers({ "content-type": "text/html" }), body: null, text: async () => "<title>landing</title>" };
  };
  const r = await safeFetch("https://a.example.com/start", opts({ lookup, fetchImpl }));
  assert.equal(r.ok, true);
  assert.equal(r.redirects, 1);
  assert.equal(r.chain[1].downgrade, true);
  assert.equal(r.chain[1].cross_domain, true);
  assert.equal(r.chain[0].downgrade, false);
  assert.equal(r.chain[0].cross_domain, false);
  assert.equal(r.final_url, "http://b.example.org/landing");
  assert.match(r.body_text, /landing/);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].init.redirect, "manual");
  assert.equal(seen[0].init.method, "GET");
  assert.equal(r.pinned, false, "fake fetchImpl cannot be pinned");
});

test("network error from fetchImpl is classified, never thrown", async () => {
  const lookup = async () => [{ address: "93.184.216.34", family: 4 }];
  const tls = await safeFetch("https://a.example.com/", opts({ lookup, fetchImpl: async () => { throw Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("certificate has expired"), { code: "CERT_HAS_EXPIRED" }) }); } }));
  assert.equal(tls.error.code, "tls_error");
  const conn = await safeFetch("https://a.example.com/", opts({ lookup, fetchImpl: async () => { throw Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }) }); } }));
  assert.equal(conn.error.code, "connection_error");
  const abort = await safeFetch("https://a.example.com/", opts({ lookup, fetchImpl: async () => { const e = new Error("aborted"); e.name = "AbortError"; throw e; } }));
  assert.equal(abort.error.code, "fetch_timeout");
  // error message never contains a Gemini-looking key
  const leaky = await safeFetch("https://a.example.com/", opts({ lookup, fetchImpl: async () => { throw new Error("key AIzaSyFAKEFAKEFAKE leaked"); } }));
  assert.equal(leaky.error.message.includes("AIzaSy"), false);
});

test("IP pinning: a hostname that does not exist in DNS is reached via the validated address", async () => {
  // 'pinned.test' resolves nowhere in real DNS. With the injected lookup returning
  // 127.0.0.1 and the origin allowlisted, the real undici fetch must connect to
  // 127.0.0.1 through the pinned Agent lookup while sending Host: pinned.test.
  const pinnedOrigin = `http://pinned.test:${port}`;
  const r = await safeFetch(`${pinnedOrigin}/echo-host`, opts({ allowOrigins: new Set([pinnedOrigin]), lookup: async () => [{ address: "127.0.0.1", family: 4 }] }));
  assert.equal(r.error, null, JSON.stringify(r.error));
  assert.equal(r.ok, true);
  assert.equal(r.pinned, true);
  assert.match(r.body_text, new RegExp(`pinned\\.test:${port}`));
  assert.deepEqual(r.chain[0].addresses, ["127.0.0.1"]);
});

test("concurrency gate limits in-flight fetches to the configured maximum (default 3)", async () => {
  state.active = 0;
  state.maxActive = 0;
  const results = await Promise.all(Array.from({ length: 7 }, () => safeFetch(`${origin}/hold`, opts())));
  assert.ok(results.every((r) => r.ok), "all held fetches complete");
  assert.ok(state.maxActive <= 3, `max concurrent on server was ${state.maxActive}`);
  assert.equal(getInflightCount(), 0);
});
