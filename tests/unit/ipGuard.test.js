import { test } from "node:test";
import assert from "node:assert/strict";
import { isBlockedAddress, isBlockedHostname, resolveAndValidate, validateTarget } from "../../server/pipeline/ipGuard.js";

const BLOCKED_IPS = [
  "0.0.0.0",
  "0.1.2.3",
  "10.0.0.1",
  "10.255.255.255",
  "100.64.0.1",
  "100.127.255.254",
  "127.0.0.1",
  "127.1.2.3",
  "169.254.169.254",
  "172.16.0.1",
  "172.31.255.255",
  "192.0.0.1",
  "192.0.2.5",
  "192.88.99.1",
  "192.168.1.1",
  "198.18.0.1",
  "198.19.255.255",
  "198.51.100.7",
  "203.0.113.9",
  "224.0.0.1",
  "239.255.255.250",
  "240.0.0.1",
  "255.255.255.255",
  "::",
  "::1",
  "[::1]",
  "::ffff:127.0.0.1",
  "::ffff:7f00:1",
  "::ffff:10.0.0.1",
  "::ffff:169.254.169.254",
  "64:ff9b::7f00:1",
  "64:ff9b::a00:1",
  "100::1",
  "2001::1",
  "2001:0:abcd::1",
  "2001:db8::1",
  "2002:7f00:1::",
  "2002:a00:1::1",
  "fc00::1",
  "fd12:3456::1",
  "fe80::1",
  "fe80::1%eth0",
  "fec0::1",
  "ff02::1",
  "ff05::2",
];

const ALLOWED_IPS = ["93.184.216.34", "8.8.8.8", "1.1.1.1", "142.250.72.14", "2606:4700::1111", "2a00:1450:4009:81f::200e", "2001:4860:4860::8888"];

test("isBlockedAddress blocks every special-use range family", () => {
  for (const ip of BLOCKED_IPS) {
    const v = isBlockedAddress(ip);
    assert.equal(v.blocked, true, `expected ${ip} blocked`);
    assert.equal(typeof v.reason, "string", `reason for ${ip}`);
  }
});

test("isBlockedAddress allows public addresses", () => {
  for (const ip of ALLOWED_IPS) {
    const v = isBlockedAddress(ip);
    assert.equal(v.blocked, false, `expected ${ip} allowed`);
    assert.equal(v.reason, null);
  }
});

test("isBlockedAddress names the embedded range for IPv4-mapped forms", () => {
  assert.match(isBlockedAddress("::ffff:127.0.0.1").reason, /loopback/);
  assert.match(isBlockedAddress("64:ff9b::7f00:1").reason, /nat64/);
  assert.match(isBlockedAddress("2002:7f00:1::").reason, /6to4/);
  assert.match(isBlockedAddress("2001::1").reason, /teredo/);
  assert.match(isBlockedAddress("fe80::1").reason, /link_local/);
  assert.match(isBlockedAddress("100.64.0.1").reason, /cgnat/);
});

test("isBlockedAddress treats garbage as blocked", () => {
  assert.equal(isBlockedAddress("").blocked, true);
  assert.equal(isBlockedAddress("not-an-ip").blocked, true);
  assert.equal(isBlockedAddress("2130706433").blocked, true);
  assert.equal(isBlockedAddress(undefined).blocked, true);
});

test("isBlockedHostname blocks local, internal, single-label and numeric hosts", () => {
  const blocked = [
    "localhost",
    "LOCALHOST",
    "foo.localhost",
    "localhost.",
    "printer.local",
    "db.internal",
    "1.0.0.127.in-addr.arpa",
    "router.home",
    "nas.lan",
    "fileserver.corp",
    "wiki.intranet",
    "abc123.onion",
    "intranet",
    "metadata",
    "",
    "127.0.0.1",
    "[::1]",
    "169.254.169.254",
    "2130706433",
    "0x7f000001",
    "0177.0.0.1",
    "a..b.com",
  ];
  for (const h of blocked) {
    assert.equal(isBlockedHostname(h).blocked, true, `expected ${JSON.stringify(h)} blocked`);
  }
});

test("isBlockedHostname allows ordinary public names and public IP literals", () => {
  for (const h of ["example.com", "www.example.com", "sub.domain.co.uk", "example.com.", "93.184.216.34", "[2606:4700::1111]"]) {
    assert.equal(isBlockedHostname(h).blocked, false, `expected ${h} allowed`);
  }
});

test("resolveAndValidate blocks when ANY address is private", async () => {
  const lookup = async () => [
    { address: "93.184.216.34", family: 4 },
    { address: "10.0.0.5", family: 4 },
  ];
  const r = await resolveAndValidate("mixed.example.com", { lookup });
  assert.equal(r.ok, false);
  assert.equal(r.code, "blocked_private_ip");
  assert.match(r.reason, /10\.0\.0\.5/);
});

test("resolveAndValidate ok for public addresses and reports them", async () => {
  const lookup = async () => [{ address: "93.184.216.34", family: 4 }, { address: "2606:4700::1111", family: 6 }];
  const r = await resolveAndValidate("example.com", { lookup });
  assert.equal(r.ok, true);
  assert.deepEqual(r.addresses.map((a) => a.address), ["93.184.216.34", "2606:4700::1111"]);
});

test("resolveAndValidate: zero addresses and ENOTFOUND -> dns_nxdomain; other errors -> dns_error", async () => {
  assert.equal((await resolveAndValidate("x.example.com", { lookup: async () => [] })).code, "dns_nxdomain");
  const enotfound = Object.assign(new Error("nope"), { code: "ENOTFOUND" });
  assert.equal((await resolveAndValidate("x.example.com", { lookup: async () => { throw enotfound; } })).code, "dns_nxdomain");
  const other = Object.assign(new Error("boom"), { code: "ESERVFAIL" });
  assert.equal((await resolveAndValidate("x.example.com", { lookup: async () => { throw other; } })).code, "dns_error");
});

test("resolveAndValidate accepts IP literals without DNS", async () => {
  const lookup = async () => { throw new Error("should not be called"); };
  const ok = await resolveAndValidate("93.184.216.34", { lookup });
  assert.equal(ok.ok, true);
  const bad = await resolveAndValidate("127.0.0.1", { lookup });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "blocked_private_ip");
});

test("validateTarget gates: scheme, port, hostname, DNS", async () => {
  const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }];
  assert.equal((await validateTarget(new URL("javascript:alert(1)"), {})).code, "blocked_scheme");
  assert.equal((await validateTarget(new URL("ftp://example.com/"), {})).code, "blocked_scheme");
  assert.equal((await validateTarget(new URL("http://example.com:8080/"), { lookup: publicLookup })).code, "non_standard_port");
  assert.equal((await validateTarget(new URL("http://localhost/"), { lookup: publicLookup })).code, "blocked_hostname");
  assert.equal((await validateTarget(new URL("http://intranet/"), { lookup: publicLookup })).code, "blocked_hostname");
  assert.equal((await validateTarget(new URL("http://127.0.0.1/"), { lookup: publicLookup })).code, "blocked_private_ip");
  assert.equal((await validateTarget(new URL("http://2130706433/"), { lookup: publicLookup })).code, "blocked_private_ip");
  assert.equal((await validateTarget(new URL("http://[::1]/"), { lookup: publicLookup })).code, "blocked_private_ip");
  assert.equal((await validateTarget(new URL("http://evil.example.com/"), { lookup: async () => [{ address: "169.254.169.254", family: 4 }] })).code, "blocked_private_ip");
  assert.equal((await validateTarget(new URL("http://gone.example.com/"), { lookup: async () => [] })).code, "dns_nxdomain");

  const ok = await validateTarget(new URL("https://example.com:443/path"), { lookup: publicLookup });
  assert.equal(ok.ok, true);
  assert.equal(ok.code, null);
  assert.deepEqual(ok.addresses.map((a) => a.address), ["93.184.216.34"]);
});

test("validateTarget allowlist short-circuits exactly matching origins only", async () => {
  const allow = new Set(["http://127.0.0.1:4555"]);
  const ok = await validateTarget(new URL("http://127.0.0.1:4555/legit"), { allowOrigins: allow });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.addresses, [{ address: "127.0.0.1", family: 4 }]);
  // different port -> no longer allowlisted -> normal gates apply
  const otherPort = await validateTarget(new URL("http://127.0.0.1:4556/legit"), { allowOrigins: allow });
  assert.equal(otherPort.ok, false);
  assert.equal(otherPort.code, "blocked_private_ip"); // hostname/IP gate runs before the port gate
  const plain = await validateTarget(new URL("http://127.0.0.1/legit"), { allowOrigins: allow });
  assert.equal(plain.code, "blocked_private_ip");
});
