import assert from "node:assert/strict";

import { parseQuery } from "@/lib/query";

let checks = 0;
function check(actual: unknown, expected: unknown, message: string) {
  checks += 1;
  assert.deepEqual(actual, expected, message);
}

// --- AS numbers --------------------------------------------------------
check(parseQuery("AS15169"), { kind: "asn", asn: "15169", label: "AS15169" }, "AS prefix");
check(parseQuery("as15169"), { kind: "asn", asn: "15169", label: "AS15169" }, "lowercase prefix");
check(parseQuery("As 15169"), { kind: "asn", asn: "15169", label: "AS15169" }, "space after prefix");
check(parseQuery("AS-15169"), { kind: "asn", asn: "15169", label: "AS15169" }, "hyphen after prefix");
check(parseQuery("15169"), { kind: "asn", asn: "15169", label: "AS15169" }, "bare number");
check(parseQuery("  AS13335  "), { kind: "asn", asn: "13335", label: "AS13335" }, "surrounding space");
check(parseQuery("AS015169").kind, "asn", "leading zeros are tolerated");
check(parseQuery("AS015169"), { kind: "asn", asn: "15169", label: "AS15169" }, "leading zeros normalise");
check(parseQuery("4294967295").kind, "asn", "the largest 32-bit ASN is accepted");
check(parseQuery("4294967296").kind, "invalid", "beyond 32 bits is rejected");
check(parseQuery("AS4294967296").kind, "invalid", "prefixed overflow is rejected");
check(parseQuery("AS-1"), { kind: "asn", asn: "1", label: "AS1" }, "the hyphen is a separator, not a sign");
check(parseQuery("-15169").kind, "invalid", "a bare negative number is not an ASN");
check(parseQuery("ASN15169").kind, "invalid", "ASN prefix is not the same as AS");

// --- IPv4 --------------------------------------------------------------
check(parseQuery("8.8.8.8"), { kind: "ip", ip: "8.8.8.8", label: "8.8.8.8" }, "plain IPv4");
check(parseQuery("1.1.1.1:443"), { kind: "ip", ip: "1.1.1.1", label: "1.1.1.1" }, "port stripped");
check(parseQuery("https://1.1.1.1"), { kind: "ip", ip: "1.1.1.1", label: "1.1.1.1" }, "scheme stripped");
check(parseQuery("http://8.8.8.8/path?q=1").kind, "ip", "path and query stripped");
check(parseQuery("255.255.255.255").kind, "ip", "the broadcast address parses");
check(parseQuery("256.1.1.1").kind, "invalid", "an octet above 255 is rejected");
check(parseQuery("1.1.1").kind, "invalid", "three octets is not an address");
check(parseQuery("1.1.1.1.1").kind, "invalid", "five octets is not an address");
check(parseQuery("01.1.1.1").kind, "invalid", "an octal-looking octet is rejected");
check(parseQuery("1.1.1.-1").kind, "invalid", "a negative octet is rejected");

// --- IPv6 --------------------------------------------------------------
check(parseQuery("2606:4700:4700::1111").kind, "ip", "compressed IPv6");
check(parseQuery("::1").kind, "ip", "loopback");
check(parseQuery("::").kind, "ip", "the unspecified address");
check(
  parseQuery("2001:4860:4860:0000:0000:0000:0000:8888").kind,
  "ip",
  "fully expanded IPv6",
);
check(parseQuery("[2606:4700::1111]:443").kind, "ip", "bracketed with a port");
check(
  parseQuery("[2606:4700::1111]:443"),
  { kind: "ip", ip: "2606:4700::1111", label: "2606:4700::1111" },
  "brackets and port are removed",
);
check(parseQuery("https://[2606:4700::1111]/").kind, "ip", "bracketed inside a URL");
check(parseQuery("::ffff:192.0.2.1").kind, "ip", "IPv4-mapped IPv6");
check(parseQuery("fe80::1%eth0").kind, "ip", "a zone index is tolerated");
check(parseQuery("2001::4860::8888").kind, "invalid", "two :: runs are rejected");
check(parseQuery("2001:::1").kind, "invalid", "a triple colon is rejected");
check(parseQuery("2001:4860:4860:0:0:0:0:0:8888").kind, "invalid", "nine groups is too many");
check(parseQuery("2001:4860:4860:0:0:0:0").kind, "invalid", "seven groups without :: is too few");
check(parseQuery("2001:gggg::1").kind, "invalid", "a non-hex group is rejected");
check(parseQuery("::ffff:999.0.2.1").kind, "invalid", "a bad embedded IPv4 is rejected");

// --- domains -----------------------------------------------------------
check(parseQuery("github.com"), { kind: "domain", domain: "github.com", label: "github.com" }, "bare domain");
check(parseQuery("GitHub.COM").kind, "domain", "case is normalised");
check(parseQuery("GitHub.COM"), { kind: "domain", domain: "github.com", label: "github.com" }, "lowercased");
check(parseQuery("https://api.stripe.com/v1/charges").kind, "domain", "a full URL reduces to its host");
check(
  parseQuery("https://api.stripe.com/v1/charges"),
  { kind: "domain", domain: "api.stripe.com", label: "api.stripe.com" },
  "host extracted from a URL",
);
check(parseQuery("user:pass@example.com").kind, "domain", "userinfo is dropped");
check(parseQuery("example.com.").kind, "domain", "a trailing root dot is dropped");
check(parseQuery("example.com:8443").kind, "domain", "a port is dropped");
check(parseQuery("xn--bcher-kva.example").kind, "domain", "a punycode label is valid");
check(parseQuery("localhost").kind, "invalid", "a single label is not a domain");
check(parseQuery("-bad.com").kind, "invalid", "a label may not start with a hyphen");
check(parseQuery("bad-.com").kind, "invalid", "a label may not end with a hyphen");
check(parseQuery("exam ple.com").kind, "invalid", "a space is not allowed in a label");
check(parseQuery("1.2.3.4.5").kind, "invalid", "a numeric TLD means a malformed IP, not a domain");
check(parseQuery(`${"a".repeat(64)}.com`).kind, "invalid", "a label over 63 characters is rejected");
check(parseQuery(`${"a".repeat(60)}.`.repeat(5) + "com").kind, "invalid", "a name over 253 characters is rejected");

// --- empty and junk ----------------------------------------------------
check(parseQuery("").kind, "invalid", "empty input is invalid");
check(parseQuery("   ").kind, "invalid", "whitespace is invalid");
{
  const empty = parseQuery("");
  check(empty.kind === "invalid" && empty.reason.includes("AS number"), true, "the empty message names what to type");
}
check(parseQuery("what is my ip").kind, "invalid", "a sentence is invalid");
check(parseQuery("!!!").kind, "invalid", "punctuation is invalid");

console.log(`query: ${checks} assertions passed`);
