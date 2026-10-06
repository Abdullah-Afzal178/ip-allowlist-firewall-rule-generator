import assert from "node:assert/strict";

import { DEFAULT_CONTROLS, buildHref, readControls } from "@/lib/controls";

let checks = 0;
function check(actual: unknown, expected: unknown, message: string) {
  checks += 1;
  assert.deepEqual(actual, expected, message);
}

// --- reading -----------------------------------------------------------
check(readControls({}), DEFAULT_CONTROLS, "no params gives the defaults");
check(readControls({ q: "AS15169" }).query, "AS15169", "the query is read");
check(readControls({ q: "  AS15169  " }).query, "AS15169", "the query is trimmed");
check(readControls({ q: "a".repeat(400) }).query.length, 253, "an overlong query is capped");
check(readControls({ format: "nftables" }).format, "nftables", "a known format is kept");
check(readControls({ format: "pf" }).format, "cidr", "an unknown format falls back");
check(readControls({ format: "" }).format, "cidr", "an empty format falls back");
check(readControls({ mode: "deny" }).mode, "deny", "deny mode is read");
check(readControls({ mode: "DENY" }).mode, "allow", "mode matching is exact");
check(readControls({ mode: "drop" }).mode, "allow", "an unknown mode falls back");
check(readControls({ version: "v4" }).version, "v4", "v4 filter is read");
check(readControls({ version: "v6" }).version, "v6", "v6 filter is read");
check(readControls({ version: "ipv4" }).version, "both", "an unknown filter falls back");

// Next.js hands repeated params through as arrays.
check(readControls({ q: ["AS13335", "AS15169"] }).query, "AS13335", "a repeated param takes the first");
check(readControls({ format: ["json", "nope"] }).format, "json", "a repeated format takes the first");
check(readControls({ q: [] }).query, "", "an empty array reads as empty");

// --- building ----------------------------------------------------------
check(buildHref(DEFAULT_CONTROLS), "/", "all defaults produce a bare path");
check(buildHref({ ...DEFAULT_CONTROLS, query: "AS15169" }), "/?q=AS15169", "the query is included");
check(
  buildHref({ ...DEFAULT_CONTROLS, query: "AS15169" }, { format: "nginx" }),
  "/?q=AS15169&format=nginx",
  "a patch overrides one control",
);
check(
  buildHref({ ...DEFAULT_CONTROLS, query: "AS15169", format: "nginx" }, { format: "cidr" }),
  "/?q=AS15169",
  "patching back to the default drops the param",
);
check(
  buildHref({ query: "AS13335", format: "iptables", mode: "deny", version: "v6" }),
  "/?q=AS13335&format=iptables&mode=deny&version=v6",
  "every non-default control is carried",
);
check(
  buildHref({ ...DEFAULT_CONTROLS, query: "api.stripe.com" }, {}, "/download"),
  "/download?q=api.stripe.com",
  "a different path is honoured",
);
check(buildHref(DEFAULT_CONTROLS, {}, "/download"), "/download", "a bare path needs no query string");
check(
  buildHref({ ...DEFAULT_CONTROLS, query: "example.com/a b" }),
  "/?q=example.com%2Fa+b",
  "the query is URL encoded",
);

// A link survives a round trip through the reader unchanged.
{
  const original = { query: "AS16509", format: "terraform", mode: "deny", version: "v4" } as const;
  const href = buildHref(original);
  const params = Object.fromEntries(new URLSearchParams(href.split("?")[1]));
  check(readControls(params), original, "controls round-trip through a built link");
}

console.log(`controls: ${checks} assertions passed`);
