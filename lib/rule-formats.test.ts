import assert from "node:assert/strict";

import {
  FORMATS,
  buildRules,
  formatFor,
  isFormatId,
  partitionPrefixes,
  type FormatId,
  type RuleInput,
} from "@/lib/rule-formats";

let checks = 0;
function check(actual: unknown, expected: unknown, message: string) {
  checks += 1;
  assert.deepEqual(actual, expected, message);
}
function truthy(value: unknown, message: string) {
  checks += 1;
  assert.ok(value, message);
}

const V4 = ["8.8.8.0/24", "8.8.4.0/24"];
const V6 = ["2001:4860:4860::/48"];

function input(overrides: Partial<RuleInput> = {}): RuleInput {
  return {
    source: "Google LLC",
    asn: "AS15169",
    ipv4: V4,
    ipv6: V6,
    mode: "allow",
    format: "cidr",
    ...overrides,
  };
}

// --- format registry ---------------------------------------------------
check(FORMATS.length, 10, "ten output formats");
check(new Set(FORMATS.map((f) => f.id)).size, 10, "format ids are unique");
truthy(
  FORMATS.every((f) => f.label && f.extension && f.note),
  "every format has a label, extension and note",
);
truthy(isFormatId("nftables"), "known id passes the guard");
truthy(!isFormatId("pf"), "unknown id fails the guard");
check(formatFor("json").label, "JSON", "formatFor finds by id");
check(formatFor("nope" as FormatId).id, "cidr", "formatFor falls back to the first format");

// --- partitioning ------------------------------------------------------
{
  const mixed = ["1.1.1.0/24", "2606:4700::/32", "8.8.8.0/24"];
  check(partitionPrefixes(mixed, "both").ipv4, ["1.1.1.0/24", "8.8.8.0/24"], "both keeps IPv4");
  check(partitionPrefixes(mixed, "both").ipv6, ["2606:4700::/32"], "both keeps IPv6");
  check(partitionPrefixes(mixed, "v4").ipv6, [], "v4 filter drops IPv6");
  check(partitionPrefixes(mixed, "v4").ipv4.length, 2, "v4 filter keeps IPv4");
  check(partitionPrefixes(mixed, "v6").ipv4, [], "v6 filter drops IPv4");
  check(partitionPrefixes(mixed, "v6").ipv6, ["2606:4700::/32"], "v6 filter keeps IPv6");
  check(partitionPrefixes([], "both"), { ipv4: [], ipv6: [] }, "empty input partitions cleanly");
}

// --- empty guard -------------------------------------------------------
for (const format of FORMATS) {
  const text = buildRules(input({ ipv4: [], ipv6: [], format: format.id }));

  if (format.id === "json") {
    // A .json download has to parse even when the filter matched nothing.
    const parsed = JSON.parse(text);
    check(parsed.counts, { ipv4: 0, ipv6: 0, total: 0 }, "an empty json result still parses");
    check(parsed.prefixes, { ipv4: [], ipv6: [] }, "an empty json result has empty arrays");
    continue;
  }

  check(text, "# No prefixes to emit for the selected filters.", `${format.id} guards an empty list`);
}

// --- respectsMode -------------------------------------------------------
check(formatFor("cidr").respectsMode, false, "a raw CIDR list has no allow/deny verb");
truthy(
  FORMATS.filter((f) => f.id !== "cidr").every((f) => f.respectsMode),
  "every other format honours the mode",
);
for (const format of FORMATS) {
  const allow = buildRules(input({ format: format.id, mode: "allow" }));
  const deny = buildRules(input({ format: format.id, mode: "deny" }));

  check(
    allow !== deny,
    format.respectsMode,
    `${format.id}: output differs by mode exactly when respectsMode says it does`,
  );
}

// --- header ------------------------------------------------------------
{
  const text = buildRules(input({ format: "iptables" }));
  truthy(text.startsWith("# Allow traffic for Google LLC (AS15169)"), "header names the source and ASN");
  truthy(text.includes("# 3 prefixes: 2 IPv4, 1 IPv6"), "header counts both families");
  truthy(text.includes("review before applying"), "header carries the caveat");

  const deny = buildRules(input({ format: "iptables", mode: "deny" }));
  truthy(deny.startsWith("# Block traffic for"), "deny mode says Block");

  const single = buildRules(input({ format: "iptables", ipv4: ["1.1.1.0/24"], ipv6: [] }));
  truthy(single.includes("# 1 prefix:"), "singular prefix is not pluralised");

  const noAsn = buildRules(input({ format: "iptables", asn: "" }));
  truthy(noAsn.startsWith("# Allow traffic for Google LLC\n"), "missing ASN leaves no empty parens");
}

// --- cidr --------------------------------------------------------------
{
  const text = buildRules(input({ format: "cidr" }));
  check(text.split("\n"), [...V4, ...V6], "cidr is the bare list, IPv4 first");
  truthy(!text.includes("#"), "cidr emits no comments");
}

// --- iptables ----------------------------------------------------------
{
  const allow = buildRules(input({ format: "iptables" }));
  truthy(allow.includes("iptables -A allow-as15169 -s 8.8.8.0/24 -j ACCEPT"), "IPv4 accepts into a dedicated chain");
  truthy(allow.includes("ip6tables -A allow-as15169 -s 2001:4860:4860::/48 -j ACCEPT"), "IPv6 uses ip6tables");
  truthy(!allow.includes("iptables -A allow-as15169 -s 2001:"), "IPv6 never lands in the v4 table");

  // An allowlist that never denies anything is a no-op on a default-ACCEPT chain.
  truthy(allow.includes("iptables -A allow-as15169 -j DROP"), "the v4 chain ends in a catch-all DROP");
  truthy(allow.includes("ip6tables -A allow-as15169 -j DROP"), "the v6 chain ends in a catch-all DROP");
  truthy(allow.includes("WARNING: this is an allowlist"), "allow mode warns about lockout");

  // The safety rules must be inserted ahead of the jump, or applying the file
  // kills the session that applied it.
  const lines = allow.split("\n");
  const loAt = lines.findIndex((l) => l.includes("-i lo -j ACCEPT"));
  const estAt = lines.findIndex((l) => l.includes("ESTABLISHED,RELATED"));
  const jumpAt = lines.findIndex((l) => l.includes("-I INPUT 3 -j allow-as15169"));
  truthy(loAt !== -1 && estAt !== -1 && jumpAt !== -1, "allow mode emits loopback, established and the jump");
  truthy(loAt < jumpAt && estAt < jumpAt, "loopback and established come before the jump");
  truthy(allow.includes("-I INPUT 1 -i lo"), "loopback is inserted at position 1");
  truthy(allow.includes("-I INPUT 2 -m conntrack"), "established is inserted at position 2");

  const deny = buildRules(input({ format: "iptables", mode: "deny" }));
  truthy(deny.includes("iptables -A block-as15169 -s 8.8.8.0/24 -j DROP"), "deny mode drops");
  truthy(!deny.includes("-j ACCEPT"), "deny mode emits no ACCEPT rule");
  truthy(!deny.includes("WARNING: this is an allowlist"), "deny mode does not warn about lockout");
  // Appending the jump would put it behind any pre-existing terminal ACCEPT.
  truthy(deny.includes("-I INPUT 1 -j block-as15169"), "the block chain is inserted at the top of INPUT");
  truthy(!deny.includes("-A INPUT -j block-as15169"), "the block chain is never appended");

  // Re-running must replace the rules, not stack a second copy.
  truthy(allow.includes("iptables -N allow-as15169 2>/dev/null || iptables -F allow-as15169"), "the chain is created or flushed");
  truthy(allow.includes("-C INPUT"), "the jump is only added when not already present");

  const v4Only = buildRules(input({ format: "iptables", ipv6: [] }));
  truthy(!v4Only.includes("ip6tables"), "no ip6tables section without IPv6");
  truthy(v4Only.includes("no IPv6 prefixes selected"), "an empty family is called out, since it stays unfiltered");

  const v6Only = buildRules(input({ format: "iptables", ipv4: [] }));
  truthy(!/\niptables /.test(v6Only), "no iptables section without IPv4");
  truthy(v6Only.includes("no IPv4 prefixes selected"), "the empty IPv4 family is called out");
  check(v6Only.split("\n").filter((l) => l.startsWith("ip6tables -A allow-as15169 -s ")).length, 1, "one rule per IPv6 prefix");
}

// --- nftables ----------------------------------------------------------
{
  const text = buildRules(input({ format: "nftables" }));
  truthy(text.includes("table inet filter {"), "opens an inet table");
  truthy(text.includes("type ipv4_addr"), "declares the v4 set type");
  truthy(text.includes("type ipv6_addr"), "declares the v6 set type");
  truthy(text.includes("flags interval"), "interval flag is required for CIDR elements");
  check(
    text.split("\n").filter((l) => l.trim() === "auto-merge").length,
    2,
    "both sets auto-merge, or overlapping BGP prefixes refuse to load",
  );
  truthy(
    text.includes("elements = {\n      8.8.8.0/24, 8.8.4.0/24\n    }"),
    "v4 elements wrap inside the braces",
  );

  // Without policy drop the ruleset loads cleanly and filters nothing.
  truthy(text.includes("type filter hook input priority 0; policy drop;"), "an allowlist chain defaults to drop");
  truthy(text.includes("iif lo accept"), "loopback survives the drop policy");
  truthy(text.includes("ct state established,related accept"), "established traffic survives the drop policy");
  truthy(text.includes("ip saddr @allowlist_v4 accept"), "v4 rule references the v4 set");
  truthy(text.includes("ip6 saddr @allowlist_v6 accept"), "v6 rule references the v6 set");

  const deny = buildRules(input({ format: "nftables", mode: "deny" }));
  truthy(deny.includes("set blocklist_v4 {"), "a block set is not called an allowlist");
  truthy(deny.includes("set blocklist_v6 {"), "the v6 block set is named for what it does");
  truthy(!deny.includes("allowlist"), "nothing in block mode mentions an allowlist");
  truthy(deny.includes("@blocklist_v4 drop"), "deny mode drops");
  // A blocklist must NOT close the chain; only the listed prefixes are denied.
  truthy(!deny.includes("policy drop"), "block mode leaves the chain's default alone");

  const v4Only = buildRules(input({ format: "nftables", ipv6: [] }));
  truthy(!v4Only.includes("ipv6_addr"), "no v6 set when there are no v6 prefixes");
  truthy(!v4Only.includes("ip6 saddr"), "no v6 rule when there is no v6 set");

  // Elements wrap four to a line, and only the last line omits the comma.
  const many = Array.from({ length: 10 }, (_, i) => `10.${i}.0.0/24`);
  const wrapped = buildRules(input({ format: "nftables", ipv4: many, ipv6: [] }));
  const elementLines = wrapped.split("\n").filter((line) => line.startsWith("      10."));
  check(elementLines.length, 3, "ten elements wrap onto three lines");
  check(
    elementLines[0],
    "      10.0.0.0/24, 10.1.0.0/24, 10.2.0.0/24, 10.3.0.0/24,",
    "a full line ends with a comma",
  );
  check(elementLines[2], "      10.8.0.0/24, 10.9.0.0/24", "the last line has no trailing comma");
  check(
    [...wrapped.matchAll(/10\.\d+\.0\.0\/24/g)].length,
    10,
    "every element survives the wrapping exactly once",
  );
}

// --- nginx -------------------------------------------------------------
{
  const allow = buildRules(input({ format: "nginx" }));
  truthy(allow.includes("allow 8.8.8.0/24;"), "allow directive per prefix");
  truthy(allow.includes("allow 2001:4860:4860::/48;"), "IPv6 uses the same directive");
  truthy(allow.trimEnd().endsWith("deny all;"), "allow mode closes with deny all");
  truthy(allow.includes("review before applying.\n\nallow "), "a blank line separates the header from the rules");
  check(allow.split("\n").filter((l) => l.startsWith("allow ")).length, 3, "one allow per prefix");

  const deny = buildRules(input({ format: "nginx", mode: "deny" }));
  truthy(deny.includes("deny 8.8.8.0/24;"), "deny directive per prefix");
  truthy(!deny.includes("deny all;"), "deny mode must not block everything else");
  truthy(!deny.includes("allow "), "deny mode emits no allow directives");
}

// --- apache ------------------------------------------------------------
{
  const allow = buildRules(input({ format: "apache" }));
  truthy(allow.includes("<RequireAny>"), "allow mode uses RequireAny");
  truthy(allow.includes("  Require ip 8.8.8.0/24"), "allow lists each prefix");
  truthy(allow.includes("</RequireAny>"), "RequireAny is closed");
  truthy(!allow.includes("Require not"), "allow mode has no negations");

  const deny = buildRules(input({ format: "apache", mode: "deny" }));
  truthy(deny.includes("<RequireAll>"), "deny mode uses RequireAll");
  truthy(deny.includes("  Require all granted"), "deny mode grants by default");
  truthy(deny.includes("  Require not ip 2001:4860:4860::/48"), "deny negates each prefix");
  truthy(deny.includes("</RequireAll>"), "RequireAll is closed");
}

// --- aws cli -----------------------------------------------------------
{
  const text = buildRules(input({ format: "aws-cli" }));
  truthy(text.includes("aws ec2 authorize-security-group-ingress"), "allow mode authorises");
  truthy(text.includes('"IpRanges":[{"CidrIp":"8.8.8.0/24"},{"CidrIp":"8.8.4.0/24"}]'), "v4 ranges inline");
  truthy(text.includes('"Ipv6Ranges":[{"CidrIpv6":"2001:4860:4860::/48"}]'), "v6 uses Ipv6Ranges/CidrIpv6");
  truthy(!text.includes('"CidrIp":"2001:'), "v6 never uses the v4 key");
  truthy(text.includes("sg-REPLACE_ME"), "the group id is an obvious placeholder");

  // Security groups are allow-only, so revoking a grant cannot block anything.
  const deny = buildRules(input({ format: "aws-cli", mode: "deny" }));
  truthy(!deny.includes("revoke-security-group-ingress"), "block mode does not pretend a revoke is a block");
  truthy(!deny.includes("authorize-security-group-ingress"), "block mode does not authorise");
  truthy(deny.includes("create-network-acl-entry"), "block mode uses the one AWS primitive that denies");
  truthy(deny.includes("--rule-action deny"), "the NACL entry actually denies");
  truthy(deny.includes("--ingress"), "the NACL entry applies inbound");
  truthy(deny.includes("--cidr-block"), "IPv4 uses --cidr-block");
  truthy(deny.includes("--ipv6-cidr-block"), "IPv6 uses --ipv6-cidr-block");
  truthy(deny.includes("RULE=$((RULE + 1))"), "rule numbers increment, since NACL entries must be unique");
  truthy(deny.includes("20 rules"), "the NACL quota is stated rather than hidden");

  // 130 prefixes must split into three batches of 60/60/10.
  const many = Array.from({ length: 130 }, (_, i) => `10.${i}.0.0/24`);
  const batched = buildRules(input({ format: "aws-cli", ipv4: many, ipv6: [] }));
  const calls = batched.split("\n").filter((l) => l.startsWith("aws ec2 "));
  check(calls.length, 3, "130 prefixes become three CLI calls");
  const emitted = [...batched.matchAll(/"CidrIp":"([^"]+)"/g)].map((m) => m[1]);
  check(emitted.length, 130, "every prefix is emitted exactly once");
  check(emitted, many, "batching preserves order with no gaps or repeats");
}

// --- terraform ---------------------------------------------------------
{
  const text = buildRules(input({ format: "terraform" }));
  truthy(text.includes('resource "aws_security_group_rule" "google_llc_allow" {'), "name is slugged and carries the mode");
  truthy(text.includes('type              = "ingress"'), "allow mode is ingress");
  truthy(text.includes('cidr_blocks       = ["8.8.8.0/24", "8.8.4.0/24"]'), "v4 list is quoted");
  truthy(text.includes('ipv6_cidr_blocks  = ["2001:4860:4860::/48"]'), "v6 list is separate");
  truthy(text.trimEnd().endsWith("}"), "the resource block is closed");

  // A security group rule is always a permit, so "egress" blocks nothing.
  const deny = buildRules(input({ format: "terraform", mode: "deny" }));
  truthy(!deny.includes('type              = "egress"'), "block mode does not emit an egress permit");
  truthy(!deny.includes("aws_security_group_rule"), "block mode does not use an allow-only resource");
  truthy(deny.includes('resource "aws_network_acl_rule"'), "block mode uses a resource that can deny");
  truthy(deny.includes('rule_action    = "deny"'), "the NACL rule denies");
  truthy(deny.includes("egress         = false"), "the NACL rule applies inbound");
  truthy(deny.includes("for_each"), "prefixes expand with for_each rather than one resource each");
  truthy(deny.includes("20 rules"), "the NACL quota is stated rather than hidden");

  // Allow and deny must be able to coexist in one state file.
  const allowNames = [...text.matchAll(/resource "[^"]+" "([^"]+)"/g)].map((m) => m[1]);
  const denyNames = [...deny.matchAll(/resource "[^"]+" "([^"]+)"/g)].map((m) => m[1]);
  check(
    allowNames.filter((name) => denyNames.includes(name)).length,
    0,
    "no resource label collides between allow and block",
  );

  const v4Only = buildRules(input({ format: "terraform", ipv6: [] }));
  truthy(!v4Only.includes("ipv6_cidr_blocks"), "no empty v6 attribute");

  const numeric = buildRules(input({ format: "terraform", source: "3M Company" }));
  truthy(numeric.includes('"asn_3m_company_allow"'), "an identifier may not start with a digit");

  const punctuated = buildRules(input({ format: "terraform", source: "Akamai Technologies, Inc." }));
  truthy(punctuated.includes('"akamai_technologies_inc_allow"'), "punctuation is stripped, no trailing underscore");

  const blank = buildRules(input({ format: "terraform", source: "!!!" }));
  truthy(blank.includes('"generated_allow"'), "an unusable name falls back to a valid identifier");
}

// --- cloudflare --------------------------------------------------------
{
  const allow = buildRules(input({ format: "cloudflare" }));
  truthy(allow.includes("(ip.src not in {8.8.8.0/24 8.8.4.0/24 2001:4860:4860::/48})"), "allow inverts the set");
  truthy(allow.includes("anything NOT in the list is blocked"), "allow explains the inversion");

  const deny = buildRules(input({ format: "cloudflare", mode: "deny" }));
  truthy(deny.includes("(ip.src in {"), "deny matches the set directly");
  truthy(!deny.includes("not in"), "deny does not invert");
}

// --- windows -----------------------------------------------------------
{
  const text = buildRules(input({ format: "windows" }));
  // The file downloads as .ps1, so REM (batch syntax) would error on line 1.
  truthy(text.startsWith("# Allow traffic for"), "comments use PowerShell syntax");
  truthy(!text.includes("REM "), "no batch-style comments in a PowerShell script");
  truthy(text.includes('-DisplayName "Allow Google LLC"'), "rule name is quoted");
  truthy(text.includes("-Direction Inbound"), "the rule applies inbound");
  truthy(text.includes("-Action Allow"), "allow mode allows");
  truthy(text.includes('  "8.8.8.0/24",'), "prefixes go in an array, not one long argument");
  truthy(text.includes('  "2001:4860:4860::/48"'), "the last array entry has no trailing comma");
  truthy(text.includes("-RemoteAddress $prefixes"), "the array is passed to the rule");
  truthy(text.includes("DefaultInboundAction Block"), "an allow rule alone filters nothing, and the file says so");

  const deny = buildRules(input({ format: "windows", mode: "deny" }));
  truthy(deny.includes("-Action Block"), "deny mode blocks");
  truthy(deny.includes('-DisplayName "Block Google LLC"'), "rule name matches the mode");
  truthy(!deny.includes("DefaultInboundAction"), "a block rule needs no default-action advice");
}

// --- json --------------------------------------------------------------
{
  const text = buildRules(input({ format: "json" }));
  const parsed = JSON.parse(text);
  check(parsed.source, "Google LLC", "source round-trips");
  check(parsed.asn, "AS15169", "asn round-trips");
  check(parsed.mode, "allow", "mode round-trips");
  check(parsed.counts, { ipv4: 2, ipv6: 1, total: 3 }, "counts are correct");
  check(parsed.prefixes.ipv4, V4, "v4 prefixes round-trip");
  check(parsed.prefixes.ipv6, V6, "v6 prefixes round-trip");
}

// --- no format leaks the wrong family ----------------------------------
for (const format of FORMATS) {
  const v4Only = buildRules(input({ format: format.id, ipv6: [] }));
  truthy(!v4Only.includes("2001:4860"), `${format.id} emits no IPv6 when filtered out`);

  const v6Only = buildRules(input({ format: format.id, ipv4: [] }));
  truthy(!v6Only.includes("8.8.8.0"), `${format.id} emits no IPv4 when filtered out`);
}


// --- sorting -----------------------------------------------------------
{
  const shuffled = ["8.8.8.0/24", "1.1.1.0/24", "203.0.113.0/24", "10.0.0.0/8"];
  check(
    partitionPrefixes(shuffled, "v4").ipv4,
    ["1.1.1.0/24", "8.8.8.0/24", "10.0.0.0/8", "203.0.113.0/24"],
    "IPv4 sorts numerically, not as text",
  );

  check(
    partitionPrefixes(["192.0.2.0/25", "192.0.2.0/24"], "v4").ipv4,
    ["192.0.2.0/24", "192.0.2.0/25"],
    "the shorter prefix comes first at the same address",
  );

  check(
    partitionPrefixes(["255.255.255.0/24", "128.0.0.0/8"], "v4").ipv4,
    ["128.0.0.0/8", "255.255.255.0/24"],
    "addresses above 127 do not sort as negative numbers",
  );

  check(
    partitionPrefixes(["2606:4700::/32", "2001:4860::/32", "::/0"], "v6").ipv6,
    ["::/0", "2001:4860::/32", "2606:4700::/32"],
    "IPv6 sorts by its 128-bit value",
  );

  check(
    partitionPrefixes(["2001:db8:0:2::/64", "2001:0db8:0:1::/64"], "v6").ipv6,
    ["2001:0db8:0:1::/64", "2001:db8:0:2::/64"],
    "zero-padded and compressed spellings compare the same way",
  );

  check(
    partitionPrefixes(["2001:db8::/48", "2001:db8::/32"], "v6").ipv6,
    ["2001:db8::/32", "2001:db8::/48"],
    "IPv6 ties break on prefix length",
  );

  check(
    partitionPrefixes(["ffff:ffff::/32", "2001:db8::/32"], "v6").ipv6,
    ["2001:db8::/32", "ffff:ffff::/32"],
    "the top of the IPv6 space sorts last",
  );

  check(
    partitionPrefixes(["2001:db8:0:0:0:0:0:0/32", "2001:db8::/32"], "v6").ipv6.length,
    2,
    "a fully expanded address still sorts without throwing",
  );
}


// --- duplicates ---------------------------------------------------------
{
  const repeated = ["1.1.1.0/24", "8.8.8.0/24", "1.1.1.0/24", "2606:4700::/32", "2606:4700::/32"];
  const split = partitionPrefixes(repeated, "both");
  check(split.ipv4, ["1.1.1.0/24", "8.8.8.0/24"], "a repeated IPv4 prefix appears once");
  check(split.ipv6, ["2606:4700::/32"], "a repeated IPv6 prefix appears once");

  // AWS and Terraform both reject a list containing the same CIDR twice.
  const aws = buildRules(input({ format: "aws-cli", ipv4: split.ipv4, ipv6: split.ipv6 }));
  check([...aws.matchAll(/"CidrIp":"1\.1\.1\.0\/24"/g)].length, 1, "no duplicate CIDR reaches the AWS call");
}

console.log(`rule-formats: ${checks} assertions passed`);
