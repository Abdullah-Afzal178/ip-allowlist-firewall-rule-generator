/**
 * Turns a list of CIDR prefixes into copy-paste firewall rules. Pure and
 * dependency-free so every output format can be unit tested.
 */

export type RuleMode = "allow" | "deny";
export type IpVersionFilter = "both" | "v4" | "v6";

export type FormatId =
  | "cidr"
  | "iptables"
  | "nftables"
  | "nginx"
  | "apache"
  | "aws-cli"
  | "terraform"
  | "cloudflare"
  | "windows"
  | "json";

export type FormatMeta = {
  id: FormatId;
  label: string;
  /** Syntax hint and file extension for the download. */
  extension: string;
  /** Shown under the tab bar. */
  note: string;
  /** True when the format needs IPv4 and IPv6 emitted separately. */
  splitsByVersion: boolean;
  /**
   * False when the format has no allow/deny verb of its own, so the rule-type
   * toggle cannot change a single byte of its output.
   */
  respectsMode: boolean;
};

export const FORMATS: FormatMeta[] = [
  {
    id: "cidr",
    label: "CIDR list",
    extension: "txt",
    note: "One prefix per line — the raw list, for anything that takes a plain file.",
    respectsMode: false,
    splitsByVersion: false,
  },
  {
    id: "iptables",
    label: "iptables",
    extension: "sh",
    note: "IPv4 rules use iptables, IPv6 rules use ip6tables — they are separate tables.",
    respectsMode: true,
    splitsByVersion: true,
  },
  {
    id: "nftables",
    label: "nftables",
    extension: "nft",
    note: "A set per address family, which scales far better than one rule per prefix. auto-merge folds the overlapping prefixes a real routing table always contains.",
    respectsMode: true,
    splitsByVersion: true,
  },
  {
    id: "nginx",
    label: "nginx",
    extension: "conf",
    note: "Drop inside a server or location block. nginx handles both families in one directive.",
    respectsMode: true,
    splitsByVersion: false,
  },
  {
    id: "apache",
    label: "Apache",
    extension: "conf",
    note: "Apache 2.4 syntax. Use inside a Directory, Location, or .htaccess context.",
    respectsMode: true,
    splitsByVersion: false,
  },
  {
    id: "aws-cli",
    label: "AWS CLI",
    extension: "sh",
    note: "Security groups cap rules per group, so large lists are split into batches.",
    respectsMode: true,
    splitsByVersion: true,
  },
  {
    id: "terraform",
    label: "Terraform",
    extension: "tf",
    note: "A security group rule with the prefixes inline.",
    respectsMode: true,
    splitsByVersion: true,
  },
  {
    id: "cloudflare",
    label: "Cloudflare",
    extension: "txt",
    note: "One expression for a WAF custom rule. Cloudflare caps expression length, so a very large network needs an IP List instead.",
    respectsMode: true,
    splitsByVersion: false,
  },
  {
    id: "windows",
    label: "Windows",
    extension: "ps1",
    note: "netsh advfirewall, one rule covering all prefixes. A very long list can exceed the command-line limit.",
    respectsMode: true,
    splitsByVersion: false,
  },
  {
    id: "json",
    label: "JSON",
    extension: "json",
    note: "Structured output for your own tooling.",
    respectsMode: true,
    splitsByVersion: false,
  },
];

export function isFormatId(value: string): value is FormatId {
  return FORMATS.some((format) => format.id === value);
}

export type RuleInput = {
  /** Display name of the source, e.g. "Google LLC". */
  source: string;
  asn: string;
  ipv4: string[];
  ipv6: string[];
  mode: RuleMode;
  format: FormatId;
};

/** Builds the rule text for one format. */
export function buildRules(input: RuleInput): string {
  const { ipv4, ipv6 } = input;

  if (ipv4.length === 0 && ipv6.length === 0) {
    // JSON has to stay parseable even when there is nothing to say, or the
    // .json download is a syntax error rather than an empty result.
    return input.format === "json"
      ? json(input)
      : "# No prefixes to emit for the selected filters.";
  }

  switch (input.format) {
    case "cidr":
      return [...ipv4, ...ipv6].join("\n");
    case "iptables":
      return iptables(input);
    case "nftables":
      return nftables(input);
    case "nginx":
      return nginx(input);
    case "apache":
      return apache(input);
    case "aws-cli":
      return awsCli(input);
    case "terraform":
      return terraform(input);
    case "cloudflare":
      return cloudflare(input);
    case "windows":
      return windows(input);
    case "json":
      return json(input);
    default:
      return "";
  }
}

function header(input: RuleInput): string {
  const verb = input.mode === "allow" ? "Allow" : "Block";
  const total = input.ipv4.length + input.ipv6.length;

  return [
    `# ${verb} traffic for ${input.source}${input.asn ? ` (${input.asn})` : ""}`,
    `# ${total} prefix${total === 1 ? "" : "es"}: ${input.ipv4.length} IPv4, ${input.ipv6.length} IPv6`,
    "# Generated from announced BGP routes — review before applying.",
  ].join("\n");
}

/**
 * An allowlist only filters if everything unlisted is denied. Saying so is not
 * optional: these rules will cut off any session that is not in the list.
 */
const LOCKOUT_WARNING = [
  "# WARNING: this is an allowlist. Everything not listed below is dropped,",
  "# including the session you are applying it from. Keep a console or",
  "# out-of-band login open until you have confirmed it works.",
].join("\n");

/** Warns when one address family has no prefixes and so is left wide open. */
function openFamilyWarning(input: RuleInput): string[] {
  if (input.mode !== "allow") {
    return [];
  }

  if (input.ipv4.length === 0) {
    return ["", "# Note: no IPv4 prefixes selected, so IPv4 is left unfiltered by this file."];
  }

  if (input.ipv6.length === 0) {
    return ["", "# Note: no IPv6 prefixes selected, so IPv6 is left unfiltered by this file."];
  }

  return [];
}

/** A chain name iptables will accept: short, lowercase, no punctuation. */
function chainName(input: RuleInput): string {
  const asn = (input.asn || "net").toLowerCase().replace(/[^a-z0-9]/g, "");

  return `${input.mode === "allow" ? "allow" : "block"}-${asn}`.slice(0, 28);
}

function iptables(input: RuleInput): string {
  const chain = chainName(input);
  const blocks: string[] = [header(input)];

  if (input.mode === "allow") {
    blocks.push("", LOCKOUT_WARNING);
  }

  blocks.push(...openFamilyWarning(input));
  blocks.push(
    "",
    "# A dedicated chain, so re-running this replaces the rules instead of",
    "# stacking a second copy behind the first.",
  );

  const emit = (command: "iptables" | "ip6tables", prefixes: string[], label: string) => {
    if (prefixes.length === 0) {
      return;
    }

    blocks.push("", `# ${label}`, `${command} -N ${chain} 2>/dev/null || ${command} -F ${chain}`);

    const target = input.mode === "allow" ? "ACCEPT" : "DROP";

    for (const cidr of prefixes) {
      blocks.push(`${command} -A ${chain} -s ${cidr} -j ${target}`);
    }

    if (input.mode === "allow") {
      blocks.push(
        `${command} -A ${chain} -j DROP`,
        "",
        `# Loopback and established traffic first, or the chain kills this session.`,
        `${command} -C INPUT -i lo -j ACCEPT 2>/dev/null || ${command} -I INPUT 1 -i lo -j ACCEPT`,
        `${command} -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ${command} -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
        `${command} -C INPUT -j ${chain} 2>/dev/null || ${command} -I INPUT 3 -j ${chain}`,
      );
    } else {
      blocks.push(
        "",
        "# Inserted at the top, so it is reached before any existing ACCEPT.",
        `${command} -C INPUT -j ${chain} 2>/dev/null || ${command} -I INPUT 1 -j ${chain}`,
      );
    }
  };

  emit("iptables", input.ipv4, "IPv4");
  emit("ip6tables", input.ipv6, "IPv6");

  return blocks.join("\n");
}

function nftables(input: RuleInput): string {
  const allow = input.mode === "allow";
  const verdict = allow ? "accept" : "drop";
  const setBase = allow ? "allowlist" : "blocklist";
  const blocks: string[] = [header(input)];

  if (allow) {
    blocks.push("", LOCKOUT_WARNING);
  }

  blocks.push(...openFamilyWarning(input));
  blocks.push("", "table inet filter {");

  if (input.ipv4.length > 0) {
    blocks.push(
      `  set ${setBase}_v4 {`,
      "    type ipv4_addr",
      "    flags interval",
      "    auto-merge",
      "    elements = {",
      ...wrapElements(input.ipv4),
      "    }",
      "  }",
    );
  }

  if (input.ipv6.length > 0) {
    blocks.push(
      `  set ${setBase}_v6 {`,
      "    type ipv6_addr",
      "    flags interval",
      "    auto-merge",
      "    elements = {",
      ...wrapElements(input.ipv6),
      "    }",
      "  }",
    );
  }

  blocks.push(
    "",
    "  chain input {",
    // Without policy drop an allowlist loads cleanly and filters nothing:
    // the chain's default is accept, so every unlisted packet still gets in.
    allow
      ? "    type filter hook input priority 0; policy drop;"
      : "    type filter hook input priority 0;",
  );

  if (allow) {
    blocks.push("    iif lo accept", "    ct state established,related accept");
  }

  if (input.ipv4.length > 0) {
    blocks.push(`    ip saddr @${setBase}_v4 ${verdict}`);
  }

  if (input.ipv6.length > 0) {
    blocks.push(`    ip6 saddr @${setBase}_v6 ${verdict}`);
  }

  blocks.push("  }", "}");

  return blocks.join("\n");
}

/** nft accepts one long line, but a set with thousands of entries is unreadable. */
const ELEMENTS_PER_LINE = 4;

function wrapElements(prefixes: string[]): string[] {
  const lines: string[] = [];

  for (let index = 0; index < prefixes.length; index += ELEMENTS_PER_LINE) {
    const chunk = prefixes.slice(index, index + ELEMENTS_PER_LINE);
    const last = index + ELEMENTS_PER_LINE >= prefixes.length;

    lines.push(`      ${chunk.join(", ")}${last ? "" : ","}`);
  }

  return lines;
}

function nginx(input: RuleInput): string {
  const directive = input.mode === "allow" ? "allow" : "deny";
  const lines = [header(input), ""];

  for (const cidr of [...input.ipv4, ...input.ipv6]) {
    lines.push(`${directive} ${cidr};`);
  }

  if (input.mode === "allow") {
    lines.push("", "# Without this the allow directives above filter nothing.", "deny all;");
  }

  return lines.join("\n");
}

function apache(input: RuleInput): string {
  const prefixes = [...input.ipv4, ...input.ipv6];
  const lines =
    input.mode === "allow"
      ? ["<RequireAny>", ...prefixes.map((cidr) => `  Require ip ${cidr}`), "</RequireAny>"]
      : [
          "<RequireAll>",
          "  Require all granted",
          ...prefixes.map((cidr) => `  Require not ip ${cidr}`),
          "</RequireAll>",
        ];

  return [header(input), "", ...lines].join("\n");
}

/** Security groups cap entries per rule, so prefixes are batched. */
const AWS_BATCH = 60;

/** Network ACLs are the only AWS primitive that can actually deny by address. */
const NACL_QUOTA_NOTE = [
  "# Security groups cannot deny — they are allow-only and already default-deny,",
  "# so blocking has to go through a network ACL. Note that a NACL holds 20 rules",
  "# by default (40 is the hard ceiling), so for a list this size use a",
  "# WAF IPSet, AWS Network Firewall, or a prefix list instead.",
].join("\n");

function awsCli(input: RuleInput): string {
  const blocks: string[] = [header(input)];

  if (input.mode === "deny") {
    blocks.push("", NACL_QUOTA_NOTE, "", 'ACL_ID="acl-REPLACE_ME"', "RULE=100", "");

    const emitDeny = (prefixes: string[], flag: "--cidr-block" | "--ipv6-cidr-block", label: string) => {
      if (prefixes.length === 0) {
        return;
      }

      blocks.push(
        `# ${label}`,
        "for cidr in \\",
        ...prefixes.map((cidr, index) => `  ${cidr}${index === prefixes.length - 1 ? "" : " \\"}`),
        "do",
        '  aws ec2 create-network-acl-entry --network-acl-id "$ACL_ID" \\',
        '    --rule-number "$RULE" --protocol -1 --rule-action deny --ingress \\',
        `    ${flag} "$cidr"`,
        "  RULE=$((RULE + 1))",
        "done",
        "",
      );
    };

    emitDeny(input.ipv4, "--cidr-block", "IPv4");
    emitDeny(input.ipv6, "--ipv6-cidr-block", "IPv6");

    return blocks.join("\n").trimEnd();
  }

  const emit = (prefixes: string[], key: "CidrIp" | "CidrIpv6") => {
    for (let index = 0; index < prefixes.length; index += AWS_BATCH) {
      const batch = prefixes.slice(index, index + AWS_BATCH);
      const ranges = batch.map((cidr) => `{"${key}":"${cidr}"}`).join(",");
      const field = key === "CidrIp" ? "IpRanges" : "Ipv6Ranges";

      blocks.push(
        "",
        "aws ec2 authorize-security-group-ingress \\",
        "  --group-id sg-REPLACE_ME \\",
        `  --ip-permissions '[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"${field}":[${ranges}]}]'`,
      );
    }
  };

  if (input.ipv4.length > 0) {
    blocks.push("", "# IPv4");
    emit(input.ipv4, "CidrIp");
  }

  if (input.ipv6.length > 0) {
    blocks.push("", "# IPv6");
    emit(input.ipv6, "CidrIpv6");
  }

  return blocks.join("\n");
}

function terraform(input: RuleInput): string {
  const name = `${slug(input.source)}_${input.mode}`;
  const blocks: string[] = [header(input)];

  if (input.mode === "deny") {
    blocks.push("", NACL_QUOTA_NOTE, "", "locals {");

    if (input.ipv4.length > 0) {
      blocks.push(`  ${name}_v4 = [${input.ipv4.map(quote).join(", ")}]`);
    }

    if (input.ipv6.length > 0) {
      blocks.push(`  ${name}_v6 = [${input.ipv6.map(quote).join(", ")}]`);
    }

    blocks.push("}");

    const emitDeny = (suffix: "v4" | "v6", attribute: string, base: number) => {
      const prefixes = suffix === "v4" ? input.ipv4 : input.ipv6;

      if (prefixes.length === 0) {
        return;
      }

      // terraform fmt aligns every "=" in a block, so the width depends on the
      // longest key present, which differs between the v4 and v6 resources.
      const keys = ["for_each", "network_acl_id", "rule_number", "egress", "protocol", "rule_action", attribute];
      const width = Math.max(...keys.map((key) => key.length));
      const pad = (key: string) => `  ${key.padEnd(width)} =`;

      blocks.push(
        "",
        `resource "aws_network_acl_rule" "${name}_${suffix}" {`,
        `${pad("for_each")} { for index, cidr in local.${name}_${suffix} : tostring(index) => cidr }`,
        `${pad("network_acl_id")} var.network_acl_id`,
        `${pad("rule_number")} ${base} + tonumber(each.key)`,
        `${pad("egress")} false`,
        `${pad("protocol")} "-1"`,
        `${pad("rule_action")} "deny"`,
        `${pad(attribute)} each.value`,
        "}",
      );
    };

    emitDeny("v4", "cidr_block", 100);
    emitDeny("v6", "ipv6_cidr_block", 20000);

    return blocks.join("\n");
  }

  blocks.push(
    "",
    `resource "aws_security_group_rule" "${name}" {`,
    '  type              = "ingress"',
    "  from_port         = 443",
    "  to_port           = 443",
    '  protocol          = "tcp"',
    "  security_group_id = var.security_group_id",
  );

  if (input.ipv4.length > 0) {
    blocks.push(`  cidr_blocks       = [${input.ipv4.map(quote).join(", ")}]`);
  }

  if (input.ipv6.length > 0) {
    blocks.push(`  ipv6_cidr_blocks  = [${input.ipv6.map(quote).join(", ")}]`);
  }

  blocks.push("}");

  return blocks.join("\n");
}

function cloudflare(input: RuleInput): string {
  const prefixes = [...input.ipv4, ...input.ipv6];
  const operator = input.mode === "allow" ? "not in" : "in";

  return [
    header(input),
    "",
    `(ip.src ${operator} {${prefixes.join(" ")}})`,
    "",
    input.mode === "allow"
      ? "# Use with a Block action: anything NOT in the list is blocked."
      : "# Use with a Block action: anything in the list is blocked.",
  ].join("\n");
}

function windows(input: RuleInput): string {
  const prefixes = [...input.ipv4, ...input.ipv6];
  const allow = input.mode === "allow";
  const name = `${allow ? "Allow" : "Block"} ${input.source}`;
  const lines = [header(input)];

  if (allow) {
    lines.push("", LOCKOUT_WARNING);
  }

  lines.push(
    "",
    "$prefixes = @(",
    ...prefixes.map((cidr, index) => `  "${cidr}"${index === prefixes.length - 1 ? "" : ","}`),
    ")",
    "",
    `New-NetFirewallRule \`` ,
    `  -DisplayName ${JSON.stringify(name)} \`` ,
    "  -Direction Inbound \`",
    `  -Action ${allow ? "Allow" : "Block"} \`` ,
    "  -RemoteAddress $prefixes",
  );

  if (allow) {
    lines.push(
      "",
      "# An Allow rule on its own filters nothing — Windows permits what is not",
      "# explicitly blocked. Set the profile's default inbound action to Block:",
      "# Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block",
    );
  }

  return lines.join("\n");
}

function json(input: RuleInput): string {
  return JSON.stringify(
    {
      source: input.source,
      asn: input.asn,
      mode: input.mode,
      counts: {
        ipv4: input.ipv4.length,
        ipv6: input.ipv6.length,
        total: input.ipv4.length + input.ipv6.length,
      },
      prefixes: { ipv4: input.ipv4, ipv6: input.ipv6 },
    },
    null,
    2,
  );
}

function quote(value: string) {
  return `"${value}"`;
}

function slug(value: string) {
  const cleaned = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");

  // Terraform identifiers cannot start with a digit.
  return /^[0-9]/.test(cleaned) ? `asn_${cleaned}` : cleaned || "generated";
}

/**
 * Splits a mixed prefix list by address family, sorts each numerically, and
 * applies the version filter. The API returns routes in announcement order,
 * which reads as noise in a config file.
 */
export function partitionPrefixes(prefixes: string[], filter: IpVersionFilter) {
  // A repeated prefix is an error to several of these tools, not a harmless
  // duplicate, so drop them before anything else sees the list.
  const unique = [...new Set(prefixes)];
  const ipv4 = unique.filter((prefix) => !prefix.includes(":")).sort(compareV4);
  const ipv6 = unique.filter((prefix) => prefix.includes(":")).sort(compareV6);

  return {
    ipv4: filter === "v6" ? [] : ipv4,
    ipv6: filter === "v4" ? [] : ipv6,
  };
}

function compareV4(a: string, b: string) {
  const left = v4Key(a);
  const right = v4Key(b);

  return left.address - right.address || left.length - right.length;
}

function v4Key(prefix: string) {
  const [address, length] = prefix.split("/");
  const octets = address.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const value =
    ((octets[0] ?? 0) << 24) + ((octets[1] ?? 0) << 16) + ((octets[2] ?? 0) << 8) + (octets[3] ?? 0);

  // Shifting past bit 31 produces a negative number, so fold it back.
  return { address: value >>> 0, length: Number.parseInt(length, 10) || 0 };
}

function compareV6(a: string, b: string) {
  const left = v6Key(a);
  const right = v6Key(b);

  if (left.address !== right.address) {
    return left.address < right.address ? -1 : 1;
  }

  return left.length - right.length;
}

function v6Key(prefix: string) {
  const [address, length] = prefix.split("/");

  return { address: expandV6(address), length: Number.parseInt(length, 10) || 0 };
}

/** Turns any IPv6 spelling into its 128-bit value for ordering. */
function expandV6(address: string): bigint {
  const [head, tail = ""] = address.split("::");
  const headGroups = head === "" ? [] : head.split(":");
  const tailGroups = tail === "" ? [] : tail.split(":");
  const missing = 8 - headGroups.length - tailGroups.length;
  const groups = address.includes("::")
    ? [...headGroups, ...Array(Math.max(missing, 0)).fill("0"), ...tailGroups]
    : headGroups;

  let value = 0n;

  for (let index = 0; index < 8; index += 1) {
    const group = Number.parseInt(groups[index] ?? "0", 16);
    value = (value << 16n) + BigInt(Number.isFinite(group) ? group : 0);
  }

  return value;
}

export function formatFor(id: FormatId): FormatMeta {
  return FORMATS.find((format) => format.id === id) ?? FORMATS[0];
}
