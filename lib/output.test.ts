import assert from "node:assert/strict";

import { DEFAULT_CONTROLS, type Controls } from "@/lib/controls";
import type { PrefixSource } from "@/lib/prefixes";
import { buildOutput, previewOf } from "@/lib/output";

let checks = 0;
function check(actual: unknown, expected: unknown, message: string) {
  checks += 1;
  assert.deepEqual(actual, expected, message);
}
function truthy(value: unknown, message: string) {
  checks += 1;
  assert.ok(value, message);
}

const SOURCE: PrefixSource = {
  asn: "AS13335",
  organization: "Cloudflare, Inc.",
  asnName: "CLOUDFLARENET",
  country: "US",
  type: "HOSTING",
  rir: "ARIN",
  domain: "cloudflare.com",
  // Deliberately unsorted and interleaved, the way the API returns them.
  routes: ["104.28.170.0/24", "2400:cb00:dd22::/48", "1.1.1.0/24"],
  declaredIpv4: 2,
  declaredIpv6: 1,
  resolvedFrom: null,
};

function controls(overrides: Partial<Controls> = {}): Controls {
  return { ...DEFAULT_CONTROLS, query: "AS13335", ...overrides };
}

// --- counts and ordering -----------------------------------------------
{
  const out = buildOutput(controls(), SOURCE);
  check(out.ipv4Count, 2, "two IPv4 prefixes");
  check(out.ipv6Count, 1, "one IPv6 prefix");
  check(out.totalLines, 3, "three lines in the CIDR list");
  check(
    out.text.split("\n"),
    ["1.1.1.0/24", "104.28.170.0/24", "2400:cb00:dd22::/48"],
    "prefixes come out sorted, IPv4 first",
  );
}

// --- the version filter reaches the counts ------------------------------
{
  const v4 = buildOutput(controls({ version: "v4" }), SOURCE);
  check([v4.ipv4Count, v4.ipv6Count], [2, 0], "the v4 filter zeroes the v6 count");
  truthy(!v4.text.includes("2400:"), "the v4 filter removes IPv6 from the text");

  const v6 = buildOutput(controls({ version: "v6" }), SOURCE);
  check([v6.ipv4Count, v6.ipv6Count], [0, 1], "the v6 filter zeroes the v4 count");
  truthy(!v6.text.includes("1.1.1.0"), "the v6 filter removes IPv4 from the text");
}

// --- the organisation name reaches the rules ----------------------------
{
  const out = buildOutput(controls({ format: "iptables" }), SOURCE);
  truthy(out.text.includes("Cloudflare, Inc. (AS13335)"), "the header names the organisation");

  const noOrg = buildOutput(controls({ format: "iptables" }), { ...SOURCE, organization: "" });
  truthy(noOrg.text.includes("CLOUDFLARENET"), "the network name is the first fallback");

  const bare = buildOutput(controls({ format: "iptables" }), {
    ...SOURCE,
    organization: "",
    asnName: "",
  });
  truthy(bare.text.includes("AS13335 (AS13335)"), "the AS number is the last fallback");
}

// --- file names ---------------------------------------------------------
check(buildOutput(controls(), SOURCE).fileName, "as13335-cidr.txt", "default file name");
check(
  buildOutput(controls({ format: "nftables" }), SOURCE).fileName,
  "as13335-nftables-allow.nft",
  "the extension and name follow the format",
);
check(
  buildOutput(controls({ format: "nginx", mode: "deny" }), SOURCE).fileName,
  "as13335-nginx-deny.conf",
  "the mode is in the file name",
);
check(
  buildOutput(controls({ format: "terraform", mode: "deny", version: "v6" }), SOURCE).fileName,
  "as13335-terraform-deny-v6.tf",
  "a non-default family is in the file name",
);
truthy(
  !buildOutput(controls({ version: "both" }), SOURCE).fileName.includes("both"),
  "the default family is left out of the file name",
);
truthy(
  !buildOutput(controls({ mode: "deny" }), SOURCE).fileName.includes("deny"),
  "a mode-independent format gets one name, not two",
);
check(
  buildOutput(controls({ mode: "deny" }), SOURCE).fileName,
  buildOutput(controls({ mode: "allow" }), SOURCE).fileName,
  "identical CIDR output downloads under an identical name",
);

// Three pairs of formats share an extension, so every name must still be unique.
{
  const names = new Set(
    (["cidr", "iptables", "nftables", "nginx", "apache", "aws-cli", "terraform", "cloudflare", "windows", "json"] as const).map(
      (format) => buildOutput(controls({ format }), SOURCE).fileName,
    ),
  );
  check(names.size, 10, "no two formats download under the same file name");
}

// --- preview trimming ---------------------------------------------------
{
  const text = Array.from({ length: 10 }, (_, index) => `line ${index + 1}`).join("\n");
  check(previewOf(text, 10), text, "a short file is not trimmed");
  check(previewOf(text, 20), text, "a limit above the length is not trimmed");
  check(previewOf(text, 3), "line 1\nline 2\nline 3", "a long file is trimmed to the limit");
  check(previewOf(text, 3).split("\n").length, 3, "the trimmed preview has exactly the limit");
  check(previewOf("", 5), "", "an empty file previews as empty");
  truthy(
    previewOf(text, 3).length < text.length && text.startsWith(previewOf(text, 3)),
    "the preview is a true prefix of the file",
  );
}

console.log(`output: ${checks} assertions passed`);
