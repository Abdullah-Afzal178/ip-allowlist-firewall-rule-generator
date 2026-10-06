/**
 * Assembles what both the page and the download route need from one source of
 * truth, so the file a visitor downloads is exactly the file they previewed.
 */

import type { Controls } from "@/lib/controls";
import type { PrefixSource } from "@/lib/prefixes";
import { buildRules, formatFor, partitionPrefixes } from "@/lib/rule-formats";

export type Output = {
  text: string;
  ipv4Count: number;
  ipv6Count: number;
  totalLines: number;
  fileName: string;
};

export function buildOutput(controls: Controls, source: PrefixSource): Output {
  const { ipv4, ipv6 } = partitionPrefixes(source.routes, controls.version);

  const text = buildRules({
    source: source.organization || source.asnName || source.asn,
    asn: source.asn,
    ipv4,
    ipv6,
    mode: controls.mode,
    format: controls.format,
  });

  return {
    text,
    ipv4Count: ipv4.length,
    ipv6Count: ipv6.length,
    totalLines: text.split("\n").length,
    fileName: buildFileName(controls, source),
  };
}

function buildFileName(controls: Controls, source: PrefixSource): string {
  const meta = formatFor(controls.format);
  // Three pairs of formats share an extension (.txt, .sh, .conf), so the
  // format has to be in the name or two downloads collide.
  const parts = [source.asn.toLowerCase(), meta.id];

  // A format with no allow/deny verb produces one file, so it gets one name.
  if (meta.respectsMode) {
    parts.push(controls.mode);
  }

  if (controls.version !== "both") {
    parts.push(controls.version);
  }

  return `${parts.join("-")}.${meta.extension}`;
}

/** Trims the on-screen copy without ever touching the downloaded file. */
export function previewOf(text: string, maxLines: number): string {
  const lines = text.split("\n");

  return lines.length <= maxLines ? text : lines.slice(0, maxLines).join("\n");
}
