/**
 * Works out what the visitor typed: an AS number, an IP address, or a domain.
 * Pure and dependency-free so the classification can be unit tested.
 */

export type ParsedQuery =
  | { kind: "asn"; asn: string; label: string }
  | { kind: "ip"; ip: string; label: string }
  | { kind: "domain"; domain: string; label: string }
  | { kind: "invalid"; reason: string };

/** The largest AS number RFC 6996 allows (32-bit). */
const MAX_ASN = 4294967295;

export function parseQuery(raw: string): ParsedQuery {
  const text = raw.trim();

  if (text === "") {
    return { kind: "invalid", reason: "Enter an AS number, an IP address, or a domain." };
  }

  const asn = parseAsn(text);

  if (asn) {
    return { kind: "asn", asn, label: `AS${asn}` };
  }

  // Strip a URL wrapper before testing for an IP so "https://1.1.1.1" works.
  const bare = stripUrl(text);

  if (isIpv4(bare) || isIpv6(bare)) {
    return { kind: "ip", ip: bare, label: bare };
  }

  const domain = parseDomain(bare);

  if (domain) {
    return { kind: "domain", domain, label: domain };
  }

  return {
    kind: "invalid",
    reason: "That does not look like an AS number, an IP address, or a domain.",
  };
}

/** Accepts "AS15169", "as15169", "15169" — but not "15169.com". */
function parseAsn(text: string): string | null {
  const match = text.match(/^(?:as)[\s-]?(\d{1,10})$/i) ?? text.match(/^(\d{1,10})$/);

  if (!match) {
    return null;
  }

  const value = Number.parseInt(match[1], 10);

  // AS0 is reserved and 23456 is the 16-bit transition placeholder, but both
  // are better rejected by the API than guessed at here — only bound the range.
  if (!Number.isFinite(value) || value < 0 || value > MAX_ASN) {
    return null;
  }

  return String(value);
}

function stripUrl(value: string): string {
  let text = value.toLowerCase();

  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  text = text.split(/[/?#]/)[0];
  text = text.replace(/^[^@]*@/, "");

  // Bracketed IPv6 with an optional port: [2606:4700::1111]:443
  const bracketed = text.match(/^\[([^\]]+)\](?::\d+)?$/);

  if (bracketed) {
    return bracketed[1];
  }

  // A trailing port, but only when it cannot be part of a bare IPv6 address.
  if (!text.includes(":") || text.split(":").length === 2) {
    text = text.replace(/:\d+$/, "");
  }

  return text.replace(/\.$/, "");
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }

    // Reject "01" so an ambiguous octal-looking octet is never accepted.
    if (part.length > 1 && part.startsWith("0")) {
      return false;
    }

    return Number.parseInt(part, 10) <= 255;
  });
}

function isIpv6(value: string): boolean {
  if (!value.includes(":") || value.includes(":::")) {
    return false;
  }

  const zoneless = value.split("%")[0];
  const doubleColons = zoneless.split("::").length - 1;

  if (doubleColons > 1) {
    return false;
  }

  const [head, tail = ""] = zoneless.split("::");
  const headGroups = head === "" ? [] : head.split(":");
  const tailGroups = tail === "" ? [] : tail.split(":");
  const groups = [...headGroups, ...tailGroups];

  // A trailing IPv4 form (::ffff:192.0.2.1) counts as two groups.
  const last = groups[groups.length - 1];
  const hasEmbeddedIpv4 = last !== undefined && last.includes(".");

  if (hasEmbeddedIpv4) {
    if (!isIpv4(last)) {
      return false;
    }

    groups.pop();
  }

  if (!groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group))) {
    return false;
  }

  const width = groups.length + (hasEmbeddedIpv4 ? 2 : 0);

  return doubleColons === 1 ? width <= 7 : width === 8;
}

function parseDomain(value: string): string | null {
  if (value.length > 253 || !value.includes(".")) {
    return null;
  }

  const labels = value.split(".");

  if (labels.length < 2) {
    return null;
  }

  const labelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

  if (!labels.every((label) => labelPattern.test(label))) {
    return null;
  }

  // A numeric TLD means this was a malformed IP, not a domain.
  if (/^\d+$/.test(labels[labels.length - 1])) {
    return null;
  }

  return value;
}
