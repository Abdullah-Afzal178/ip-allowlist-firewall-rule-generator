export const SITE_NAME = "IP Allowlist Generator";

export const PAGE_TITLE = "IP Allowlist & Firewall Rule Generator";

export const PAGE_DESCRIPTION =
  "Turn an AS number, IP, or domain into ready-to-paste firewall rules — iptables, nftables, nginx, Apache, AWS, Terraform, Cloudflare, and more, built from live BGP route data.";

export const POWERED_BY_URL = "https://ipgeolocation.io";

/** Lines rendered on screen. The download always contains everything. */
export const PREVIEW_LINES = 300;

/** Above this, the full text is not embedded for copying — it is downloaded. */
export const COPY_LIMIT_BYTES = 400_000;

/**
 * Suggestions under an empty search box. Each shows the query itself rather
 * than a brand name: a domain resolves to whoever *hosts* it, which is often
 * not the brand you typed.
 */
export const EXAMPLES = [
  { query: "AS13335", hint: "Cloudflare" },
  { query: "AS15169", hint: "Google" },
  { query: "wikipedia.org", hint: "by domain" },
  { query: "1.1.1.1", hint: "by IP" },
];
