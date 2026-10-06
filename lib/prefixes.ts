import "server-only";

import { resolve4, resolve6 } from "node:dns/promises";

import { parseQuery } from "@/lib/query";
import { getSessionCache, setSessionCache } from "@/lib/session-cache";

export type PrefixSource = {
  /** Always in "AS13335" form. */
  asn: string;
  organization: string;
  asnName: string;
  country: string;
  type: string;
  rir: string;
  domain: string;
  /** Announced prefixes, both families, in the order the API returned them. */
  routes: string[];
  /** What the API claims, which is usually a few off the actual array. */
  declaredIpv4: number;
  declaredIpv6: number;
  /** Set when the query was a domain or IP rather than an AS number. */
  resolvedFrom: string | null;
};

export type PrefixResult =
  | { ok: true; cached: boolean; data: PrefixSource }
  | { ok: false; error: { title: string; message: string } };

const ASN_ENDPOINT = "https://api.ipgeolocation.io/v3/asn";

export async function lookupPrefixes(query: string): Promise<PrefixResult> {
  const parsed = parseQuery(query);

  if (parsed.kind === "invalid") {
    return fail("Check the query", parsed.reason);
  }

  if (parsed.kind === "asn") {
    return fetchAsn({ asn: parsed.asn, resolvedFrom: null });
  }

  if (parsed.kind === "ip") {
    return fetchAsn({ ip: parsed.ip, resolvedFrom: `${parsed.label} belongs to this network` });
  }

  const address = await resolveDomain(parsed.domain);

  if (!address) {
    return fail(
      "Domain did not resolve",
      `No A or AAAA record was found for ${parsed.domain}. Try an AS number or an IP address instead.`,
    );
  }

  return fetchAsn({
    ip: address,
    resolvedFrom: `${parsed.domain} resolves to ${address}`,
  });
}

/** Prefers IPv4 because more networks announce it, then falls back to IPv6. */
async function resolveDomain(domain: string): Promise<string | null> {
  const [v4, v6] = await Promise.all([
    resolve4(domain).catch(() => [] as string[]),
    resolve6(domain).catch(() => [] as string[]),
  ]);

  return v4[0] ?? v6[0] ?? null;
}

async function fetchAsn({
  asn,
  ip,
  resolvedFrom,
}: {
  asn?: string;
  ip?: string;
  resolvedFrom: string | null;
}): Promise<PrefixResult> {
  const apiKey = process.env.IPGEOLOCATION_API_KEY;

  if (!apiKey) {
    return fail(
      "Missing API key",
      "Set IPGEOLOCATION_API_KEY in your .env file before starting the app.",
    );
  }

  // Routes are public data, so one cache entry serves every visitor.
  const cacheKey = asn ? `asn:${asn}` : `ip:${ip}`;
  const cached = getSessionCache<PrefixSource>(cacheKey);

  if (cached) {
    return { ok: true, cached: true, data: { ...cached, resolvedFrom } };
  }

  const params = new URLSearchParams({ apiKey, include: "routes" });

  if (asn) {
    params.set("asn", asn);
  }

  if (ip) {
    params.set("ip", ip);
  }

  let response: Response;

  try {
    response = await fetch(`${ASN_ENDPOINT}?${params.toString()}`, {
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
  } catch (error) {
    return fail(
      "Network error",
      error instanceof Error ? error.message : "The lookup could not be completed.",
    );
  }

  if (!response.ok) {
    const body = (await safeJson(response)) as { message?: string } | null;

    return fail(errorTitle(response.status), body?.message || defaultMessage(response.status));
  }

  const payload = (await safeJson(response)) as Record<string, unknown> | null;
  const record = asObject(payload?.asn);
  const asNumber = readString(record?.as_number);

  if (!record || !asNumber) {
    return fail(
      "No network found",
      "The API did not return an autonomous system for that query.",
    );
  }

  const routes = Array.isArray(record.routes)
    ? record.routes.filter(
        (route): route is string => typeof route === "string" && route.includes("/"),
      )
    : [];

  if (routes.length === 0) {
    return fail(
      "No announced prefixes",
      `${asNumber} exists but announces no routes, so there is nothing to build a rule from.`,
    );
  }

  const data: PrefixSource = {
    asn: asNumber.toUpperCase().startsWith("AS") ? asNumber.toUpperCase() : `AS${asNumber}`,
    organization: clean(record.organization),
    asnName: clean(record.asn_name),
    country: clean(record.country),
    type: clean(record.type),
    rir: clean(record.rir),
    domain: clean(record.domain),
    routes,
    declaredIpv4: readCount(record.num_of_ipv4_routes),
    declaredIpv6: readCount(record.num_of_ipv6_routes),
    resolvedFrom: null,
  };

  setSessionCache(cacheKey, data);

  return { ok: true, cached: false, data: { ...data, resolvedFrom } };
}

function fail(title: string, message: string): PrefixResult {
  return { ok: false, error: { title, message } };
}

function errorTitle(status: number) {
  if (status === 401 || status === 403) {
    return "Authentication failed";
  }

  if (status === 404) {
    return "Network not found";
  }

  if (status === 423) {
    return "Private address";
  }

  if (status === 429) {
    return "Rate limit reached";
  }

  return status >= 500 ? "API unavailable" : "Lookup failed";
}

function defaultMessage(status: number) {
  if (status === 423) {
    return "That is a private or reserved address, so it belongs to no public network.";
  }

  return `The lookup failed with status ${status}.`;
}

/** The API uses "??" and "Unknown" where it has no value. */
function clean(value: unknown) {
  const text = typeof value === "string" ? value.trim() : "";

  return text === "??" || text === "Unknown" ? "" : text;
}

function readString(value: unknown) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

function readCount(value: unknown) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  const parsed = typeof value === "string" ? Number.parseInt(value, 10) : Number.NaN;

  return Number.isFinite(parsed) ? parsed : 0;
}

function asObject(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

async function safeJson(response: Response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}
