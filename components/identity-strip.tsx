import { CornerDownRight, Globe2, Network } from "lucide-react";

import type { PrefixSource } from "@/lib/prefixes";

/** A single wide band identifying whose network the rules cover. */
export function IdentityStrip({
  source,
  ipv4Count,
  ipv6Count,
}: {
  source: PrefixSource;
  ipv4Count: number;
  ipv6Count: number;
}) {
  const facts = [
    { label: "AS number", value: source.asn },
    { label: "Network name", value: source.asnName },
    { label: "Type", value: titleCase(source.type) },
    { label: "Registry", value: source.rir },
    { label: "Country", value: source.country },
  ].filter((fact) => fact.value);

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-300 bg-white">
      <div className="flex flex-wrap items-start justify-between gap-4 px-5 py-4 sm:px-6">
        <div className="min-w-0">
          <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.08em] text-emerald-700">
            <Network className="h-3.5 w-3.5" />
            Rules cover
          </p>
          <h2 className="mt-1.5 truncate text-xl font-semibold tracking-tight text-slate-950 sm:text-2xl">
            {source.organization || source.asnName || source.asn}
          </h2>
          {source.domain ? (
            <p className="mt-0.5 flex items-center gap-1.5 text-sm text-slate-500">
              <Globe2 className="h-3.5 w-3.5" />
              {source.domain}
            </p>
          ) : null}
        </div>

        <div className="flex shrink-0 gap-3">
          <Count value={ipv4Count} label="IPv4 prefixes" />
          <Count value={ipv6Count} label="IPv6 prefixes" />
        </div>
      </div>

      <dl className="flex flex-wrap gap-x-8 gap-y-3 border-t border-slate-200 bg-slate-50/70 px-5 py-3.5 sm:px-6">
        {facts.map((fact) => (
          <div key={fact.label}>
            <dt className="text-[11px] font-medium uppercase tracking-[0.08em] text-slate-400">
              {fact.label}
            </dt>
            <dd className="mt-0.5 font-mono text-sm text-slate-800">{fact.value}</dd>
          </div>
        ))}
      </dl>

      {source.resolvedFrom ? (
        <p className="flex items-center gap-1.5 border-t border-slate-200 bg-emerald-50/60 px-5 py-2.5 text-xs text-emerald-900 sm:px-6">
          <CornerDownRight className="h-3.5 w-3.5 shrink-0" />
          {source.resolvedFrom}
        </p>
      ) : null}
    </section>
  );
}

function Count({ value, label }: { value: number; label: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-right">
      <p className="font-mono text-xl font-semibold tabular-nums text-slate-950">
        {value.toLocaleString("en-US")}
      </p>
      <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-slate-400">{label}</p>
    </div>
  );
}

function titleCase(value: string) {
  if (!value) {
    return "";
  }

  // The API shouts these ("HOSTING", "ISP"); only ISP reads better left alone.
  return value === value.toUpperCase() && value.length <= 3
    ? value
    : value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
}
