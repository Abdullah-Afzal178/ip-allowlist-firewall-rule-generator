import { Search } from "lucide-react";

import { buildHref, DEFAULT_CONTROLS, type Controls } from "@/lib/controls";
import { EXAMPLES } from "@/lib/constants";
import { formatFor } from "@/lib/rule-formats";

const MODES = [
  { value: "allow", label: "Allow" },
  { value: "deny", label: "Block" },
] as const;

const VERSIONS = [
  { value: "both", label: "Both" },
  { value: "v4", label: "IPv4" },
  { value: "v6", label: "IPv6" },
] as const;

/**
 * A plain GET form, so the generated rules live at a shareable URL and the
 * tool keeps working with JavaScript switched off.
 */
export function QueryBar({ controls }: { controls: Controls }) {
  return (
    <section className="rounded-2xl border border-slate-300 bg-white p-4 shadow-[0_1px_0_rgba(15,23,42,0.04)] sm:p-5">
      <form action="/" method="get" className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search
            className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
            aria-hidden="true"
          />
          <label htmlFor="query" className="sr-only">
            AS number, IP address, or domain
          </label>
          <input
            id="query"
            name="q"
            type="text"
            defaultValue={controls.query}
            placeholder="AS13335, 1.1.1.1, or api.stripe.com"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            className="w-full rounded-xl border border-slate-300 bg-slate-50 py-3 pl-11 pr-4 font-mono text-sm text-slate-900 outline-none transition placeholder:font-sans placeholder:text-slate-400 focus:border-emerald-500 focus:bg-white focus:ring-4 focus:ring-emerald-500/15"
          />
        </div>

        {/*
          The current view is carried through the submit so a search keeps the
          format. Defaults are omitted, so a plain search still produces the
          short URL that buildHref would have made.
        */}
        {controls.format === DEFAULT_CONTROLS.format ? null : (
          <input type="hidden" name="format" value={controls.format} />
        )}
        {controls.mode === DEFAULT_CONTROLS.mode ? null : (
          <input type="hidden" name="mode" value={controls.mode} />
        )}
        {controls.version === DEFAULT_CONTROLS.version ? null : (
          <input type="hidden" name="version" value={controls.version} />
        )}

        <button
          type="submit"
          className="rounded-xl bg-emerald-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-emerald-700 focus:outline-none focus:ring-4 focus:ring-emerald-500/25"
        >
          Generate rules
        </button>
      </form>

      <div className="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3 border-t border-slate-200 pt-4">
        <ToggleGroup
          legend="Rule type"
          options={MODES}
          current={controls.mode}
          hrefFor={(value) => buildHref(controls, { mode: value })}
          inert={
            formatFor(controls.format).respectsMode
              ? undefined
              : "a raw CIDR list has no verb — same prefixes either way"
          }
        />
        <ToggleGroup
          legend="Addresses"
          options={VERSIONS}
          current={controls.version}
          hrefFor={(value) => buildHref(controls, { version: value })}
        />

        {controls.query ? null : (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-400">
              Try
            </span>
            {EXAMPLES.map((example) => (
              <a
                key={example.query}
                href={buildHref(controls, { query: example.query })}
                className="group rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs transition hover:border-emerald-400"
              >
                <span className="font-mono font-medium text-slate-700 group-hover:text-emerald-700">
                  {example.query}
                </span>
                <span className="ml-1.5 text-slate-400">{example.hint}</span>
              </a>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function ToggleGroup<T extends string>({
  legend,
  options,
  current,
  hrefFor,
  inert,
}: {
  legend: string;
  options: readonly { value: T; label: string }[];
  current: T;
  hrefFor: (value: T) => string;
  /** Why this group cannot affect the current format; shown beside it. */
  inert?: string;
}) {
  const labelId = `toggle-${legend.toLowerCase().replace(/\s+/g, "-")}`;

  return (
    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
      <span
        id={labelId}
        className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-400"
      >
        {legend}
      </span>

      <div
        role="group"
        aria-labelledby={labelId}
        className="inline-flex rounded-lg border border-slate-300 bg-slate-100 p-0.5"
      >
        {options.map((option) => {
          const active = option.value === current;

          // These stay links even when inert: the choice still has to survive a
          // switch back to a format that honours it.
          return (
            <a
              key={option.value}
              href={hrefFor(option.value)}
              aria-current={active ? "true" : undefined}
              aria-disabled={inert ? "true" : undefined}
              className={`rounded-md px-3 py-1.5 text-xs font-semibold transition ${
                active
                  ? `bg-white shadow-sm ring-1 ring-slate-900/5 ${
                      inert ? "text-slate-400" : "text-emerald-700"
                    }`
                  : `${inert ? "text-slate-300" : "text-slate-500"} hover:text-slate-900`
              }`}
            >
              {option.label}
            </a>
          );
        })}
      </div>

      {inert ? <span className="text-xs italic text-slate-400">{inert}</span> : null}
    </div>
  );
}
