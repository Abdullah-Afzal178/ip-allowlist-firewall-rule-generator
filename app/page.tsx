import { AlertTriangle, ListChecks, ShieldCheck, Workflow } from "lucide-react";
import { Suspense } from "react";

import { IdentityStrip } from "@/components/identity-strip";
import { PoweredByBadge } from "@/components/powered-by-badge";
import { QueryBar } from "@/components/query-bar";
import { RulePanel } from "@/components/rule-panel";
import { COPY_LIMIT_BYTES, PAGE_TITLE, PREVIEW_LINES } from "@/lib/constants";
import { buildHref, readControls, type Controls, type RawParams } from "@/lib/controls";
import { buildOutput, previewOf } from "@/lib/output";
import { lookupPrefixes } from "@/lib/prefixes";

export const dynamic = "force-dynamic";

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<RawParams>;
}) {
  const controls = readControls(await searchParams);

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 sm:py-12">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">
            {PAGE_TITLE}
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600 sm:text-base">
            Name a network — by AS number, IP address, or domain — and get every prefix it
            announces, already written as rules for your firewall, proxy, or cloud console.
          </p>
        </div>
        <PoweredByBadge className="shrink-0" />
      </header>

      <div className="mt-7 space-y-5">
        <QueryBar controls={controls} />

        {controls.query ? (
          <Suspense key={`${controls.query}:${controls.version}`} fallback={<PanelSkeleton />}>
            <Result controls={controls} />
          </Suspense>
        ) : (
          <Introduction />
        )}
      </div>

      <Explainer />
    </div>
  );
}

async function Result({ controls }: { controls: Controls }) {
  const result = await lookupPrefixes(controls.query);

  if (!result.ok) {
    return (
      <section className="rounded-2xl border border-amber-300 bg-amber-50 px-5 py-4 sm:px-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-amber-900">
          <AlertTriangle className="h-4 w-4" />
          {result.error.title}
        </p>
        <p className="mt-1.5 text-sm leading-6 text-amber-900/90">{result.error.message}</p>
      </section>
    );
  }

  const source = result.data;
  const output = buildOutput(controls, source);
  const preview = previewOf(output.text, PREVIEW_LINES);

  return (
    <>
      <IdentityStrip
        source={source}
        ipv4Count={output.ipv4Count}
        ipv6Count={output.ipv6Count}
      />
      <RulePanel
        controls={controls}
        preview={preview}
        copyText={output.text.length <= COPY_LIMIT_BYTES ? output.text : null}
        totalLines={output.totalLines}
        fileName={output.fileName}
        downloadHref={buildHref(controls, {}, "/download")}
      />
    </>
  );
}

function PanelSkeleton() {
  return (
    <>
      <div className="h-36 animate-pulse rounded-2xl border border-slate-300 bg-white" />
      <div className="h-96 animate-pulse rounded-2xl bg-slate-200" />
    </>
  );
}

function Introduction() {
  const steps = [
    {
      icon: ListChecks,
      title: "Name the network",
      body: "An AS number like AS13335, any IP inside the network, or a domain such as api.stripe.com.",
    },
    {
      icon: Workflow,
      title: "Pick your syntax",
      body: "Ten formats, from a plain CIDR list to nftables sets, Terraform, and a Cloudflare WAF expression.",
    },
    {
      icon: ShieldCheck,
      title: "Allow or block",
      body: "The same prefixes, inverted. Allow-listing adds a closing deny; blocking leaves the rest of the internet alone.",
    },
  ];

  return (
    <section className="grid gap-4 sm:grid-cols-3">
      {steps.map((step) => {
        const Icon = step.icon;

        return (
          <div key={step.title} className="rounded-2xl border border-slate-300 bg-white p-5">
            <Icon className="h-5 w-5 text-emerald-600" />
            <h2 className="mt-3 text-sm font-semibold text-slate-950">{step.title}</h2>
            <p className="mt-1.5 text-sm leading-6 text-slate-600">{step.body}</p>
          </div>
        );
      })}
    </section>
  );
}

function Explainer() {
  const notes = [
    {
      question: "Where do the prefixes come from?",
      answer:
        "The global BGP routing table — the blocks the network actually announces to the internet right now, not a hand-maintained list that goes stale.",
    },
    {
      question: "Is this the same as a vendor's published IP list?",
      answer:
        "Not quite. A vendor's list covers the addresses they use for one service; an AS number covers everything that network announces. For a narrow service, the vendor's own list is tighter.",
    },
    {
      question: "Why did the IPv6 count surprise me?",
      answer:
        "Large networks often announce more IPv6 prefixes than IPv4 ones, because IPv6 allocations are handed out in bigger, more numerous blocks. Cloudflare announces more than 3,000.",
    },
    {
      question: "Should I paste this straight into production?",
      answer:
        "Read it first. Announcements change, allow-lists fail closed, and a rule built from thousands of prefixes belongs in an ipset or an nftables set rather than one rule per line.",
    },
  ];

  return (
    <section className="mt-10 border-t border-slate-300 pt-8">
      <h2 className="text-lg font-semibold tracking-tight text-slate-950">Before you apply these</h2>
      <dl className="mt-5 grid gap-x-10 gap-y-6 sm:grid-cols-2">
        {notes.map((note) => (
          <div key={note.question}>
            <dt className="text-sm font-semibold text-slate-900">{note.question}</dt>
            <dd className="mt-1.5 text-sm leading-6 text-slate-600">{note.answer}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
