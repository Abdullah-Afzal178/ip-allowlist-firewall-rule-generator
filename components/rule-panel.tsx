import { Check, Download, FileCode2 } from "lucide-react";

import { buildHref, type Controls } from "@/lib/controls";
import { FORMATS, formatFor } from "@/lib/rule-formats";

export type PanelProps = {
  controls: Controls;
  /** Everything that fits on screen; may be shorter than the download. */
  preview: string;
  /** Null when the output is too large to hold in the page for copying. */
  copyText: string | null;
  totalLines: number;
  fileName: string;
  downloadHref: string;
};

/**
 * The generated rules, shown as a dark editor panel with the format list
 * docked down its left edge. Switching format is a link, so the panel is
 * rendered on the server and never waits for hydration.
 */
export function RulePanel({
  controls,
  preview,
  copyText,
  totalLines,
  fileName,
  downloadHref,
}: PanelProps) {
  const meta = formatFor(controls.format);
  const previewLines = preview.split("\n");
  const hiddenLines = totalLines - previewLines.length;

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-950/10 bg-slate-950 shadow-[0_18px_40px_-24px_rgba(2,6,23,0.6)]">
      <div className="lg:grid lg:grid-cols-[13.5rem_minmax(0,1fr)]">
        <nav
          aria-label="Output format"
          className="rail-scroll flex gap-1 overflow-x-auto border-b border-white/10 bg-slate-900 p-2 lg:max-h-none lg:flex-col lg:overflow-x-visible lg:border-b-0 lg:border-r lg:p-3"
        >
          <p className="hidden px-2 pb-2 pt-1 text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-500 lg:block">
            Output format
          </p>
          {FORMATS.map((format) => {
            const active = format.id === controls.format;

            return (
              <a
                key={format.id}
                href={buildHref(controls, { format: format.id })}
                aria-current={active ? "page" : undefined}
                className={`flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-sm transition lg:shrink ${
                  active
                    ? "bg-emerald-500/15 font-semibold text-emerald-300"
                    : "text-slate-400 hover:bg-white/5 hover:text-slate-100"
                }`}
              >
                {active ? (
                  <Check className="h-3.5 w-3.5 shrink-0" />
                ) : (
                  <span className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                )}
                <span className="whitespace-nowrap">{format.label}</span>
              </a>
            );
          })}
        </nav>

        <div className="min-w-0">
          <header className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-4 py-3">
            <p className="flex min-w-0 items-center gap-2 font-mono text-sm text-slate-300">
              <FileCode2 className="h-4 w-4 shrink-0 text-slate-500" />
              <span className="truncate">{fileName}</span>
              <span className="shrink-0 rounded-md bg-white/5 px-2 py-0.5 text-xs tabular-nums text-slate-400">
                {totalLines.toLocaleString("en-US")} lines
              </span>
            </p>

            <div className="flex items-center gap-2">
              {copyText === null ? (
                <span className="rounded-lg border border-white/10 px-3 py-1.5 text-xs text-slate-500">
                  Too large to copy
                </span>
              ) : (
                <button
                  type="button"
                  id="copy-button"
                  className="rounded-lg border border-white/15 px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-emerald-400/60 hover:text-emerald-300"
                >
                  Copy
                </button>
              )}
              <a
                href={downloadHref}
                className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-semibold text-slate-950 transition hover:bg-emerald-400"
              >
                <Download className="h-3.5 w-3.5" />
                Download
              </a>
            </div>
          </header>

          <div className="rail-scroll max-h-[32rem] overflow-auto">
            <div className="flex min-w-max">
              <div
                aria-hidden="true"
                className="select-none border-r border-white/5 bg-white/[0.02] px-3 py-4 text-right font-mono text-xs leading-6 tabular-nums text-slate-600"
              >
                {previewLines.map((_, index) => (
                  <div key={index}>{index + 1}</div>
                ))}
              </div>
              <pre className="px-4 py-4 font-mono text-xs leading-6 text-slate-200">
                <code>{preview}</code>
              </pre>
            </div>
          </div>

          <footer className="border-t border-white/10 px-4 py-3">
            {hiddenLines > 0 ? (
              <p className="text-xs text-amber-300/90">
                Showing the first {previewLines.length.toLocaleString("en-US")} lines.{" "}
                {hiddenLines.toLocaleString("en-US")} more are in the download.
              </p>
            ) : null}
            <p className={`text-xs text-slate-400 ${hiddenLines > 0 ? "mt-1" : ""}`}>{meta.note}</p>
          </footer>
        </div>
      </div>

      {copyText === null ? null : (
        <>
          <textarea id="copy-source" readOnly hidden value={copyText} aria-hidden="true" />
          <script dangerouslySetInnerHTML={{ __html: COPY_SCRIPT }} />
        </>
      )}
    </section>
  );
}

/**
 * Plain inline script rather than a client component: it runs the moment the
 * button is parsed, so Copy works even if React never hydrates.
 */
const COPY_SCRIPT = `(function () {
  var button = document.getElementById("copy-button");
  var source = document.getElementById("copy-source");
  if (!button || !source) return;

  var timer = null;

  function flash(label) {
    button.textContent = label;
    if (timer) clearTimeout(timer);
    timer = setTimeout(function () { button.textContent = "Copy"; }, 1600);
  }

  function reveal() {
    // Offscreen rather than hidden: a hidden textarea cannot be selected, and
    // the selection is what makes the manual fallback work.
    source.hidden = false;
    source.style.position = "fixed";
    source.style.top = "0";
    source.style.left = "-9999px";
    source.style.height = "1px";
    source.focus();
    source.select();
  }

  function legacyCopy() {
    // clipboard.writeText needs a focused document in a secure context, which
    // a background tab or a plain-http deployment will not always give us.
    reveal();
    var copied = false;
    try { copied = document.execCommand("copy"); } catch (error) { copied = false; }

    // On failure the text stays selected, so "press Ctrl+C" is real advice.
    if (copied) source.hidden = true;
    return copied;
  }

  button.addEventListener("click", function () {
    var text = source.value;

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(
        function () { flash("Copied"); },
        function () { flash(legacyCopy() ? "Copied" : "Now press Ctrl+C"); }
      );
      return;
    }

    flash(legacyCopy() ? "Copied" : "Now press Ctrl+C");
  });
})();`;
