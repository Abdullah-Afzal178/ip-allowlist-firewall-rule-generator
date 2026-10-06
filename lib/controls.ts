/**
 * Every control on the page is a link, not a React state update: the format,
 * mode and address-family choices all live in the URL. That makes each view
 * shareable and bookmarkable, and means the output renders correctly even if
 * JavaScript never runs.
 */

import { isFormatId, type FormatId, type IpVersionFilter, type RuleMode } from "@/lib/rule-formats";

export type Controls = {
  query: string;
  format: FormatId;
  mode: RuleMode;
  version: IpVersionFilter;
};

export const DEFAULT_CONTROLS: Controls = {
  query: "",
  format: "cidr",
  mode: "allow",
  version: "both",
};

export type RawParams = Record<string, string | string[] | undefined>;

export function readControls(params: RawParams): Controls {
  const format = first(params.format);
  const mode = first(params.mode);
  const version = first(params.version);

  return {
    // Long pastes are not queries; cap it so a bad URL cannot bloat the page.
    query: first(params.q).trim().slice(0, 253),
    format: isFormatId(format) ? format : DEFAULT_CONTROLS.format,
    mode: mode === "deny" ? "deny" : DEFAULT_CONTROLS.mode,
    version: version === "v4" || version === "v6" ? version : DEFAULT_CONTROLS.version,
  };
}

/** Builds a link to the same page with some controls changed. */
export function buildHref(controls: Controls, patch: Partial<Controls> = {}, path = "/"): string {
  const next = { ...controls, ...patch };
  const params = new URLSearchParams();

  if (next.query) {
    params.set("q", next.query);
  }

  // Defaults are left out so a shared link stays readable.
  if (next.format !== DEFAULT_CONTROLS.format) {
    params.set("format", next.format);
  }

  if (next.mode !== DEFAULT_CONTROLS.mode) {
    params.set("mode", next.mode);
  }

  if (next.version !== DEFAULT_CONTROLS.version) {
    params.set("version", next.version);
  }

  const search = params.toString();

  return search ? `${path}?${search}` : path;
}

function first(value: string | string[] | undefined): string {
  if (Array.isArray(value)) {
    return value[0] ?? "";
  }

  return value ?? "";
}
