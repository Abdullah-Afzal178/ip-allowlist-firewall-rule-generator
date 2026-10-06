import type { NextRequest } from "next/server";

import { readControls } from "@/lib/controls";
import { buildOutput } from "@/lib/output";
import { lookupPrefixes } from "@/lib/prefixes";

/**
 * Regenerates the full rule set server-side rather than shipping it to the
 * browser: a large network can announce tens of thousands of prefixes, which
 * the preview deliberately never holds in the page.
 */
export async function GET(request: NextRequest) {
  const controls = readControls(
    Object.fromEntries(request.nextUrl.searchParams.entries()),
  );

  if (!controls.query) {
    return new Response("Add a ?q= query for the network to generate rules for.\n", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  const result = await lookupPrefixes(controls.query);

  if (!result.ok) {
    return new Response(`${result.error.title}: ${result.error.message}\n`, {
      status: 404,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  const output = buildOutput(controls, result.data);

  return new Response(`${output.text}\n`, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${output.fileName}"`,
      "Cache-Control": "no-store",
    },
  });
}
