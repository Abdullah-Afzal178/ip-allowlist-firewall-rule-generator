import { ImageResponse } from "next/og";

import { PAGE_TITLE, SITE_NAME } from "@/lib/constants";

export const alt = PAGE_TITLE;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpenGraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#020617",
          padding: "72px",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
              color: "#34d399",
              fontSize: "22px",
              fontWeight: 600,
              letterSpacing: "0.12em",
              textTransform: "uppercase",
            }}
          >
            <div
              style={{ width: "12px", height: "12px", borderRadius: "999px", background: "#34d399" }}
            />
            {SITE_NAME}
          </div>

          <div
            style={{
              marginTop: "28px",
              color: "#f8fafc",
              fontSize: "70px",
              fontWeight: 700,
              lineHeight: 1.08,
              letterSpacing: "-0.02em",
              maxWidth: "900px",
            }}
          >
            Every prefix a network announces, as firewall rules.
          </div>

          <div style={{ marginTop: "24px", color: "#94a3b8", fontSize: "28px", maxWidth: "860px" }}>
            iptables · nftables · nginx · Apache · AWS · Terraform · Cloudflare
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div
            style={{
              display: "flex",
              fontFamily: "monospace",
              fontSize: "26px",
              color: "#34d399",
              background: "rgba(52, 211, 153, 0.1)",
              border: "1px solid rgba(52, 211, 153, 0.3)",
              borderRadius: "12px",
              padding: "14px 22px",
            }}
          >
            iptables -A INPUT -s 104.28.170.0/24 -j ACCEPT
          </div>
          <div style={{ display: "flex", color: "#64748b", fontSize: "24px" }}>
            ipgeolocation.io
          </div>
        </div>
      </div>
    ),
    size,
  );
}
