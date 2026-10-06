# IP Allowlist & Firewall Rule Generator

Name a network — by AS number, IP address, or domain — and get every prefix it announces, already written as rules for your firewall, proxy, or cloud console. Powered by [ipgeolocation.io](https://ipgeolocation.io).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built with Next.js](https://img.shields.io/badge/Built%20with-Next.js-000?logo=nextdotjs)](https://nextjs.org/)
[![Powered by ipgeolocation.io](https://img.shields.io/badge/Powered%20by-ipgeolocation.io-10b981)](https://ipgeolocation.io)

<!-- Add a screenshot of the tool running locally at ./public/tool.png and reference it here -->

---

## What It Does

Type `AS13335` and you get Cloudflare's 5,768 announced prefixes. Switch the tab and the same list becomes an nftables set, an nginx `allow` block, or a Terraform resource. Flip one toggle and the allow-list becomes a block-list.

| Input | Example | What happens |
|---|---|---|
| **AS number** | `AS15169`, `15169` | Looked up directly |
| **IP address** | `1.1.1.1`, `2606:4700:4700::1111` | Resolved to the network that announces it |
| **Domain** | `wikipedia.org` | Resolved to an address, then to its network |

> A domain resolves to whoever *hosts* it. `api.stripe.com` returns **Amazon's** 27,270 prefixes, not Stripe's — the tool says so on screen rather than quietly pretending otherwise.

### Ten output formats

| Format | File | Allow | Block |
|---|---|---|---|
| **CIDR list** | `.txt` | One prefix per line, sorted | *(identical — a raw list has no verb)* |
| **iptables** | `.sh` | Dedicated chain + catch-all `DROP`, hooked in after loopback and established | Dedicated chain, jump inserted at the **top** of `INPUT` |
| **nftables** | `.nft` | Sets with `auto-merge`, chain set to `policy drop` | `blocklist` sets, chain policy left alone |
| **nginx** | `.conf` | `allow` directives + closing `deny all` | `deny` directives only |
| **Apache** | `.conf` | `<RequireAny>` + `Require ip` | `<RequireAll>` + `Require not ip` |
| **AWS CLI** | `.sh` | `authorize-security-group-ingress`, 60 CIDRs per call | `create-network-acl-entry --rule-action deny` |
| **Terraform** | `.tf` | `aws_security_group_rule` (ingress) | `aws_network_acl_rule` with `for_each` |
| **Cloudflare** | `.txt` | `ip.src not in {…}` | `ip.src in {…}` |
| **Windows** | `.ps1` | `New-NetFirewallRule -Action Allow` | `-Action Block` |
| **JSON** | `.json` | Structured output for your own tooling | same, with `"mode"` flipped |

Every format is filtered by IPv4 / IPv6 / both. Nine of the ten invert on the allow-or-block toggle; **CIDR list is the exception**, and the UI greys the toggle out and says so rather than pretending otherwise.

---

## Design notes

Three decisions are worth calling out, because each one fixes a real failure:

**Every control is a URL, not React state.** The format, mode, and address family all live in the query string and the page is rendered on the server. A generated rule set is therefore a shareable link, and the tool works with JavaScript switched off. The only script on the page is the Copy button.

**The preview is capped; the download is not.** Amazon announces 27,270 prefixes — as `iptables` rules that is roughly 1.4 MB of text. The page renders the first 300 lines and the download route regenerates the complete file server-side, so a large network never bloats the HTML. Above 400 KB the Copy button steps aside and says so instead of silently truncating.

**nftables sets use `auto-merge`.** A real routing table contains overlapping announcements — `34.0.0.0/15` and `34.0.0.0/20` both appear in Google's. An `interval` set refuses to load overlapping elements, so without `auto-merge` the generated file would fail at `nft -f`.

**An allowlist that never denies is a no-op.** `iptables` and `nftables` both default to ACCEPT, so a file full of `-j ACCEPT` rules loads cleanly and filters nothing. Allow mode therefore emits a catch-all `DROP` / `policy drop`, preceded by loopback and `ESTABLISHED,RELATED` rules so applying the file does not cut off the session applying it — and the file says so in a warning at the top. Block mode does the opposite: it inserts its jump at the **top** of `INPUT`, because an appended `DROP` sits behind any pre-existing terminal `ACCEPT` and never matches.

**AWS cannot deny with a security group.** Security groups are allow-only and already default-deny, so there is no "block" rule to write — `revoke-security-group-ingress` deletes a grant, and an `egress` rule describes outbound traffic. Block mode therefore emits network ACL entries, which *can* deny, along with an explicit note that a NACL holds 20 rules by default (40 hard ceiling) and a large list needs a WAF IPSet, Network Firewall, or prefix list instead.

---

## Why ipgeolocation.io

The whole tool rests on one endpoint:

- **[ASN API](https://ipgeolocation.io/documentation/asn-api.html)** — `GET /v3/asn` with `include=routes` returns the network's identity *and* its complete announced prefix list in a single call. The same endpoint accepts either an AS number or an IP address, which is what makes "paste anything" work.
- **Free tier** — route data included, so the tool costs one call per network and the result is cached for 30 minutes.

> ipgeolocation.io also offers [IP Geolocation](https://ipgeolocation.io/documentation/ip-location-api.html), [Security](https://ipgeolocation.io/documentation/ip-security-api.html) (VPN, proxy, Tor detection), [Timezone](https://ipgeolocation.io/documentation/timezone-api.html), [User-Agent](https://ipgeolocation.io/documentation/user-agent-api.html), [Astronomy](https://ipgeolocation.io/documentation/astronomy-api.html), and [Abuse Contact](https://ipgeolocation.io/documentation/ip-abuse-contact-api.html) APIs.

**[Get your free API key →](https://ipgeolocation.io/signup)**

---

## Features

- **Three input forms** — AS number, IPv4/IPv6 address, or domain, told apart without asking the user which is which
- **Ten output formats**, each with the syntax quirks its tool actually requires
- **Allow or block**, IPv4 / IPv6 / both — with the toggle visibly inert on the one format it cannot affect
- **Numerically sorted** prefixes, not the API's announcement order
- **Duplicate-free** — a repeated CIDR is an error to AWS and Terraform, not a harmless duplicate
- **Shareable URLs** — every view is a link, and the server renders it
- **Download route** that regenerates the complete file, however large, under a per-format unique filename
- **Copy that degrades properly** — clipboard API, then `execCommand`, then leaving the text selected so "press Ctrl+C" is real advice
- **SEO-ready** — Open Graph tags, meta description, `robots.txt`, `sitemap.xml`, and favicon

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | [Next.js](https://nextjs.org/) (App Router) |
| Styling | [Tailwind CSS](https://tailwindcss.com/) |
| Language | TypeScript |
| Icons | [lucide-react](https://lucide.dev/) |
| Route data | [ipgeolocation.io](https://ipgeolocation.io) |

---

## Getting Started

### Prerequisites

- Node.js 18+
- An [ipgeolocation.io](https://ipgeolocation.io/signup) API key (free tier is enough)

### Run It Locally

1. Clone the repo:

```bash
git clone https://github.com/Abdullah-Afzal178/ip-allowlist-firewall-rule-generator.git
cd ip-allowlist-firewall-rule-generator
```

2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file in the project root:

```env
IPGEOLOCATION_API_KEY=your_api_key_here
```

4. Start the development server:

```bash
npm run dev
```

5. Open [http://localhost:3000](http://localhost:3000).

---

## Tests

The rule generators, input parser, URL controls, and output assembler are pure functions with no dependencies, covered by 302 assertions:

```bash
npm test
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `IPGEOLOCATION_API_KEY` | Yes | Your [ipgeolocation.io](https://ipgeolocation.io/signup) API key |
| `NEXT_PUBLIC_SITE_URL` | No | Your production URL if you deploy (used for sitemap and OG metadata) |

---

## How It Works

1. The query is classified as an AS number, an IP address, or a domain.
2. A domain is resolved to an address with `dns.resolve4` / `resolve6`, preferring IPv4.
3. One call to `GET /v3/asn?include=routes` returns the network and its announced prefixes, cached for 30 minutes since route data is public and identical for every visitor.
4. Prefixes are deduplicated, split by address family, and sorted numerically — IPv4 as a 32-bit integer, IPv6 as a 128-bit `BigInt`.
5. The selected format turns that list into rules. The page shows the first 300 lines; `/download` regenerates the whole file and serves it as an attachment.

---

## Project Structure

```
ip-allowlist-generator/
├── app/
│   ├── layout.tsx
│   ├── page.tsx              # Query bar, identity strip, rule panel
│   ├── download/route.ts     # Full file, regenerated server-side
│   ├── opengraph-image.tsx
│   ├── robots.ts
│   └── sitemap.ts
├── components/
│   ├── query-bar.tsx         # GET form + mode and family toggles
│   ├── identity-strip.tsx    # Whose network the rules cover
│   ├── rule-panel.tsx        # Format rail + dark code panel
│   └── powered-by-badge.tsx
├── lib/
│   ├── rule-formats.ts       # The ten generators (pure)
│   ├── query.ts              # ASN / IP / domain classification (pure)
│   ├── controls.ts           # URL state (pure)
│   ├── output.ts             # Shared by the page and the download route
│   ├── prefixes.ts           # ASN API lookup (server only)
│   └── session-cache.ts
├── .env                      # API key (not committed)
└── README.md
```

---

## Want to Deploy It?

Works out of the box on any platform that supports Next.js:

- **Vercel** — import the repo, add `IPGEOLOCATION_API_KEY`, deploy.
- **Netlify**, **Cloudflare Pages**, **Railway** — similar process.
- **Self-hosted** — `npm run build && npm start`.

---

## License

MIT — see [LICENSE](LICENSE) for details.
