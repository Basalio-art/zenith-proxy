# stream-proxy

A dedicated stream playback/proxy layer sitting between local **anivexa-api** and real provider streams:

```
Zenith → stream-proxy → provider streams
       (port 9190)     (anivexa-api on 9189)
```

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Zenith    │────▶│   stream-proxy   │────▶│   provider CDN   │
│  (frontend) │     │    (port 9190)   │     │  (flixcloud,     │
└─────────────┘     └────────┬─────────┘     │   megaplay, etc) │
                             │               └──────────────────┘
                             ▼
                    ┌──────────────────┐
                    │   anivexa-api    │
                    │    (port 9189)   │
                    └──────────────────┘
```

## Features

- **HLS** — master/variant/media playlists, EXT-X-KEY/MAP/MEDIA/I-FRAME tags, relative/absolute/signed URLs
- **DASH** — MPD with SegmentTemplate/BaseURL/init/media, template expansion
- **MP4/WebM** — Range/seek support (206 Partial Content)
- **FlixCloud decoding** — base64 + XOR (32-byte repeating key) for master/child playlists; `.webp`/`.png` → `.ts` segment rewrite
- **SSRF protection** — pinned DNS, private/metadata IP blocking, scheme/port filtering, signed allowlist
- **CORS** — OPTIONS/GET/HEAD/Range, exposes `Content-Length`, `Content-Range`, `Accept-Ranges`, `ETag`, `Cache-Control`
- **Caching** — per-type TTL (master 60s, variant 15s, media 15s, MPD 30s, embed 60s)

## Quick Start

```bash
# 1. Start anivexa-api (source of truth) on :9189
cd anivexa-api
PORT=9189 node server.js &

# 2. Build & run stream-proxy on :9190
cd ../stream-proxy
set -a && source .env && set +a   # Go reads env vars, not .env directly
go build -o /tmp/stream-proxy ./cmd/stream-proxy
/tmp/stream-proxy &
```

Requires: Go 1.23+, anivexa-api running on `http://localhost:9189`.

## Configuration (`.env`)

The Go binary does **not** auto-load `.env` — export it first
(`set -a && source .env && set +a`) or pass the variables inline.

| Variable | Default | Description |
|---|---|---|
| `PROXY_PORT` | `9190` | stream-proxy listen port (code fallback default: `9191`) |
| `ANIVEXA_BASE` | `http://localhost:9189` | local anivexa-api base URL (code fallback default: `:9190`) |
| `HMAC_SECRET` | dev default | 32-byte secret for signed play tokens |
| `CORS_ALLOWED_ORIGINS` | `*` | comma-separated origins or `*` |
| `UPSTREAM_DIAL_TIMEOUT` | `10s` | upstream dial timeout |
| `UPSTREAM_RESPONSE_TIMEOUT` | `15s` | upstream response timeout |
| `CACHE_MASTER_TTL` | `60s` | master playlist cache TTL |
| `CACHE_VARIANT_TTL` | `15s` | variant playlist cache TTL |
| `CACHE_MEDIA_TTL` | `15s` | media segment cache TTL |
| `CACHE_MPD_TTL` | `30s` | DASH MPD cache TTL |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Health check |
| `GET` | `/v1/meta` | Provider list & version |
| `GET` | `/v1/sources` | Resolve sources via anivexa |
| `GET` | `/stream/proxy` | Stream media (primary playback endpoint) |
| `GET` | `/v1/embed` | Embed player (HTML for iframe, JSON for API) |

### `/v1/sources`

```
GET /v1/sources?anilist=16498&provider=animedunya&audio=sub&ep=1
```

Returns normalized sources with Kind (`hls`/`mp4`/`dash`/`embed`), URL, headers, subtitles, Codec (`flixcloud-b64-xor`), PlaylistKey.

**Error classification:**
- `errorClass: "ok"` — sources returned
- `errorClass: "no_source"` — provider has no match for this anime (AniList ID not in their catalog)
- `errorClass: "upstream_error"` — provider returned error (503, 526, etc.)

### `/stream/proxy`

Two modes:

**Signed token (new integrations):**
```
GET /stream/proxy?token=<hmac-signed>
```

**Query params:**
```
GET /stream/proxy?url=<encoded>&referer=<ref>&origin=<o>&playlist_key=<b64>
```



### `/v1/embed`

```
GET /v1/embed?url=<encoded>&referer=<ref>
```

Dual-mode, selected by `Accept` header (or `?format=html`):

- **`Accept: text/html`** — iframe-player page. Tries native source extraction
  first (timeboxed, ~6 s); if extraction is unavailable, fails, or upstream
  presents anti-bot protection, it serves a **full-window fallback iframe**
  pointing at the provider's embed page. The fallback iframe is intentionally
  not sandboxed so JavaScript, DOM storage and cookies keep working — a
  Turnstile challenge, if shown, is completed normally by the user inside the
  browser/WebView. Hosts known to be non-extractable (e.g. `megaplay.buzz`)
  skip straight to the fallback for an instant load.
- **`Accept: application/json`** — extraction report (unchanged schema):
  iframes, player scripts, API candidates, direct streams + verdict
  (`stream_extracted`, `iframe_only`, `api_candidates`, `unknown`,
  `unsupported_anti_bot`).

Inspection fetches are SSRF-validated (target, each redirect, each probed API
candidate and each recursed iframe), use Chrome-131 impersonated headers, and
recursively follow iframes (depth ≤ 3) looking for a playable stream.

## Provider Matrix (Attack on Titan, AniList 16498, ep 1)

| Provider | Sub | Dub | Notes |
|---|---|---|---|
| animedunya | ✅ | ❌ | HLS, multi-sub, bare access |
| anikoto | ✅ | ✅ | HLS (megaplay), Referer required, segments ignore Range |
| animegg | ✅ | ✅ | MP4 via `/play/`, 2 redirects, Range OK |
| anizone | ✅ | ❌ | HLS + AES-128 (relative keys), bare |
| reanime | ✅ | ✅ | **FlixCloud** base64+XOR, child playlists same encoding, `.webp`/`.png`→`.ts` |
| aniwaves | ✅ | ✅ | HLS (wrong Content-Type), segments ignore Range |
| kaa | ✅ | ⚠️ | BirdStream 502, VidStreaming works; Origin **no trailing slash** |
| animeonsen | ✅ | ❌ | DASH (.m4s), Authorization optional |
| senshi | ❌ | ❌ | Source returned but playlist 404 (upstream broken) |
| anineko | ❌ | ❌ | No match for 16498 (alt ID 140960 works) |
| anidbapp | ❌ | ❌ | No match for 16498 (alt ID 113415 works) |
| animenosub | ❌ | ❌ | No match for 16498 (alt ID 154587 works) |
| anibd | ❌ | ❌ | API 404 for 16498 (alt ID 101922 works) |
| mkissa | ✅ | ❌ | HLS (wixmp, streamsb, ok.ru), embed handling |



## Security Model

### SSRF Protection
- Blocks: `localhost`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, cloud metadata (`169.254.169.254`, `100.100.100.200`), `.local`/`.internal` hosts, non-http(s) schemes, non-80/443 ports
- Pinned DNS resolution at request time (no rebinding)
- Redirect validation against allowlist

### Upstream Header Policy
- **Never forwards** client headers (Authorization, Cookie, custom headers)
- Uses provider-specific header sets from manifest (Referer, Origin, User-Agent)
- Never leaks API keys, session cookies, or auth tokens

### Signed Play Tokens
- HMAC-SHA256 over base64url-encoded JSON payload
- Binds: target URL + header set + provider + expiry (default 5 min)
- Token mode available for new integrations; query-param mode for direct use

## Project Structure

```
stream-proxy/
├── cmd/stream-proxy/main.go          # entry point
├── internal/
│   ├── config/                       # .env loading
│   ├── server/router.go              # Gin routes + middleware
│   ├── middleware/middleware.go      # CORS, rate limit, recovery, request ID
│   ├── policy/
│   │   ├── token.go                  # HMAC tokens, URL validation, IP checks
│   │   └── allowlist.go              # dynamic allowlist + patterns
│   ├── providers/manifest.go         # provider config (YAML) loader
│   ├── resolve/anivexa.go            # anivexa client + normalization
│   ├── upstream/client.go            # tls-client wrapper with redirect validation
│   ├── hls/rewrite.go                # playlist parsing, rewrite, flixcloud decode
│   ├── dash/parse.go                 # MPD parsing, SegmentTemplate rewrite
│   ├── direct/proxy.go               # MP4/WebM Range streaming
│   ├── media/stream.go               # kind routing, probe, streaming
│   ├── embed/
│   │   ├── inspect.go                # embed page extraction
│   │   ├── player.go                 # dual-mode embed player (HTML/JSON)
│   │   ├── assets/                   # vendored hls.js, dash.js
│   │   └── templates/                # HTML player template
│   └── cache/playlist.go             # TTL caches (master/variant/media/MPD)
├── providers/manifest.yaml           # provider hosts, headers, quirks
└── .env.example
```

## Key Implementation Details

### FlixCloud (reanime) Encoding
- Response body is single-line base64
- Decode: `base64decode(body) XOR playlist_key` (repeating 32-byte key)
- Child playlists use same encoding, **no `?token=` needed**
- Segment URIs listed as `.webp`/`.png` but **same path with `.ts` returns MPEG-TS** (verified 7485/7485 sync)

### Header Requirements (from probe testing)
| Host | Required Headers |
|---|---|
| `fetch.nexabloom.top`, `wolfn.goldenanchor.space` | `Referer: https://megaplay.buzz/` |
| `hls.krussdomi.com` (master) | `Referer: https://krussdomi.com/` |
| `st1.advancedairesearchlab.xyz` (segments) | `Origin: https://krussdomi.com` (NO trailing slash!) |
| `fetch8/9.flixcloud.cc`, `vault-*.electrocdn.top` | `Referer: https://flixcloud.cc/`, `Origin: https://flixcloud.cc` |
| `fs2c.anime-dunya.com` | `Referer: https://anime-dunya.com/` |
| `cdn.animeonsen.xyz` | `Referer: https://www.animeonsen.xyz/` (Auth optional) |
| `www.animegg.org` | `Referer: https://www.animegg.org/` (bare → 302→500) |

### CORS Blockers (prove proxy necessity)
- `seiryuu.vid-cdn.xyz` → `ACAO: https://anizone.to`
- `fs2c.anime-dunya.com` → `ACAO: https://anime-dunya.com`

## Debugging

```bash
# Enable debug logs
LOG_LEVEL=debug /tmp/stream-proxy

# Check logs
tail -f /tmp/opencode/stream-proxy.log

# Probe a specific URL
curl -v "http://localhost:9190/stream/proxy?url=<enc>&referer=<ref>&origin=<o>"

# Test Range
curl -H "Range: bytes=0-1023" "http://localhost:9190/stream/proxy?url=<enc>&referer=<ref>"
```

## License

MIT