package embed

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stream-proxy/internal/config"
	"stream-proxy/internal/policy"
)

//go:embed assets/hls.min.js
var hlsJS string

//go:embed assets/dash.all.min.js
var dashJS string

//go:embed templates/player.html
var playerTemplate string

// PlayerData holds data for the HTML player template
type PlayerData struct {
	StreamURL  string
	StreamType string
	Poster     string
	Referer    string
	HLSJS      template.JS
	DASHJS     template.JS
}

// ErrUnsupportedAntiBot indicates upstream returned a challenge page
var ErrUnsupportedAntiBot = errors.New("unsupported_anti_bot")

// nativeAttemptTimeout bounds the server-side native extraction attempt so
// the iframe fallback page is served quickly.
const nativeAttemptTimeout = 6 * time.Second

// nativeUnavailableHosts lists hosts where native source extraction is known
// unavailable (timeboxed decode spike failed). Requests for these go straight
// to iframe playback — the browser/WebView runs the player (and any
// Turnstile challenge) normally inside the framed embed page.
var nativeUnavailableHosts = map[string]bool{
	"megaplay.buzz":     true,
	"www.megaplay.buzz": true,
}

// isNativeUnavailable reports whether native extraction is skipped for this URL
func isNativeUnavailable(rawURL string) bool {
	host := strings.ToLower(ExtractHost(rawURL))
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	return nativeUnavailableHosts[host]
}

// IsAcceptHTML checks if the request prefers HTML over JSON
func IsAcceptHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	// Explicit format=html override
	if r.URL.Query().Get("format") == "html" {
		return true
	}
	// Browser/iframe requests typically send text/html
	for _, v := range strings.Split(accept, ",") {
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "text/html") {
			return true
		}
	}
	return false
}

// RenderPlayerPage renders the HTML player page
func RenderPlayerPage(w http.ResponseWriter, data PlayerData) error {
	data.HLSJS = template.JS(hlsJS)
	data.DASHJS = template.JS(dashJS)

	tmpl, err := template.New("player").Parse(playerTemplate)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	return tmpl.Execute(w, data)
}

// GetStreamFromEmbed inspects the embed URL and extracts a playable stream
func GetStreamFromEmbed(ctx context.Context, embedURL, referer string, cfg *config.Config) (streamURL, streamType, poster string, err error) {
	// First, check if embedURL is already a direct stream
	if isDirectStreamURL(embedURL) {
		streamType = detectTypeFromURL(embedURL)
		return embedURL, streamType, "", nil
	}

	// Inspect the embed page
	report, err := InspectEmbed(ctx, embedURL, referer, cfg)
	if err != nil {
		return "", "", "", err
	}

	if report.Cloudflare {
		return "", "", "", ErrUnsupportedAntiBot
	}

	// Try direct streams first (best quality)
	if len(report.DirectStreams) > 0 {
		// Prefer HLS > MP4 > DASH
		for _, pref := range []string{"hls", "mp4", "dash", "webm"} {
			for _, ds := range report.DirectStreams {
				if ds.Type == pref {
					return ds.URL, ds.Type, "", nil
				}
			}
		}
		// Fallback to first direct stream
		ds := report.DirectStreams[0]
		return ds.URL, ds.Type, "", nil
	}

	// Try iframes (some providers use nested iframe players)
	if len(report.Iframes) > 0 {
		// For iframe-only, we can't easily proxy - return the iframe URL
		// The player page could embed this iframe, but many block framing
		return report.Iframes[0], "iframe", "", nil
	}

	return "", "", "", fmt.Errorf("no playable stream found: %s", report.Verdict)
}

// isDirectStreamURL checks if a URL is already a direct media stream
func isDirectStreamURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	return strings.HasSuffix(path, ".m3u8") ||
		strings.HasSuffix(path, ".mpd") ||
		strings.HasSuffix(path, ".mp4") ||
		strings.HasSuffix(path, ".webm") ||
		strings.HasSuffix(path, ".m4s") ||
		strings.HasSuffix(path, ".ts") ||
		strings.Contains(path, "/master.m3u8") ||
		strings.Contains(path, "/playlist.m3u8") ||
		strings.Contains(path, "manifest.mpd")
}

// detectTypeFromURL infers stream type from URL
func detectTypeFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	path := strings.ToLower(u.Path)
	switch {
	case strings.HasSuffix(path, ".m3u8") || strings.Contains(path, "/master.m3u8") || strings.Contains(path, "/playlist.m3u8"):
		return "hls"
	case strings.HasSuffix(path, ".mpd") || strings.Contains(path, "manifest.mpd"):
		return "dash"
	case strings.HasSuffix(path, ".mp4") || strings.HasSuffix(path, ".m4v") || strings.HasSuffix(path, ".m4s"):
		return "mp4"
	case strings.HasSuffix(path, ".webm") || strings.HasSuffix(path, ".mkv"):
		return "webm"
	case strings.HasSuffix(path, ".ts"):
		return "hls" // TS segments are usually HLS
	}
	return "unknown"
}

// EmbedPlayerHandler returns a handler for the dual-mode /v1/embed endpoint
func EmbedPlayerHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tokenStr := r.URL.Query().Get("token")
		var targetURL, referer string

		if tokenStr != "" {
			// Token-based flow
			// Note: token verification happens in the main Embed handler
			// Here we just use the legacy params
			targetURL = r.URL.Query().Get("url")
			referer = r.URL.Query().Get("referer")
		} else {
			// Legacy flow
			targetURL = r.URL.Query().Get("url")
			if targetURL == "" {
				http.Error(w, `{"error":"url parameter required"}`, http.StatusBadRequest)
				return
			}
			referer = r.URL.Query().Get("referer")
			if referer == "" {
				referer = "https://" + ExtractHost(targetURL) + "/"
			}
		}

		// Check if client wants HTML (iframe/browser) or JSON (API)
		wantsHTML := IsAcceptHTML(r)

		// SSRF validation for both modes: scheme/host/port/DNS/private-IP checks
		if _, err := policy.ValidateURL(targetURL, policy.GlobalAllowlist, false); err != nil {
			if wantsHTML {
				renderErrorPage(w, http.StatusForbidden, "Invalid URL", err.Error(), "SSRF_BLOCKED")
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			}
			return
		}

		if !wantsHTML {
			// JSON mode — report schema unchanged
			report, err := InspectEmbed(ctx, targetURL, referer, cfg)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{
					"error":  "embed_inspection_failed",
					"detail": err.Error(),
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(report)
			return
		}

		// HTML mode: native extraction first (timeboxed), iframe playback as
		// the fallback so the embed always renders inside the iframe.
		var streamURL, streamType, poster string
		nativeOK := false

		if !isNativeUnavailable(targetURL) {
			var err error
			nativeCtx, cancel := context.WithTimeout(ctx, nativeAttemptTimeout)
			streamURL, streamType, poster, err = GetStreamFromEmbed(nativeCtx, targetURL, referer, cfg)
			cancel()
			if err == nil && streamType != "" && streamType != "iframe" {
				nativeOK = true
			}
		}

		if !nativeOK {
			// Fallback: frame the provider's embed page directly. The iframe is
			// intentionally NOT sandboxed so JavaScript, DOM storage and cookies
			// keep working — a Turnstile challenge, if the provider shows one,
			// is completed normally by the user inside the WebView/browser.
			renderIframeFallback(w, targetURL)
			return
		}

		// Build the proxied stream URL
		proxyURL := "/stream/proxy?" + url.Values{
			"url":     {streamURL},
			"referer": {referer},
		}.Encode()

		data := PlayerData{
			StreamURL:  proxyURL,
			StreamType: streamType,
			Poster:     poster,
			Referer:    referer,
		}

		if err := RenderPlayerPage(w, data); err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
		}
	}
}

// renderErrorPage renders a minimal styled error page with an HTTP status
func renderErrorPage(w http.ResponseWriter, status int, title, msg, code string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	page := `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Error</title><style>*{margin:0;padding:0;box-sizing:border-box}html,body{height:100%;background:#000;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;padding:20px;text-align:center}.err{max-width:500px}.err h1{font-size:1.5rem;margin-bottom:1rem}.err p{opacity:.8}.err code{font-size:.85rem;opacity:.6;display:block;margin-top:1rem}</style></head><body><div class="err"><h1>` +
		template.HTMLEscapeString(title) + `</h1><p>` + template.HTMLEscapeString(msg) +
		`</p><code>` + template.HTMLEscapeString(code) + `</code></div></body></html>`
	w.Write([]byte(page))
}

// renderIframeFallback serves a full-window, unrestricted iframe pointing at
// the provider's embed page so playback (incl. interactive Turnstile) happens
// natively in the client's browser/WebView.
func renderIframeFallback(w http.ResponseWriter, targetURL string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	page := `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Stream Player</title><style>*{margin:0;padding:0;box-sizing:border-box}html,body{height:100%;width:100%;background:#000;overflow:hidden}iframe{width:100%;height:100%;border:0;display:block;background:#000}</style></head><body><iframe src="` +
		template.HTMLEscapeString(targetURL) +
		`" allow="autoplay; fullscreen; encrypted-media; picture-in-picture; clipboard-write" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></body></html>`
	w.Write([]byte(page))
}
