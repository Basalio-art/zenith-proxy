package embed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"stream-proxy/internal/config"
	"stream-proxy/internal/policy"
	"stream-proxy/internal/upstream"
)

type EmbedReport struct {
	FinalURL      string            `json:"finalUrl"`
	Status        int               `json:"status"`
	ContentType   string            `json:"contentType"`
	Cloudflare    bool              `json:"cloudflare"`
	Iframes       []string          `json:"iframes"`
	PlayerScripts []string          `json:"playerScripts"`
	APICandidates []string          `json:"apiCandidates"`
	DirectStreams []DirectStream    `json:"directStreams"`
	Verdict       string            `json:"verdict"`
	Error         string            `json:"error,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

type DirectStream struct {
	URL     string            `json:"url"`
	Type    string            `json:"type"`
	Headers map[string]string `json:"headers,omitempty"`
}

const (
	maxIframeRecursion = 3
	maxAPICandidates   = 5
	maxPagesFetched    = 8
	inspectTotalBudget = 30 * time.Second
)

// fetchedPage is a single fetched HTML/JSON document
type fetchedPage struct {
	finalURL string
	status   int
	headers  http.Header
	body     []byte
}

// InspectEmbed fetches an embed page, extracts stream candidates, probes API
// candidates and recursively follows iframes (SSRF-validated) to find a
// playable stream.
func InspectEmbed(ctx context.Context, targetURL string, referer string, cfg *config.Config) (*EmbedReport, error) {
	// Overall budget so JSON mode cannot hang indefinitely
	ctx, cancel := context.WithTimeout(ctx, inspectTotalBudget)
	defer cancel()

	clientCfg := &upstream.ClientConfig{
		DialTimeout:     cfg.UpstreamDialTimeout,
		ResponseTimeout: cfg.UpstreamResponseTimeout,
		IdleTimeout:     cfg.UpstreamIdleTimeout,
		MaxRedirects:    3,
		MaxBodySize:     cfg.MaxEmbedSize,
	}

	pagesFetched := 0
	seen := make(map[string]bool)

	page, err := fetchPage(ctx, clientCfg, targetURL, referer, htmlAccept, cfg, &pagesFetched)
	if err != nil {
		return nil, err
	}
	markSeen(seen, page.finalURL)

	report := &EmbedReport{
		FinalURL:    page.finalURL,
		Status:      page.status,
		ContentType: page.headers.Get("Content-Type"),
		Headers:     make(map[string]string),
	}
	for k, v := range page.headers {
		if len(v) > 0 {
			report.Headers[k] = v[0]
		}
	}

	if page.status != 200 {
		report.Verdict = "http_error"
		report.Error = fmt.Sprintf("HTTP %d", page.status)
		return report, nil
	}

	report.Cloudflare = isCloudflareChallenge(page.body)

	// Extract from the top-level page
	extractFromDocument(page.body, page.finalURL, report)

	// If the page itself is a challenge, don't poke further — the browser
	// (WebView) handles that via iframe fallback in the HTML mode.
	if !report.Cloudflare {
		// Probe promising API candidates for embedded stream URLs
		probeAPICandidates(ctx, clientCfg, report, cfg, &pagesFetched, seen)

		// Recursively follow iframes until a stream is found
		recurseIframes(ctx, clientCfg, report, cfg, &pagesFetched, seen, 1)
	}

	dedupeStreams(report)
	report.Verdict = determineVerdict(report)

	return report, nil
}

const htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

// fetchPage performs a single SSRF-validated page fetch with browser headers
func fetchPage(ctx context.Context, clientCfg *upstream.ClientConfig, pageURL, referer, accept string, cfg *config.Config, counter *int) (*fetchedPage, error) {
	if *counter >= maxPagesFetched {
		return nil, fmt.Errorf("embed page budget exceeded")
	}
	*counter++

	// SSRF: validate the target itself (scheme/host/port/DNS/private IP)
	if _, err := policy.ValidateURL(pageURL, policy.GlobalAllowlist, false); err != nil {
		return nil, err
	}

	client, err := upstream.GetClient(extractHost(pageURL), clientCfg)
	if err != nil {
		return nil, err
	}

	stdHeaders := http.Header{
		"User-Agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		"Accept":          {accept},
		"Accept-Language": {"en-US,en;q=0.9"},
	}
	if referer != "" {
		stdHeaders.Set("Referer", referer)
	}
	// BuildRequest merges the Chrome impersonation defaults
	// (sec-ch-ua, sec-fetch-*, Accept-Encoding) on top of these.
	req, err := upstream.BuildRequest("GET", pageURL, upstream.ConvertHeadersFromStd(stdHeaders), nil)
	if err != nil {
		return nil, err
	}

	validateRedirect := func(u *url.URL) error {
		_, err := policy.ValidateURL(u.String(), policy.GlobalAllowlist, false)
		return err
	}

	resp, err := upstream.DoRequest(ctx, client, req, clientCfg, validateRedirect)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxEmbedSize))
	if err != nil && len(body) == 0 {
		return nil, err
	}

	finalURL := pageURL
	if resp.FinalURL != nil {
		finalURL = resp.FinalURL.String()
	}

	return &fetchedPage{
		finalURL: finalURL,
		status:   resp.StatusCode,
		headers:  upstream.ConvertResponseHeadersToStd(resp.Headers),
		body:     body,
	}, nil
}

// extractFromDocument runs all regex extractors against a fetched document
func extractFromDocument(body []byte, baseURL string, report *EmbedReport) {
	html := string(body)
	// Unescaped copy for stream/API URL matching (JSON embeds use \/ etc.)
	unescaped := unescapeJS(html)

	// Extract iframes (from the raw HTML — src attributes are not JS-escaped)
	iframeRe := regexp.MustCompile(`(?i)<iframe[^>]+src=["']([^"']+)["']`)
	for _, match := range iframeRe.FindAllStringSubmatch(html, -1) {
		if len(match) > 1 {
			if abs := resolveURL(baseURL, match[1]); abs != "" {
				report.Iframes = append(report.Iframes, abs)
			}
		}
	}

	// Extract script srcs
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	for _, match := range scriptRe.FindAllStringSubmatch(unescaped, -1) {
		if len(match) > 1 {
			if abs := resolveURL(baseURL, match[1]); abs != "" {
				report.PlayerScripts = append(report.PlayerScripts, abs)
			}
		}
	}

	// Extract potential API endpoints / stream URLs
	apiRe := regexp.MustCompile(`["']?(?:https?:)?//[^"'\s<>]+(?:/api/|/stream/|/play/|/source/|/video/|/manifest/|/playlist/|/m3u8|/mpd|/mp4|/m4s|/ts)[^"'\s<>]*`)
	for _, match := range apiRe.FindAllString(unescaped, -1) {
		if abs := resolveURL(baseURL, match); abs != "" {
			report.APICandidates = append(report.APICandidates, abs)
		}
	}

	// Extract direct stream URLs from common patterns
	extractDirectStreams(unescaped, baseURL, &report.DirectStreams)
}

// probeAPICandidates fetches the most promising API candidates and extracts
// stream URLs from their responses.
func probeAPICandidates(ctx context.Context, clientCfg *upstream.ClientConfig, report *EmbedReport, cfg *config.Config, counter *int, seen map[string]bool) {
	probed := 0
	for _, cand := range report.APICandidates {
		if probed >= maxAPICandidates || *counter >= maxPagesFetched {
			return
		}
		if !isProbeableCandidate(cand) {
			continue
		}
		key := strings.Split(cand, "#")[0]
		if seen[key] {
			continue
		}
		seen[key] = true

		page, err := fetchPage(ctx, clientCfg, cand, report.FinalURL, "*/*", cfg, counter)
		if err != nil || page.status != 200 {
			continue
		}
		probed++

		// Parse the API response for stream URLs
		before := len(report.DirectStreams)
		extractDirectStreams(unescapeJS(string(page.body)), page.finalURL, &report.DirectStreams)
		// Also pick up any nested API links (one extra level)
		apiRe := regexp.MustCompile(`["']?(?:https?:)?//[^"'\s<>]+(?:/m3u8|/mpd|/mp4|/manifest|/playlist)[^"'\s<>]*`)
		for _, match := range apiRe.FindAllString(unescapeJS(string(page.body)), -1) {
			if abs := resolveURL(page.finalURL, match); abs != "" {
				report.APICandidates = append(report.APICandidates, abs)
			}
		}
		if len(report.DirectStreams) > before {
			// Found what we need — stop probing
			return
		}
	}
}

// recurseIframes follows page iframes (SSRF-validated) looking for a stream
func recurseIframes(ctx context.Context, clientCfg *upstream.ClientConfig, report *EmbedReport, cfg *config.Config, counter *int, seen map[string]bool, depth int) {
	if depth > maxIframeRecursion || *counter >= maxPagesFetched {
		return
	}
	if len(report.DirectStreams) > 0 {
		return
	}

	// Snapshot candidates discovered at this level
	queue := make([]string, len(report.Iframes))
	copy(queue, report.Iframes)

	for _, src := range queue {
		if len(report.DirectStreams) > 0 || *counter >= maxPagesFetched {
			return
		}
		key := strings.Split(src, "#")[0]
		if seen[key] {
			continue
		}
		seen[key] = true

		page, err := fetchPage(ctx, clientCfg, src, report.FinalURL, htmlAccept, cfg, counter)
		if err != nil || page.status != 200 {
			continue
		}
		markSeen(seen, page.finalURL)

		// Challenge page inside an iframe: stop here; HTML mode falls back
		// to iframe playback so the browser can clear it if interactive.
		if isCloudflareChallenge(page.body) {
			report.Cloudflare = true
			continue
		}

		// Extract into the shared report (nested iframes/scripts accumulate)
		extractFromDocument(page.body, page.finalURL, report)
		if len(report.DirectStreams) > 0 {
			return
		}

		// One level of API probing from the nested page
		probeAPICandidates(ctx, clientCfg, report, cfg, counter, seen)
		if len(report.DirectStreams) > 0 {
			return
		}
	}

	// Continue deeper with any iframes discovered along the way
	if len(report.DirectStreams) == 0 {
		recurseIframes(ctx, clientCfg, report, cfg, counter, seen, depth+1)
	}
}

func markSeen(seen map[string]bool, u string) {
	seen[strings.Split(u, "#")[0]] = true
}

func isProbeableCandidate(u string) bool {
	lower := strings.ToLower(u)
	switch {
	case strings.Contains(lower, ".m3u8"), strings.Contains(lower, ".mpd"), strings.Contains(lower, ".mp4"):
		return true
	case strings.Contains(lower, "/api/") || strings.Contains(lower, "getsource"),
		strings.Contains(lower, "/stream/"), strings.Contains(lower, "/source"):
		return true
	}
	return false
}

// jsEscaper unescapes common JSON/JS string escapes so regexes can see URLs
var jsEscaper = strings.NewReplacer(
	`\/`, `/`,
	`\u002F`, `/`,
	`\u002f`, `/`,
	`\u0026`, `&`,
	`\u003D`, `=`,
	`\u003d`, `=`,
	`\u003A`, `:`,
	`\u003a`, `:`,
	`&amp;`, `&`,
)

func unescapeJS(s string) string {
	return jsEscaper.Replace(s)
}

func dedupeStreams(r *EmbedReport) {
	seen := make(map[string]bool)
	out := r.DirectStreams[:0]
	for _, ds := range r.DirectStreams {
		if seen[ds.URL] {
			continue
		}
		seen[ds.URL] = true
		out = append(out, ds)
	}
	r.DirectStreams = out
}

func extractDirectStreams(html, baseURL string, streams *[]DirectStream) {
	// Common patterns for direct streams
	patterns := []struct {
		regex *regexp.Regexp
		typ   string
	}{
		{regexp.MustCompile(`["'](https?://[^"'\s]+\.m3u8[^"'\s]*)["']`), "hls"},
		{regexp.MustCompile(`["'](https?://[^"'\s]+\.mp4[^"'\s]*)["']`), "mp4"},
		{regexp.MustCompile(`["'](https?://[^"'\s]+\.mpd[^"'\s]*)["']`), "dash"},
		{regexp.MustCompile(`["'](https?://[^"'\s]+/play/[^"'\s]+\.mp4[^"'\s]*)["']`), "mp4"},
		{regexp.MustCompile(`["'](https?://[^"'\s]+/stream/[^"'\s]*)["']`), "hls"},
		{regexp.MustCompile(`["'](https?://[^"'\s]+/manifest/[^"'\s]*)["']`), "dash"},
		// JWPlayer sources
		{regexp.MustCompile(`(?i)sources\s*:\s*\[\s*\{\s*["']file["']\s*:\s*["']([^"']+)["']`), "hls"},
		{regexp.MustCompile(`(?i)file\s*:\s*["']([^"']+\.m3u8[^"']*)["']`), "hls"},
		{regexp.MustCompile(`(?i)file\s*:\s*["']([^"']+\.mp4[^"']*)["']`), "mp4"},
		// Clappr / other players
		{regexp.MustCompile(`(?i)source\s*:\s*["']([^"']+\.m3u8[^"']*)["']`), "hls"},
		{regexp.MustCompile(`(?i)source\s*:\s*["']([^"']+\.mp4[^"']*)["']`), "mp4"},
		// JSON: "file": "..." / "src": "..." / "url": "..." with media extensions
		{regexp.MustCompile(`(?i)["'](?:file|src|url|source)["']\s*:\s*["'](https?://[^"']+\.(?:m3u8|mp4|mpd)[^"']*)["']`), "hls"},
	}

	seen := make(map[string]bool)
	for _, p := range patterns {
		for _, match := range p.regex.FindAllStringSubmatch(html, -1) {
			if len(match) > 1 {
				raw := match[1]
				if seen[raw] {
					continue
				}
				seen[raw] = true
				abs := resolveURL(baseURL, raw)
				if abs != "" {
					typ := p.typ
					// Correct type by extension for the generic JSON pattern
					lower := strings.ToLower(abs)
					switch {
					case strings.Contains(lower, ".mpd"):
						typ = "dash"
					case strings.Contains(lower, ".mp4"):
						typ = "mp4"
					case strings.Contains(lower, ".m3u8"):
						typ = "hls"
					}
					*streams = append(*streams, DirectStream{
						URL:  abs,
						Type: typ,
					})
				}
			}
		}
	}
}

func determineVerdict(r *EmbedReport) string {
	if r.Cloudflare {
		return "unsupported_anti_bot"
	}
	if len(r.DirectStreams) > 0 {
		return "stream_extracted"
	}
	if len(r.Iframes) > 0 {
		return "iframe_only"
	}
	if len(r.APICandidates) > 0 {
		return "api_candidates"
	}
	return "unknown"
}

func isCloudflareChallenge(body []byte) bool {
	html := strings.ToLower(string(body))
	return strings.Contains(html, "cf-browser-verification") ||
		strings.Contains(html, "cf-challenge") ||
		strings.Contains(html, "just a moment") ||
		strings.Contains(html, "checking your browser") ||
		strings.Contains(html, "cdn-cgi/challenge-platform") ||
		strings.Contains(html, "__cf$cv$params") ||
		strings.Contains(html, "ray id")
}

func resolveURL(base, ref string) string {
	if ref == "" {
		return ""
	}
	// Handle protocol-relative URLs
	if strings.HasPrefix(ref, "//") {
		ref = "https:" + ref
	}
	ref = strings.Trim(ref, `"' `)
	if strings.HasPrefix(strings.ToLower(ref), "data:") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	resolved := baseURL.ResolveReference(u)
	return resolved.String()
}

func extractHost(urlStr string) string {
	if strings.HasPrefix(urlStr, "http://") {
		urlStr = urlStr[7:]
	} else if strings.HasPrefix(urlStr, "https://") {
		urlStr = urlStr[8:]
	}
	if idx := strings.Index(urlStr, "/"); idx >= 0 {
		return urlStr[:idx]
	}
	return urlStr
}

// ExtractHost extracts the host from a URL string (exported for use by other packages)
func ExtractHost(urlStr string) string {
	return extractHost(urlStr)
}
