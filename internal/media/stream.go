package media

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	tls_client "github.com/bogdanfinn/tls-client"

	"stream-proxy/internal/config"
	"stream-proxy/internal/dash"
	"stream-proxy/internal/hls"
	"stream-proxy/internal/upstream"
)

const (
	maxPlaylistRead = 2 * 1024 * 1024 // 2MB for playlists
	maxMPDRead      = 1024 * 1024     // 1MB for MPD
	peekSize        = 512             // bytes to peek for magic-byte detection
	streamBufSize   = 32 * 1024       // 32KB streaming buffer
)

// MediaKind represents the detected media type
type MediaKind int

const (
	MediaKindUnknown MediaKind = iota
	MediaKindHLS
	MediaKindDASH
	MediaKindMP4
	MediaKindWebM
	MediaKindEmbed
)

// ProbeResult holds the result of a probe request
type ProbeResult struct {
	Kind         MediaKind
	ContentType  string
	StatusCode   int
	RedirectURL  *url.URL
	Headers      http.Header
	Sample       []byte
}

// Cloudflare/anti-bot challenge detection patterns
var challengePatterns = []string{
	"cf-browser-verification",
	"cf-challenge",
	"just a moment",
	"checking your browser",
	"cdn-cgi/challenge-platform",
	"__cf$cv$params",
	"ray id",
	"access denied",
	"challenge-platform",
	"turnstile",
}

// isChallengeResponse detects if the upstream response is a Cloudflare/anti-bot challenge page
func isChallengeResponse(body []byte, contentType string) bool {
	ct := strings.ToLower(contentType)
	// HTML or text responses with challenge indicators
	if strings.Contains(ct, "html") || strings.Contains(ct, "text") || ct == "" {
		lower := strings.ToLower(string(body))
		for _, p := range challengePatterns {
			if strings.Contains(lower, p) {
				return true
			}
		}
	}
	// Some challenge pages have weird content types
	if len(body) > 0 && body[0] == '<' {
		lower := strings.ToLower(string(body))
		for _, p := range challengePatterns {
			if strings.Contains(lower, p) {
				return true
			}
		}
	}
	// Specific Cloudflare content type seen in the wild
	if strings.Contains(ct, "trolltech") || strings.Contains(ct, "linguist") {
		return true
	}
	return false
}

// correctContentType infers the real Content-Type from magic bytes
func correctContentType(body []byte, originalCT string) string {
	if len(body) == 0 {
		return originalCT
	}

	// HLS: #EXTM3U
	if len(body) >= 7 && strings.HasPrefix(strings.TrimSpace(string(body)), "#EXTM3U") {
		return "application/vnd.apple.mpegurl"
	}
	// DASH: <?xml ... <MPD
	if len(body) >= 4 && (string(body[:4]) == "<?xml" || strings.Contains(string(body[:min(200, len(body))]), "<MPD")) {
		return "application/dash+xml"
	}
	// MP4: ftyp box at offset 4
	if len(body) >= 8 && string(body[4:8]) == "ftyp" {
		return "video/mp4"
	}
	// MPEG-TS: sync byte 0x47 at 188-byte intervals
	if len(body) >= 188 && body[0] == 0x47 && body[188] == 0x47 {
		return "video/mp2t"
	}
	// WebM/MKV: EBML magic
	if len(body) >= 4 && body[0] == 0x1a && body[1] == 0x45 && body[2] == 0xdf && body[3] == 0xa3 {
		return "video/webm"
	}
	// MP4 without ftyp at 4 (some variants)
	if len(body) >= 8 && body[0] == 0x00 && body[1] == 0x00 && body[2] == 0x00 {
		return "video/mp4"
	}
	return originalCT
}

// min returns the smaller of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ProbeMedia does a lightweight HEAD/GET to detect media type
func ProbeMedia(ctx context.Context, targetURL string, headers http.Header, cfg *config.Config) (*ProbeResult, error) {
	clientCfg := &upstream.ClientConfig{
		DialTimeout:     cfg.UpstreamDialTimeout,
		ResponseTimeout: cfg.UpstreamResponseTimeout,
		IdleTimeout:     cfg.UpstreamIdleTimeout,
		MaxRedirects:    5,
		MaxBodySize:     8192,
	}

	client, err := upstream.GetClient(extractHost(targetURL), clientCfg)
	if err != nil {
		return nil, err
	}

	fhttpHeaders := upstream.ConvertHeadersFromStd(headers)

	req, err := upstream.BuildRequest("GET", targetURL, fhttpHeaders, nil)
	if err != nil {
		return nil, err
	}

	validateRedirect := func(u *url.URL) error {
		return nil // allow for probe
	}

	resp, err := upstream.DoRequest(ctx, client, req, clientCfg, validateRedirect)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	sample := make([]byte, 8192)
	n, _ := resp.Body.Read(sample)
	sample = sample[:n]

	respHeaders := upstream.ConvertResponseHeadersToStd(resp.Headers)

	kind := DetectKind(sample, respHeaders.Get("Content-Type"))

	return &ProbeResult{
		Kind:         kind,
		ContentType:  respHeaders.Get("Content-Type"),
		StatusCode:   resp.StatusCode,
		RedirectURL:  resp.FinalURL,
		Headers:      respHeaders,
		Sample:       sample,
	}, nil
}

// DetectKind classifies media from sample bytes and Content-Type header
func DetectKind(body []byte, contentType string) MediaKind {
	ct := strings.ToLower(contentType)

	if strings.Contains(ct, "mpegurl") || strings.Contains(ct, "m3u8") || strings.Contains(ct, "vnd.apple.mpegurl") {
		return MediaKindHLS
	}
	if strings.Contains(ct, "dash") || strings.Contains(ct, "mpd") {
		return MediaKindDASH
	}
	if strings.Contains(ct, "mp4") {
		return MediaKindMP4
	}
	if strings.Contains(ct, "webm") || (len(body) >= 4 && body[0] == 0x1a && body[1] == 0x45 && body[2] == 0xdf && body[3] == 0xa3) {
		return MediaKindWebM
	}

	// Fallback to magic bytes
	if len(body) >= 7 && strings.HasPrefix(strings.TrimSpace(string(body)), "#EXTM3U") {
		return MediaKindHLS
	}
	if len(body) >= 4 && (string(body[:4]) == "<?xml" || strings.Contains(string(body[:min(200, len(body))]), "<MPD")) {
		return MediaKindDASH
	}
	if len(body) >= 8 && (string(body[4:8]) == "ftyp" || (body[0] == 0x00 && body[1] == 0x00 && body[2] == 0x00)) {
		return MediaKindMP4
	}
	if len(body) >= 4 && body[0] == 0x1a && body[1] == 0x45 && body[2] == 0xdf && body[3] == 0xa3 {
		return MediaKindWebM
	}

	return MediaKindUnknown
}

// StreamMedia is the main entry point for streaming
func StreamMedia(ctx context.Context, w http.ResponseWriter, r *http.Request, targetURL string, headers http.Header, kind MediaKind, codec string, playlistKey []byte, cfg *config.Config) error {
	clientCfg := &upstream.ClientConfig{
		DialTimeout:     cfg.UpstreamDialTimeout,
		ResponseTimeout: cfg.UpstreamResponseTimeout,
		IdleTimeout:     cfg.UpstreamIdleTimeout,
		MaxRedirects:    5,
		MaxBodySize:     0, // no limit for streaming
	}

	client, err := upstream.GetClient(extractHost(targetURL), clientCfg)
	if err != nil {
		return err
	}

	validateRedirect := func(u *url.URL) error {
		return nil
	}

	switch kind {
	case MediaKindHLS:
		return streamHLS(ctx, w, r, targetURL, headers, client, clientCfg, validateRedirect, codec, playlistKey, cfg)
	case MediaKindDASH:
		return streamDASH(ctx, w, r, targetURL, headers, client, clientCfg, validateRedirect, cfg)
	case MediaKindMP4, MediaKindWebM:
		return streamDirect(ctx, w, r, targetURL, headers, client, clientCfg, validateRedirect, cfg)
	default:
		return streamDirect(ctx, w, r, targetURL, headers, client, clientCfg, validateRedirect, cfg)
	}
}

// streamHLS handles HLS manifests and segments
func streamHLS(ctx context.Context, w http.ResponseWriter, r *http.Request, targetURL string, headers http.Header, client tls_client.HttpClient, clientCfg *upstream.ClientConfig, validateRedirect func(*url.URL) error, codec string, playlistKey []byte, cfg *config.Config) error {
	fhttpHeaders := upstream.ConvertHeadersFromStd(headers)

	req, err := upstream.BuildRequest(r.Method, targetURL, fhttpHeaders, nil)
	if err != nil {
		return err
	}

	// Forward Range for segment requests
	if rangeHdr := r.Header.Get("Range"); rangeHdr != "" {
		req.Header.Set("Range", rangeHdr)
	}

	resp, err := upstream.DoRequest(ctx, client, req, clientCfg, validateRedirect)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Peek first 512 bytes to decide playlist vs media without buffering full body
	peekBuf := make([]byte, peekSize)
	n, _ := io.ReadFull(io.LimitReader(resp.Body, int64(peekSize)), peekBuf)
	peekBuf = peekBuf[:n]

	// Check for Cloudflare challenge immediately
	if isChallengeResponse(peekBuf, resp.Headers.Get("Content-Type")) {
		return errors.New("unsupported_anti_bot: upstream returned Cloudflare challenge")
	}

	// Detect if this is a playlist by magic bytes
	isPlaylist := false
	if codec == "flixcloud-b64-xor" && len(playlistKey) > 0 {
		// For flixcloud, we MUST read full body and decode first
		// The upstream response is base64 encoded, not the decoded manifest
		isPlaylist = true // Force full read + decode
	} else {
		if len(peekBuf) >= 7 && strings.HasPrefix(strings.TrimSpace(string(peekBuf)), "#EXTM3U") {
			isPlaylist = true
		}
	}

	// For playlist: read full body (limited), decode/rewrite, serve
	if isPlaylist {
		// Read the rest of the playlist
		rest, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxPlaylistRead-peekSize)))
		if err != nil {
			return err
		}
		fullBody := append(peekBuf, rest...)

		// For flixcloud, decode first
		var manifest string
		if codec == "flixcloud-b64-xor" && len(playlistKey) > 0 {
			decoded, err := hls.DecodeFlixcloudPlaylist(fullBody, playlistKey)
			if err != nil {
				return err
			}
			manifest = string(decoded)
		} else {
			kind := hls.DetectPlaylistType(fullBody)
			if kind == hls.PlaylistTypeUnknown {
				// Not a playlist after all - stream it as media
				return streamMediaBody(w, r, resp, fullBody, "video/mp2t")
			}
			manifest = string(fullBody)
		}

		// Rewrite manifest
		baseURL := resp.FinalURL
		if baseURL == nil {
			baseURL, _ = url.Parse(targetURL)
		}

		referer := headers.Get("Referer")
		origin := headers.Get("Origin")
		token := ""

		rewritten := hls.RewriteManifest(manifest, baseURL, referer, origin, token, codec, playlistKey)

		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Length", strconv.Itoa(len(rewritten)))
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(rewritten))
		return err
	}

	// Not a playlist - stream as media (segment)
	return streamMediaBody(w, r, resp, peekBuf, "video/mp2t")
}

// streamDASH handles DASH MPD manifests
func streamDASH(ctx context.Context, w http.ResponseWriter, r *http.Request, targetURL string, headers http.Header, client tls_client.HttpClient, clientCfg *upstream.ClientConfig, validateRedirect func(*url.URL) error, cfg *config.Config) error {
	fhttpHeaders := upstream.ConvertHeadersFromStd(headers)

	req, err := upstream.BuildRequest(r.Method, targetURL, fhttpHeaders, nil)
	if err != nil {
		return err
	}

	resp, err := upstream.DoRequest(ctx, client, req, clientCfg, validateRedirect)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Peek for challenge detection and MPD detection
	peekBuf := make([]byte, peekSize)
	n, _ := io.ReadFull(io.LimitReader(resp.Body, int64(peekSize)), peekBuf)
	peekBuf = peekBuf[:n]

	if isChallengeResponse(peekBuf, resp.Headers.Get("Content-Type")) {
		return errors.New("unsupported_anti_bot: upstream returned Cloudflare challenge")
	}

	// Check if it's an MPD
	isMPD := len(peekBuf) >= 4 && (string(peekBuf[:4]) == "<?xml" || strings.Contains(string(peekBuf[:min(200, len(peekBuf))]), "<MPD"))

	if isMPD {
		rest, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxMPDRead-peekSize)))
		if err != nil {
			return err
		}
		fullBody := append(peekBuf, rest...)

		baseURL := resp.FinalURL
		if baseURL == nil {
			baseURL, _ = url.Parse(targetURL)
		}

		referer := headers.Get("Referer")
		origin := headers.Get("Origin")
		token := ""

		rewritten, err := dash.RewriteMPD(string(fullBody), baseURL, referer, origin, token)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/dash+xml")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Length", strconv.Itoa(len(rewritten)))
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(rewritten))
		return err
	}

	// Not an MPD - could be an init segment or media segment
	ct := correctContentType(peekBuf, resp.Headers.Get("Content-Type"))
	return streamMediaBody(w, r, resp, peekBuf, ct)
}

// streamDirect handles MP4, WebM, and other direct media with Range support
func streamDirect(ctx context.Context, w http.ResponseWriter, r *http.Request, targetURL string, headers http.Header, client tls_client.HttpClient, clientCfg *upstream.ClientConfig, validateRedirect func(*url.URL) error, cfg *config.Config) error {
	fhttpHeaders := upstream.ConvertHeadersFromStd(headers)

	clientRange := r.Header.Get("Range")
	clientIfRange := r.Header.Get("If-Range")

	// Helper to make request and peek response
	makeRequest := func(withRange bool) (*upstream.Response, []byte, http.Header, string, error) {
		req, err := upstream.BuildRequest(r.Method, targetURL, fhttpHeaders, nil)
		if err != nil {
			return nil, nil, nil, "", err
		}
		if withRange && clientRange != "" {
			req.Header.Set("Range", clientRange)
		}
		if withRange && clientIfRange != "" {
			req.Header.Set("If-Range", clientIfRange)
		}

		resp, err := upstream.DoRequest(ctx, client, req, clientCfg, validateRedirect)
		if err != nil {
			return nil, nil, nil, "", err
		}

		peekBuf := make([]byte, peekSize)
		n, err := io.ReadFull(io.LimitReader(resp.Body, int64(peekSize)), peekBuf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			resp.Body.Close()
			return nil, nil, nil, "", err
		}
		peekBuf = peekBuf[:n]

		if isChallengeResponse(peekBuf, resp.Headers.Get("Content-Type")) {
			resp.Body.Close()
			return nil, nil, nil, "", errors.New("unsupported_anti_bot: upstream returned Cloudflare challenge")
		}

		respHeaders := upstream.ConvertResponseHeadersToStd(resp.Headers)
		ct := correctContentType(peekBuf, respHeaders.Get("Content-Type"))
		return resp, peekBuf, respHeaders, ct, nil
	}

	// First attempt with Range if requested
	requestedRange := r.Header.Get("Range")
	var resp *upstream.Response
	var peekBuf []byte
	var respHeaders http.Header
	var ct string
	var upstreamStatus int
	var err error

	if requestedRange != "" {
		resp, peekBuf, respHeaders, ct, err = makeRequest(true)
		if err != nil {
			return err
		}
		upstreamStatus = resp.StatusCode

		// If upstream ignored Range (200) or rejected it (416), retry without Range
		if upstreamStatus == http.StatusOK || upstreamStatus == http.StatusRequestedRangeNotSatisfiable {
			resp.Body.Close()
			resp, peekBuf, respHeaders, ct, err = makeRequest(false)
			if err != nil {
				return err
			}
			upstreamStatus = resp.StatusCode
		}
	} else {
		resp, peekBuf, respHeaders, ct, err = makeRequest(false)
		if err != nil {
			return err
		}
		upstreamStatus = resp.StatusCode
	}
	defer resp.Body.Close()

	// Handle Range enforcement: if client requested Range but upstream didn't honor it
	if requestedRange != "" && upstreamStatus == http.StatusOK {
		// Upstream ignored Range - enforce locally
		return enforceRange(w, resp, peekBuf, ct, requestedRange, respHeaders.Get("Content-Length"))
	}

	// Normal case: upstream respected Range (206) or no Range requested
	return streamMediaBodyWithHeaders(w, r, resp, peekBuf, ct, respHeaders, upstreamStatus)
}

// enforceRange manually skips/seeks when upstream ignores Range
func enforceRange(w http.ResponseWriter, resp *upstream.Response, peekBuf []byte, contentType, requestedRange, contentLengthStr string) error {
	// Parse Content-Length
	contentLength := int64(0)
	if contentLengthStr != "" {
		contentLength, _ = strconv.ParseInt(contentLengthStr, 10, 64)
	}

	// Parse Range header: "bytes=start-end"
	var start, end int64
	if !strings.HasPrefix(requestedRange, "bytes=") {
		return errors.New("invalid range format")
	}
	rangeVal := strings.TrimPrefix(requestedRange, "bytes=")
	parts := strings.Split(rangeVal, "-")
	if len(parts) != 2 {
		return errors.New("invalid range format")
	}
	start, _ = strconv.ParseInt(parts[0], 10, 64)
	if parts[1] != "" {
		end, _ = strconv.ParseInt(parts[1], 10, 64)
	} else {
		end = contentLength - 1
	}

	// If contentLength is unknown (0), read the full body into memory to determine it
	if contentLength == 0 {
		// Combine peekBuf with remaining body
		bodyData := bytes.NewBuffer(peekBuf)
		buf := make([]byte, streamBufSize)
		_, err := io.CopyBuffer(bodyData, resp.Body, buf)
		if err != nil {
			return err
		}
		fullBody := bodyData.Bytes()
		contentLength = int64(len(fullBody))

		// Adjust end if needed
		if end >= contentLength {
			end = contentLength - 1
		}
		if start > end || start >= contentLength {
			w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(contentLength, 10))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return nil
		}

		// Serve the requested range from memory
		rangeData := fullBody[start : end+1]

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(contentLength, 10))
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.WriteHeader(http.StatusPartialContent)

		_, err = w.Write(rangeData)
		return err
	}

	if end >= contentLength {
		end = contentLength - 1
	}
	if start > end || start >= contentLength {
		w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(contentLength, 10))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return nil
	}

	// Skip bytes before start
	if start > 0 {
		skipBuf := make([]byte, min(int(start), streamBufSize))
		for skipped := int64(0); skipped < start; {
			toRead := min(len(skipBuf), int(start-skipped))
			n, err := io.ReadFull(resp.Body, skipBuf[:toRead])
			if err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					break
				}
				return err
			}
			skipped += int64(n)
		}
	}

	// Set response headers for 206
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(contentLength, 10))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(http.StatusPartialContent)

	// Stream the requested range
	limitReader := io.LimitReader(resp.Body, end-start+1)
	buf := make([]byte, streamBufSize)
	_, err := io.CopyBuffer(w, limitReader, buf)
	return err
}

// streamMediaBody streams a media body (peekBuf + remaining body) with corrected Content-Type
func streamMediaBody(w http.ResponseWriter, r *http.Request, resp *upstream.Response, peekBuf []byte, contentType string) error {
	respHeaders := upstream.ConvertResponseHeadersToStd(resp.Headers)
	return streamMediaBodyWithHeaders(w, r, resp, peekBuf, contentType, respHeaders, resp.StatusCode)
}

// streamMediaBodyWithHeaders writes headers then streams body
func streamMediaBodyWithHeaders(w http.ResponseWriter, r *http.Request, resp *upstream.Response, peekBuf []byte, contentType string, respHeaders http.Header, statusCode int) error {
	// Copy relevant headers from upstream
	for _, name := range []string{
		"Content-Length", "Content-Range", "Accept-Ranges",
		"ETag", "Last-Modified", "Cache-Control", "Expires",
	} {
		if v := respHeaders.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	// Override Content-Type with corrected one
	w.Header().Set("Content-Type", contentType)
	if w.Header().Get("Accept-Ranges") == "" {
		w.Header().Set("Accept-Ranges", "bytes")
	}

	w.WriteHeader(statusCode)

	if r.Method == http.MethodHead {
		return nil
	}

	// Write peekBuf first, then stream the rest
	if len(peekBuf) > 0 {
		if _, err := w.Write(peekBuf); err != nil {
			return err
		}
	}

	buf := make([]byte, streamBufSize)
	_, err := io.CopyBuffer(w, resp.Body, buf)
	return err
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