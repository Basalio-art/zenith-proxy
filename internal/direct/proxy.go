package direct

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"stream-proxy/internal/config"
	"stream-proxy/internal/policy"
	"stream-proxy/internal/upstream"
)

func ProxyDirect(ctx context.Context, w http.ResponseWriter, r *http.Request, targetURL string, headers http.Header, cfg *config.Config, allowRange bool) error {
	clientCfg := &upstream.ClientConfig{
		DialTimeout:     cfg.UpstreamDialTimeout,
		ResponseTimeout: cfg.UpstreamResponseTimeout,
		IdleTimeout:     cfg.UpstreamIdleTimeout,
		MaxRedirects:    5,
		MaxBodySize:     0, // streaming
	}

	client, err := upstream.GetClient(extractHost(targetURL), clientCfg)
	if err != nil {
		return err
	}

	// Build upstream request - convert http.Header to fhttp.Header
	fhttpHeaders := upstream.ConvertHeadersFromStd(headers)
	req, err := upstream.BuildRequest(r.Method, targetURL, fhttpHeaders, nil)
	if err != nil {
		return err
	}

	// Forward Range header if allowed
	if allowRange {
		if rangeHdr := r.Header.Get("Range"); rangeHdr != "" {
			req.Header.Set("Range", rangeHdr)
		}
		if ifRange := r.Header.Get("If-Range"); ifRange != "" {
			req.Header.Set("If-Range", ifRange)
		}
	}

	// Validate redirects against allowlist
	validateRedirect := func(u *url.URL) error {
		host := u.Hostname()
		if host == "" {
			return policy.ErrInvalidURL
		}
		return nil
	}

	resp, err := upstream.DoRequest(ctx, client, req, clientCfg, validateRedirect)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Copy relevant headers - convert fhttp.Header to http.Header
	respHeaders := upstream.ConvertResponseHeadersToStd(resp.Headers)
	copyResponseHeaders(w, respHeaders)

	// Set content type
	if ct := respHeaders.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	// Ensure Accept-Ranges is set
	if w.Header().Get("Accept-Ranges") == "" {
		w.Header().Set("Accept-Ranges", "bytes")
	}

	w.WriteHeader(resp.StatusCode)

	if r.Method == http.MethodHead {
		return nil
	}

	// Stream the body
	bufSize := 32 * 1024
	buf := make([]byte, bufSize)
	_, err = io.CopyBuffer(w, resp.Body, buf)
	return err
}

func copyResponseHeaders(w http.ResponseWriter, respHeaders http.Header) {
	for _, name := range []string{
		"Content-Length",
		"Content-Range",
		"Accept-Ranges",
		"ETag",
		"Last-Modified",
		"Cache-Control",
		"Expires",
	} {
		if v := respHeaders.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
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