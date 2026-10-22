package upstream

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	httpclient "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"stream-proxy/internal/policy"
)

var (
	clientPool sync.Map // host -> tls_client.HttpClient
	poolMu     sync.Mutex
)

type ClientConfig struct {
	DialTimeout     time.Duration
	ResponseTimeout time.Duration
	IdleTimeout     time.Duration
	MaxRedirects    int
	MaxBodySize     int64
}

func GetClient(host string, cfg *ClientConfig) (tls_client.HttpClient, error) {
	if v, ok := clientPool.Load(host); ok {
		return v.(tls_client.HttpClient), nil
	}

	poolMu.Lock()
	defer poolMu.Unlock()

	// Double-check
	if v, ok := clientPool.Load(host); ok {
		return v.(tls_client.HttpClient), nil
	}

	jar := tls_client.NewCookieJar()

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(int(cfg.ResponseTimeout.Seconds())),
		tls_client.WithClientProfile(profiles.Chrome_131),
		tls_client.WithCookieJar(jar),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithInsecureSkipVerify(),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS client: %w", err)
	}

	clientPool.Store(host, client)
	return client, nil
}

type Response struct {
	StatusCode    int
	Headers       httpclient.Header
	Body          io.ReadCloser
	ContentLength int64
	FinalURL      *url.URL
}

func DoRequest(ctx context.Context, client tls_client.HttpClient, req *httpclient.Request, cfg *ClientConfig, validateRedirect policy.ValidateRedirectFunc) (*Response, error) {
	// Custom redirect policy
	redirectCount := 0
	var finalURL *url.URL
	var finalReq *httpclient.Request = req

	for {
		resp, err := client.Do(finalReq)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}

		finalURL = finalReq.URL
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL
		}

		// Check redirect
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc != "" && redirectCount < cfg.MaxRedirects {
				resp.Body.Close()
				redirectCount++

				nextURL, err := finalURL.Parse(loc)
				if err != nil {
					return nil, fmt.Errorf("invalid redirect location: %w", err)
				}

				// Validate redirect target
				if validateRedirect != nil {
					if err := validateRedirect(nextURL); err != nil {
						return nil, fmt.Errorf("redirect blocked: %w", err)
					}
				}

				// Create new request for redirect
				newReq, err := httpclient.NewRequest(finalReq.Method, nextURL.String(), nil)
				if err != nil {
					return nil, fmt.Errorf("failed to create redirect request: %w", err)
				}
				// Copy headers
				for k, v := range finalReq.Header {
					newReq.Header[k] = v
				}
				// Update Host header
				newReq.Header.Set("Host", nextURL.Host)
				finalReq = newReq
				continue
			}
		}

		return &Response{
			StatusCode:    resp.StatusCode,
			Headers:       resp.Header,
			Body:          resp.Body,
			ContentLength: resp.ContentLength,
			FinalURL:      finalURL,
		}, nil
	}
}

func BuildRequest(method, urlStr string, headers httpclient.Header, body io.Reader) (*httpclient.Request, error) {
	req, err := httpclient.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}

	// Set default headers
	req.Header = httpclient.Header{
		"User-Agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		"Accept":             {"*/*"},
		"Accept-Language":    {"en-US,en;q=0.9"},
		"Accept-Encoding":    {"identity"},
		"sec-ch-ua":          {`"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {`"Windows"`},
		"sec-fetch-site":     {"cross-site"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"Priority":           {"u=1, i"},
	}

	// Override with provided headers
	for k, v := range headers {
		req.Header[k] = v
	}

	return req, nil
}

func ConvertHeaders(src httpclient.Header) httpclient.Header {
	dst := make(httpclient.Header)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func ConvertResponseHeaders(src httpclient.Header) httpclient.Header {
	dst := make(httpclient.Header)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func ConvertHeadersFromStd(src http.Header) httpclient.Header {
	dst := make(httpclient.Header)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func ConvertResponseHeadersToStd(src httpclient.Header) http.Header {
	dst := make(http.Header)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func CopyHeaders(dst httpclient.Header, src httpclient.Header, keys []string) {
	for _, k := range keys {
		if v := src.Get(k); v != "" {
			dst.Set(k, v)
		}
	}
}

func DetectContentType(body []byte, headerCT string) string {
	ct := strings.ToLower(headerCT)
	if strings.Contains(ct, "mpegurl") || strings.Contains(ct, "m3u8") || strings.Contains(ct, "vnd.apple.mpegurl") {
		return "hls"
	}
	if strings.Contains(ct, "dash") || strings.Contains(ct, "mpd") {
		return "dash"
	}
	if strings.Contains(ct, "mp4") || strings.Contains(ct, "octet-stream") {
		// Check magic bytes
		if len(body) >= 8 && (string(body[4:8]) == "ftyp" || body[0] == 0x00 && body[1] == 0x00 && body[2] == 0x00) {
			return "mp4"
		}
	}
	if strings.Contains(ct, "webm") || (len(body) >= 4 && body[0] == 0x1a && body[1] == 0x45 && body[2] == 0xdf && body[3] == 0xa3) {
		return "webm"
	}
	if len(body) >= 7 && string(body[:7]) == "#EXTM3U" {
		return "hls"
	}
	if len(body) >= 4 && string(body[:4]) == "<?xml" {
		return "dash"
	}
	if len(body) > 0 && body[0] == '<' {
		return "html"
	}
	return "unknown"
}